package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	listener         net.Listener
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	Address          string
	Banner           string
	SSHConfig        *ssh.ServerConfig
	Authenticator    Authenticator
	LogWriter        io.Writer
	ProxyPolicy      ProxyPolicyConfig
	HandshakeTimeout time.Duration
	UpstreamTimeout  time.Duration
	Metrics          *Metrics
}

const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultAuthTimeout      = 30 * time.Second
	defaultUpstreamTimeout  = 30 * time.Second
)

type upstreamInformation struct {
	Address          string
	Signer           ssh.Signer
	Password         *string
	ProxyProtocol    *byte
	ProxyDestination string
}

func validateKey(config SSHKeyConfig) (ssh.Signer, error) {
	if config.Path == "" && config.Base64 == "" && config.Content == "" {
		return nil, errors.New("one of path, base64 or content of the SSH key must be set")
	}
	if (config.Path != "" && config.Base64 != "") || (config.Path != "" && config.Content != "") || (config.Base64 != "" && config.Content != "") {
		return nil, errors.New("only one of path, base64 or content of the SSH key can be set")
	}
	var pemFile []byte
	if config.Path != "" {
		bytes, err := os.ReadFile(config.Path)
		if err != nil {
			return nil, err
		}
		pemFile = bytes
	}
	if config.Base64 != "" {
		bytes, err := base64.StdEncoding.DecodeString(config.Base64)
		if err != nil {
			return nil, err
		}
		pemFile = bytes
	}
	if config.Content != "" {
		pemFile = []byte(config.Content)
	}
	return ssh.ParsePrivateKey(pemFile)
}

func makeServer(config Config) (*Server, error) {
	sshConfig := &ssh.ServerConfig{
		ServerVersion:           "SSH-2.0-taokystrong",
		PublicKeyAuthAlgorithms: ssh.SupportedAlgorithms().PublicKeyAuths,
	}
	for _, keyConf := range config.SSH.HostKeys {
		key, err := validateKey(keyConf)
		if err != nil {
			return nil, err
		}
		sshConfig.AddHostKey(key)
	}
	proxyPolicyConfig, err := convertProxyPolicyConfig(config.ProxyProtocol)
	if err != nil {
		return nil, err
	}
	var logWriter io.Writer
	if config.Logger.Enabled {
		loggerURL, err := url.Parse(config.Logger.Endpoint)
		if err != nil {
			return nil, err
		}
		if loggerURL.Scheme == "udp" {
			conn, err := net.Dial("udp", loggerURL.Host)
			if err != nil {
				return nil, fmt.Errorf("logger dial failed: %w", err)
			}
			logWriter = conn
		} else {
			return nil, fmt.Errorf("unsupported logger endpoint: %s", config.Logger.Endpoint)
		}
	} else {
		logWriter = io.Discard
	}
	metrics, err := makeMetrics(config.Metrics)
	if err != nil {
		return nil, err
	}
	var authenticator Authenticator
	if config.Auth.Version == "" || config.Auth.Version == "legacy" {
		legacyAuthenticator := makeLegacyAuthenticator(config.Auth, config.Recovery)
		authenticator = &legacyAuthenticator
	} else {
		authenticator, err = makeAuthenticator(config.Auth)
		if err != nil {
			return nil, err
		}
	}
	authenticator = &instrumentedAuthenticator{inner: authenticator, metrics: metrics}
	sshmux := &Server{
		Address:          config.Address,
		Banner:           config.SSH.Banner,
		SSHConfig:        sshConfig,
		Authenticator:    authenticator,
		LogWriter:        logWriter,
		ProxyPolicy:      proxyPolicyConfig,
		HandshakeTimeout: timeoutFromSeconds(config.SSH.HandshakeTimeoutSeconds, defaultHandshakeTimeout),
		UpstreamTimeout:  timeoutFromSeconds(config.SSH.UpstreamTimeoutSeconds, defaultUpstreamTimeout),
		Metrics:          metrics,
	}
	return sshmux, nil
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					// Context cancelled, stop accepting connections
					return
				}
				log.Printf("Error on Accept: %s\n", err)
				continue
			}
			s.wg.Add(1)
			go s.handler(conn)
		}
	}
}

func (s *Server) handler(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	connectTime := time.Now()
	ctx := s.ctx
	s.Metrics.ConnectionAccepted(ctx)
	var sessionErr error
	var info connectionInfo
	defer func() {
		s.Metrics.ConnectionClosed(ctx, info, sessionErr, time.Since(connectTime))
	}()

	if err := conn.SetDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		sessionErr = err
		return
	}
	session, err := ssh.NewPipeSession(conn, s.SSHConfig)
	if err != nil {
		sessionErr = err
		return
	}
	defer session.Close()

	logger := slog.New(slog.NewJSONHandler(s.LogWriter, nil))
	logger = logger.With(
		slog.Int64("connect_time", time.Now().Unix()),
		slog.String("remote_ip", conn.RemoteAddr().String()),
		slog.String("client_type", "SSH"),
	)
	defer func() {
		logger.Info("SSH proxy session", slog.Int64("disconnect_time", time.Now().Unix()))
	}()

	select {
	case <-s.ctx.Done():
		return
	default:
		attrs, err := s.RunPipeSession(ctx, session, &info)
		if err != nil && err != io.EOF {
			log.Println("runPipeSession:", err)
		}
		// Once the session is up, the client ends it by disconnecting, so only
		// a failure to establish one counts against the session result.
		if !info.Established {
			sessionErr = err
		}
		for _, attr := range attrs {
			logger = logger.With(attr)
		}
	}
}

// answerChallenges prompts the downstream user with the given challenges over
// keyboard-interactive, and stores the collected answers into req's payload.
func answerChallenges(session *ssh.PipeSession, req *AuthRequest, challenges []AuthChallenge) error {
	for _, challenge := range challenges {
		questions := make([]string, 0, len(challenge.Fields))
		withEcho := make([]bool, 0, len(challenge.Fields))
		for _, field := range challenge.Fields {
			questions = append(questions, field.Prompt)
			withEcho = append(withEcho, !field.Secret)
		}
		answers, err := session.Downstream.InteractiveChallenge("", challenge.Instruction, questions, withEcho)
		if err != nil {
			return err
		}
		if len(answers) != len(questions) {
			return errors.New("ssh: numbers of answers and questions do not match")
		}
		if req.Payload == nil {
			req.Payload = make(map[string]string, len(challenge.Fields))
		}
		for i, answer := range answers {
			req.Payload[challenge.Fields[i].Key] = answer
		}
	}
	return nil
}

func (s *Server) Handshake(ctx context.Context, session *ssh.PipeSession, info *connectionInfo) error {
	hasSetUser := false
	var user string
	var upstream *upstreamInformation
	if s.Banner != "" {
		err := session.Downstream.SendBanner(s.Banner)
		if err != nil {
			return err
		}
	}
	// Basic information about the downstream client, constant for the connection
	clientAddress := session.Downstream.RemoteAddr().String()
	clientVersion := string(session.Downstream.ClientVersion())
	sessionID := base64.StdEncoding.EncodeToString(session.Downstream.SessionID())
	// Stage 1: Authenticate the user with API
	// The public key accepted by the API server, carried over to the later auth
	// requests, so that it can still recognize the user by it.
	var acceptedPublicKey string
auth_requests:
	for {
		authReq, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		if !hasSetUser {
			user = authReq.User
			session.Downstream.SetUser(user)
			info.Username = user
			hasSetUser = true
		}
		req := AuthRequest{
			ClientAddress: clientAddress,
			ClientVersion: clientVersion,
			SessionID:     sessionID,
			Method:        authReq.Method,
			PublicKey:     acceptedPublicKey,
		}
		if authReq.Method == "publickey" && !authReq.IsPublicKeyQuery {
			req.PublicKey = string(ssh.MarshalAuthorizedKey(*authReq.PublicKey))
		}
		for {
			status, resp, err := s.Authenticator.Auth(ctx, req, user)
			if err != nil {
				return err
			}
			switch status {
			case 200:
				if resp.Upstream == nil {
					// The API server partially accepts the publickey auth and requests
					// challenges instead. Report the partial success and send the user
					// to keyboard-interactive, the only method that can answer them.
					if req.Method != "publickey" {
						return fmt.Errorf("no upstream returned for user %s on %s auth", user, req.Method)
					}
					if len(resp.Challenges) == 0 {
						return fmt.Errorf("neither upstream nor challenges returned for user %s", user)
					}
					acceptedPublicKey = req.PublicKey
					err := session.Downstream.WriteAuthFailure([]string{"keyboard-interactive"}, true)
					if err != nil {
						return err
					}
					for {
						authReq, err := session.Downstream.ReadAuthRequest(true)
						if err != nil {
							return err
						}
						if authReq.Method == "keyboard-interactive" {
							req.Method = authReq.Method
							break
						}
						session.Downstream.WriteAuthFailure([]string{"keyboard-interactive"}, false)
					}
					err = answerChallenges(session, &req, resp.Challenges)
					if err != nil {
						return err
					}
					continue
				}
				upstreamResp := *resp.Upstream
				if upstreamResp.Port == 0 {
					upstreamResp.Port = 22
				}
				signer, err := parsePrivateKey(upstreamResp.PrivateKey, upstreamResp.Certificate)
				if err != nil {
					return fmt.Errorf("failed to parse private key for user %s: %v", user, err)
				}
				upstream = &upstreamInformation{
					Signer:   signer,
					Password: upstreamResp.Password,
				}
				upstream.Address = net.JoinHostPort(upstreamResp.Host, strconv.Itoa(int(upstreamResp.Port)))
				// Report the backend the API picked, not the PROXY protocol
				// hop that the address below may be rewritten to.
				info.UpstreamHost, info.UpstreamPort = upstreamResp.Host, upstreamResp.Port
				if resp.Proxy != nil {
					proxyConfig := *resp.Proxy
					// parse protocol version
					var protocolVersion byte
					if proxyConfig.Protocol != nil {
						switch *proxyConfig.Protocol {
						case "v1":
							protocolVersion = 1
						case "v2":
							protocolVersion = 2
						default:
							return fmt.Errorf("unknown PROXY protocol version: %s", *proxyConfig.Protocol)
						}
					}
					upstream.ProxyProtocol = &protocolVersion
					// parse protocol destination
					upstream.ProxyDestination = upstream.Address
					if proxyConfig.Host == "" {
						proxyConfig.Host = upstreamResp.Host
					}
					if proxyConfig.Port == 0 {
						proxyConfig.Port = upstreamResp.Port
					}
					upstream.Address = net.JoinHostPort(proxyConfig.Host, strconv.Itoa(int(proxyConfig.Port)))
				}
				break auth_requests
			case 401:
				if len(resp.Challenges) == 0 {
					// The API server is requesting no challenges, which is abnormal and will
					// likely lead to an infinite loop
					session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
					continue auth_requests
				}
				err := answerChallenges(session, &req, resp.Challenges)
				if err != nil {
					return err
				}
				continue
			case 403:
				if resp.Failure != nil {
					failure := *resp.Failure
					if failure.Disconnect {
						if failure.Reason == 0 {
							// 11: SSH_DISCONNECT_BY_APPLICATION
							failure.Reason = 11
						}
						session.Downstream.WriteDisconnectMsg(failure.Reason, failure.Message)
						return fmt.Errorf("ssh(%d): %s", failure.Reason, failure.Message)
					}
				}
				fallthrough
			default:
				session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
				continue auth_requests
			}
		}
	}
	// Stage 2: connect to upstream
	conn, err := net.DialTimeout("tcp", upstream.Address, s.UpstreamTimeout)
	s.Metrics.UpstreamDialed(s.ctx, err)
	if err != nil {
		return err
	}
	upstreamInitialized := false
	defer func() {
		if !upstreamInitialized {
			conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(s.UpstreamTimeout)); err != nil {
		return err
	}
	if upstream.ProxyProtocol != nil {
		dest := conn.RemoteAddr()
		if upstream.ProxyDestination != upstream.Address {
			if addr, err := net.ResolveTCPAddr("tcp", upstream.ProxyDestination); err == nil {
				dest = addr
			}
		}
		header := proxyproto.HeaderProxyFromAddrs(*upstream.ProxyProtocol, session.Downstream.RemoteAddr(), dest)
		_, err := header.WriteTo(conn)
		if err != nil {
			return err
		}
	}
	sshConfig := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	err = session.InitUpstream(conn, upstream.Address, sshConfig)
	if err != nil {
		return err
	}
	upstreamInitialized = true
	// Firstly try publickey or password
	if upstream.Signer != nil {
		err = session.Upstream.WriteAuthRequestPublicKey(user, upstream.Signer)
	} else if upstream.Password != nil {
		err = session.Upstream.WriteAuthRequestPassword(user, *upstream.Password)
	} else {
		// Send a none auth request
		err = session.Upstream.WriteAuthNone(user)
	}
	if err != nil {
		return err
	}
	res, err := session.Upstream.ReadAuthResult()
	if err != nil {
		return err
	}
	// For the first auth fail, we mark it as partial success
	if !res.Success {
		err = session.Downstream.WriteAuthFailure(removePublicKeyMethod(res.Methods), true)
	} else {
		err = session.Downstream.WriteAuthResult(res)
	}
	if err != nil {
		return err
	}
	if res.Success {
		return nil
	}
	// Finally, pipe downstream and upstream's auth requests and results
	// Note that publickey auth cannot be used anymore after this point
	for {
		req, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		err = session.Upstream.WriteAuthRequest(req)
		if err != nil {
			return err
		}
		res, err := session.Upstream.ReadAuthResult()
		if err != nil {
			return err
		}
		if !res.Success {
			err = session.Downstream.WriteAuthFailure(removePublicKeyMethod(res.Methods), res.PartialSuccess)
		} else {
			err = session.Downstream.WriteAuthResult(res)
		}
		if err != nil {
			return err
		}
		if res.Success {
			return nil
		}
	}
}

func (s *Server) RunPipeSession(ctx context.Context, session *ssh.PipeSession, info *connectionInfo) ([]slog.Attr, error) {
	handshakeTime := time.Now()
	err := s.Handshake(ctx, session, info)
	s.Metrics.HandshakeFinished(s.ctx, *info, err, time.Since(handshakeTime))
	if err != nil {
		return nil, err
	}
	info.Established = true
	if err := session.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	attrs := []slog.Attr{
		slog.String("username", session.Downstream.User()),
		slog.String("host_ip", session.Upstream.RemoteAddr().String()),
		slog.Bool("authenticated", true),
	}
	return attrs, session.RunPipe()
}

func (s *Server) Start() error {
	// set up the metrics exporters before serving any connection
	if err := s.Metrics.Start(); err != nil {
		return err
	}
	// set up TCP listener
	listener, err := reuse.Listen("tcp", s.Address)
	if err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
		s.Metrics.Shutdown(shutdownCtx)
		cancel()
		return err
	}
	if len(s.ProxyPolicy.AllowedCIDRs) > 0 || len(s.ProxyPolicy.AllowedHosts) > 0 {
		listener = &proxyproto.Listener{
			Listener: listener,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				// parse upstream address
				upstreamAddrPort, err := netip.ParseAddrPort(upstream.String())
				if err != nil {
					return proxyproto.SKIP, nil
				}
				upstreamAddr := upstreamAddrPort.Addr()
				// only read PROXY header from allowed CIDRs or hosts
				for _, network := range s.ProxyPolicy.AllowedCIDRs {
					if network.Contains(upstreamAddr) {
						return proxyproto.USE, nil
					}
				}
				for _, host := range s.ProxyPolicy.AllowedHosts {
					ips, err := net.LookupIP(host)
					if err != nil {
						continue
					}
					for _, ip := range ips {
						ipAddr, ok := netip.AddrFromSlice(ip)
						if ok && ipAddr.Unmap() == upstreamAddr {
							return proxyproto.USE, nil
						}
					}
				}
				// do nothing if upstream not in the allow list
				return proxyproto.SKIP, nil
			},
		}
	}

	// set up server context
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.listener = listener
	s.wg.Add(1)

	// main handler loop
	go s.serve()
	return nil
}

// Addr returns the address the server is listening on, or nil before Start.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) Shutdown() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	// flush the final measurements once no handler can record anymore
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	s.Metrics.Shutdown(ctx)
}
