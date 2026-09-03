package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/pires/go-proxyproto"
	"go.opentelemetry.io/otel/attribute"
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
	Logger           *Logger
	ProxyPolicy      ProxyPolicyConfig
	HandshakeTimeout time.Duration
	UpstreamTimeout  time.Duration
	Metrics          *Metrics
	Tracer           *Tracer
}

const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultAuthTimeout      = 30 * time.Second
	defaultUpstreamTimeout  = 30 * time.Second
)

type upstreamInformation struct {
	Address          string
	Username         string
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
	logger, err := makeLoggerWithBase(config.Logger, slog.Default())
	if err != nil {
		return nil, err
	}
	// What the metrics and the tracer have to say about themselves goes where
	// everything else sshmux says does.
	metrics, err := makeMetricsWithLogger(config.Metrics, logger)
	if err != nil {
		return nil, err
	}
	tracer, err := makeTracerWithLogger(config.Tracer, logger)
	if err != nil {
		return nil, err
	}
	// The auth API is named on the span of every call made to it.
	authEndpoint, err := url.Parse(config.Auth.Endpoint)
	if err != nil {
		return nil, err
	}
	var authenticator Authenticator
	if config.Auth.Version == "" || config.Auth.Version == "legacy" {
		legacyAuthenticator := makeLegacyAuthenticator(config.Auth, config.Recovery, tracer)
		authenticator = &legacyAuthenticator
	} else {
		authenticator, err = makeAuthenticator(config.Auth, tracer)
		if err != nil {
			return nil, err
		}
	}
	authenticator = &instrumentedAuthenticator{inner: authenticator, metrics: metrics, tracer: tracer, server: authEndpoint}
	sshmux := &Server{
		Address:          config.Address,
		Banner:           config.SSH.Banner,
		SSHConfig:        sshConfig,
		Authenticator:    authenticator,
		Logger:           logger,
		ProxyPolicy:      proxyPolicyConfig,
		HandshakeTimeout: timeoutFromSeconds(config.SSH.HandshakeTimeoutSeconds, defaultHandshakeTimeout),
		UpstreamTimeout:  timeoutFromSeconds(config.SSH.UpstreamTimeoutSeconds, defaultUpstreamTimeout),
		Metrics:          metrics,
		Tracer:           tracer,
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
				s.Logger.LogAttrs(s.ctx, slog.LevelError,
					"sshmux could not accept a connection", s.Logger.errorAttributes(err)...)
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
	// Shutdown cancels the server context before waiting for handlers. Closing
	// the connection makes an active RunPipe return, so the final log record can
	// be emitted before the telemetry providers are flushed.
	stopClosing := context.AfterFunc(s.ctx, func() { conn.Close() })
	defer stopClosing()

	connectTime := time.Now()
	var info connectionInfo
	if address, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		info.ClientHost, info.ClientPort = address.IP.String(), uint16(address.Port)
	}
	// RemoteAddr is what a PROXY protocol header claims, so the connection has
	// to be asked for the address it was really made from.
	info.ClientPeer = conn.RemoteAddr()
	if proxied, ok := conn.(*proxyproto.Conn); ok {
		info.ClientPeer = proxied.Raw().RemoteAddr()
	}

	// The span covers establishing the session, not its lifetime: a session
	// that is up lasts as long as the client stays connected, and a span left
	// open that long is held in memory and reaches no exporter until it ends.
	// How long a session lived is reported by `sshmux.session.duration`.
	ctx, span := s.Tracer.Start(s.ctx, "establish ssh session", spanKindServer)
	s.Metrics.ConnectionAccepted(ctx)
	var sessionErr error
	defer func() {
		s.Metrics.ConnectionClosed(ctx, info, sessionErr, time.Since(connectTime))
	}()

	session, err := s.establishSession(ctx, conn, &info)
	endSpan(span, err, append(s.Tracer.connectionSpanAttributes(info),
		s.Tracer.peerAttributes(info.ClientPeer)...)...)
	// A connection that never reached the SSH transport has nothing to log
	// about a session, and nothing to close.
	if session == nil {
		sessionErr = err
		return
	}
	defer session.Close()

	// The record is written on the way out, from whatever is known by then.
	// Logging it against the span's context is what carries the trace and span
	// IDs onto the record.
	defer func() {
		s.Logger.LogAttrs(ctx, slog.LevelInfo, "SSH proxy session",
			s.Logger.sessionAttributes(info, sessionErr, connectTime, time.Now())...)
	}()

	if err != nil {
		// Once the session is up, the client ends it by disconnecting, so only
		// a failure to establish one counts against the session result.
		sessionErr = err
	} else {
		select {
		case <-s.ctx.Done():
			return
		default:
			err = session.RunPipe()
		}
	}
	if err != nil && err != io.EOF {
		slog.LogAttrs(ctx, slog.LevelWarn, "sshmux lost a session",
			slogAttributes(defaultAttributeNames.errorAttributes(err))...)
	}
}

// sshProtocolVersion reads the protocol version out of an SSH identification
// string, which RFC 4253 shapes as "SSH-protoversion-softwareversion".
func sshProtocolVersion(identification string) string {
	fields := strings.SplitN(identification, "-", 3)
	if len(fields) < 3 || fields[0] != "SSH" {
		return ""
	}
	return fields[1]
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
	sessionID := info.SessionID
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
				// Granted, or granted in part where challenges follow: either
				// way, this method authenticated the user as far as it goes.
				info.appendDownstreamAuthMethod(req.Method)
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
				if upstreamResp.Username == "" {
					upstreamResp.Username = user
				}
				signer, err := parsePrivateKey(upstreamResp.PrivateKey, upstreamResp.Certificate)
				if err != nil {
					return fmt.Errorf("failed to parse private key for user %s: %v", user, err)
				}
				upstream = &upstreamInformation{
					Username: upstreamResp.Username,
					Signer:   signer,
					Password: upstreamResp.Password,
				}
				upstream.Address = net.JoinHostPort(upstreamResp.Host, strconv.Itoa(int(upstreamResp.Port)))
				// Report the backend the API picked, not the PROXY protocol
				// hop that the address below may be rewritten to.
				info.UpstreamHost, info.UpstreamPort = upstreamResp.Host, upstreamResp.Port
				info.UpstreamUsername = upstreamResp.Username
				info.UpstreamRole = upstreamResp.Role
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
	_, dialSpan := s.Tracer.Start(ctx, "connect upstream", spanKindClient)
	conn, err := net.DialTimeout("tcp", upstream.Address, s.UpstreamTimeout)
	dialAttrs := []attribute.KeyValue{
		s.Tracer.attrs.serverAddress.String(info.UpstreamHost),
		s.Tracer.attrs.serverPort.Int(int(info.UpstreamPort)),
	}
	if err == nil {
		info.UpstreamPeer = conn.RemoteAddr()
		dialAttrs = append(dialAttrs, s.Tracer.peerAttributes(conn.RemoteAddr())...)
	}
	endSpan(dialSpan, err, dialAttrs...)
	s.Metrics.UpstreamDialed(ctx, err)
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
		User:            upstream.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	err = session.InitUpstream(conn, upstream.Address, sshConfig)
	if err != nil {
		return err
	}
	upstreamInitialized = true
	// Firstly try publickey or password
	var method string
	if upstream.Signer != nil {
		method = "publickey"
		err = session.Upstream.WriteAuthRequestPublicKey(upstream.Username, upstream.Signer)
	} else if upstream.Password != nil {
		method = "password"
		err = session.Upstream.WriteAuthRequestPassword(upstream.Username, *upstream.Password)
	} else {
		// Send a none auth request
		method = "none"
		err = session.Upstream.WriteAuthNone(upstream.Username)
	}
	if err != nil {
		return err
	}
	res, err := session.Upstream.ReadAuthResult()
	if err != nil {
		return err
	}
	if res.Success || res.PartialSuccess {
		info.appendUpstreamAuthMethod(method)
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
		// Every request reaching the backend carries the username it knows the
		// user by, which the auth API may have chosen rather than the client.
		req.User = upstream.Username
		err = session.Upstream.WriteAuthRequest(req)
		if err != nil {
			return err
		}
		res, err := session.Upstream.ReadAuthResult()
		if err != nil {
			return err
		}
		if res.Success || res.PartialSuccess {
			info.appendUpstreamAuthMethod(req.Method)
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

// establishSession brings a connection up to a session ready to be piped. The
// session is reported as soon as the SSH transport is up, so that a handshake
// that fails afterwards is still closed and logged.
func (s *Server) establishSession(ctx context.Context, conn net.Conn, info *connectionInfo) (*ssh.PipeSession, error) {
	if err := conn.SetDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		return nil, err
	}
	session, err := ssh.NewPipeSession(conn, s.SSHConfig)
	if err != nil {
		return nil, err
	}

	// The transport is up, so the session it carries has an identity and a
	// version, and has begun.
	info.SessionID = base64.StdEncoding.EncodeToString(session.Downstream.SessionID())
	info.ProtocolVersion = sshProtocolVersion(string(session.Downstream.ClientVersion()))
	info.HandshakeStart = time.Now()
	s.Logger.LogAttrs(ctx, slog.LevelInfo, "SSH proxy session started",
		s.Logger.sessionStartAttributes(*info, info.HandshakeStart)...)

	handshakeCtx, handshakeSpan := s.Tracer.Start(ctx, "ssh handshake")
	err = s.Handshake(handshakeCtx, session, info)
	info.HandshakeEnd = time.Now()
	// The handshake is where a session authenticates, so the span covering it
	// says what each side authenticated by.
	endSpan(handshakeSpan, err, append(s.Tracer.connectionSpanAttributes(*info),
		s.Tracer.authMethodSpanAttributes(*info)...)...)
	s.Metrics.HandshakeFinished(ctx, *info, err, info.HandshakeEnd.Sub(info.HandshakeStart))
	if err != nil {
		return session, err
	}
	info.Established = true
	if err := session.SetDeadline(time.Time{}); err != nil {
		return session, err
	}
	return session, nil
}

func (s *Server) Start() error {
	starting := time.Now()
	// set up the metrics exporters before serving any connection
	if err := s.Metrics.Start(); err != nil {
		return err
	}
	// set up TCP listener
	listener, err := reuse.Listen("tcp", s.Address)
	if err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
		s.Metrics.Shutdown(shutdownCtx)
		s.Tracer.Shutdown(shutdownCtx)
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

	s.Logger.LogAttrs(s.ctx, slog.LevelInfo, "sshmux started",
		s.Logger.serverStartAttributes(listener.Addr(), time.Since(starting))...)

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
	stopping := time.Now()
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	// flush the final records and measurements once no handler can emit anymore
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	s.Metrics.Shutdown(ctx)

	s.Logger.LogAttrs(ctx, slog.LevelInfo, "sshmux stopped",
		s.Logger.serverStopAttributes(s.Addr(), time.Since(stopping))...)

	// The logger goes last, being what the other two report through.
	s.Tracer.Shutdown(ctx)
	s.Logger.Shutdown(ctx)
}
