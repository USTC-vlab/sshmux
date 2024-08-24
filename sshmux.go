package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	listener      net.Listener
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	Address       string
	Banner        string
	SSHConfig     *ssh.ServerConfig
	Authenticator Authenticator
	LogWriter     io.Writer
	ProxyPolicy   ProxyPolicyConfig
}

type UpstreamInformation struct {
	Host          string
	Signer        ssh.Signer
	Password      *string
	ProxyProtocol byte
}

func validateKey(config SSHKeyConfig) (ssh.Signer, error) {
	if config.Path == "" && config.Base64 == "" && config.Content == "" {
		return nil, fmt.Errorf("one of path, base64 or content of the SSH key must be set")
	}
	if (config.Path != "" && config.Base64 != "") || (config.Path != "" && config.Content != "") || (config.Base64 != "" && config.Content != "") {
		return nil, fmt.Errorf("only one of path, base64 or content of the SSH key can be set")
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
		PublicKeyAuthAlgorithms: ssh.DefaultPubKeyAuthAlgos(),
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
				log.Fatalf("Logger Dial failed: %s\n", err)
			}
			logWriter = conn
		} else {
			log.Fatalf("unsupported logger endpoint: %s\n", config.Logger.Endpoint)
		}
	} else {
		logWriter = io.Discard
	}
	authenticator := makeLegacyAuthenticator(config.Auth, config.Recovery)
	sshmux := &Server{
		Address:       config.Address,
		Banner:        config.SSH.Banner,
		SSHConfig:     sshConfig,
		Authenticator: &authenticator,
		LogWriter:     logWriter,
		ProxyPolicy:   proxyPolicyConfig,
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

	session, err := ssh.NewPipeSession(conn, s.SSHConfig)
	if err != nil {
		return
	}
	defer session.Close()

	logger := slog.New(slog.NewJSONHandler(s.LogWriter, nil))
	logger = logger.With(
		slog.Int64("connect_time", time.Now().Unix()),
		slog.String("remote_ip", conn.RemoteAddr().String()),
		slog.String("client_type", "SSH"),
	)
	defer logger.Info("SSH proxy session", slog.Int64("disconnect_time", time.Now().Unix()))

	select {
	case <-s.ctx.Done():
		return
	default:
		attrs, err := s.RunPipeSession(session)
		if err != nil {
			log.Println("runPipeSession:", err)
		}
		for _, attr := range attrs {
			logger = logger.With(attr)
		}
	}
}

func (s *Server) Handshake(session *ssh.PipeSession) error {
	hasSetUser := false
	var user string
	var upstream *UpstreamInformation
	if s.Banner != "" {
		err := session.Downstream.SendBanner(s.Banner)
		if err != nil {
			return err
		}
	}
	// Stage 1: Get publickey or keyboard-interactive answers, and authenticate the user with with API
auth_requests:
	for {
		authReq, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		if !hasSetUser {
			user = authReq.User
			session.Downstream.SetUser(user)
			hasSetUser = true
		}
		req := AuthRequest{Method: authReq.Method}
		if authReq.Method == "publickey" && !authReq.IsPublicKeyQuery {
			req.PublicKey = string(ssh.MarshalAuthorizedKey(*authReq.PublicKey))
		}
		for {
			status, resp, err := s.Authenticator.Auth(req, user)
			if err != nil {
				return err
			}
			switch status {
			case 200:
				upstreamResp := *resp.Upstream
				upstream = &UpstreamInformation{
					Host:          upstreamResp.Host,
					Signer:        parsePrivateKey(upstreamResp.PrivateKey, upstreamResp.Certificate),
					Password:      upstreamResp.Password,
					ProxyProtocol: upstreamResp.ProxyProtocol,
				}
				break auth_requests
			case 401:
				for _, challenge := range resp.Challenges {
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
						return fmt.Errorf("ssh: numbers of answers and questions do not match")
					}
					if req.Payload == nil {
						req.Payload = make(map[string]string, len(challenge.Fields))
					}
					for i, answer := range answers {
						req.Payload[challenge.Fields[i].Key] = answer
					}
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
	conn, err := net.Dial("tcp", upstream.Host)
	if err != nil {
		return err
	}
	if upstream.ProxyProtocol > 0 {
		header := proxyproto.HeaderProxyFromAddrs(upstream.ProxyProtocol, session.Downstream.RemoteAddr(), conn.RemoteAddr())
		_, err := header.WriteTo(conn)
		if err != nil {
			return err
		}
	}
	sshConfig := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	err = session.InitUpstream(conn, upstream.Host, sshConfig)
	if err != nil {
		return err
	}
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
	// For the first auth fail, we mark it partial succss
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
	// Finally, pipe downstream and upstream's auth request and result
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

func (s *Server) RunPipeSession(session *ssh.PipeSession) ([]slog.Attr, error) {
	err := s.Handshake(session)
	if err != nil {
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
	// set up TCP listener
	listener, err := reuse.Listen("tcp", s.Address)
	if err != nil {
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
}
