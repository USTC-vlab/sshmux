package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Banner         string
	SSHConfig      *ssh.ServerConfig
	ProxyUpstreams []netip.Prefix
	Authenticator  Authenticator
	Logger         Logger
	UsernamePolicy UsernamePolicyConfig
	PasswordPolicy PasswordPolicyConfig
}

func makeServer(config Config) (*Server, error) {
	sshConfig := &ssh.ServerConfig{
		ServerVersion:           "SSH-2.0-taokystrong",
		PublicKeyAuthAlgorithms: ssh.DefaultPubKeyAuthAlgos(),
	}
	for _, keyFile := range config.HostKeys {
		bytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		key, err := ssh.ParsePrivateKey(bytes)
		if err != nil {
			return nil, err
		}
		sshConfig.AddHostKey(key)
	}
	proxyUpstreams := make([]netip.Prefix, 0)
	for _, cidr := range config.ProxyCIDRs {
		network, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		proxyUpstreams = append(proxyUpstreams, network)
	}
	sshmux := &Server{
		Banner:         config.Banner,
		SSHConfig:      sshConfig,
		ProxyUpstreams: proxyUpstreams,
		Authenticator:  makeAuthenticator(config),
		Logger:         makeLogger(config.Logger),
		UsernamePolicy: UsernamePolicyConfig{
			InvalidUsername:        config.InvalidUsername,
			InvalidUsernameMessage: config.InvalidUsernameMessage,
		},
		PasswordPolicy: PasswordPolicyConfig{
			AllUsernameNoPassword: config.AllUsernameNoPassword,
			UsernameNoPassword:    config.UsernameNoPassword,
		},
	}
	return sshmux, nil
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
	for {
		req, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		if !hasSetUser {
			user = req.User
			session.Downstream.SetUser(user)
			hasSetUser = true
		}
		if slices.Contains(s.UsernamePolicy.InvalidUsername, user) {
			// 15: SSH_DISCONNECT_ILLEGAL_USER_NAME
			msg := fmt.Sprintf(s.UsernamePolicy.InvalidUsernameMessage, user)
			session.Downstream.WriteDisconnectMsg(15, msg)
			return fmt.Errorf("ssh: invalid username")
		}
		if req.Method == "none" {
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else if req.Method == "publickey" && !req.IsPublicKeyQuery {
			upstream, err = s.Authenticator.AuthUserWithPublicKey(*req.PublicKey, user)
			if err != nil {
				return err
			}
			if upstream != nil {
				break
			}
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else if req.Method == "keyboard-interactive" {
			// FIXME: Can this be handled by API server?
			requireUnixPassword := !s.PasswordPolicy.AllUsernameNoPassword &&
				!slices.Contains(s.Authenticator.Recovery.Username, user) &&
				!slices.Contains(s.PasswordPolicy.UsernameNoPassword, user)
			interactiveQuestions := []string{"Vlab username (Student ID): ", "Vlab password: "}
			interactiveEcho := []bool{true, false}

			answers, err := session.Downstream.InteractiveChallenge("",
				"Please enter Vlab username & password.",
				interactiveQuestions, interactiveEcho)
			if err != nil {
				return err
			}
			if len(answers) != len(interactiveQuestions) {
				return fmt.Errorf("ssh: numbers of answers and questions do not match")
			}
			username := answers[0]
			password := answers[1]
			upstream, err = s.Authenticator.AuthUserWithUserPass(username, password, user)
			if err != nil {
				return err
			}
			if upstream != nil {
				if requireUnixPassword {
					answers, err := session.Downstream.InteractiveChallenge("",
						"Please enter UNIX password.",
						[]string{"UNIX password: "}, []bool{false})
					if err != nil {
						return err
					}
					if len(answers) != 1 {
						return fmt.Errorf("ssh: expected UNIX password")
					}
					upstream.Password = &answers[0]
				}
				break
			}
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else {
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		}
	}
	// Stage 2: connect to upstream
	conn, err := net.Dial("tcp", upstream.Host)
	if err != nil {
		return err
	}
	if upstream.ProxyProtocol > 0 {
		header := proxyproto.HeaderProxyFromAddrs(upstream.ProxyProtocol, session.Downstream.RemoteAddr(), nil)
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

func (s *Server) ListenAddr(address string) error {
	// set up TCP listener
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	if len(s.ProxyUpstreams) > 0 {
		listener = &proxyproto.Listener{
			Listener: listener,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				// parse upstream address
				upstreamAddrPort, err := netip.ParseAddrPort(upstream.String())
				if err != nil {
					return proxyproto.SKIP, nil
				}
				upstreamAddr := upstreamAddrPort.Addr()
				// only read PROXY header from allowed CIDRs
				for _, network := range s.ProxyUpstreams {
					if network.Contains(upstreamAddr) {
						return proxyproto.USE, nil
					}
				}
				// do nothing if upstream not in the allow list
				return proxyproto.SKIP, nil
			},
		}
	}
	defer listener.Close()

	// main handler loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error on Accept: %s\n", err)
			continue
		}
		go func() {
			session, err := ssh.NewPipeSession(conn, s.SSHConfig)
			logMessage := LogMessage{
				LoginTime: time.Now().Unix(),
				ClientIp:  conn.RemoteAddr().String(),
			}
			if err != nil {
				return
			}
			defer func() {
				session.Close()
				s.Logger.SendLog(&logMessage)
			}()
			if err := s.RunPipeSession(session, &logMessage); err != nil {
				log.Println("runPipeSession:", err)
			}
		}()
	}
}

func (s *Server) RunPipeSession(session *ssh.PipeSession, logMessage *LogMessage) error {
	err := s.Handshake(session)
	if err != nil {
		return err
	}
	logMessage.Username = session.Downstream.User()
	logMessage.HostIp = session.Upstream.RemoteAddr().String()
	return session.RunPipe()
}
