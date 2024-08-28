// Copyright 2022-2024 Dinglan Peng <pengdinglan@gmail.com>, Jiawei Fu <i@ibugone.com> and Keyu Tao <me@taoky.moe>
// Use of this source code is governed by MIT license

package ssh

import (
	"errors"
	"fmt"
	"net"
)

// Helper functions to export variables from this module
func DefaultPubKeyAuthAlgos() []string {
	return supportedPubKeyAuthAlgos
}

type Downstream struct {
	*connection
}

type Upstream struct {
	*connection
	extensions map[string][]byte
}

type PipeSession struct {
	Downstream *Downstream
	Upstream   *Upstream
}

type AuthRequest struct {
	userAuthRequestMsg
	PublicKey        *PublicKey
	IsPublicKeyQuery bool
	Password         []byte
}

type AuthResult struct {
	Packet         []byte
	Success        bool
	Methods        []string
	PartialSuccess bool
}

func NewPipeSession(c net.Conn, config *ServerConfig) (session *PipeSession, err error) {
	serverConfig := *config
	serverConfig.SetDefaults()
	conn := &connection{
		sshConn: sshConn{conn: c},
	}
	downstream := &Downstream{
		connection: conn,
	}
	_, err = downstream.handshakeBeforeAuth(&serverConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			downstream.Close()
		}
	}()

	session = &PipeSession{
		Downstream: downstream,
	}

	return session, nil
}

func (s *Downstream) handshakeBeforeAuth(config *ServerConfig) (*Permissions, error) {
	if len(config.hostKeys) == 0 {
		return nil, errors.New("ssh: server has no host keys")
	}

	if config.ServerVersion != "" {
		s.serverVersion = []byte(config.ServerVersion)
	} else {
		s.serverVersion = []byte(packageVersion)
	}
	var err error
	s.clientVersion, err = exchangeVersions(s.sshConn.conn, s.serverVersion)
	if err != nil {
		return nil, err
	}

	tr := newTransport(s.sshConn.conn, config.Rand, false /* not client */)
	s.transport = newServerTransport(tr, s.clientVersion, s.serverVersion, config)

	if err := s.transport.waitSession(); err != nil {
		return nil, err
	}

	// We just did the key change, so the session ID is established.
	s.sessionID = s.transport.getSessionID()

	var packet []byte
	if packet, err = s.transport.readPacket(); err != nil {
		return nil, err
	}

	var serviceRequest serviceRequestMsg
	if err = Unmarshal(packet, &serviceRequest); err != nil {
		return nil, err
	}
	if serviceRequest.Service != serviceUserAuth {
		return nil, errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := s.transport.writePacket(Marshal(&serviceAccept)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *Downstream) readAuthRequestMsg() (*userAuthRequestMsg, error) {
	var userAuthReq userAuthRequestMsg
	if packet, err := s.transport.readPacket(); err != nil {
		return nil, err
	} else if err = Unmarshal(packet, &userAuthReq); err != nil {
		return nil, err
	}

	if userAuthReq.Service != serviceSSH {
		return nil, errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
	}

	return &userAuthReq, nil
}

func (s *Downstream) ReadAuthRequest(skipQuery bool) (*AuthRequest, error) {
	for {
		msg, err := s.readAuthRequestMsg()
		if err != nil {
			return nil, err
		}
		if msg.Method == "publickey" {
			payload := msg.Payload
			isQuery := payload[0] == 0
			payload = payload[1:]
			algoBytes, payload, ok := parseString(payload)
			if !ok {
				return nil, parseError(msgUserAuthRequest)
			}
			algo := string(algoBytes)
			if !isAcceptableAlgo(algo) {
				return nil, fmt.Errorf("ssh: algorithm %q not accepted", algo)
			}

			pubKeyData, payload, ok := parseString(payload)
			if !ok {
				return nil, parseError(msgUserAuthRequest)
			}

			pubKey, err := ParsePublicKey(pubKeyData)
			if err != nil {
				return nil, err
			}
			if !isQuery {
				sig, payload, ok := parseSignature(payload)
				if !ok || len(payload) > 0 {
					return nil, parseError(msgUserAuthRequest)
				}
				if !isAcceptableAlgo(sig.Format) {
					return nil, fmt.Errorf("ssh: algorithm %q not accepted", sig.Format)
				}
				if underlyingAlgo(algo) != sig.Format {
					return nil, fmt.Errorf("ssh: signature %q not compatible with selected algorithm %q", sig.Format, algo)
				}
				signedData := buildDataSignedForAuth(s.transport.getSessionID(), *msg, algo, pubKey.Marshal())
				err = pubKey.Verify(signedData, sig)
				if err != nil {
					return nil, err
				}
			} else if skipQuery {
				s.AckPublicKey(pubKey)
				continue
			}
			return &AuthRequest{
				userAuthRequestMsg: *msg,
				PublicKey:          &pubKey,
				IsPublicKeyQuery:   isQuery,
			}, err
		} else if msg.Method == "password" {
			payload := msg.Payload
			if len(payload) < 1 || payload[0] != 0 {
				return nil, parseError(msgUserAuthRequest)
			}
			payload = payload[1:]
			password, payload, ok := parseString(payload)
			if !ok || len(payload) > 0 {
				return nil, parseError(msgUserAuthRequest)
			}
			return &AuthRequest{
				userAuthRequestMsg: *msg,
				Password:           password,
			}, err
		}
		return &AuthRequest{
			userAuthRequestMsg: *msg,
		}, nil
	}
}

func (s *Downstream) AckPublicKey(key PublicKey) error {
	return s.transport.writePacket(Marshal(&userAuthPubKeyOkMsg{
		Algo:   key.Type(),
		PubKey: key.Marshal(),
	}))
}

func (s *Downstream) WriteAuthResult(res *AuthResult) error {
	return s.transport.writePacket(res.Packet)
}

func (s *Downstream) WriteAuthFailure(methods []string, partialSuccess bool) error {
	return s.transport.writePacket(Marshal(&userAuthFailureMsg{
		Methods:        methods,
		PartialSuccess: partialSuccess,
	}))
}

func (s *Downstream) InteractiveChallenge(name string, instruction string,
	questions []string, echo []bool) ([]string, error) {
	prompter := sshClientKeyboardInteractive{s.connection}
	return prompter.Challenge(name, instruction, questions, echo)
}

func (s *Downstream) SetUser(user string) {
	s.user = user
}

func (s *Downstream) SendBanner(banner string) error {
	return s.transport.writePacket(Marshal(&userAuthBannerMsg{
		Message: banner,
	}))
}

func (s *Downstream) WriteDisconnectMsg(reason uint32, msg string) error {
	return s.transport.writePacket(Marshal(&disconnectMsg{
		Reason:  reason,
		Message: msg,
	}))
}

func (c *Upstream) handshakeBeforeAuth(addr string, config *ClientConfig) error {
	// BEGIN (*connection).clientHandshake
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	} else {
		c.clientVersion = []byte(packageVersion)
	}
	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, config, addr, c.sshConn.RemoteAddr())
	if err := c.transport.waitSession(); err != nil {
		return err
	}

	c.sessionID = c.transport.getSessionID()

	// BEGIN (*connection).clientAuthenticate
	// initiate user auth session
	if err := c.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}
	packet, err := c.transport.readPacket()
	if err != nil {
		return err
	}
	// The server may choose to send a SSH_MSG_EXT_INFO at this point (if we
	// advertised willingness to receive one, which we always do) or not. See
	// RFC 8308, Section 2.4.
	extensions := make(map[string][]byte)
	if len(packet) > 0 && packet[0] == msgExtInfo {
		var extInfo extInfoMsg
		if err := Unmarshal(packet, &extInfo); err != nil {
			return err
		}
		payload := extInfo.Payload
		for i := uint32(0); i < extInfo.NumExtensions; i++ {
			name, rest, ok := parseString(payload)
			if !ok {
				return parseError(msgExtInfo)
			}
			value, rest, ok := parseString(rest)
			if !ok {
				return parseError(msgExtInfo)
			}
			extensions[string(name)] = value
			payload = rest
		}
		packet, err = c.transport.readPacket()
		if err != nil {
			return err
		}
	}
	var serviceAccept serviceAcceptMsg
	if err := Unmarshal(packet, &serviceAccept); err != nil {
		return err
	}
	// END (*connection).clientAuthenticate
	// END (*connection).clientHandshake

	c.extensions = extensions
	return nil
}

func (c *Upstream) WriteAuthRequest(req *AuthRequest) error {
	return c.transport.writePacket(Marshal(req.userAuthRequestMsg))
}

func (c *Upstream) ReadAuthResult() (*AuthResult, error) {
	for {
		packet, err := c.transport.readPacket()
		if err != nil {
			return nil, err
		}
		msgType := packet[0]
		if msgType == msgUserAuthSuccess {
			return &AuthResult{
				Packet:  packet,
				Success: true,
			}, nil
		} else if msgType == msgUserAuthFailure {
			var msg userAuthFailureMsg
			err = Unmarshal(packet, &msg)
			if err != nil {
				return nil, parseError(msgUserAuthFailure)
			}
			return &AuthResult{
				Packet:         packet,
				Success:        false,
				Methods:        msg.Methods,
				PartialSuccess: msg.PartialSuccess,
			}, nil
		} else if msgType == msgUserAuthBanner {
			continue
		}
		return nil, fmt.Errorf("ssh: unexpected msg type: %d", int(msgType))
	}
}

func (c *Upstream) WriteAuthRequestPublicKey(user string, signer Signer) error {
	rand := c.transport.config.Rand
	session := c.transport.getSessionID()

	pub := signer.PublicKey()
	as, algo, err := pickSignatureAlgorithm(signer, c.extensions)
	if err != nil {
		return err
	}

	pubKey := pub.Marshal()
	data := buildDataSignedForAuth(session, userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "publickey",
	}, algo, pubKey)
	sign, err := as.SignWithAlgorithm(rand, data, underlyingAlgo(algo))
	if err != nil {
		return err
	}

	// manually wrap the serialized signature in a string
	s := Marshal(sign)
	sig := make([]byte, stringLength(len(s)))
	marshalString(sig, s)
	msg := publickeyAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "publickey",
		HasSig:   true,
		Algoname: algo,
		PubKey:   pubKey,
		Sig:      sig,
	}
	p := Marshal(&msg)
	if err := c.transport.writePacket(p); err != nil {
		return err
	}
	return nil
}

func (c *Upstream) WriteAuthRequestPassword(user string, password string) error {
	type passwordAuthMsg struct {
		User     string `sshtype:"50"`
		Service  string
		Method   string
		Reply    bool
		Password string
	}
	return c.transport.writePacket(Marshal(&passwordAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "password",
		Reply:    false,
		Password: password,
	}))
}

func (c *Upstream) WriteAuthNone(user string) error {
	return c.transport.writePacket(Marshal(&userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "none",
	}))
}

func (s *PipeSession) InitUpstream(c net.Conn, addr string, config *ClientConfig) error {
	clientConfig := *config
	clientConfig.SetDefaults()
	conn := &connection{
		sshConn: sshConn{conn: c},
	}
	upstream := &Upstream{
		connection: conn,
	}
	err := upstream.handshakeBeforeAuth(addr, &clientConfig)
	if err != nil {
		return err
	}
	s.Upstream = upstream
	return nil
}

func (s *PipeSession) Close() {
	if s.Downstream != nil {
		s.Downstream.Close()
	}
	if s.Upstream != nil {
		s.Upstream.Close()
	}
}

func pipe(dst, src packetConn, handlePing bool) error {
	for {
		msg, err := src.readPacket()
		if err != nil {
			return err
		}
		if handlePing && msg[0] == msgPing {
			var ping pingMsg
			if err := Unmarshal(msg, &ping); err != nil {
				return fmt.Errorf("failed to unmarshal ping@openssh.com message: %w", err)
			}
			err = src.writePacket(Marshal(pongMsg(ping)))
			if err != nil {
				return err
			}
			continue
		}
		err = dst.writePacket(msg)
		if err != nil {
			return err
		}
	}
}

func (s *PipeSession) RunPipe() error {
	c := make(chan error)
	go func() {
		defer s.Downstream.transport.Close()
		c <- pipe(s.Downstream.transport, s.Upstream.transport, false)
	}()
	go func() {
		defer s.Upstream.transport.Close()
		// If the upstream doesn't support ping@openssh.com, short-circuit with a pong response
		upstream_ping_version := s.Upstream.extensions["ping@openssh.com"]
		upstream_supports_ping := len(upstream_ping_version) == 1 && upstream_ping_version[0] == byte('0')
		c <- pipe(s.Upstream.transport, s.Downstream.transport, !upstream_supports_ping)
	}()
	return <-c
}

func isAcceptableAlgo(algo string) bool {
	switch algo {
	case KeyAlgoRSA, KeyAlgoRSASHA256, KeyAlgoRSASHA512, KeyAlgoDSA, KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521, KeyAlgoSKECDSA256, KeyAlgoED25519, KeyAlgoSKED25519,
		CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoSKECDSA256v01, CertAlgoED25519v01, CertAlgoSKED25519v01,
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01:
		return true
	}
	return false
}
