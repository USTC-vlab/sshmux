package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type Downstream struct {
	*ssh.ServerConn
	Channels <-chan ssh.NewChannel
}

type Upstream struct {
	ssh.Conn
	extensions map[string][]byte
}

type PipeSession struct {
	Downstream *Downstream
	Upstream   *Upstream
}

func NewPipeSession(c net.Conn, config *ssh.ServerConfig) (session *PipeSession, err error) {
	conn, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	session = &PipeSession{
		Downstream: &Downstream{conn, chans},
	}
	return session, nil
}

func (s *PipeSession) InitUpstream(c net.Conn, addr string, config *ssh.ClientConfig) error {
	conn, _, _, err := ssh.NewClientConn(nil, addr, config)
	if err != nil {
		return err
	}
	s.Upstream = &Upstream{conn, nil}
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
