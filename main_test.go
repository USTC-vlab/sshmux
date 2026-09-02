package main

import (
	"errors"
	"os"
	"testing"
)

type fakeServerLifecycle struct {
	startErr error
	started  bool
	shutDown bool
}

func (s *fakeServerLifecycle) Start() error {
	s.started = true
	return s.startErr
}

func (s *fakeServerLifecycle) Shutdown() {
	s.shutDown = true
}

func TestRunUntilSignalShutsDownServer(t *testing.T) {
	server := &fakeServerLifecycle{}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	if err := runUntilSignal(server, signals); err != nil {
		t.Fatal(err)
	}
	if !server.started || !server.shutDown {
		t.Fatalf("started = %t, shut down = %t; want both true", server.started, server.shutDown)
	}
}

func TestRunUntilSignalReturnsStartError(t *testing.T) {
	want := errors.New("start failed")
	server := &fakeServerLifecycle{startErr: want}

	if err := runUntilSignal(server, make(chan os.Signal)); !errors.Is(err, want) {
		t.Fatalf("runUntilSignal() error = %v, want %v", err, want)
	}
	if server.shutDown {
		t.Fatal("server shut down after Start failed")
	}
}
