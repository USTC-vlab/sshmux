package main

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTimeoutFromSeconds(t *testing.T) {
	const fallback = 17 * time.Second
	if got := timeoutFromSeconds(0, fallback); got != fallback {
		t.Fatalf("zero timeout = %s, want %s", got, fallback)
	}
	if got := timeoutFromSeconds(9, fallback); got != 9*time.Second {
		t.Fatalf("configured timeout = %s, want %s", got, 9*time.Second)
	}
}

func TestAuthenticatorTimeouts(t *testing.T) {
	endpoint, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := makeAuthenticator(AuthConfig{
		Endpoint:       endpoint.String(),
		Version:        "v1",
		TimeoutSeconds: 7,
	}, noopTracer())
	if err != nil {
		t.Fatal(err)
	}
	if got := authenticator.(*RESTfulAuthenticator).Client.Timeout; got != 7*time.Second {
		t.Fatalf("REST auth timeout = %s, want %s", got, 7*time.Second)
	}

	legacy := makeLegacyAuthenticator(AuthConfig{TimeoutSeconds: 11}, RecoveryConfig{}, noopTracer())
	if got := legacy.Client.Timeout; got != 11*time.Second {
		t.Fatalf("legacy auth timeout = %s, want %s", got, 11*time.Second)
	}
}

type stubAuthenticator struct {
	status int
	err    error
}

func (a *stubAuthenticator) Auth(context.Context, AuthRequest, string) (int, *AuthResponse, error) {
	return a.status, nil, a.err
}

func TestInstrumentedAuthenticator(t *testing.T) {
	metrics := prometheusMetrics(t)
	authenticator := &instrumentedAuthenticator{
		inner:   &stubAuthenticator{status: 401},
		metrics: metrics,
		tracer:  noopTracer(),
	}
	status, _, err := authenticator.Auth(t.Context(), AuthRequest{Method: "publickey"}, "vlab")
	if err != nil || status != 401 {
		t.Fatalf("Auth() = (%d, %v), want (401, nil)", status, err)
	}

	failing := &instrumentedAuthenticator{
		inner:   &stubAuthenticator{err: io.ErrUnexpectedEOF},
		metrics: metrics,
		tracer:  noopTracer(),
	}
	if _, _, err := failing.Auth(t.Context(), AuthRequest{Method: "keyboard-interactive"}, "vlab"); err == nil {
		t.Fatal("Auth() error = nil, want an error")
	}

	body := scrape(t, metrics)
	for _, want := range []string{
		`sshmux_auth_requests_total{event_outcome="success",sshmux_auth_method="publickey",sshmux_auth_status_code="401"} 1`,
		`sshmux_auth_requests_total{error_type="eof",event_outcome="failure",sshmux_auth_method="keyboard-interactive",sshmux_auth_status_code="0"} 1`,
		`sshmux_auth_duration_seconds_count{event_outcome="success",sshmux_auth_method="publickey",sshmux_auth_status_code="401"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}
