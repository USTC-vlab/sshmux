package main

import (
	"net/url"
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := authenticator.(*RESTfulAuthenticator).Client.Timeout; got != 7*time.Second {
		t.Fatalf("REST auth timeout = %s, want %s", got, 7*time.Second)
	}

	legacy := makeLegacyAuthenticator(AuthConfig{TimeoutSeconds: 11}, RecoveryConfig{})
	if got := legacy.Client.Timeout; got != 11*time.Second {
		t.Fatalf("legacy auth timeout = %s, want %s", got, 11*time.Second)
	}
}
