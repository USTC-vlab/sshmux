package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"
)

type AuthRequest struct {
	ClientAddress string            `json:"client_address"`
	ClientVersion string            `json:"client_version"`
	SessionID     string            `json:"session_id"`
	Method        string            `json:"method"`
	PublicKey     string            `json:"public_key,omitempty"`
	Payload       map[string]string `json:"payload"`
}

type AuthResponse struct {
	Challenges []AuthChallenge `json:"challenges,omitempty"`
	Failure    *AuthFailure    `json:"failure,omitempty"`
	Upstream   *AuthUpstream   `json:"upstream,omitempty"`
	Proxy      *AuthProxy      `json:"proxy,omitempty"`
}

type AuthChallenge struct {
	Instruction string               `json:"instruction"`
	Fields      []AuthChallengeField `json:"fields"`
}

type AuthChallengeField struct {
	Key    string `json:"key"`
	Prompt string `json:"prompt"`
	Secret bool   `json:"secret"`
}

type AuthFailure struct {
	Message    string `json:"message"`
	Disconnect bool   `json:"disconnect,omitempty"`
	Reason     uint32 `json:"reason,omitempty"`
}

type AuthUpstream struct {
	Host        string  `json:"host"`
	Port        uint16  `json:"port,omitempty"`
	PrivateKey  string  `json:"private_key,omitempty"`
	Certificate string  `json:"certificate,omitempty"`
	Password    *string `json:"password,omitempty"`
}

type AuthProxy struct {
	Host     string  `json:"host,omitempty"`
	Port     uint16  `json:"port,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
}

type Authenticator interface {
	Auth(ctx context.Context, request AuthRequest, username string) (int, *AuthResponse, error)
}

func makeAuthenticator(auth AuthConfig, tracer *Tracer) (Authenticator, error) {
	if auth.Version == "" {
		auth.Version = "v1"
	}
	headers := http.Header{}
	for _, header := range auth.Headers {
		headers.Add(header.Name, header.Value)
	}
	auth_url, err := url.Parse(auth.Endpoint)
	if err != nil {
		return nil, err
	}
	authenticator := RESTfulAuthenticator{
		Endpoint: auth_url,
		Version:  auth.Version,
		Headers:  headers,
		Client:   &http.Client{Timeout: timeoutFromSeconds(auth.TimeoutSeconds, defaultAuthTimeout)},
		Tracer:   tracer,
	}
	return &authenticator, nil
}

type RESTfulAuthenticator struct {
	Endpoint *url.URL
	Version  string
	Headers  http.Header
	Client   *http.Client
	Tracer   *Tracer
}

func (auth *RESTfulAuthenticator) Auth(ctx context.Context, request AuthRequest, username string) (int, *AuthResponse, error) {
	if auth.Version != "v1" {
		return 500, nil, fmt.Errorf("unsupported API version: %s", auth.Version)
	}
	auth_url := auth.Endpoint.JoinPath("v1", "auth", username).String()

	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(request); err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequestWithContext(auth.Tracer.tracePeer(ctx), "POST", auth_url, payload)
	if err != nil {
		return 0, nil, err
	}
	req.Header = auth.Headers.Clone()
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	auth.Tracer.Inject(ctx, req.Header)

	res, err := auth.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, nil, err
	}

	var response AuthResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return res.StatusCode, nil, err
	}
	return res.StatusCode, &response, nil
}

// instrumentedAuthenticator records the outcome and latency of every auth API
// request made through the wrapped Authenticator.
type instrumentedAuthenticator struct {
	inner   Authenticator
	metrics *Metrics
	tracer  *Tracer
	// server is the auth API the wrapped Authenticator calls.
	server *url.URL
}

func (a *instrumentedAuthenticator) Auth(ctx context.Context, request AuthRequest, username string) (int, *AuthResponse, error) {
	start := time.Now()
	ctx, span := a.tracer.Start(ctx, "authenticate user", spanKindClient)
	status, response, err := a.inner.Auth(ctx, request, username)
	endSpan(span, err, append(a.tracer.serverAttributes(a.server),
		a.tracer.attrs.sshmuxAuthMethod.String(request.Method),
		a.tracer.attrs.sshmuxAuthStatus.Int(status))...)
	a.metrics.AuthFinished(ctx, request.Method, status, err, time.Since(start))
	return status, response, err
}

func timeoutFromSeconds(seconds uint, defaultTimeout time.Duration) time.Duration {
	if seconds == 0 {
		return defaultTimeout
	}
	return time.Duration(seconds) * time.Second
}

func removePublicKeyMethod(methods []string) []string {
	res := make([]string, 0, len(methods))
	for _, s := range methods {
		if s != "publickey" {
			res = append(res, s)
		}
	}
	return res
}

func parsePrivateKey(key string, cert string) (ssh.Signer, error) {
	if key == "" {
		return nil, nil
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	if cert == "" {
		return signer, nil
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		return signer, err
	}
	certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
	if err != nil {
		return signer, err
	}
	return certSigner, nil
}
