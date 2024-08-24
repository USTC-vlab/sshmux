package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ssh"
)

type AuthRequest struct {
	Method    string            `json:"method"`
	PublicKey string            `json:"public_key,omitempty"`
	Payload   map[string]string `json:"payload"`
}

type AuthResponse struct {
	Challenges []AuthChallenge `json:"challenges,omitempty"`
	Failure    *AuthFailure    `json:"failure,omitempty"`
	Upstream   *AuthUpstream   `json:"upstream,omitempty"`
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
	Host          string  `json:"host"`
	Port          uint16  `json:"port,omitempty"`
	PrivateKey    string  `json:"private_key,omitempty"`
	Certificate   string  `json:"certificate,omitempty"`
	Password      *string `json:"password,omitempty"`
	ProxyProtocol byte    `json:"proxy_protocol,omitempty"`
}

type Authenticator interface {
	Auth(request AuthRequest, username string) (int, *AuthResponse, error)
}

func makeAuthenticator(auth AuthConfig) (Authenticator, error) {
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
	}
	return &authenticator, nil
}

type RESTfulAuthenticator struct {
	Endpoint *url.URL
	Version  string
	Headers  http.Header
}

func (auth *RESTfulAuthenticator) Auth(request AuthRequest, username string) (int, *AuthResponse, error) {
	if auth.Version != "v1" {
		return 500, nil, fmt.Errorf("unsupported API version: %s", auth.Version)
	}
	auth_url := auth.Endpoint.JoinPath("v1", "auth", username).String()

	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(request); err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest("POST", auth_url, payload)
	if err != nil {
		return 0, nil, err
	}
	req.Header = auth.Headers

	res, err := http.DefaultClient.Do(req)
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

func removePublicKeyMethod(methods []string) []string {
	res := make([]string, 0, len(methods))
	for _, s := range methods {
		if s != "publickey" {
			res = append(res, s)
		}
	}
	return res
}

func parsePrivateKey(key string, cert string) ssh.Signer {
	if key == "" {
		return nil
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil
	}
	if cert == "" {
		return signer
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		return signer
	}
	certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
	if err != nil {
		return signer
	}
	return certSigner
}
