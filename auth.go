package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

type RESTfulAuthenticator struct {
	Endpoint string
	Version  string
}

func (auth *RESTfulAuthenticator) Auth(request AuthRequest, username string) (int, *AuthResponse, error) {
	if auth.Version != "v1" {
		return 500, nil, fmt.Errorf("unsupported API version: %s", auth.Version)
	}
	url := fmt.Sprintf("%s/v1/auth/%s", auth.Endpoint, username)
	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(request); err != nil {
		return 0, nil, err
	}
	res, err := http.Post(url, "application/json", payload)
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
