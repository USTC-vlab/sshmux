package main

import "golang.org/x/crypto/ssh"

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
	Reason     uint32 `json:"reason,omitempty"`
	Disconnect bool   `json:"disconnect,omitempty"`
}

type AuthUpstream struct {
	Host          string  `json:"host"`
	PrivateKey    string  `json:"private_key,omitempty"`
	Certificate   string  `json:"certificate,omitempty"`
	Password      *string `json:"password,omitempty"`
	ProxyProtocol byte    `json:"proxy_protocol,omitempty"`
}

type Authenticator interface {
	Auth(request AuthRequest, username string) (int, *AuthResponse, error)
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
