package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"

	"golang.org/x/crypto/ssh"
)

type AuthRequestPublicKey struct {
	AuthType      string `json:"auth_type"`
	UnixUsername  string `json:"unix_username"`
	PublicKeyType string `json:"public_key_type"`
	PublicKeyData string `json:"public_key_data"`
	Token         string `json:"token"`
}

type AuthRequestPassword struct {
	AuthType     string `json:"auth_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	UnixUsername string `json:"unix_username"`
	Token        string `json:"token"`
}

type AuthResponse struct {
	Status        string `json:"status"`
	Address       string `json:"address"`
	PrivateKey    string `json:"private_key"`
	Cert          string `json:"cert"`
	Id            int    `json:"vmid"`
	ProxyProtocol byte   `json:"proxy_protocol,omitempty"`
}

type UpstreamInformation struct {
	Host          string
	Signer        ssh.Signer
	Password      *string
	ProxyProtocol byte
}

type Authenticator struct {
	Endpoint string
	Token    string
	Recovery RecoveryConfig
}

func makeAuthenticator(auth AuthConfig, recovery RecoveryConfig) Authenticator {
	return Authenticator{
		Endpoint: auth.Endpoint,
		Token:    auth.Token,
		Recovery: recovery,
	}
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

func (auth Authenticator) AuthUser(request any, username string) (*UpstreamInformation, error) {
	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(request); err != nil {
		return nil, err
	}
	res, err := http.Post(auth.Endpoint, "application/json", payload)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var response AuthResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}
	if response.Status != "ok" {
		return nil, nil
	}

	var upstream UpstreamInformation
	// FIXME: Can this be handled in API server?
	if slices.Contains(auth.Recovery.Usernames, username) {
		upstream.Host = auth.Recovery.Address
		password := fmt.Sprintf("%d %s", response.Id, auth.Recovery.Token)
		upstream.Password = &password
	} else {
		upstream.Host = response.Address
	}
	upstream.Signer = parsePrivateKey(response.PrivateKey, response.Cert)
	upstream.ProxyProtocol = response.ProxyProtocol
	return &upstream, nil
}

func (auth Authenticator) AuthUserWithPublicKey(key ssh.PublicKey, unixUsername string) (*UpstreamInformation, error) {
	keyType := key.Type()
	keyData := base64.StdEncoding.EncodeToString(key.Marshal())
	request := &AuthRequestPublicKey{
		AuthType:      "key",
		UnixUsername:  unixUsername,
		PublicKeyType: keyType,
		PublicKeyData: keyData,
		Token:         auth.Token,
	}
	return auth.AuthUser(request, unixUsername)
}

func (auth Authenticator) AuthUserWithUserPass(username string, password string, unixUsername string) (*UpstreamInformation, error) {
	request := &AuthRequestPassword{
		AuthType:     "key",
		Username:     username,
		Password:     password,
		UnixUsername: unixUsername,
		Token:        auth.Token,
	}
	return auth.AuthUser(request, unixUsername)
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
