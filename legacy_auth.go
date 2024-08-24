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

type LegacyAuthRequestPublicKey struct {
	AuthType      string `json:"auth_type"`
	UnixUsername  string `json:"unix_username"`
	PublicKeyType string `json:"public_key_type"`
	PublicKeyData string `json:"public_key_data"`
	Token         string `json:"token"`
}

type LegacyAuthRequestPassword struct {
	AuthType     string `json:"auth_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	UnixUsername string `json:"unix_username"`
	Token        string `json:"token"`
}

type LegacyAuthResponse struct {
	Status        string `json:"status"`
	Address       string `json:"address"`
	PrivateKey    string `json:"private_key"`
	Cert          string `json:"cert"`
	Id            int    `json:"vmid"`
	ProxyProtocol byte   `json:"proxy_protocol,omitempty"`
}

type LegacyAuthenticator struct {
	Endpoint string
	Token    string
	Recovery RecoveryConfig
}

func makeLegacyAuthenticator(auth AuthConfig, recovery RecoveryConfig) LegacyAuthenticator {
	return LegacyAuthenticator{
		Endpoint: auth.Endpoint,
		Token:    auth.Token,
		Recovery: recovery,
	}
}

func (auth LegacyAuthenticator) AuthUser(request any, username string) (*UpstreamInformation, error) {
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
	var response LegacyAuthResponse
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

func (auth LegacyAuthenticator) AuthUserWithPublicKey(key ssh.PublicKey, unixUsername string) (*UpstreamInformation, error) {
	keyType := key.Type()
	keyData := base64.StdEncoding.EncodeToString(key.Marshal())
	request := &LegacyAuthRequestPublicKey{
		AuthType:      "key",
		UnixUsername:  unixUsername,
		PublicKeyType: keyType,
		PublicKeyData: keyData,
		Token:         auth.Token,
	}
	return auth.AuthUser(request, unixUsername)
}

func (auth LegacyAuthenticator) AuthUserWithUserPass(username string, password string, unixUsername string) (*UpstreamInformation, error) {
	request := &LegacyAuthRequestPassword{
		AuthType:     "key",
		Username:     username,
		Password:     password,
		UnixUsername: unixUsername,
		Token:        auth.Token,
	}
	return auth.AuthUser(request, unixUsername)
}
