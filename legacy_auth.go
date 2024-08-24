package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
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

type LegacyAuthUpstream struct {
	Host          string
	PrivateKey    string
	Certificate   string
	Password      *string
	ProxyProtocol byte
}

type LegacyAuthenticator struct {
	Endpoint       string
	Token          string
	Recovery       RecoveryConfig
	UsernamePolicy UsernamePolicyConfig
	PasswordPolicy PasswordPolicyConfig
}

func makeLegacyAuthenticator(auth AuthConfig, recovery RecoveryConfig) LegacyAuthenticator {
	return LegacyAuthenticator{
		Endpoint: auth.Endpoint,
		Token:    auth.Token,
		Recovery: recovery,
		UsernamePolicy: UsernamePolicyConfig{
			InvalidUsernames:       auth.InvalidUsernames,
			InvalidUsernameMessage: auth.InvalidUsernameMessage,
		},
		PasswordPolicy: PasswordPolicyConfig{
			AllUsernameNoPassword: auth.AllUsernameNoPassword,
			UsernamesNoPassword:   auth.UsernamesNoPassword,
		},
	}
}

func (auth *LegacyAuthenticator) Auth(request AuthRequest, username string) (int, *AuthResponse, error) {
	var upstream *LegacyAuthUpstream
	var err error
	if slices.Contains(auth.UsernamePolicy.InvalidUsernames, username) {
		// 15: SSH_DISCONNECT_ILLEGAL_USER_NAME
		msg := fmt.Sprintf(auth.UsernamePolicy.InvalidUsernameMessage, username)
		failure := AuthFailure{Message: msg, Reason: 15, Disconnect: true}
		return 403, &AuthResponse{Failure: &failure}, nil
	}
	if request.Method == "publickey" {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(request.PublicKey))
		if err != nil {
			return 500, nil, err
		}
		upstream, err = auth.AuthUserWithPublicKey(publicKey, username)
		if err != nil {
			return 500, nil, err
		}
	}
	if request.Method == "keyboard-interactive" {
		requireUnixPassword := !auth.PasswordPolicy.AllUsernameNoPassword &&
			!slices.Contains(auth.Recovery.Usernames, username) &&
			!slices.Contains(auth.PasswordPolicy.UsernamesNoPassword, username)
		username, has_username := request.Payload["username"]
		password, has_password := request.Payload["password"]
		if !has_username || !has_password {
			challenge := AuthChallenge{
				Instruction: "Please enter Vlab username & password.",
				Fields: []AuthChallengeField{
					{Key: "username", Prompt: "Vlab username (Student ID): "},
					{Key: "password", Prompt: "Vlab password: ", Secret: true},
				},
			}
			resp := AuthResponse{Challenges: []AuthChallenge{challenge}}
			return 401, &resp, nil
		}
		_, has_unix_password := request.Payload["unix_password"]
		if requireUnixPassword && !has_unix_password {
			challenge := AuthChallenge{
				Instruction: "Please enter UNIX password.",
				Fields: []AuthChallengeField{
					{Key: "unix_password", Prompt: "UNIX password: ", Secret: true},
				},
			}
			resp := AuthResponse{Challenges: []AuthChallenge{challenge}}
			return 401, &resp, nil
		}
		upstream, err = auth.AuthUserWithUserPass(username, password, username)
		if err != nil {
			return 500, nil, err
		}
	}
	if upstream != nil {
		address, err := netip.ParseAddrPort(upstream.Host)
		if err != nil {
			return 500, nil, err
		}
		auth_upstream := AuthUpstream{
			Host:        address.Addr().String(),
			Port:        address.Port(),
			PrivateKey:  upstream.PrivateKey,
			Certificate: upstream.Certificate,
			Password:    upstream.Password,
		}
		unix_password, has_unix_password := request.Payload["unix_password"]
		if has_unix_password {
			auth_upstream.Password = &unix_password
		}
		if upstream.ProxyProtocol > 0 {
			proxyProtocol := fmt.Sprintf("v%d", upstream.ProxyProtocol)
			auth_upstream.ProxyProtocol = &proxyProtocol
		}
		resp := AuthResponse{Upstream: &auth_upstream}
		return 200, &resp, nil
	}
	return 403, &AuthResponse{}, nil
}

func (auth LegacyAuthenticator) AuthUser(request any, username string) (*LegacyAuthUpstream, error) {
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
	var upstream LegacyAuthUpstream
	if slices.Contains(auth.Recovery.Usernames, username) {
		upstream.Host = auth.Recovery.Address
		password := fmt.Sprintf("%d %s", response.Id, auth.Recovery.Token)
		upstream.Password = &password
	} else {
		upstream.Host = response.Address
	}
	upstream.PrivateKey = response.PrivateKey
	upstream.Certificate = response.Cert
	upstream.ProxyProtocol = response.ProxyProtocol
	return &upstream, nil
}

func (auth LegacyAuthenticator) AuthUserWithPublicKey(key ssh.PublicKey, unixUsername string) (*LegacyAuthUpstream, error) {
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

func (auth LegacyAuthenticator) AuthUserWithUserPass(username string, password string, unixUsername string) (*LegacyAuthUpstream, error) {
	request := &LegacyAuthRequestPassword{
		AuthType:     "key",
		Username:     username,
		Password:     password,
		UnixUsername: unixUsername,
		Token:        auth.Token,
	}
	return auth.AuthUser(request, unixUsername)
}
