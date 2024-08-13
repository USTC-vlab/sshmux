package main

type Config struct {
	Address    string   `json:"address"`
	ProxyCIDRs []string `json:"proxy-protocol-allowed-cidrs"`
	HostKeys   []string `json:"host-keys"`
	API        string   `json:"api"`
	Logger     string   `json:"logger"`
	Banner     string   `json:"banner"`
	Token      string   `json:"token"`
	// The following should be moved into API server
	RecoveryToken          string   `json:"recovery-token"`
	RecoveryServer         string   `json:"recovery-server"`
	RecoveryUsername       []string `json:"recovery-username"`
	AllUsernameNoPassword  bool     `json:"all-username-nopassword"`
	UsernameNoPassword     []string `json:"username-nopassword"`
	InvalidUsername        []string `json:"invalid-username"`
	InvalidUsernameMessage string   `json:"invalid-username-message"`
}

type UsernamePolicyConfig struct {
	InvalidUsername        []string `json:"invalid-username"`
	InvalidUsernameMessage string   `json:"invalid-username-message"`
}

type PasswordPolicyConfig struct {
	AllUsernameNoPassword bool     `json:"all-username-nopassword"`
	UsernameNoPassword    []string `json:"username-nopassword"`
}

type RecoveryConfig struct {
	Server   string   `json:"recovery-server"`
	Username []string `json:"recovery-username"`
	Token    string   `json:"token"`
}
