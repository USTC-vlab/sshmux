package main

import (
	"fmt"
	"net/netip"
)

type SSHConfig struct {
	Banner   string         `toml:"banner,omitempty"`
	HostKeys []SSHKeyConfig `toml:"host-keys"`
}

type SSHKeyConfig struct {
	Path    string `toml:"path,omitempty"`
	Base64  string `toml:"base64,omitempty"`
	Content string `toml:"content,omitempty"`
}

type AuthConfig struct {
	Endpoint string `toml:"endpoint"`
	Version  string `toml:"version,omitempty"`
	// The following settings are for legacy API only
	Token                  string   `toml:"token,omitempty"`
	InvalidUsernames       []string `toml:"invalid-usernames,omitempty"`
	InvalidUsernameMessage string   `toml:"invalid-username-message,omitempty"`
	AllUsernameNoPassword  bool     `toml:"all-username-nopassword,omitempty"`
	UsernamesNoPassword    []string `toml:"usernames-nopassword,omitempty"`
}

type LoggerConfig struct {
	Enabled  bool   `toml:"enabled"`
	Endpoint string `toml:"endpoint,omitempty"`
}

type ProxyProtocolConfig struct {
	Enabled  bool     `toml:"enabled"`
	Networks []string `toml:"networks,omitempty"`
	Hosts    []string `toml:"hosts,omitempty"`
}

type RecoveryConfig struct {
	Address   string   `toml:"address,omitempty"`
	Usernames []string `toml:"usernames,omitempty"`
	Token     string   `toml:"token,omitempty"`
}

type Config struct {
	Address       string              `toml:"address"`
	SSH           SSHConfig           `toml:"ssh"`
	Auth          AuthConfig          `toml:"auth"`
	Logger        LoggerConfig        `toml:"logger"`
	ProxyProtocol ProxyProtocolConfig `toml:"proxy-protocol"`
	Recovery      RecoveryConfig      `toml:"recovery"`
}

type LegacyConfig struct {
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

type ProxyPolicyConfig struct {
	AllowedCIDRs []netip.Prefix
	AllowedHosts []string
}

type UsernamePolicyConfig struct {
	InvalidUsernames       []string
	InvalidUsernameMessage string
}

type PasswordPolicyConfig struct {
	AllUsernameNoPassword bool
	UsernamesNoPassword   []string
}

func convertLegacyConfig(config LegacyConfig) Config {
	if config.RecoveryToken == "" {
		config.RecoveryToken = config.Token
	}
	hostKeys := make([]SSHKeyConfig, 0, len(config.HostKeys))
	for _, path := range config.HostKeys {
		hostKeys = append(hostKeys, SSHKeyConfig{Path: path})
	}
	return Config{
		Address: config.Address,
		SSH: SSHConfig{
			Banner:   config.Banner,
			HostKeys: hostKeys,
		},
		Auth: AuthConfig{
			Endpoint:               config.API,
			Version:                "legacy",
			Token:                  config.Token,
			InvalidUsernames:       config.InvalidUsername,
			InvalidUsernameMessage: config.InvalidUsernameMessage,
			AllUsernameNoPassword:  config.AllUsernameNoPassword,
			UsernamesNoPassword:    config.UsernameNoPassword,
		},
		Logger: LoggerConfig{
			Enabled:  config.Logger != "",
			Endpoint: fmt.Sprintf("udp://%s", config.Logger),
		},
		ProxyProtocol: ProxyProtocolConfig{
			Enabled:  len(config.ProxyCIDRs) > 0,
			Networks: config.ProxyCIDRs,
		},
		Recovery: RecoveryConfig{
			Address:   config.RecoveryServer,
			Usernames: config.RecoveryUsername,
			Token:     config.RecoveryToken,
		},
	}
}

func convertProxyPolicyConfig(config ProxyProtocolConfig) (ProxyPolicyConfig, error) {
	if !config.Enabled {
		return ProxyPolicyConfig{}, nil
	}
	allowedCIDRs := make([]netip.Prefix, 0, len(config.Networks))
	for _, cidr := range config.Networks {
		network, err := netip.ParsePrefix(cidr)
		if err != nil {
			return ProxyPolicyConfig{}, err
		}
		allowedCIDRs = append(allowedCIDRs, network)
	}
	allowedHosts := make([]string, 0)
	for _, host := range config.Hosts {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			allowedHosts = append(allowedHosts, host)
			continue
		}
		allowedCIDRs = append(allowedCIDRs, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return ProxyPolicyConfig{AllowedCIDRs: allowedCIDRs, AllowedHosts: allowedHosts}, nil
}
