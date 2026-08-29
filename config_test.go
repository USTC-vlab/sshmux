package main

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// configFixture pairs a configuration file under `fixtures` with the values it
// is expected to decode to.
type configFixture struct {
	path  string
	check func(*testing.T, Config)
}

var configFixtures = []configFixture{
	{"fixtures/config.toml", checkConfigTOML},
	{"fixtures/legacy.toml", checkLegacyTOML},
	{"fixtures/config.json", checkLegacyJSON},
	{"fixtures/metrics.toml", checkMetricsTOML},
	{"fixtures/tracer.toml", checkTracerTOML},
}

func TestLoadConfigFixtures(t *testing.T) {
	for _, fixture := range configFixtures {
		t.Run(fixture.path, func(t *testing.T) {
			config, err := loadConfig(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.path == "fixtures/metrics.toml" || fixture.path == "fixtures/tracer.toml" {
				fixture.check(t, config)
				return
			}
			if config.Address != "0.0.0.0:8022" {
				t.Errorf("address = %q, want %q", config.Address, "0.0.0.0:8022")
			}
			if config.SSH.Banner != "Welcome to Vlab\n" {
				t.Errorf("ssh.banner = %q", config.SSH.Banner)
			}
			if len(config.SSH.HostKeys) != 3 {
				t.Errorf("ssh.host-keys has %d entries, want 3", len(config.SSH.HostKeys))
			}
			fixture.check(t, config)
		})
	}
}

// checkConfigTOML covers the v1 auth API and the three ways of giving a host key.
func checkConfigTOML(t *testing.T, config Config) {
	keys := config.SSH.HostKeys
	if len(keys) == 3 {
		if keys[0].Content == "" || keys[1].Base64 == "" {
			t.Errorf("ssh.host-keys = %+v, want an inline and a base64 key", keys)
		}
		if keys[2].Path != "fixtures/ssh_host_rsa_key" {
			t.Errorf("ssh.host-keys[2].path = %q", keys[2].Path)
		}
	}
	if config.Auth.Version != "v1" {
		t.Errorf("auth.version = %q, want %q", config.Auth.Version, "v1")
	}
	if config.Auth.Endpoint != "http://127.0.0.1:5000" {
		t.Errorf("auth.endpoint = %q", config.Auth.Endpoint)
	}
	if len(config.Auth.Headers) != 1 || config.Auth.Headers[0].Name != "Authorization" ||
		config.Auth.Headers[0].Value != "ApiKey 12345678" {
		t.Errorf("auth.headers = %+v", config.Auth.Headers)
	}
	if config.Logger.Enabled {
		t.Error("logger is enabled, want disabled")
	}
	checkProxyAndRecovery(t, config)
}

// checkLegacyTOML covers the settings only the legacy auth API reads.
func checkLegacyTOML(t *testing.T, config Config) {
	if config.Auth.Version != "legacy" {
		t.Errorf("auth.version = %q, want %q", config.Auth.Version, "legacy")
	}
	if config.Auth.Endpoint != "http://127.0.0.1:5000/ssh" {
		t.Errorf("auth.endpoint = %q", config.Auth.Endpoint)
	}
	if config.Auth.Token != "token" {
		t.Errorf("auth.token = %q", config.Auth.Token)
	}
	if !config.Auth.AllUsernameNoPassword {
		t.Error("auth.all-username-nopassword is false, want true")
	}
	if len(config.Auth.UsernamesNoPassword) != 3 {
		t.Errorf("auth.usernames-nopassword = %v", config.Auth.UsernamesNoPassword)
	}
	if len(config.Auth.InvalidUsernames) != 1 || config.Auth.InvalidUsernames[0] != "用户名" {
		t.Errorf("auth.invalid-usernames = %v", config.Auth.InvalidUsernames)
	}
	if !config.Logger.Enabled || config.Logger.Endpoint != "udp://127.0.0.1:5556" {
		t.Errorf("logger = %+v", config.Logger)
	}
	checkProxyAndRecovery(t, config)
}

// checkLegacyJSON covers convertLegacyConfig, which maps the deprecated flat
// keys onto the current groups.
func checkLegacyJSON(t *testing.T, config Config) {
	// convertLegacyConfig sets the version, as JSON has no key for it.
	if config.Auth.Version != "legacy" {
		t.Errorf("auth.version = %q, want %q", config.Auth.Version, "legacy")
	}
	// `api` becomes auth.endpoint, and the bare `logger` host gains a scheme.
	if config.Auth.Endpoint != "http://127.0.0.1:5000/ssh" {
		t.Errorf("auth.endpoint = %q", config.Auth.Endpoint)
	}
	if !config.Logger.Enabled || config.Logger.Endpoint != "udp://127.0.0.1:5556" {
		t.Errorf("logger = %+v", config.Logger)
	}
	// Host keys are paths only in the JSON form.
	for i, key := range config.SSH.HostKeys {
		if key.Path == "" || key.Content != "" || key.Base64 != "" {
			t.Errorf("ssh.host-keys[%d] = %+v, want a path", i, key)
		}
	}
	// `proxy-protocol-allowed-cidrs` becomes networks, not hosts.
	if !config.ProxyProtocol.Enabled || len(config.ProxyProtocol.Networks) != 1 {
		t.Errorf("proxy-protocol = %+v", config.ProxyProtocol)
	}
	// recovery-token falls back to the shared token when it is absent.
	if config.Recovery.Token != "token" {
		t.Errorf("recovery.token = %q", config.Recovery.Token)
	}
	if config.Recovery.Address != "172.30.0.101:2222" || len(config.Recovery.Usernames) != 3 {
		t.Errorf("recovery = %+v", config.Recovery)
	}
}

func checkProxyAndRecovery(t *testing.T, config Config) {
	t.Helper()
	if !config.ProxyProtocol.Enabled || len(config.ProxyProtocol.Hosts) != 1 ||
		config.ProxyProtocol.Hosts[0] != "127.0.0.22" {
		t.Errorf("proxy-protocol = %+v", config.ProxyProtocol)
	}
	if config.Recovery.Address != "172.30.0.101:2222" || len(config.Recovery.Usernames) != 3 ||
		config.Recovery.Token != "token" {
		t.Errorf("recovery = %+v", config.Recovery)
	}
}

// checkMetricsTOML covers every key of the metrics group.
func checkMetricsTOML(t *testing.T, config Config) {
	metrics := config.Metrics
	if !metrics.Enabled {
		t.Error("metrics are not enabled")
	}
	if metrics.ServiceName != "sshmux-fixture" {
		t.Errorf("metrics.service-name = %q", metrics.ServiceName)
	}
	if metrics.IntervalSeconds != 15 {
		t.Errorf("metrics.interval-seconds = %d, want 15", metrics.IntervalSeconds)
	}
	if len(metrics.Attributes) != 1 || metrics.Attributes[0].Name != "deployment.environment.name" ||
		metrics.Attributes[0].Value != "staging" {
		t.Errorf("metrics.attributes = %+v", metrics.Attributes)
	}

	otlp := metrics.OTLP
	if !otlp.Enabled || otlp.Protocol != "http" {
		t.Errorf("metrics.otlp = %+v", otlp)
	}
	if otlp.Endpoint != "http://127.0.0.1:4318/v1/metrics" {
		t.Errorf("metrics.otlp.endpoint = %q, want the full metrics path", otlp.Endpoint)
	}
	if otlp.TimeoutSeconds != 5 {
		t.Errorf("metrics.otlp.timeout-seconds = %d, want 5", otlp.TimeoutSeconds)
	}
	if len(otlp.Headers) != 1 || otlp.Headers[0].Name != "Authorization" {
		t.Errorf("metrics.otlp.headers = %+v", otlp.Headers)
	}

	prometheus := metrics.Prometheus
	if !prometheus.Enabled || prometheus.Address != "127.0.0.1:9123" ||
		prometheus.Path != "/sshmux/metrics" {
		t.Errorf("metrics.prometheus = %+v", prometheus)
	}
	if metrics.ConnectionGrouping == nil || *metrics.ConnectionGrouping {
		t.Errorf("metrics.connection-grouping = %v, want an explicit false", metrics.ConnectionGrouping)
	}
}

// checkTracerTOML covers every key of the tracer group.
func checkTracerTOML(t *testing.T, config Config) {
	tracer := config.Tracer
	if !tracer.Enabled || tracer.Convention != AttributeConventionECS {
		t.Errorf("tracer = %+v", tracer)
	}
	if tracer.ServiceName != "sshmux-fixture" {
		t.Errorf("tracer.service-name = %q", tracer.ServiceName)
	}
	if len(tracer.Attributes) != 1 || tracer.Attributes[0].Name != "deployment.environment.name" {
		t.Errorf("tracer.attributes = %+v", tracer.Attributes)
	}
	if tracer.SampleRatio == nil || *tracer.SampleRatio != 0.25 {
		t.Errorf("tracer.sample-ratio = %v, want 0.25", tracer.SampleRatio)
	}
	if tracer.Propagation == nil || *tracer.Propagation {
		t.Errorf("tracer.propagation = %v, want an explicit false", tracer.Propagation)
	}

	otlp := tracer.OTLP
	if !otlp.Enabled || otlp.Protocol != "grpc" || otlp.Endpoint != "http://127.0.0.1:4317" {
		t.Errorf("tracer.otlp = %+v", otlp)
	}
	if otlp.TimeoutSeconds != 5 || len(otlp.Headers) != 1 {
		t.Errorf("tracer.otlp = %+v", otlp)
	}
}

// TestTracerConfigAbsent checks that a configuration without a tracer group
// leaves it off, with both tri-state keys unset.
func TestTracerConfigAbsent(t *testing.T) {
	config, err := loadConfig("fixtures/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Tracer.Enabled || config.Tracer.OTLP.Enabled {
		t.Errorf("tracer = %+v, want it disabled", config.Tracer)
	}
	if config.Tracer.SampleRatio != nil || config.Tracer.Propagation != nil {
		t.Errorf("tracer tri-state keys = %v, %v, want both nil", config.Tracer.SampleRatio, config.Tracer.Propagation)
	}
	if !boolOrDefault(config.Tracer.Propagation, true) {
		t.Error("an absent propagation must leave it enabled")
	}
}

// TestMetricsConfigAbsent checks that a configuration without a metrics group
// leaves it switched off.
func TestMetricsConfigAbsent(t *testing.T) {
	config, err := loadConfig("fixtures/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Metrics.Enabled || config.Metrics.OTLP.Enabled || config.Metrics.Prometheus.Enabled {
		t.Errorf("metrics = %+v, want it disabled", config.Metrics)
	}
	// An absent connection-grouping has to stay distinguishable from an explicit
	// false, since the grouping is on by default.
	if config.Metrics.ConnectionGrouping != nil {
		t.Errorf("metrics.connection-grouping = %v, want nil", config.Metrics.ConnectionGrouping)
	}
	if !boolOrDefault(config.Metrics.ConnectionGrouping, true) {
		t.Error("an absent connection-grouping must leave the grouping on")
	}
}

// TestConvertProxyPolicyConfig covers the translation of the PROXY protocol
// allow list, where a bare address becomes a single-host prefix and a name is
// kept for resolution at connection time.
func TestConvertProxyPolicyConfig(t *testing.T) {
	policy, err := convertProxyPolicyConfig(ProxyProtocolConfig{
		Enabled:  true,
		Networks: []string{"10.10.0.0/24"},
		Hosts:    []string{"127.0.0.22", "nginx.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.10.0.0/24"),
		netip.MustParsePrefix("127.0.0.22/32"),
	}
	if len(policy.AllowedCIDRs) != len(want) {
		t.Fatalf("allowed CIDRs = %v, want %v", policy.AllowedCIDRs, want)
	}
	for i, prefix := range want {
		if policy.AllowedCIDRs[i] != prefix {
			t.Errorf("allowed CIDR %d = %v, want %v", i, policy.AllowedCIDRs[i], prefix)
		}
	}
	if len(policy.AllowedHosts) != 1 || policy.AllowedHosts[0] != "nginx.local" {
		t.Errorf("allowed hosts = %v, want [nginx.local]", policy.AllowedHosts)
	}

	// A disabled allow list must not be populated at all.
	policy, err = convertProxyPolicyConfig(ProxyProtocolConfig{Hosts: []string{"127.0.0.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.AllowedCIDRs) != 0 || len(policy.AllowedHosts) != 0 {
		t.Errorf("disabled policy = %+v, want empty", policy)
	}
}

// TestEnumeratedMetricsKeys checks the keys whose accepted values config.go
// declares as types: that a good value decodes, that a bad one is refused
// while parsing rather than later, and that every accepted value resolves.
func TestEnumeratedMetricsKeys(t *testing.T) {
	conventions := []AttributeConvention{AttributeConventionDefault, AttributeConventionECS}
	strategies := []PrometheusTranslationStrategy{UnderscoreEscaping, NoUTF8Escaping, NoTranslation}

	for _, convention := range conventions {
		var config Config
		toml := fmt.Sprintf("[metrics]\nconvention = %q\n", convention)
		if err := unmarshalConfig(toml, &config); err != nil {
			t.Errorf("convention %q: %v", convention, err)
		} else if config.Metrics.Convention != convention {
			t.Errorf("convention decoded as %q, want %q", config.Metrics.Convention, convention)
		}
	}
	for _, strategy := range strategies {
		var config Config
		toml := fmt.Sprintf("[metrics.prometheus]\ntranslation-strategy = %q\n", strategy)
		if err := unmarshalConfig(toml, &config); err != nil {
			t.Errorf("strategy %q: %v", strategy, err)
		}
	}

	// A bad value fails while the file is being read, so the error can name it.
	var config Config
	if err := unmarshalConfig("[metrics]\nconvention = \"nonsense\"\n", &config); err == nil {
		t.Error("an unknown convention should be refused while parsing")
	}
	// Prometheus does not support this one, so it is not among the accepted values.
	if err := unmarshalConfig("[metrics.prometheus]\ntranslation-strategy = \"UnderscoreEscapingWithoutSuffixes\"\n", &config); err == nil {
		t.Error("UnderscoreEscapingWithoutSuffixes should be refused while parsing")
	}

	// Every accepted value must resolve, or the type and the resolver drifted.
	for _, convention := range conventions {
		if _, err := conventionAttributeNames(convention); err != nil {
			t.Errorf("convention %q is accepted but does not resolve: %v", convention, err)
		}
	}
	for _, strategy := range strategies {
		if _, err := prometheusTranslationStrategy(strategy); err != nil {
			t.Errorf("strategy %q is accepted but does not resolve: %v", strategy, err)
		}
	}
}

func unmarshalConfig(text string, config *Config) error {
	return toml.Unmarshal([]byte(text), config)
}
