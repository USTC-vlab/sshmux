package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// testConnection is the connection identity used by the metric assertions.
var testConnection = connectionInfo{
	Username:     "vlab",
	UpstreamHost: "10.0.0.7",
	UpstreamPort: 22,
	Established:  true,
}

// prometheusMetrics starts a Metrics instance with only the Prometheus
// endpoint enabled, bound to an ephemeral port.
func prometheusMetrics(t *testing.T) *Metrics {
	t.Helper()
	metrics, err := makeMetrics(MetricsConfig{
		Enabled:    true,
		Prometheus: MetricsPrometheusConfig{Enabled: true, Address: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer cancel()
		metrics.Shutdown(ctx)
	})
	return metrics
}

func scrape(t *testing.T, metrics *Metrics) string {
	t.Helper()
	addr := metrics.PrometheusAddr()
	if addr == nil {
		t.Fatal("Prometheus endpoint is not listening")
	}
	res, err := http.Get(fmt.Sprintf("http://%s%s", addr, metrics.promPath))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("scrape status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestMetricsDisabled(t *testing.T) {
	metrics, err := makeMetrics(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	if addr := metrics.PrometheusAddr(); addr != nil {
		t.Fatalf("disabled metrics listen on %s, want no endpoint", addr)
	}
	// Every record method must stay a no-op.
	ctx := context.Background()
	metrics.ConnectionAccepted(ctx)
	metrics.HandshakeFinished(ctx, testConnection, nil, time.Second)
	metrics.UpstreamDialed(ctx, io.EOF)
	metrics.AuthFinished(ctx, "publickey", 200, nil, time.Second)
	metrics.ConnectionClosed(ctx, testConnection, nil, time.Second)
	metrics.Shutdown(ctx)
}

func TestMetricsWithoutExporter(t *testing.T) {
	if _, err := makeMetrics(MetricsConfig{Enabled: true}); err == nil {
		t.Fatal("metrics without any exporter should fail to start")
	}
}

func TestMetricsPrometheusEndpoint(t *testing.T) {
	metrics := prometheusMetrics(t)
	ctx := context.Background()

	metrics.ConnectionAccepted(ctx)
	metrics.ConnectionAccepted(ctx)
	metrics.HandshakeFinished(ctx, testConnection, nil, 100*time.Millisecond)
	metrics.UpstreamDialed(ctx, nil)
	metrics.ConnectionClosed(ctx, testConnection, nil, time.Second)
	metrics.ConnectionClosed(ctx, testConnection, os.ErrDeadlineExceeded, 2*time.Second)

	body := scrape(t, metrics)
	const group = `event_outcome="success",server_address="10.0.0.7",server_port="22",user_name="vlab"`
	for _, want := range []string{
		`sshmux_connections_total 2`,
		`sshmux_connections_active 0`,
		`sshmux_sessions_total{` + group + `} 1`,
		`sshmux_sessions_total{error_type="timeout",event_outcome="failure",server_address="10.0.0.7",server_port="22",user_name="vlab"} 1`,
		`sshmux_upstream_connections_total{event_outcome="success"} 1`,
		`sshmux_session_duration_seconds_count{` + group + `} 1`,
		`sshmux_handshake_duration_seconds_count{` + group + `} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}

func TestMetricsPrometheusPathNormalized(t *testing.T) {
	metrics, err := makeMetrics(MetricsConfig{
		Enabled:    true,
		Prometheus: MetricsPrometheusConfig{Enabled: true, Path: "sshmux/metrics"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if metrics.promPath != "/sshmux/metrics" {
		t.Fatalf("Prometheus path = %q, want %q", metrics.promPath, "/sshmux/metrics")
	}
	if metrics.promAddress != defaultPrometheusAddress {
		t.Fatalf("Prometheus address = %q, want %q", metrics.promAddress, defaultPrometheusAddress)
	}
}

type stubAuthenticator struct {
	status int
	err    error
}

func (a *stubAuthenticator) Auth(AuthRequest, string) (int, *AuthResponse, error) {
	return a.status, nil, a.err
}

func TestInstrumentedAuthenticator(t *testing.T) {
	metrics := prometheusMetrics(t)
	authenticator := &instrumentedAuthenticator{
		inner:   &stubAuthenticator{status: 401},
		metrics: metrics,
	}
	status, _, err := authenticator.Auth(AuthRequest{Method: "publickey"}, "vlab")
	if err != nil || status != 401 {
		t.Fatalf("Auth() = (%d, %v), want (401, nil)", status, err)
	}

	failing := &instrumentedAuthenticator{
		inner:   &stubAuthenticator{err: io.ErrUnexpectedEOF},
		metrics: metrics,
	}
	if _, _, err := failing.Auth(AuthRequest{Method: "keyboard-interactive"}, "vlab"); err == nil {
		t.Fatal("Auth() error = nil, want an error")
	}

	body := scrape(t, metrics)
	for _, want := range []string{
		`sshmux_auth_requests_total{event_outcome="success",sshmux_auth_method="publickey",sshmux_auth_status="401"} 1`,
		`sshmux_auth_requests_total{error_type="eof",event_outcome="failure",sshmux_auth_method="keyboard-interactive",sshmux_auth_status="0"} 1`,
		`sshmux_auth_duration_seconds_count{event_outcome="success",sshmux_auth_method="publickey",sshmux_auth_status="401"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}

func TestMetricsOTLPHTTPExport(t *testing.T) {
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	metrics, err := makeMetrics(MetricsConfig{
		Enabled: true,
		OTLP: MetricsOTLPConfig{
			Enabled:  true,
			Endpoint: server.URL + "/v1/metrics",
			Headers:  []HTTPHeaderConfig{{Name: "Authorization", Value: "ApiKey 12345678"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	metrics.ConnectionAccepted(context.Background())

	// Shutdown flushes the periodic reader, so an export must have happened.
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	defer cancel()
	metrics.Shutdown(ctx)

	select {
	case path := <-requests:
		if path != "/v1/metrics" {
			t.Fatalf("OTLP request path = %q, want %q", path, "/v1/metrics")
		}
	default:
		t.Fatal("no OTLP export was received")
	}
}

func TestMakeOTLPExporterErrors(t *testing.T) {
	cases := []struct {
		name   string
		config MetricsOTLPConfig
	}{
		{"bad scheme", MetricsOTLPConfig{Enabled: true, Endpoint: "udp://127.0.0.1:4318"}},
		{"unknown protocol", MetricsOTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4318", Protocol: "thrift"}},
		{"grpc with path", MetricsOTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4317/v1/metrics", Protocol: "grpc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := makeOTLPExporter(tc.config); err == nil {
				t.Fatal("makeOTLPExporter() error = nil, want an error")
			}
		})
	}
}

// TestOTLPEndpointPaths pins that a configured endpoint is used verbatim, the
// way a signal-specific endpoint is, with no signal path appended to it.
func TestOTLPEndpointPaths(t *testing.T) {
	cases := []struct{ endpoint, want string }{
		{"http://%s/v1/metrics", "/v1/metrics"},
		{"http://%s/otlp/v1/metrics", "/otlp/v1/metrics"},
		{"http://%s/custom", "/custom"},
		// No path means the root, not the signal path.
		{"http://%s", "/"},
		{"http://%s/", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			server, requests := otlpTestCollector(t)
			host := strings.TrimPrefix(server.URL, "http://")
			exportOnce(t, MetricsConfig{
				Enabled: true,
				OTLP:    MetricsOTLPConfig{Enabled: true, Endpoint: fmt.Sprintf(tc.endpoint, host)},
			})
			if got := awaitExport(t, requests).Path; got != tc.want {
				t.Fatalf("endpoint %q posted to %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestMakeOTLPExporterProtocols(t *testing.T) {
	for _, protocol := range []string{"", "http", "http/protobuf", "grpc"} {
		endpoint := "https://otel.example.com:4318/otlp"
		if protocol == "grpc" {
			endpoint = "https://otel.example.com:4317"
		}
		exporter, err := makeOTLPExporter(MetricsOTLPConfig{Enabled: true, Protocol: protocol, Endpoint: endpoint})
		if err != nil {
			t.Fatalf("protocol %q: %v", protocol, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		exporter.Shutdown(ctx)
		cancel()
	}
}

func TestErrorType(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{io.EOF, "eof"},
		{io.ErrUnexpectedEOF, "eof"},
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "timeout"},
		{os.ErrDeadlineExceeded, "timeout"},
		{net.ErrClosed, "closed"},
		{fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), "timeout"},
		{errors.New("boom"), "other"},
	}
	for _, tc := range cases {
		if got := errorType(tc.err); got != tc.want {
			t.Errorf("errorType(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestServerMetricsWiring checks that a connection served by the real server
// shows up in the exported metrics, i.e. that the instruments are wired into
// the connection handler and not just reachable in isolation.
func TestServerMetricsWiring(t *testing.T) {
	sshmux, err := makeServer(Config{
		Address: "127.0.0.1:0",
		SSH:     SSHConfig{HostKeys: []SSHKeyConfig{{Path: "fixtures/ssh_host_ed25519_key"}}},
		Auth:    AuthConfig{Endpoint: "http://127.0.0.1:5000", Version: "v1"},
		Metrics: MetricsConfig{
			Enabled:    true,
			Prometheus: MetricsPrometheusConfig{Enabled: true, Address: "127.0.0.1:0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sshmux.Start(); err != nil {
		t.Fatal(err)
	}
	defer sshmux.Shutdown()

	// A connection that goes away before the SSH handshake completes still has
	// to be accounted for as an accepted and then failed session.
	conn, err := net.Dial("tcp", sshmux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = scrape(t, sshmux.Metrics)
		if strings.Contains(body, "sshmux_sessions_total{") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, want := range []string{
		`sshmux_connections_total 1`,
		`sshmux_connections_active 0`,
		`sshmux_sessions_total{`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}

func TestConnectionGrouping(t *testing.T) {
	metrics := prometheusMetrics(t)
	metrics.ConnectionClosed(t.Context(), testConnection, nil, time.Second)
	// A connection that failed before authentication has neither a username nor
	// an upstream, since the auth API never answered.
	metrics.ConnectionClosed(t.Context(), connectionInfo{}, io.EOF, time.Second)

	body := scrape(t, metrics)
	for _, want := range []string{
		`sshmux_sessions_total{event_outcome="success",server_address="10.0.0.7",server_port="22",user_name="vlab"} 1`,
		`sshmux_session_duration_seconds_count{event_outcome="success",server_address="10.0.0.7",server_port="22",user_name="vlab"} 1`,
		`sshmux_sessions_total{error_type="eof",event_outcome="failure",server_address="unknown",server_port="0",user_name="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}

func TestOTLPProtocolPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		env        map[string]string
		want       string
		wantErr    bool
	}{
		{name: "default", want: "http/protobuf"},
		{name: "configured", configured: "grpc", want: "grpc"},
		{
			name: "from the generic environment variable",
			env:  map[string]string{envOTLPProtocol: "grpc"},
			want: "grpc",
		},
		{
			name: "the metrics environment variable wins over the generic one",
			env:  map[string]string{envOTLPProtocol: "grpc", envOTLPMetricsProtocol: "http/protobuf"},
			want: "http/protobuf",
		},
		{
			name:       "configuration wins over the environment",
			configured: "http",
			env:        map[string]string{envOTLPMetricsProtocol: "grpc"},
			want:       "http/protobuf",
		},
		{
			name:    "http/json is not supported",
			env:     map[string]string{envOTLPProtocol: "http/json"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			got, err := otlpProtocol(tc.configured)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("otlpProtocol(%q) error = nil, want an error", tc.configured)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("otlpProtocol(%q) = %q, want %q", tc.configured, got, tc.want)
			}
		})
	}
}

type otlpRequest struct {
	Path   string
	Header http.Header
}

// otlpTestCollector serves as an OTLP/HTTP endpoint and reports the requests it
// received.
func otlpTestCollector(t *testing.T) (*httptest.Server, chan otlpRequest) {
	t.Helper()
	requests := make(chan otlpRequest, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- otlpRequest{Path: r.URL.Path, Header: r.Header.Clone()}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

// awaitExport waits for the next export to reach the collector.
func awaitExport(t *testing.T, requests chan otlpRequest) otlpRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("no OTLP export was received")
		return otlpRequest{}
	}
}

func exportOnce(t *testing.T, config MetricsConfig) {
	t.Helper()
	metrics, err := makeMetrics(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	metrics.ConnectionAccepted(t.Context())
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	defer cancel()
	metrics.Shutdown(ctx)
}

// TestOTLPEndpointFromEnvironment covers the other half of the rule: the
// generic environment variable is a base URL, so the signal path is appended.
func TestOTLPEndpointFromEnvironment(t *testing.T) {
	server, paths := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)

	// No endpoint in the config file, so the environment has to supply it.
	exportOnce(t, MetricsConfig{Enabled: true, OTLP: MetricsOTLPConfig{Enabled: true}})

	if path := awaitExport(t, paths).Path; path != "/v1/metrics" {
		t.Fatalf("OTLP request path = %q, want %q", path, "/v1/metrics")
	}
}

func TestOTLPEndpointConfigWinsOverEnvironment(t *testing.T) {
	configured, paths := otlpTestCollector(t)
	unused, unusedPaths := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", unused.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", unused.URL+"/v1/metrics")

	exportOnce(t, MetricsConfig{
		Enabled: true,
		OTLP:    MetricsOTLPConfig{Enabled: true, Endpoint: configured.URL + "/otlp/v1/metrics"},
	})

	if path := awaitExport(t, paths).Path; path != "/otlp/v1/metrics" {
		t.Fatalf("OTLP request path = %q, want %q", path, "/otlp/v1/metrics")
	}
	select {
	case request := <-unusedPaths:
		t.Fatalf("the endpoint from the environment was called on %q", request.Path)
	default:
	}
}

func TestOTLPHeadersPrecedence(t *testing.T) {
	t.Run("from the environment", func(t *testing.T) {
		server, requests := otlpTestCollector(t)
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
		t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-scope-orgid=vlab")

		exportOnce(t, MetricsConfig{Enabled: true, OTLP: MetricsOTLPConfig{Enabled: true}})

		if got := awaitExport(t, requests).Header.Get("X-Scope-Orgid"); got != "vlab" {
			t.Fatalf("X-Scope-OrgID = %q, want %q", got, "vlab")
		}
	})

	t.Run("configuration wins", func(t *testing.T) {
		server, requests := otlpTestCollector(t)
		t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-scope-orgid=from-environment")

		exportOnce(t, MetricsConfig{Enabled: true, OTLP: MetricsOTLPConfig{
			Enabled:  true,
			Endpoint: server.URL + "/v1/metrics",
			Headers:  []HTTPHeaderConfig{{Name: "X-Scope-OrgID", Value: "from-config"}},
		}})

		if got := awaitExport(t, requests).Header.Get("X-Scope-Orgid"); got != "from-config" {
			t.Fatalf("X-Scope-OrgID = %q, want %q", got, "from-config")
		}
	})
}

// TestOTLPIntervalFromEnvironment checks that an export happens on the interval
// set by the environment, without a shutdown flush forcing it.
func TestOTLPIntervalFromEnvironment(t *testing.T) {
	server, requests := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "200")

	metrics, err := makeMetrics(MetricsConfig{Enabled: true, OTLP: MetricsOTLPConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	defer metrics.Shutdown(t.Context())
	metrics.ConnectionAccepted(t.Context())

	if path := awaitExport(t, requests).Path; path != "/v1/metrics" {
		t.Fatalf("OTLP request path = %q, want %q", path, "/v1/metrics")
	}
}

func TestMetricsResourceAttributePrecedence(t *testing.T) {
	fromEnv := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("from-environment"),
		semconv.ServiceVersion("v9.9.9"),
	)
	unnamed := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("unknown_service:sshmux"),
	)

	// The environment supplies the name, so sshmux must not override it.
	attrs, err := metricsResourceAttributes(MetricsConfig{}, fromEnv)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := findAttribute(attrs, semconv.ServiceNameKey); ok {
		t.Errorf("service.name = %q, want it left to the environment", name)
	}
	if version, ok := findAttribute(attrs, semconv.ServiceVersionKey); ok {
		t.Errorf("service.version = %q, want it left to the environment", version)
	}

	// An explicit name in the config file wins over the environment.
	attrs, err = metricsResourceAttributes(MetricsConfig{ServiceName: "from-config"}, fromEnv)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := findAttribute(attrs, semconv.ServiceNameKey); name != "from-config" {
		t.Errorf("service.name = %q, want %q", name, "from-config")
	}

	// With neither set, sshmux falls back to its own default.
	attrs, err = metricsResourceAttributes(MetricsConfig{}, unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := findAttribute(attrs, semconv.ServiceNameKey); name != defaultMetricsServiceName {
		t.Errorf("service.name = %q, want %q", name, defaultMetricsServiceName)
	}
	if _, ok := findAttribute(attrs, semconv.ServiceVersionKey); !ok {
		t.Error("service.version is missing, want the build version")
	}

	// Attributes from the config file are always applied.
	attrs, err = metricsResourceAttributes(MetricsConfig{
		Attributes: []MetricsAttributeConfig{{Name: "env", Value: "staging"}},
	}, unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := findAttribute(attrs, attribute.Key("env")); value != "staging" {
		t.Errorf("env = %q, want %q", value, "staging")
	}

	if _, err := metricsResourceAttributes(MetricsConfig{
		Attributes: []MetricsAttributeConfig{{Value: "no name"}},
	}, unnamed); err == nil {
		t.Error("a nameless resource attribute should be rejected")
	}
}

func findAttribute(attrs []attribute.KeyValue, key attribute.Key) (string, bool) {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

// TestServerMetricsUpstreamGrouping drives a real SSH client through sshmux and
// checks that the backend address the auth API returned reaches the metrics.
func TestServerMetricsUpstreamGrouping(t *testing.T) {
	if _, err := exec.LookPath("sshd"); err != nil {
		t.Skip("sshd is not available")
	}
	initEnv(t)
	enableProxy = false

	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sshmux, err := makeServer(Config{
		Address: "127.0.0.1:0",
		SSH:     SSHConfig{HostKeys: []SSHKeyConfig{{Path: "fixtures/ssh_host_ed25519_key"}}},
		Auth:    AuthConfig{Endpoint: "http://127.0.0.1:5000", Version: "v1"},
		Metrics: MetricsConfig{
			Enabled:    true,
			Prometheus: MetricsPrometheusConfig{Enabled: true, Address: "127.0.0.1:0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sshmux.Start(); err != nil {
		t.Fatal(err)
	}
	defer sshmux.Shutdown()

	sshd := onetimeSSHDServer(t)
	defer stopSSHD(t, sshd)
	address := sshmux.Addr().(*net.TCPAddr)
	sshCommand := exec.Command(
		"ssh", "-p", fmt.Sprint(address.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "ControlMaster=no",
		"-i", "fixtures/ssh_id_rsa",
		"-o", "IdentityAgent=no",
		address.IP.String(), "uname")
	sshCommand.Dir, _ = os.Getwd()
	if err := sshCommand.Run(); err != nil {
		t.Fatal("ssh: ", err)
	}

	// The session is recorded once its handler winds down, shortly after the
	// client exits.
	want := fmt.Sprintf(`sshmux_sessions_total{event_outcome="success",server_address=%q,server_port="%d",user_name=%q} 1`,
		sshdServerAddr.IP.String(), sshdServerAddr.Port, currentUser.Username)
	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = scrape(t, sshmux.Metrics)
		if strings.Contains(body, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("scrape output does not contain %q:\n%s", want, body)
}

// countSeries counts the exported sshmux_sessions_total series.
func countSeries(body string) int {
	count := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "sshmux_sessions_total{") {
			count++
		}
	}
	return count
}

// recordSessions records one session per distinct username, so that each one
// lands on its own time series.
func recordSessions(t *testing.T, metrics *Metrics, count int) {
	t.Helper()
	for i := range count {
		info := connectionInfo{
			Username:     fmt.Sprintf("user%d", i),
			UpstreamHost: fmt.Sprintf("10.0.0.%d", i),
			UpstreamPort: 22,
			Established:  true,
		}
		metrics.ConnectionClosed(t.Context(), info, nil, time.Second)
	}
}

// TestConnectionGroupingHitsDefaultCap demonstrates why a large deployment has
// to turn the grouping off: past the SDK's default of 2000 series per
// instrument, further users stop getting a series of their own.
func TestConnectionGroupingHitsDefaultCap(t *testing.T) {
	metrics := prometheusMetrics(t)

	recordSessions(t, metrics, 2500)
	body := scrape(t, metrics)
	if !strings.Contains(body, `otel_metric_overflow="true"`) {
		t.Errorf("scrape output has no overflow series, so the cap was not reached:\n%s", body)
	}
	// 1999 users keep a series of their own, the rest share the overflow one.
	if got := countSeries(body); got != 2000 {
		t.Errorf("exported %d session series, want 2000", got)
	}
}

// TestConnectionGroupingDisabled checks the opt-out large deployments need: the
// connection metrics collapse to a single series per outcome, no matter how
// many distinct users connect.
func TestConnectionGroupingDisabled(t *testing.T) {
	metrics, err := makeMetrics(MetricsConfig{
		Enabled:            true,
		ConnectionGrouping: new(bool),
		Prometheus:         MetricsPrometheusConfig{Enabled: true, Address: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	defer metrics.Shutdown(t.Context())

	// Well past the SDK default of 2000, which would cap a grouped build.
	recordSessions(t, metrics, 2500)
	body := scrape(t, metrics)
	if strings.Contains(body, `otel_metric_overflow="true"`) {
		t.Error("scrape output has an overflow series, so the cap was still reached")
	}
	if got := countSeries(body); got != 1 {
		t.Errorf("exported %d session series, want 1", got)
	}
	for _, unwanted := range []string{"username=", "upstream_address="} {
		if strings.Contains(body, unwanted) {
			t.Errorf("scrape output still contains %q:\n%s", unwanted, body)
		}
	}
	if want := `sshmux_sessions_total{event_outcome="success"} 2500`; !strings.Contains(body, want) {
		t.Errorf("scrape output does not contain %q:\n%s", want, body)
	}
}
