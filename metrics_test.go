package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
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
		ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
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
	const group = `event_outcome="success",server_address="10.0.0.7",server_port="22",sshmux_upstream_role="",user_name="vlab"`
	for _, want := range []string{
		`sshmux_connections_total 2`,
		`sshmux_connections_active 0`,
		`sshmux_sessions_total{` + group + `} 1`,
		`sshmux_sessions_total{error_type="timeout",event_outcome="failure",server_address="10.0.0.7",server_port="22",sshmux_upstream_role="",user_name="vlab"} 1`,
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

func TestMetricsOTLPExport(t *testing.T) {
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	metrics, err := makeMetrics(MetricsConfig{
		Enabled: true,
		OTLP: OTLPConfig{
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
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
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

func TestMakeOTLPMetricExporterErrors(t *testing.T) {
	cases := []struct {
		name   string
		config OTLPConfig
	}{
		{"bad scheme", OTLPConfig{Enabled: true, Endpoint: "udp://127.0.0.1:4318"}},
		{"unknown protocol", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4318", Protocol: "thrift"}},
		{"grpc with path", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4317/v1/metrics", Protocol: "grpc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := makeOTLPMetricExporter(tc.config); err == nil {
				t.Fatal("makeOTLPMetricExporter() error = nil, want an error")
			}
		})
	}
}

// TestMetricsOTLPEndpointPaths pins that a configured endpoint is used verbatim, the
// way a signal-specific endpoint is, with no signal path appended to it.
func TestMetricsOTLPEndpointPaths(t *testing.T) {
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
				OTLP:    OTLPConfig{Enabled: true, Endpoint: fmt.Sprintf(tc.endpoint, host)},
			})
			if got := awaitExport(t, requests).Path; got != tc.want {
				t.Fatalf("endpoint %q posted to %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestMakeOTLPMetricExporterProtocols(t *testing.T) {
	for _, protocol := range []string{"", "http", "http/protobuf", "grpc"} {
		endpoint := "https://otel.example.com:4318/otlp"
		if protocol == "grpc" {
			endpoint = "https://otel.example.com:4317"
		}
		exporter, err := makeOTLPMetricExporter(OTLPConfig{Enabled: true, Protocol: protocol, Endpoint: endpoint})
		if err != nil {
			t.Fatalf("protocol %q: %v", protocol, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
		exporter.Shutdown(ctx)
		cancel()
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
		`sshmux_sessions_total{event_outcome="success",server_address="10.0.0.7",server_port="22",sshmux_upstream_role="",user_name="vlab"} 1`,
		`sshmux_session_duration_seconds_count{event_outcome="success",server_address="10.0.0.7",server_port="22",sshmux_upstream_role="",user_name="vlab"} 1`,
		`sshmux_sessions_total{error_type="eof",event_outcome="failure",server_address="unknown",server_port="0",sshmux_upstream_role="",user_name="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	metrics.Shutdown(ctx)
}

// TestMetricsOTLPEndpointFromEnvironment covers the other half of the rule: the
// generic environment variable is a base URL, so the signal path is appended.
func TestMetricsOTLPEndpointFromEnvironment(t *testing.T) {
	server, paths := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)

	// No endpoint in the config file, so the environment has to supply it.
	exportOnce(t, MetricsConfig{Enabled: true, OTLP: OTLPConfig{Enabled: true}})

	if path := awaitExport(t, paths).Path; path != "/v1/metrics" {
		t.Fatalf("OTLP request path = %q, want %q", path, "/v1/metrics")
	}
}

func TestMetricsOTLPEndpointConfigWinsOverEnvironment(t *testing.T) {
	configured, paths := otlpTestCollector(t)
	unused, unusedPaths := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", unused.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", unused.URL+"/v1/metrics")

	exportOnce(t, MetricsConfig{
		Enabled: true,
		OTLP:    OTLPConfig{Enabled: true, Endpoint: configured.URL + "/otlp/v1/metrics"},
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

func TestMetricsOTLPHeadersPrecedence(t *testing.T) {
	t.Run("from the environment", func(t *testing.T) {
		server, requests := otlpTestCollector(t)
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
		t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-scope-orgid=vlab")

		exportOnce(t, MetricsConfig{Enabled: true, OTLP: OTLPConfig{Enabled: true}})

		if got := awaitExport(t, requests).Header.Get("X-Scope-Orgid"); got != "vlab" {
			t.Fatalf("X-Scope-OrgID = %q, want %q", got, "vlab")
		}
	})

	t.Run("configuration wins", func(t *testing.T) {
		server, requests := otlpTestCollector(t)
		t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-scope-orgid=from-environment")

		exportOnce(t, MetricsConfig{Enabled: true, OTLP: OTLPConfig{
			Enabled:  true,
			Endpoint: server.URL + "/v1/metrics",
			Headers:  []HTTPHeaderConfig{{Name: "X-Scope-OrgID", Value: "from-config"}},
		}})

		if got := awaitExport(t, requests).Header.Get("X-Scope-Orgid"); got != "from-config" {
			t.Fatalf("X-Scope-OrgID = %q, want %q", got, "from-config")
		}
	})
}

// TestMetricsOTLPIntervalFromEnvironment checks that an export happens on the interval
// set by the environment, without a shutdown flush forcing it.
func TestMetricsOTLPIntervalFromEnvironment(t *testing.T) {
	server, requests := otlpTestCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "200")

	metrics, err := makeMetrics(MetricsConfig{Enabled: true, OTLP: OTLPConfig{Enabled: true}})
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
	if want := `sshmux_sessions_total{event_outcome="success",sshmux_upstream_role=""} 2500`; !strings.Contains(body, want) {
		t.Errorf("scrape output does not contain %q:\n%s", want, body)
	}
}

// scrapeAs fetches the Prometheus endpoint with a given Accept header, so that
// UTF-8 name negotiation can be exercised.
func scrapeAs(t *testing.T, metrics *Metrics, accept string) string {
	t.Helper()
	request, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", metrics.PrometheusAddr(), metrics.promPath), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", accept)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// startPrometheus brings up a Metrics with only the Prometheus endpoint, on the
// given translation strategy, and records one session.
func startPrometheus(t *testing.T, strategy PrometheusTranslationStrategy) *Metrics {
	t.Helper()
	metrics, err := makeMetrics(MetricsConfig{
		Enabled: true,
		Prometheus: MetricsPrometheusConfig{
			Enabled: true, Address: "127.0.0.1:0", TranslationStrategy: strategy,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { metrics.Shutdown(context.Background()) })
	metrics.ConnectionClosed(t.Context(), testConnection, nil, time.Second)
	return metrics
}

// TestPrometheusTranslationStrategy pins what each accepted strategy actually
// produces. Note that a scraper only ever sees the untranslated names if it
// negotiates UTF-8; without that the exposition escapes them regardless.
func TestPrometheusTranslationStrategy(t *testing.T) {
	const utf8Accept = "text/plain;version=1.0.0;escaping=allow-utf-8"

	t.Run("escaped by default", func(t *testing.T) {
		for _, strategy := range []PrometheusTranslationStrategy{"", UnderscoreEscaping} {
			body := scrape(t, startPrometheus(t, strategy))
			if !strings.Contains(body, `sshmux_sessions_total{`) {
				t.Errorf("strategy %q: no escaped name with suffix:\n%s", strategy, body)
			}
		}
	})

	t.Run("NoTranslation drops the suffix", func(t *testing.T) {
		body := scrape(t, startPrometheus(t, NoTranslation))
		if !strings.Contains(body, `sshmux_sessions{`) {
			t.Errorf("no unsuffixed name:\n%s", body)
		}
		if strings.Contains(body, `sshmux_sessions_total{`) {
			t.Error("the _total suffix should not be added")
		}
	})

	t.Run("dots survive for a UTF-8 scraper", func(t *testing.T) {
		metrics := startPrometheus(t, NoUTF8Escaping)
		if body := scrapeAs(t, metrics, utf8Accept); !strings.Contains(body, `{"sshmux.sessions_total"`) ||
			!strings.Contains(body, `"user.name"="vlab"`) {
			t.Errorf("names were escaped despite negotiation:\n%s", body)
		}
		// The same endpoint still escapes for a scraper that does not ask.
		if body := scrape(t, metrics); !strings.Contains(body, `sshmux_sessions_total{`) {
			t.Errorf("names were not escaped for a plain scraper:\n%s", body)
		}
	})

	t.Run("rejected values", func(t *testing.T) {
		// Prometheus does not support this one directly.
		for _, strategy := range []PrometheusTranslationStrategy{"UnderscoreEscapingWithoutSuffixes", "nonsense"} {
			_, err := makeMetrics(MetricsConfig{
				Enabled:    true,
				Prometheus: MetricsPrometheusConfig{Enabled: true, TranslationStrategy: strategy},
			})
			if err == nil {
				t.Errorf("strategy %q should be rejected", strategy)
			}
		}
	})
}

// TestMetricsConvention checks that the configured convention reaches the
// exported labels.
func TestMetricsConvention(t *testing.T) {
	for _, convention := range []AttributeConvention{AttributeConventionDefault, AttributeConventionECS} {
		t.Run(string(convention), func(t *testing.T) {
			metrics, err := makeMetrics(MetricsConfig{
				Enabled:    true,
				Convention: convention,
				Prometheus: MetricsPrometheusConfig{Enabled: true, Address: "127.0.0.1:0"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := metrics.Start(); err != nil {
				t.Fatal(err)
			}
			defer metrics.Shutdown(t.Context())

			metrics.ConnectionClosed(t.Context(), testConnection, nil, time.Second)
			want := `sshmux_sessions_total{event_outcome="success",server_address="10.0.0.7",server_port="22",sshmux_upstream_role="",user_name="vlab"} 1`
			if body := scrape(t, metrics); !strings.Contains(body, want) {
				t.Errorf("scrape does not contain %q:\n%s", want, body)
			}
		})
	}

	// A value that never came from a configuration file still cannot slip past.
	if _, err := makeMetrics(MetricsConfig{Enabled: true, Convention: "nonsense"}); err == nil {
		t.Error("an unknown convention should be refused at startup")
	}
}
