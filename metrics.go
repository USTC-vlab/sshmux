package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

const (
	defaultMetricsServiceName = "sshmux"
	defaultPrometheusAddress  = "127.0.0.1:9100"
	defaultPrometheusPath     = "/metrics"
	metricsShutdownTimeout    = 5 * time.Second
	metricsScopeName          = "github.com/USTC-vlab/sshmux"
	// unknownAttributeValue is recorded for a grouping attribute whose value is
	// not known, e.g. the username of a connection that failed before auth.
	unknownAttributeValue = "unknown"
)

const (
	envOTLPProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOTLPMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
)

// From the OpenTelemetry semantic conventions.
const (
	attrErrorType     = attribute.Key("error.type")
	attrUserName      = attribute.Key("user.name")
	attrServerAddress = attribute.Key("server.address")
	attrServerPort    = attribute.Key("server.port")
)

// From the Elastic Common Schema, which the semantic conventions have no
// equivalent for yet.
const attrResult = attribute.Key("event.outcome")

// sshmux's own, namespaced so that they cannot collide with a future
// convention. Neither schema describes an authentication method.
const (
	attrAuthMethod = attribute.Key("sshmux.auth.method")
	attrAuthStatus = attribute.Key("sshmux.auth.status")
)

var (
	resultSuccess = attrResult.String("success")
	resultFailure = attrResult.String("failure")
)

// connectionInfo is the per-connection state reported to the metrics recorder.
// Fields are zero until they become known: Username is only set once the client
// has sent its first auth request, and the upstream only once the auth API has
// answered.
type connectionInfo struct {
	Username string
	// UpstreamHost and UpstreamPort are the backend the auth API returned,
	// before any PROXY protocol override.
	UpstreamHost string
	UpstreamPort uint16
	// Established records whether the handshake completed.
	Established bool
}

// Metrics owns the OpenTelemetry meter provider of an sshmux server, the
// instruments recorded by it, and the optional Prometheus scrape endpoint.
// Its record methods are no-ops while metrics are disabled.
type Metrics struct {
	enabled bool
	// groupConnections reports whether the connection metrics carry the username
	// and upstream dimensions.
	groupConnections bool
	provider         *sdkmetric.MeterProvider

	promAddress  string
	promPath     string
	promHandler  http.Handler
	promServer   *http.Server
	promListener net.Listener

	connectionsTotal  metric.Int64Counter
	connectionsActive metric.Int64UpDownCounter
	sessionsTotal     metric.Int64Counter
	sessionDuration   metric.Float64Histogram
	handshakeDuration metric.Float64Histogram
	authRequestsTotal metric.Int64Counter
	authDuration      metric.Float64Histogram
	upstreamTotal     metric.Int64Counter
}

func makeMetrics(config MetricsConfig) (*Metrics, error) {
	metrics := &Metrics{
		enabled:          config.Enabled,
		groupConnections: boolOrDefault(config.ConnectionGrouping, true),
	}
	if !config.Enabled {
		return newMetrics(metrics, noop.NewMeterProvider().Meter(metricsScopeName))
	}
	if !config.OTLP.Enabled && !config.Prometheus.Enabled {
		return nil, errors.New("metrics are enabled but no exporter is configured")
	}

	readers := make([]sdkmetric.Reader, 0, 2)
	if config.OTLP.Enabled {
		exporter, err := makeOTLPExporter(config.OTLP)
		if err != nil {
			return nil, err
		}
		var readerOptions []sdkmetric.PeriodicReaderOption
		// Leaving the interval unset defers to OTEL_METRIC_EXPORT_INTERVAL.
		if config.IntervalSeconds != 0 {
			readerOptions = append(readerOptions, sdkmetric.WithInterval(time.Duration(config.IntervalSeconds)*time.Second))
		}
		readers = append(readers, sdkmetric.NewPeriodicReader(exporter, readerOptions...))
	}
	if config.Prometheus.Enabled {
		strategy, err := prometheusTranslationStrategy(config.Prometheus.TranslationStrategy)
		if err != nil {
			return nil, err
		}
		registry := prometheus.NewRegistry()
		reader, err := otelprom.New(
			otelprom.WithRegisterer(registry),
			otelprom.WithoutScopeInfo(),
			otelprom.WithTranslationStrategy(strategy),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to set up Prometheus exporter: %w", err)
		}
		readers = append(readers, reader)
		metrics.promAddress = valueOrDefault(config.Prometheus.Address, defaultPrometheusAddress)
		metrics.promPath = valueOrDefault(config.Prometheus.Path, defaultPrometheusPath)
		if !strings.HasPrefix(metrics.promPath, "/") {
			metrics.promPath = "/" + metrics.promPath
		}
		mux := http.NewServeMux()
		mux.Handle(metrics.promPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
			Registry:      registry,
		}))
		metrics.promHandler = mux
	}

	res, err := makeMetricsResource(config)
	if err != nil {
		return nil, err
	}
	options := []sdkmetric.Option{
		sdkmetric.WithResource(res),
		sdkmetric.WithView(durationViews()...),
	}
	for _, reader := range readers {
		options = append(options, sdkmetric.WithReader(reader))
	}
	metrics.provider = sdkmetric.NewMeterProvider(options...)
	return newMetrics(metrics, metrics.provider.Meter(metricsScopeName))
}

// prometheusTranslationStrategy resolves how OTLP names are rendered for
// Prometheus. The names are the ones the OpenTelemetry Collector's Prometheus
// exporter uses, so that a strategy can be carried over from a collector
// configuration unchanged.
//
// UnderscoreEscapingWithoutSuffixes is deliberately not accepted: Prometheus
// does not support it directly and it is rarely wanted.
func prometheusTranslationStrategy(configured PrometheusTranslationStrategy) (otlptranslator.TranslationStrategyOption, error) {
	switch configured {
	case "", UnderscoreEscaping:
		return otlptranslator.UnderscoreEscapingWithSuffixes, nil
	case NoUTF8Escaping:
		return otlptranslator.NoUTF8EscapingWithSuffixes, nil
	case NoTranslation:
		return otlptranslator.NoTranslation, nil
	default:
		// Unreachable: validateMetricsConfig accepts only the names above.
		return "", fmt.Errorf("unsupported Prometheus translation strategy: %s", configured)
	}
}

// durationViews replaces the SDK's default histogram buckets, which are tuned
// for millisecond-scale measurements, with boundaries that fit the durations
// sshmux actually records in seconds.
func durationViews() []sdkmetric.View {
	// Handshakes and auth API calls are expected to finish within seconds.
	shortBuckets := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}
	// SSH sessions routinely stay open for hours.
	longBuckets := []float64{1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200, 21600, 86400}
	view := func(name string, buckets []float64) sdkmetric.View {
		return sdkmetric.NewView(
			sdkmetric.Instrument{Name: name, Scope: instrumentation.Scope{Name: metricsScopeName}},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: buckets,
				NoMinMax:   false,
			}},
		)
	}
	return []sdkmetric.View{
		view("sshmux.handshake.duration", shortBuckets),
		view("sshmux.auth.duration", shortBuckets),
		view("sshmux.session.duration", longBuckets),
	}
}

func makeMetricsResource(config MetricsConfig) (*resource.Resource, error) {
	// resource.Default reads OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
	base := resource.Default()
	attrs, err := metricsResourceAttributes(config, base)
	if err != nil {
		return nil, err
	}
	// The base resource and our attributes share the same semantic convention
	// schema, so the merge below never conflicts. Attributes from the second
	// resource win, which is why only the ones the environment did not already
	// provide are added.
	res, err := resource.Merge(base, resource.NewWithAttributes(semconv.SchemaURL, attrs...))
	if err != nil {
		return nil, fmt.Errorf("failed to build metrics resource: %w", err)
	}
	return res, nil
}

// metricsResourceAttributes returns the resource attributes to layer on top of
// base, honouring the config file over the environment over sshmux's defaults.
func metricsResourceAttributes(config MetricsConfig, base *resource.Resource) ([]attribute.KeyValue, error) {
	var attrs []attribute.KeyValue
	// resource.Default only reports an `unknown_service:...` name when neither
	// OTEL_SERVICE_NAME nor OTEL_RESOURCE_ATTRIBUTES supplied one.
	if config.ServiceName != "" {
		attrs = append(attrs, semconv.ServiceName(config.ServiceName))
	} else if name, ok := resourceAttribute(base, semconv.ServiceNameKey); !ok || strings.HasPrefix(name, "unknown_service") {
		attrs = append(attrs, semconv.ServiceName(defaultMetricsServiceName))
	}
	if _, ok := resourceAttribute(base, semconv.ServiceVersionKey); !ok {
		attrs = append(attrs, semconv.ServiceVersion(buildVersion()))
	}
	if _, ok := resourceAttribute(base, semconv.HostNameKey); !ok {
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			attrs = append(attrs, semconv.HostName(hostname))
		}
	}
	for _, attr := range config.Attributes {
		if attr.Name == "" {
			return nil, errors.New("metrics resource attributes must have a name")
		}
		attrs = append(attrs, attribute.String(attr.Name, attr.Value))
	}
	return attrs, nil
}

func resourceAttribute(res *resource.Resource, key attribute.Key) (string, bool) {
	if res == nil {
		return "", false
	}
	for _, attr := range res.Attributes() {
		if attr.Key == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

// otlpProtocol resolves the OTLP transport, honouring the config file over
// OTEL_EXPORTER_OTLP_METRICS_PROTOCOL over OTEL_EXPORTER_OTLP_PROTOCOL. Unlike
// the endpoint and the headers, the protocol selects which exporter package is
// used, so it cannot be delegated to the exporter itself.
func otlpProtocol(configured string) (string, error) {
	protocol := configured
	for _, key := range []string{envOTLPMetricsProtocol, envOTLPProtocol} {
		if protocol != "" {
			break
		}
		protocol = strings.TrimSpace(os.Getenv(key))
	}
	switch protocol {
	case "", "http", "http/protobuf":
		return "http/protobuf", nil
	case "grpc":
		return "grpc", nil
	default:
		return "", fmt.Errorf("unsupported OTLP protocol: %s", protocol)
	}
}

func makeOTLPExporter(config MetricsOTLPConfig) (sdkmetric.Exporter, error) {
	protocol, err := otlpProtocol(config.Protocol)
	if err != nil {
		return nil, err
	}
	// An unset endpoint defers to OTEL_EXPORTER_OTLP_[METRICS_]ENDPOINT, and in
	// turn to the OTLP default of localhost:4317 or localhost:4318.
	var endpoint *url.URL
	if config.Endpoint != "" {
		endpoint, err = url.Parse(config.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OTLP endpoint: %w", err)
		}
		switch endpoint.Scheme {
		case "http", "https":
		default:
			return nil, fmt.Errorf("unsupported OTLP endpoint scheme: %s", endpoint.Scheme)
		}
	}
	headers := make(map[string]string, len(config.Headers))
	for _, header := range config.Headers {
		headers[header.Name] = header.Value
	}

	if protocol == "grpc" {
		var options []otlpmetricgrpc.Option
		if endpoint != nil {
			if path := strings.Trim(endpoint.Path, "/"); path != "" {
				return nil, fmt.Errorf("gRPC OTLP endpoint must not have a path: %s", config.Endpoint)
			}
			options = append(options, otlpmetricgrpc.WithEndpointURL(endpoint.String()))
		}
		if len(headers) > 0 {
			options = append(options, otlpmetricgrpc.WithHeaders(headers))
		}
		if config.TimeoutSeconds != 0 {
			options = append(options, otlpmetricgrpc.WithTimeout(time.Duration(config.TimeoutSeconds)*time.Second))
		}
		return otlpmetricgrpc.New(context.Background(), options...)
	}

	var options []otlpmetrichttp.Option
	if endpoint != nil {
		// A configured endpoint is a signal-specific one, so it is used as-is,
		// the same way OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is. Only the generic
		// OTEL_EXPORTER_OTLP_ENDPOINT is a base URL that `/v1/metrics` is
		// appended to, which the exporter handles itself.
		options = append(options, otlpmetrichttp.WithEndpointURL(endpoint.String()))
	}
	if len(headers) > 0 {
		options = append(options, otlpmetrichttp.WithHeaders(headers))
	}
	if config.TimeoutSeconds != 0 {
		options = append(options, otlpmetrichttp.WithTimeout(time.Duration(config.TimeoutSeconds)*time.Second))
	}
	return otlpmetrichttp.New(context.Background(), options...)
}

func newMetrics(metrics *Metrics, meter metric.Meter) (*Metrics, error) {
	var errs []error
	collect := func(err error) { errs = append(errs, err) }

	var err error
	metrics.connectionsTotal, err = meter.Int64Counter("sshmux.connections",
		metric.WithDescription("Number of connections accepted by sshmux."),
		metric.WithUnit("{connection}"))
	collect(err)
	metrics.connectionsActive, err = meter.Int64UpDownCounter("sshmux.connections.active",
		metric.WithDescription("Number of connections currently being served by sshmux."),
		metric.WithUnit("{connection}"))
	collect(err)
	metrics.sessionsTotal, err = meter.Int64Counter("sshmux.sessions",
		metric.WithDescription("Number of finished SSH proxy sessions."),
		metric.WithUnit("{session}"))
	collect(err)
	metrics.sessionDuration, err = meter.Float64Histogram("sshmux.session.duration",
		metric.WithDescription("Duration of an SSH proxy session, from accept to close."),
		metric.WithUnit("s"))
	collect(err)
	metrics.handshakeDuration, err = meter.Float64Histogram("sshmux.handshake.duration",
		metric.WithDescription("Duration of the downstream handshake and authentication."),
		metric.WithUnit("s"))
	collect(err)
	metrics.authRequestsTotal, err = meter.Int64Counter("sshmux.auth.requests",
		metric.WithDescription("Number of authentication requests sent to the auth API."),
		metric.WithUnit("{request}"))
	collect(err)
	metrics.authDuration, err = meter.Float64Histogram("sshmux.auth.duration",
		metric.WithDescription("Duration of an authentication API request."),
		metric.WithUnit("s"))
	collect(err)
	metrics.upstreamTotal, err = meter.Int64Counter("sshmux.upstream.connections",
		metric.WithDescription("Number of connection attempts to upstream SSH servers."),
		metric.WithUnit("{connection}"))
	collect(err)

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("failed to create metric instruments: %w", err)
	}
	return metrics, nil
}

// Start binds and serves the Prometheus scrape endpoint, if configured.
func (m *Metrics) Start() error {
	if !m.enabled || m.promHandler == nil {
		return nil
	}
	listener, err := net.Listen("tcp", m.promAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on Prometheus address: %w", err)
	}
	m.promListener = listener
	m.promServer = &http.Server{Handler: m.promHandler}
	go func() {
		if err := m.promServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Error on Prometheus endpoint: %s\n", err)
		}
	}()
	return nil
}

// PrometheusAddr returns the address the Prometheus endpoint is listening on,
// or nil when it is not enabled or not started yet.
func (m *Metrics) PrometheusAddr() net.Addr {
	if m.promListener == nil {
		return nil
	}
	return m.promListener.Addr()
}

// Shutdown flushes pending metrics and tears down the exporters.
func (m *Metrics) Shutdown(ctx context.Context) {
	if !m.enabled {
		return
	}
	if m.promServer != nil {
		if err := m.promServer.Shutdown(ctx); err != nil {
			m.promServer.Close()
		}
		m.promServer, m.promListener = nil, nil
	}
	if m.provider != nil {
		if err := m.provider.Shutdown(ctx); err != nil {
			log.Printf("Error on metrics shutdown: %s\n", err)
		}
		m.provider = nil
	}
}

// ConnectionAccepted is recorded before the username of a connection is known,
// so it carries no grouping attributes.
func (m *Metrics) ConnectionAccepted(ctx context.Context) {
	if !m.enabled {
		return
	}
	m.connectionsTotal.Add(ctx, 1)
	m.connectionsActive.Add(ctx, 1)
}

func (m *Metrics) ConnectionClosed(ctx context.Context, info connectionInfo, err error, duration time.Duration) {
	if !m.enabled {
		return
	}
	m.connectionsActive.Add(ctx, -1)
	attrs := metric.WithAttributeSet(m.connectionAttributeSet(info, err))
	m.sessionsTotal.Add(ctx, 1, attrs)
	m.sessionDuration.Record(ctx, duration.Seconds(), attrs)
}

func (m *Metrics) HandshakeFinished(ctx context.Context, info connectionInfo, err error, duration time.Duration) {
	if !m.enabled {
		return
	}
	m.handshakeDuration.Record(ctx, duration.Seconds(), metric.WithAttributeSet(m.connectionAttributeSet(info, err)))
}

func (m *Metrics) UpstreamDialed(ctx context.Context, err error) {
	if !m.enabled {
		return
	}
	m.upstreamTotal.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(resultAttributes(err)...)))
}

func (m *Metrics) AuthFinished(ctx context.Context, method string, status int, err error, duration time.Duration) {
	if !m.enabled {
		return
	}
	attrs := append(resultAttributes(err), attrAuthMethod.String(method), attrAuthStatus.Int(status))
	set := metric.WithAttributeSet(attribute.NewSet(attrs...))
	m.authRequestsTotal.Add(ctx, 1, set)
	m.authDuration.Record(ctx, duration.Seconds(), set)
}

// connectionAttributeSet combines the outcome of a connection with the two
// dimensions the connection metrics are grouped by, unless the grouping has
// been turned off.
func (m *Metrics) connectionAttributeSet(info connectionInfo, err error) attribute.Set {
	attrs := resultAttributes(err)
	if m.groupConnections {
		attrs = append(attrs,
			attrUserName.String(valueOrDefault(info.Username, unknownAttributeValue)),
			attrServerAddress.String(valueOrDefault(info.UpstreamHost, unknownAttributeValue)),
			attrServerPort.Int(int(info.UpstreamPort)),
		)
	}
	return attribute.NewSet(attrs...)
}

func resultAttributes(err error) []attribute.KeyValue {
	if err == nil {
		return []attribute.KeyValue{resultSuccess}
	}
	return []attribute.KeyValue{resultFailure, attrErrorType.String(errorType(err))}
}

func errorType(err error) string {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "other"
}

// instrumentedAuthenticator records the outcome and latency of every auth API
// request made through the wrapped Authenticator.
type instrumentedAuthenticator struct {
	inner   Authenticator
	metrics *Metrics
}

func (a *instrumentedAuthenticator) Auth(request AuthRequest, username string) (int, *AuthResponse, error) {
	start := time.Now()
	status, response, err := a.inner.Auth(request, username)
	a.metrics.AuthFinished(context.Background(), request.Method, status, err, time.Since(start))
	return status, response, err
}

func boolOrDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func valueOrDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "unknown"
	}
	return info.Main.Version
}
