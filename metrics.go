package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
)

const (
	defaultPrometheusAddress = "127.0.0.1:9100"
	defaultPrometheusPath    = "/metrics"
)

// Metrics owns the OpenTelemetry meter provider of an sshmux server, the
// instruments recorded by it, and the optional Prometheus scrape endpoint.
// Its record methods are no-ops while metrics are disabled.
type Metrics struct {
	// logger is what the metrics report through.
	logger  *Logger
	enabled bool
	// groupConnections reports whether the connection metrics carry the username
	// and upstream dimensions.
	groupConnections bool
	// attrs holds the attribute names the configured convention resolved to.
	attrs    attributeNames
	provider *sdkmetric.MeterProvider

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

// makeMetrics builds the metrics, discarding what they have to say about
// themselves.
func makeMetrics(config MetricsConfig) (*Metrics, error) {
	return makeMetricsWithLogger(config, nil)
}

// makeMetricsWithLogger builds the metrics, which report what they have to say
// about themselves through the logger given. A nil one discards those reports.
func makeMetricsWithLogger(config MetricsConfig, logger *Logger) (*Metrics, error) {
	names, err := conventionAttributeNames(config.Convention)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = &Logger{Logger: slog.New(slog.DiscardHandler), attrs: names}
	}
	metrics := &Metrics{
		logger:           logger,
		enabled:          config.Enabled,
		groupConnections: boolOrDefault(config.ConnectionGrouping, true),
		attrs:            names,
	}
	if !config.Enabled {
		return newMetrics(metrics, noop.NewMeterProvider().Meter(otelScopeName))
	}
	if !config.OTLP.Enabled && !config.Prometheus.Enabled {
		return nil, errors.New("metrics are enabled but no exporter is configured")
	}

	readers := make([]sdkmetric.Reader, 0, 2)
	if config.OTLP.Enabled {
		exporter, err := makeOTLPMetricExporter(config.OTLP)
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

	res, err := otelResource(config.ServiceName, config.Attributes)
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
	return newMetrics(metrics, metrics.provider.Meter(otelScopeName))
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
		// Unreachable: UnmarshalText accepts only the names above.
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
			sdkmetric.Instrument{Name: name, Scope: instrumentation.Scope{Name: otelScopeName}},
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

func makeOTLPMetricExporter(config OTLPConfig) (sdkmetric.Exporter, error) {
	protocol, err := otlpProtocol(config.Protocol, envOTLPMetricsProtocol)
	if err != nil {
		return nil, err
	}
	endpoint, err := otlpEndpoint(config, protocol)
	if err != nil {
		return nil, err
	}
	headers := otlpHeaders(config)

	if protocol == "grpc" {
		var options []otlpmetricgrpc.Option
		if endpoint != nil {
			options = append(options, otlpmetricgrpc.WithEndpointURL(endpoint.String()))
		}
		if len(headers) > 0 {
			options = append(options, otlpmetricgrpc.WithHeaders(headers))
		}
		if timeout, ok := otlpTimeout(config); ok {
			options = append(options, otlpmetricgrpc.WithTimeout(timeout))
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
	if timeout, ok := otlpTimeout(config); ok {
		options = append(options, otlpmetrichttp.WithTimeout(timeout))
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
			m.logger.LogAttrs(context.Background(), slog.LevelError,
				"sshmux stopped serving the Prometheus endpoint", m.logger.errorAttributes(err)...)
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
			m.logger.LogAttrs(ctx, slog.LevelError,
				"sshmux could not shut the metrics down", m.logger.errorAttributes(err)...)
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
	m.upstreamTotal.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(m.attrs.outcomeAttributes(err)...)))
}

func (m *Metrics) AuthFinished(ctx context.Context, method string, status int, err error, duration time.Duration) {
	if !m.enabled {
		return
	}
	attrs := append(m.attrs.outcomeAttributes(err), m.attrs.sshmuxAuthMethod.String(method), m.attrs.sshmuxAuthStatus.Int(status))
	set := metric.WithAttributeSet(attribute.NewSet(attrs...))
	m.authRequestsTotal.Add(ctx, 1, set)
	m.authDuration.Record(ctx, duration.Seconds(), set)
}

// connectionAttributeSet combines the outcome of a connection with the
// dimensions the connection metrics carry.
func (m *Metrics) connectionAttributeSet(info connectionInfo, err error) attribute.Set {
	attrs := append(m.attrs.outcomeAttributes(err),
		m.attrs.connectionMetricAttributes(info, m.groupConnections)...)
	return attribute.NewSet(attrs...)
}
