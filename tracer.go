package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracer owns the OpenTelemetry tracer provider of an sshmux server and the
// tracer that spans are started from. Its span methods are no-ops while
// tracing is disabled.
type Tracer struct {
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	// attrs holds the attribute names the configured convention resolved to.
	attrs attributeNames
	// propagator is nil when trace context is not carried to the auth API.
	propagator propagation.TextMapPropagator
}

func makeTracer(config TracerConfig) (*Tracer, error) {
	names, err := conventionAttributeNames(config.Convention)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return &Tracer{tracer: noop.NewTracerProvider().Tracer(otelScopeName), attrs: names}, nil
	}
	if !config.OTLP.Enabled {
		return nil, errors.New("tracing is enabled but no exporter is configured")
	}
	if config.SampleRatio != nil && (*config.SampleRatio < 0 || *config.SampleRatio > 1) {
		return nil, fmt.Errorf("tracer.sample-ratio must be between 0 and 1, got %v", *config.SampleRatio)
	}

	exporter, err := makeOTLPTraceExporter(config.OTLP)
	if err != nil {
		return nil, err
	}
	res, err := otelResource(config.ServiceName, config.Attributes)
	if err != nil {
		return nil, err
	}
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	}
	// Leaving the ratio unset defers to OTEL_TRACES_SAMPLER, and in turn to the
	// SDK default of sampling every trace whose parent is sampled.
	if config.SampleRatio != nil {
		options = append(options, sdktrace.WithSampler(
			sdktrace.ParentBased(sdktrace.TraceIDRatioBased(*config.SampleRatio))))
	}
	provider := sdktrace.NewTracerProvider(options...)
	tracer := &Tracer{enabled: true, provider: provider, tracer: provider.Tracer(otelScopeName), attrs: names}
	if boolOrDefault(config.Propagation, true) {
		tracer.propagator = propagation.TraceContext{}
	}
	return tracer, nil
}

func makeOTLPTraceExporter(config OTLPConfig) (*otlptrace.Exporter, error) {
	protocol, err := otlpProtocol(config.Protocol, envOTLPTracesProtocol)
	if err != nil {
		return nil, err
	}
	endpoint, err := otlpEndpoint(config, protocol)
	if err != nil {
		return nil, err
	}
	headers := otlpHeaders(config)
	ctx := context.Background()

	if protocol == "grpc" {
		var options []otlptracegrpc.Option
		if endpoint != nil {
			options = append(options, otlptracegrpc.WithEndpointURL(endpoint.String()))
		}
		if len(headers) > 0 {
			options = append(options, otlptracegrpc.WithHeaders(headers))
		}
		if timeout, ok := otlpTimeout(config); ok {
			options = append(options, otlptracegrpc.WithTimeout(timeout))
		}
		return otlptracegrpc.New(ctx, options...)
	}

	var options []otlptracehttp.Option
	if endpoint != nil {
		// A configured endpoint is a signal-specific one, so it is used as-is,
		// the same way OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is. Only the generic
		// OTEL_EXPORTER_OTLP_ENDPOINT is a base URL that `/v1/traces` is
		// appended to, which the exporter handles itself.
		options = append(options, otlptracehttp.WithEndpointURL(endpoint.String()))
	}
	if len(headers) > 0 {
		options = append(options, otlptracehttp.WithHeaders(headers))
	}
	if timeout, ok := otlpTimeout(config); ok {
		options = append(options, otlptracehttp.WithTimeout(timeout))
	}
	return otlptracehttp.New(ctx, options...)
}

// Start begins a span. The returned context carries it, so that spans started
// from it nest, and the trace context reaches the auth API. It is safe to call
// while tracing is disabled, when the span is a no-op.
func (t *Tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// The kinds of span sshmux records: what it serves to a client, and the calls
// it makes to other services on that client's behalf.
var (
	spanKindServer = trace.WithSpanKind(trace.SpanKindServer)
	spanKindClient = trace.WithSpanKind(trace.SpanKindClient)
)

// endSpan records the outcome of a span and ends it. Attributes are only built
// for a span that is actually recording.
func endSpan(span trace.Span, err error, attrs ...attribute.KeyValue) {
	if span.IsRecording() {
		setSpanAttributes(span, attrs)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
	}
	span.End()
}

// setSpanAttributes records attrs on span, dropping the ones a convention has
// no name for and so left with an empty key. Every attribute sshmux records
// reaches a span through here.
func setSpanAttributes(span trace.Span, attrs []attribute.KeyValue) {
	attrs = slices.DeleteFunc(attrs, func(attr attribute.KeyValue) bool { return attr.Key == "" })
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
}

// connectionSpanAttributes reports the parts of a connection's identity that
// are known. Unlike the metrics, an unknown value is left off rather than
// recorded as "unknown", since a span has no cardinality budget to protect.
func (t *Tracer) connectionSpanAttributes(info connectionInfo) []attribute.KeyValue {
	attrs := []attribute.KeyValue{t.attrs.networkProtocolName.String("ssh")}
	if info.ProtocolVersion != "" {
		attrs = append(attrs, t.attrs.networkProtocolVersion.String(info.ProtocolVersion))
	}
	if info.Username != "" {
		attrs = append(attrs, t.attrs.userName.String(info.Username))
	}
	if info.ClientHost != "" {
		attrs = append(attrs, t.attrs.clientAddress.String(info.ClientHost),
			t.attrs.clientPort.Int(int(info.ClientPort)))
	}
	if info.UpstreamHost != "" {
		attrs = append(attrs, t.attrs.serverAddress.String(info.UpstreamHost),
			t.attrs.serverPort.Int(int(info.UpstreamPort)))
	}
	return attrs
}

// serverAttributes names the service a client span called, taking the port a
// URL leaves out from its scheme.
func (t *Tracer) serverAttributes(server *url.URL) []attribute.KeyValue {
	if server == nil || server.Hostname() == "" {
		return nil
	}
	attrs := []attribute.KeyValue{t.attrs.serverAddress.String(server.Hostname())}
	port := server.Port()
	if port == "" {
		port = portForScheme(server.Scheme)
	}
	if number, err := strconv.Atoi(port); err == nil {
		attrs = append(attrs, t.attrs.serverPort.Int(number))
	}
	return attrs
}

func portForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// tracePeer arranges for the address an HTTP request ends up connected to be
// recorded on the span already in ctx, which only the transport knows.
func (t *Tracer) tracePeer(ctx context.Context) context.Context {
	if !t.enabled {
		return ctx
	}
	span := trace.SpanFromContext(ctx)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			setSpanAttributes(span, t.peerAttributes(info.Conn.RemoteAddr()))
		},
	})
}

// peerAttributes names the other end of the network connection a span covers:
// where it was reached from for a server span, and what it reached out to for
// a client span.
func (t *Tracer) peerAttributes(peer net.Addr) []attribute.KeyValue {
	tcp, ok := peer.(*net.TCPAddr)
	if !ok {
		return nil
	}
	return []attribute.KeyValue{
		t.attrs.networkPeerAddress.String(tcp.IP.String()),
		t.attrs.networkPeerPort.Int(tcp.Port),
	}
}

// Inject writes the trace context of ctx into an outgoing request's headers,
// so that the server handling it can continue the same trace. It does nothing
// while tracing or propagation is off, or while ctx carries no span.
func (t *Tracer) Inject(ctx context.Context, header http.Header) {
	if t.propagator == nil {
		return
	}
	t.propagator.Inject(ctx, propagation.HeaderCarrier(header))
}

// ForceFlush exports whatever the batcher is holding, without tearing the
// provider down.
func (t *Tracer) ForceFlush(ctx context.Context) error {
	if !t.enabled || t.provider == nil {
		return nil
	}
	return t.provider.ForceFlush(ctx)
}

// Shutdown flushes pending spans and tears down the exporter.
func (t *Tracer) Shutdown(ctx context.Context) {
	if !t.enabled || t.provider == nil {
		return
	}
	if err := t.provider.Shutdown(ctx); err != nil {
		log.Printf("Error on tracer shutdown: %s\n", err)
	}
	t.provider = nil
}
