package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"

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
	// logger is what a tracer reports through.
	logger   *Logger
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	// attrs holds the attribute names the configured convention resolved to.
	attrs attributeNames
	// propagator is nil when trace context is not carried to the auth API.
	propagator propagation.TextMapPropagator
}

// makeTracer builds the tracer, discarding what it has to say about itself.
func makeTracer(config TracerConfig) (*Tracer, error) {
	return makeTracerWithLogger(config, nil)
}

// makeTracerWithLogger builds the tracer, which reports what it has to say
// about itself through the logger given. A nil one discards those reports.
func makeTracerWithLogger(config TracerConfig, logger *Logger) (*Tracer, error) {
	names, err := conventionAttributeNames(config.Convention)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = &Logger{Logger: slog.New(slog.DiscardHandler), attrs: names}
	}
	if !config.Enabled {
		return &Tracer{logger: logger, tracer: noop.NewTracerProvider().Tracer(otelScopeName), attrs: names}, nil
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
	tracer := &Tracer{logger: logger, enabled: true, provider: provider, tracer: provider.Tracer(otelScopeName), attrs: names}
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

// setSpanAttributes records attrs on span. The builders drop what a convention
// has no name for, and this is the backstop for an attribute assembled
// anywhere else, since every one sshmux records reaches a span through here.
func setSpanAttributes(span trace.Span, attrs []attribute.KeyValue) {
	attrs = slices.DeleteFunc(attrs, func(attr attribute.KeyValue) bool { return attr.Key == "" })
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
}

// connectionSpanAttributes names a connection for a span, under the convention
// the tracer was configured with.
func (t *Tracer) connectionSpanAttributes(info connectionInfo) []attribute.KeyValue {
	return t.attrs.connectionAttributes(info)
}

// serverAttributes names the service a client span called.
func (t *Tracer) serverAttributes(server *url.URL) []attribute.KeyValue {
	return t.attrs.serverAttributes(server)
}

// peerAttributes names the other end of the network connection a span covers:
// where it was reached from for a server span, and what it reached out to for
// a client span.
func (t *Tracer) peerAttributes(peer net.Addr) []attribute.KeyValue {
	return t.attrs.peerAttributes(peer)
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
		t.logger.LogAttrs(ctx, slog.LevelError,
			"sshmux could not shut the tracer down", t.logger.errorAttributes(err)...)
	}
	t.provider = nil
}
