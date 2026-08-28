package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

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

// Inject writes the trace context of ctx into an outgoing request's headers,
// so that the server handling it can continue the same trace. It does nothing
// while tracing or propagation is off, or while ctx carries no span.
func (t *Tracer) Inject(ctx context.Context, header http.Header) {
	if t.propagator == nil {
		return
	}
	t.propagator.Inject(ctx, propagation.HeaderCarrier(header))
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
