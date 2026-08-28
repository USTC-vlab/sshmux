package main

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracerDisabled(t *testing.T) {
	tracer, err := makeTracer(TracerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// The tracer must stay usable, so that span call sites need no guard.
	_, span := tracer.tracer.Start(context.Background(), "test")
	span.End()
	tracer.Shutdown(context.Background())
}

func TestTracerWithoutExporter(t *testing.T) {
	if _, err := makeTracer(TracerConfig{Enabled: true}); err == nil {
		t.Fatal("tracing without an exporter should fail to start")
	}
}

func TestTracerSampleRatioRange(t *testing.T) {
	for _, ratio := range []float64{-0.5, 1.5} {
		config := TracerConfig{
			Enabled:     true,
			SampleRatio: &ratio,
			OTLP:        OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4318/v1/traces"},
		}
		if _, err := makeTracer(config); err == nil {
			t.Errorf("sample-ratio %v should be rejected", ratio)
		}
	}
}

// TestTracerOTLPExport drives a span all the way to an OTLP collector, so that
// the exporter wiring and the shutdown flush are both covered.
func TestTracerOTLPExport(t *testing.T) {
	paths := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case paths <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tracer, err := makeTracer(TracerConfig{
		Enabled: true,
		OTLP:    OTLPConfig{Enabled: true, Endpoint: server.URL + "/v1/traces"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, span := tracer.tracer.Start(context.Background(), "establish ssh session")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	tracer.Shutdown(ctx)

	select {
	case path := <-paths:
		if path != "/v1/traces" {
			t.Fatalf("OTLP request path = %q, want %q", path, "/v1/traces")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no OTLP export was received")
	}
}

func TestMakeOTLPTraceExporterErrors(t *testing.T) {
	cases := []struct {
		name   string
		config OTLPConfig
	}{
		{"bad scheme", OTLPConfig{Enabled: true, Endpoint: "udp://127.0.0.1:4318"}},
		{"unknown protocol", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4318", Protocol: "thrift"}},
		{"grpc with path", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4317/v1/traces", Protocol: "grpc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := makeOTLPTraceExporter(tc.config); err == nil {
				t.Fatal("makeOTLPTraceExporter() error = nil, want an error")
			}
		})
	}
}

func TestMakeOTLPTraceExporterProtocols(t *testing.T) {
	for _, protocol := range []string{"", "http", "http/protobuf", "grpc"} {
		endpoint := "https://otel.example.com:4318/otlp"
		if protocol == "grpc" {
			endpoint = "https://otel.example.com:4317"
		}
		exporter, err := makeOTLPTraceExporter(OTLPConfig{Enabled: true, Protocol: protocol, Endpoint: endpoint})
		if err != nil {
			t.Fatalf("protocol %q: %v", protocol, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
		exporter.Shutdown(ctx)
		cancel()
	}
}

// noopTracer is a disabled tracer, for tests that only need the argument.
func noopTracer() *Tracer {
	tracer, err := makeTracer(TracerConfig{})
	if err != nil {
		panic(err)
	}
	return tracer
}

// TestTracerPropagation checks that a span's context reaches the auth API as a
// W3C traceparent header, and that tracer.propagation turns it off.
func TestTracerPropagation(t *testing.T) {
	cases := []struct {
		name        string
		propagation *bool
		enabled     bool
		wantHeader  bool
	}{
		{name: "on by default", enabled: true, wantHeader: true},
		{name: "explicitly off", enabled: true, propagation: new(bool)},
		{name: "tracing disabled", enabled: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(chan string, 4)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case headers <- r.Header.Get("Traceparent"):
				default:
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"upstream":{"host":"127.0.0.1","port":22}}`))
			}))
			defer api.Close()

			collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer collector.Close()

			config := TracerConfig{Enabled: tc.enabled, Propagation: tc.propagation}
			if tc.enabled {
				config.OTLP = OTLPConfig{Enabled: true, Endpoint: collector.URL + "/v1/traces"}
			}
			tracer, err := makeTracer(config)
			if err != nil {
				t.Fatal(err)
			}
			defer tracer.Shutdown(t.Context())

			authenticator, err := makeAuthenticator(AuthConfig{Endpoint: api.URL, Version: "v1"}, tracer)
			if err != nil {
				t.Fatal(err)
			}
			// A span has to be active for there to be any context to carry.
			ctx, span := tracer.tracer.Start(t.Context(), "ssh handshake")
			_, _, err = authenticator.Auth(ctx, AuthRequest{Method: "publickey"}, "vlab")
			span.End()
			if err != nil {
				t.Fatal(err)
			}

			got := <-headers
			if tc.wantHeader {
				if !strings.HasPrefix(got, "00-") || len(got) != 55 {
					t.Fatalf("traceparent = %q, want a W3C header", got)
				}
				if id := span.SpanContext().TraceID().String(); !strings.Contains(got, id) {
					t.Errorf("traceparent %q does not carry trace ID %s", got, id)
				}
			} else if got != "" {
				t.Fatalf("traceparent = %q, want none", got)
			}
		})
	}
}

// TestSpanAttributesDropUnnamed covers the rule that a convention with no name
// for an attribute leaves its key empty, and that nothing with an empty key
// reaches a span.
func TestSpanAttributesDropUnnamed(t *testing.T) {
	tracer, err := makeTracer(TracerConfig{Convention: AttributeConventionECS})
	if err != nil {
		t.Fatal(err)
	}
	attrs := tracer.connectionSpanAttributes(connectionInfo{Username: "vlab", ProtocolVersion: "2.0"})
	// ECS has no name for the protocol version, so its key is left empty.
	unnamed := 0
	for _, attr := range attrs {
		if attr.Key == "" {
			unnamed++
		}
	}
	if unnamed != 1 {
		t.Errorf("%d attributes have no key, want 1 for the protocol version", unnamed)
	}

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	_, span := provider.Tracer("test").Start(context.Background(), "test")
	setSpanAttributes(span, attrs)
	span.End()

	recorded := recorder.Ended()
	if len(recorded) != 1 {
		t.Fatalf("%d spans were recorded, want 1", len(recorded))
	}
	keys := map[string]bool{}
	for _, attr := range recorded[0].Attributes() {
		if attr.Key == "" {
			t.Error("an attribute with no key reached the span")
		}
		keys[string(attr.Key)] = true
	}
	if !keys["network.protocol"] {
		t.Errorf(`no "network.protocol" attribute; got %v`, slices.Sorted(maps.Keys(keys)))
	}
	if keys["network.protocol.version"] {
		t.Error("ECS has no name for the protocol version, want it dropped")
	}
}
