package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	_, span := tracer.tracer.Start(context.Background(), "sshmux.session")
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
			ctx, span := tracer.tracer.Start(t.Context(), "sshmux.handshake")
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
