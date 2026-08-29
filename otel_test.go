package main

import (
	"reflect"
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

func TestOTLPProtocolPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		generic    string
		signal     string
		want       string
		wantErr    bool
	}{
		{name: "default", want: "http/protobuf"},
		{name: "configured", configured: "grpc", want: "grpc"},
		{name: "from the generic environment variable", generic: "grpc", want: "grpc"},
		{name: "the signal variable wins over the generic one", generic: "grpc", signal: "http/protobuf", want: "http/protobuf"},
		{name: "configuration wins over the environment", configured: "http", signal: "grpc", want: "http/protobuf"},
		{name: "http/json is not supported", generic: "http/json", wantErr: true},
	}
	// The rules are the same for every signal, so each case is checked against
	// each of the signal variables.
	signals := []struct{ name, env string }{
		{"metrics", envOTLPMetricsProtocol},
		{"traces", envOTLPTracesProtocol},
	}
	for _, signal := range signals {
		t.Run(signal.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// Both variables are set on every case, so that whatever
					// the environment running the tests carries is not read.
					t.Setenv(envOTLPProtocol, tc.generic)
					t.Setenv(signal.env, tc.signal)

					got, err := otlpProtocol(tc.configured, signal.env)
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
		})
	}
}

func TestResourceAttributePrecedence(t *testing.T) {
	fromEnv := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("from-environment"),
		semconv.ServiceVersion("v9.9.9"),
	)
	unnamed := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("unknown_service:sshmux"),
	)

	// The environment supplies the name, so sshmux must not override it.
	attrs, err := otelResourceAttributes("", nil, fromEnv)
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
	attrs, err = otelResourceAttributes("from-config", nil, fromEnv)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := findAttribute(attrs, semconv.ServiceNameKey); name != "from-config" {
		t.Errorf("service.name = %q, want %q", name, "from-config")
	}

	// With neither set, sshmux falls back to its own default.
	attrs, err = otelResourceAttributes("", nil, unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := findAttribute(attrs, semconv.ServiceNameKey); name != defaultServiceName {
		t.Errorf("service.name = %q, want %q", name, defaultServiceName)
	}
	if _, ok := findAttribute(attrs, semconv.ServiceVersionKey); !ok {
		t.Error("service.version is missing, want the build version")
	}

	// Attributes from the config file are always applied.
	attrs, err = otelResourceAttributes("", []ResourceAttributeConfig{{Name: "env", Value: "staging"}}, unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := findAttribute(attrs, attribute.Key("env")); value != "staging" {
		t.Errorf("env = %q, want %q", value, "staging")
	}

	if _, err := otelResourceAttributes("", []ResourceAttributeConfig{{Value: "no name"}}, unnamed); err == nil {
		t.Error("a nameless resource attribute should be rejected")
	}
}

// findAttribute reports the value carried for key, and whether it is there.
func findAttribute(attrs []attribute.KeyValue, key attribute.Key) (string, bool) {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

// TestConventionAttributeNames pins how each convention resolves, and that the
// two lines currently agree — the property that lets `ecs` be the stable choice
// today at no cost.
func TestConventionAttributeNames(t *testing.T) {
	for _, convention := range []AttributeConvention{"", AttributeConventionDefault} {
		names, err := conventionAttributeNames(convention)
		if err != nil {
			t.Fatalf("convention %q: %v", convention, err)
		}
		if names != defaultAttributeNames {
			t.Errorf("convention %q did not resolve to the semantic conventions", convention)
		}
	}
	names, err := conventionAttributeNames(AttributeConventionECS)
	if err != nil {
		t.Fatal(err)
	}
	if names != ecsAttributeNames {
		t.Error(`convention "ecs" did not resolve to the Elastic Common Schema`)
	}

	// The conventions adopted most of these fields from ECS, so they name all
	// but the application protocol and its version identically. A further
	// difference needs a row in the README table, and this is what says so.
	var differing []string
	defaults, ecs := reflect.ValueOf(defaultAttributeNames), reflect.ValueOf(ecsAttributeNames)
	for i := range defaults.NumField() {
		// String, not Interface: the fields are unexported, and every one of
		// them is an attribute.Key.
		if defaults.Field(i).String() != ecs.Field(i).String() {
			differing = append(differing, defaults.Type().Field(i).Name)
		}
	}
	want := []string{"networkProtocolName", "networkProtocolVersion"}
	if !slices.Equal(differing, want) {
		t.Errorf("the conventions differ in %v, want %v", differing, want)
	}
	if ecsAttributeNames.networkProtocolVersion != "" {
		t.Error("ECS has no name for the protocol version, want the attribute dropped")
	}

	if _, err := conventionAttributeNames("nonsense"); err == nil {
		t.Error("an unknown convention should be refused")
	}
}
