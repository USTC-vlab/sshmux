package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Plumbing shared by the OpenTelemetry signals: the attribute names a
// convention resolves to, an OTLP exporter's settings, and the resource that
// identifies this process.

const (
	defaultServiceName  = "sshmux"
	otelScopeName       = "github.com/USTC-vlab/sshmux"
	otelShutdownTimeout = 5 * time.Second
)

const (
	envOTLPProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOTLPMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	envOTLPTracesProtocol  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envOTLPLogsProtocol    = "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"
)

// connectionInfo is the per-connection state the metrics and the spans are
// recorded from. Fields are zero until they become known: Username is only set
// once the client has sent its first auth request, and the upstream only once
// the auth API has answered.
type connectionInfo struct {
	Username string
	// UpstreamHost and UpstreamPort are the backend the auth API returned,
	// before any PROXY protocol override, UpstreamUsername the account sshmux
	// signs in to it as, and UpstreamRole the label the API put on that
	// backend, empty where it labelled none.
	UpstreamHost     string
	UpstreamPort     uint16
	UpstreamUsername string
	UpstreamRole     string
	// ClientHost and ClientPort are the downstream address, as the PROXY
	// protocol header reports it where there is one, and ClientPeer the address
	// actually connected from. They are for the spans: grouping metrics by
	// client would be a series per connection.
	ClientHost string
	ClientPort uint16
	ClientPeer net.Addr
	// SessionID identifies the SSH session, which is what the auth API is told
	// as `session_id`. It is set once the SSH transport is up.
	SessionID string
	// DownstreamAuthMethods are the methods the client authenticated to sshmux
	// by, and UpstreamAuthMethods those sshmux authenticated to the backend by.
	// Both keep what was accepted and only that, in whole or in part: a method
	// that gets a step of the way, as a key does where challenges follow it,
	// counts as much as one that completes the exchange. A method that was
	// refused is left out, so that a record says how a session got in rather
	// than everything it knocked with.
	DownstreamAuthMethods []string
	UpstreamAuthMethods   []string
	// EndedBy is the connection that ended a session that was being piped,
	// which is the downstream where a client disconnects and the upstream where
	// a backend goes away under one. It is empty where no session was piped.
	EndedBy string
	// HandshakeStart and HandshakeEnd are when the downstream handshake and the
	// upstream dial began and concluded, which is the session's own span within
	// the connection carrying it. Both are zero until the SSH transport is up.
	HandshakeStart time.Time
	HandshakeEnd   time.Time
	// UpstreamPeer is the address the upstream connection ends at, which is the
	// PROXY protocol hop where one is configured and the backend otherwise, and
	// is resolved where UpstreamHost is whatever the auth API named.
	UpstreamPeer net.Addr
	// ProtocolVersion is the SSH protocol version the client identified with,
	// e.g. "2.0" out of "SSH-2.0-OpenSSH_9.9".
	ProtocolVersion string
	// Established records whether the handshake completed.
	Established bool
}

func otelResource(serviceName string, configured []ResourceAttributeConfig) (*resource.Resource, error) {
	// resource.Default reads OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
	base := resource.Default()
	attrs, err := otelResourceAttributes(serviceName, configured, base)
	if err != nil {
		return nil, err
	}
	// The base resource and our attributes share the same semantic convention
	// schema, so the merge below never conflicts. Attributes from the second
	// resource win, which is why only the ones the environment did not already
	// provide are added.
	res, err := resource.Merge(base, resource.NewWithAttributes(semconv.SchemaURL, attrs...))
	if err != nil {
		return nil, fmt.Errorf("failed to build resource: %w", err)
	}
	return res, nil
}

// otelResourceAttributes returns the resource attributes to layer on top of
// base, honouring the config file over the environment over sshmux's defaults.
func otelResourceAttributes(serviceName string, configured []ResourceAttributeConfig, base *resource.Resource) ([]attribute.KeyValue, error) {
	var attrs []attribute.KeyValue
	// resource.Default only reports an `unknown_service:...` name when neither
	// OTEL_SERVICE_NAME nor OTEL_RESOURCE_ATTRIBUTES supplied one.
	if serviceName != "" {
		attrs = append(attrs, semconv.ServiceName(serviceName))
	} else if name, ok := resourceAttribute(base, semconv.ServiceNameKey); !ok || strings.HasPrefix(name, "unknown_service") {
		attrs = append(attrs, semconv.ServiceName(defaultServiceName))
	}
	if _, ok := resourceAttribute(base, semconv.ServiceVersionKey); !ok {
		attrs = append(attrs, semconv.ServiceVersion(buildVersion()))
	}
	if _, ok := resourceAttribute(base, semconv.HostNameKey); !ok {
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			attrs = append(attrs, semconv.HostName(hostname))
		}
	}
	for _, attr := range configured {
		if attr.Name == "" {
			return nil, errors.New("resource attributes must have a name")
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
func otlpProtocol(configured string, signalEnv string) (string, error) {
	protocol := configured
	for _, key := range []string{signalEnv, envOTLPProtocol} {
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

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "unknown"
	}
	return info.Main.Version
}

// otlpEndpoint parses a configured endpoint. A nil result means none was set,
// so the exporter falls back to OTEL_EXPORTER_OTLP_[SIGNAL_]ENDPOINT and in
// turn to the OTLP defaults.
func otlpEndpoint(config OTLPConfig, protocol string) (*url.URL, error) {
	if config.Endpoint == "" {
		return nil, nil
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OTLP endpoint: %w", err)
	}
	switch endpoint.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported OTLP endpoint scheme: %s", endpoint.Scheme)
	}
	if protocol == "grpc" && strings.Trim(endpoint.Path, "/") != "" {
		return nil, fmt.Errorf("gRPC OTLP endpoint must not have a path: %s", config.Endpoint)
	}
	return endpoint, nil
}

func otlpHeaders(config OTLPConfig) map[string]string {
	headers := make(map[string]string, len(config.Headers))
	for _, header := range config.Headers {
		headers[header.Name] = header.Value
	}
	return headers
}

// otlpTimeout reports the configured export timeout, and whether one was set:
// leaving it unset defers to OTEL_EXPORTER_OTLP_[SIGNAL_]TIMEOUT.
func otlpTimeout(config OTLPConfig) (time.Duration, bool) {
	if config.TimeoutSeconds == 0 {
		return 0, false
	}
	return time.Duration(config.TimeoutSeconds) * time.Second, true
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

// appendDownstreamAuthMethod keeps a method the auth API accepted. One it
// refused is left to the span of the request that refused it, and several
// rounds of one method, as keyboard-interactive takes, are the one method.
func (info *connectionInfo) appendDownstreamAuthMethod(method string) {
	if n := len(info.DownstreamAuthMethods); n > 0 && info.DownstreamAuthMethods[n-1] == method {
		return
	}
	info.DownstreamAuthMethods = append(info.DownstreamAuthMethods, method)
}

// appendUpstreamAuthMethod keeps a method the backend accepted, as the
// downstream side keeps what the auth API accepted.
func (info *connectionInfo) appendUpstreamAuthMethod(method string) {
	if n := len(info.UpstreamAuthMethods); n > 0 && info.UpstreamAuthMethods[n-1] == method {
		return
	}
	info.UpstreamAuthMethods = append(info.UpstreamAuthMethods, method)
}
