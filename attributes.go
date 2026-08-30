package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
)

// How sshmux names what it observes. A connection, an outcome and a peer are
// described from the vocabulary here, whichever signal carries them, so that
// one convention resolves them the same way for all three.

// unknownAttributeValue is recorded for a grouping attribute whose value is
// not known, e.g. the username of a connection that failed before auth.
const unknownAttributeValue = "unknown"

// attributeNames is the set of attribute keys one convention resolves to.
// Only the names differ between conventions; the values never do.
type attributeNames struct {
	eventOutcome           attribute.Key
	errorType              attribute.Key
	userName               attribute.Key
	clientAddress          attribute.Key
	clientPort             attribute.Key
	serverAddress          attribute.Key
	serverPort             attribute.Key
	networkProtocolName    attribute.Key
	networkProtocolVersion attribute.Key
	// The peer is the other end of a network connection, as against the logical
	// end behind any intermediary. It names that end wherever the client and
	// server roles are settled, as a span's kind settles them: the client for a
	// server span, the callee for a client span.
	networkPeerAddress attribute.Key
	networkPeerPort    attribute.Key
	sshmuxAuthMethod   attribute.Key
	sshmuxAuthStatus   attribute.Key
}

// defaultAttributeNames resolves each attribute against the OpenTelemetry
// semantic conventions first, then the Elastic Common Schema, then sshmux's
// own namespace, and follows the conventions wherever they move.
var defaultAttributeNames = attributeNames{
	errorType:              attribute.Key("error.type"),               // semconv
	userName:               attribute.Key("user.name"),                // semconv
	clientAddress:          attribute.Key("client.address"),           // semconv
	clientPort:             attribute.Key("client.port"),              // semconv
	serverAddress:          attribute.Key("server.address"),           // semconv
	serverPort:             attribute.Key("server.port"),              // semconv
	networkProtocolName:    attribute.Key("network.protocol.name"),    // semconv
	networkProtocolVersion: attribute.Key("network.protocol.version"), // semconv
	networkPeerAddress:     attribute.Key("network.peer.address"),     // semconv
	networkPeerPort:        attribute.Key("network.peer.port"),        // semconv
	eventOutcome:           attribute.Key("event.outcome"),            // ECS; semconv has no equivalent
	sshmuxAuthMethod:       attribute.Key("sshmux.auth.method"),
	sshmuxAuthStatus:       attribute.Key("sshmux.auth.status"),
}

// ecsAttributeNames resolves against the Elastic Common Schema only, which does
// not move when the semantic conventions do.
//
// Most of these it names identically to defaultAttributeNames, the conventions
// having adopted the fields from ECS. The two tables are kept apart for the
// ones that have since diverged, marked below, and for those that will.
var ecsAttributeNames = attributeNames{
	errorType:     attribute.Key("error.type"),
	userName:      attribute.Key("user.name"),
	clientAddress: attribute.Key("client.address"),
	clientPort:    attribute.Key("client.port"),
	serverAddress: attribute.Key("server.address"),
	serverPort:    attribute.Key("server.port"),
	// The two attributes the conventions do not share: ECS names the
	// application protocol without the namespace the semantic conventions put
	// it in, and has nothing for its version. An empty key drops the attribute.
	networkProtocolName: attribute.Key("network.protocol"),
	networkPeerAddress:  attribute.Key("network.peer.address"),
	networkPeerPort:     attribute.Key("network.peer.port"),
	eventOutcome:        attribute.Key("event.outcome"),
	sshmuxAuthMethod:    attribute.Key("sshmux.auth.method"),
	sshmuxAuthStatus:    attribute.Key("sshmux.auth.status"),
}

// conventionAttributeNames resolves the configured convention.
func conventionAttributeNames(convention AttributeConvention) (attributeNames, error) {
	switch convention {
	case "", AttributeConventionDefault:
		return defaultAttributeNames, nil
	case AttributeConventionECS:
		return ecsAttributeNames, nil
	default:
		// Unreachable: UnmarshalText accepts only the names above.
		return attributeNames{}, fmt.Errorf("unsupported convention: %s", convention)
	}
}

func (n attributeNames) success() attribute.KeyValue { return n.eventOutcome.String("success") }
func (n attributeNames) failure() attribute.KeyValue { return n.eventOutcome.String("failure") }

// connectionAttributes reports the parts of a connection's identity that are
// known. Both the spans and the log records are built from it, so that one
// connection is described the same way whichever signal carries it. Unlike the
// metrics, an unknown value is left off rather than recorded as "unknown",
// since neither has a cardinality budget to protect, and so is an attribute
// the convention has no name for.
func (n attributeNames) connectionAttributes(info connectionInfo) []attribute.KeyValue {
	attrs := []attribute.KeyValue{n.networkProtocolName.String("ssh")}
	if info.ProtocolVersion != "" {
		attrs = append(attrs, n.networkProtocolVersion.String(info.ProtocolVersion))
	}
	if info.Username != "" {
		attrs = append(attrs, n.userName.String(info.Username))
	}
	if info.ClientHost != "" {
		attrs = append(attrs,
			n.clientAddress.String(info.ClientHost),
			n.clientPort.Int(int(info.ClientPort)))
	}
	if info.UpstreamHost != "" {
		attrs = append(attrs,
			n.serverAddress.String(info.UpstreamHost),
			n.serverPort.Int(int(info.UpstreamPort)))
	}
	return named(attrs)
}

// named drops the attributes the convention has no name for, which it resolves
// to an empty key. Every builder here returns through it, so that a sink takes
// what it is given.
func named(attrs []attribute.KeyValue) []attribute.KeyValue {
	return slices.DeleteFunc(attrs, func(attr attribute.KeyValue) bool { return attr.Key == "" })
}

func (n attributeNames) outcomeAttributes(err error) []attribute.KeyValue {
	if err == nil {
		return []attribute.KeyValue{n.success()}
	}
	return []attribute.KeyValue{n.failure(), n.errorType.String(errorType(err))}
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

// serverAttributes names the service at a URL, taking the port it leaves out
// from its scheme.
func (n attributeNames) serverAttributes(server *url.URL) []attribute.KeyValue {
	if server == nil || server.Hostname() == "" {
		return nil
	}
	attrs := []attribute.KeyValue{n.serverAddress.String(server.Hostname())}
	port := server.Port()
	if port == "" {
		port = portForScheme(server.Scheme)
	}
	if number, err := strconv.Atoi(port); err == nil {
		attrs = append(attrs, n.serverPort.Int(number))
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

// peerAttributes names the other end of the network connection a span covers:
// where it was reached from for a server span, and what it reached out to for
// a client span.
func (n attributeNames) peerAttributes(peer net.Addr) []attribute.KeyValue {
	tcp, ok := peer.(*net.TCPAddr)
	if !ok {
		return nil
	}
	return []attribute.KeyValue{
		n.networkPeerAddress.String(tcp.IP.String()),
		n.networkPeerPort.Int(tcp.Port),
	}
}
