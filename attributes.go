package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
)

// How sshmux names what it observes. A connection and its outcome are described
// from the vocabulary here whichever signal carries them, so that one convention
// resolves them the same way for all three.
//
// Which name an address takes follows from what is being described, not from
// the signal describing it. Across one connection whose client and server roles
// are settled, the peer names its other end. Across a session, where sshmux
// forwards between two connections and neither role is its own, that name
// cannot say which of them is meant, so each is named in turn under `sshmux`.

// unknownAttributeValue is recorded for a grouping attribute whose value is
// not known, e.g. the username of a connection that failed before auth.
const unknownAttributeValue = "unknown"

// attributeNames is the set of attribute keys one convention resolves to.
// Only the names differ between conventions; the values never do.
type attributeNames struct {
	errorType attribute.Key
	// What an error said. The semantic conventions name it on the exception it
	// came from, where ECS names it on the error and calls the two equivalent.
	errorMessage attribute.Key

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
	// The class of event a record is one of, which the OpenTelemetry Logs Data
	// Model holds in a field of its own rather than an attribute. A logging
	// library has no way to set that field, so each convention names an
	// attribute to carry it in until a sink that has the field promotes it.
	eventName attribute.Key
	// What the session an event belongs to is identified by, which the event
	// the conventions define for a session's end requires.
	sessionID attribute.Key

	eventOutcome attribute.Key
	// What a finished event is categorized and timed by, which ECS has and the
	// semantic conventions have nothing for, so both resolve them alike today.
	eventKind     attribute.Key
	eventCategory attribute.Key
	eventType     attribute.Key
	eventStart    attribute.Key
	eventEnd      attribute.Key
	eventDuration attribute.Key

	sshmuxAuthMethod attribute.Key
	sshmuxAuthStatus attribute.Key
	// The moments the downstream handshake and the upstream dial began and
	// concluded, which sshmux.handshake.duration measures between. The end of
	// it, on a session that came up, is when it began being proxied.
	sshmuxHandshakeStart attribute.Key
	sshmuxHandshakeEnd   attribute.Key
	// A session covers two network connections, and sshmux forwards between
	// them rather than being the client or the server of either, so the peer
	// above cannot say which one it means. Each is named its own instead,
	// against the logical ends that client.* and server.* name.
	sshmuxDownstreamAddress attribute.Key
	sshmuxDownstreamPort    attribute.Key
	sshmuxUpstreamAddress   attribute.Key
	sshmuxUpstreamPort      attribute.Key
}

// defaultAttributeNames resolves each attribute against the OpenTelemetry
// semantic conventions first, then the Elastic Common Schema, then sshmux's
// own namespace, and follows the conventions wherever they move.
var defaultAttributeNames = attributeNames{
	errorType:               attribute.Key("error.type"),               // semconv
	errorMessage:            attribute.Key("exception.message"),        // semconv
	userName:                attribute.Key("user.name"),                // semconv
	clientAddress:           attribute.Key("client.address"),           // semconv
	clientPort:              attribute.Key("client.port"),              // semconv
	serverAddress:           attribute.Key("server.address"),           // semconv
	serverPort:              attribute.Key("server.port"),              // semconv
	networkProtocolName:     attribute.Key("network.protocol.name"),    // semconv
	networkProtocolVersion:  attribute.Key("network.protocol.version"), // semconv
	networkPeerAddress:      attribute.Key("network.peer.address"),     // semconv
	networkPeerPort:         attribute.Key("network.peer.port"),        // semconv
	eventName:               attribute.Key("otel.event.name"),          // semconv
	sessionID:               attribute.Key("session.id"),               // semconv
	eventOutcome:            attribute.Key("event.outcome"),            // ECS; semconv has no equivalent
	eventKind:               attribute.Key("event.kind"),               // ECS; semconv has no equivalent
	eventCategory:           attribute.Key("event.category"),           // ECS; semconv has no equivalent
	eventType:               attribute.Key("event.type"),               // ECS; semconv has no equivalent
	eventStart:              attribute.Key("event.start"),              // ECS; semconv has no equivalent
	eventEnd:                attribute.Key("event.end"),                // ECS; semconv has no equivalent
	eventDuration:           attribute.Key("event.duration"),           // ECS; semconv has no equivalent
	sshmuxAuthMethod:        attribute.Key("sshmux.auth.method"),
	sshmuxAuthStatus:        attribute.Key("sshmux.auth.status"),
	sshmuxHandshakeStart:    attribute.Key("sshmux.handshake.start"),
	sshmuxHandshakeEnd:      attribute.Key("sshmux.handshake.end"),
	sshmuxDownstreamAddress: attribute.Key("sshmux.downstream.address"),
	sshmuxDownstreamPort:    attribute.Key("sshmux.downstream.port"),
	sshmuxUpstreamAddress:   attribute.Key("sshmux.upstream.address"),
	sshmuxUpstreamPort:      attribute.Key("sshmux.upstream.port"),
}

// ecsAttributeNames resolves against the Elastic Common Schema only, which does
// not move when the semantic conventions do.
//
// Most of these it names identically to defaultAttributeNames, the conventions
// having adopted the fields from ECS. The two tables are kept apart for the
// ones that have since diverged, marked below, and for those that will.
var ecsAttributeNames = attributeNames{
	errorType:     attribute.Key("error.type"),
	errorMessage:  attribute.Key("error.message"),
	userName:      attribute.Key("user.name"),
	clientAddress: attribute.Key("client.address"),
	clientPort:    attribute.Key("client.port"),
	serverAddress: attribute.Key("server.address"),
	serverPort:    attribute.Key("server.port"),
	// The two attributes the conventions do not share: ECS names the
	// application protocol without the namespace the semantic conventions put
	// it in, and has nothing for its version. An empty key drops the attribute.
	networkProtocolName:     attribute.Key("network.protocol"),
	networkPeerAddress:      attribute.Key("network.peer.address"),
	networkPeerPort:         attribute.Key("network.peer.port"),
	eventName:               attribute.Key("event.action"),
	sessionID:               attribute.Key("session.id"),
	eventOutcome:            attribute.Key("event.outcome"),
	eventKind:               attribute.Key("event.kind"),
	eventCategory:           attribute.Key("event.category"),
	eventType:               attribute.Key("event.type"),
	eventStart:              attribute.Key("event.start"),
	eventEnd:                attribute.Key("event.end"),
	eventDuration:           attribute.Key("event.duration"),
	sshmuxAuthMethod:        attribute.Key("sshmux.auth.method"),
	sshmuxAuthStatus:        attribute.Key("sshmux.auth.status"),
	sshmuxHandshakeStart:    attribute.Key("sshmux.handshake.start"),
	sshmuxHandshakeEnd:      attribute.Key("sshmux.handshake.end"),
	sshmuxDownstreamAddress: attribute.Key("sshmux.downstream.address"),
	sshmuxDownstreamPort:    attribute.Key("sshmux.downstream.port"),
	sshmuxUpstreamAddress:   attribute.Key("sshmux.upstream.address"),
	sshmuxUpstreamPort:      attribute.Key("sshmux.upstream.port"),
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

// errorAttributes names an error the service carried on from, by the class the
// metrics classify one by and the text ECS names. It says nothing of a session,
// having none to say anything about.
func (n attributeNames) errorAttributes(err error) []slog.Attr {
	return []slog.Attr{
		slog.String(string(n.errorType), errorType(err)),
		slog.String(string(n.errorMessage), err.Error()),
	}
}

// connectionAttributes reports the parts of a connection's identity that are
// known. Both the spans and the log records are built from it, so that one
// connection is described the same way whichever signal carries it. Unlike the
// metrics, an unknown value is left off rather than recorded as "unknown",
// since neither has a cardinality budget to protect, and so is an attribute
// the convention has no name for.
func (n attributeNames) connectionAttributes(info connectionInfo) []attribute.KeyValue {
	attrs := []attribute.KeyValue{n.networkProtocolName.String("ssh")}
	// The session's own identifier, which the auth API is told as well, so that
	// a record, a span and an auth request can be read as one session. The
	// metrics name a connection without it, there being one value per session.
	if info.SessionID != "" {
		attrs = append(attrs, n.sessionID.String(info.SessionID))
	}
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

// outcomeAttributes names the outcome of an operation, which succeeded if it
// returned no error, along with the class of the error where it did.
func (n attributeNames) outcomeAttributes(err error) []attribute.KeyValue {
	return n.outcome(err == nil, err)
}

// sessionOutcomeAttributes names the outcome of a session, which is whether it
// was established rather than whether anything went wrong: a client ends a
// healthy session by disconnecting, and an error reached afterwards did not
// stop the session from happening. The class of one is recorded either way.
func (n attributeNames) sessionOutcomeAttributes(established bool, err error) []attribute.KeyValue {
	return n.outcome(established, err)
}

func (n attributeNames) outcome(succeeded bool, err error) []attribute.KeyValue {
	outcome := n.failure()
	if succeeded {
		outcome = n.success()
	}
	attrs := []attribute.KeyValue{outcome}
	if err != nil {
		attrs = append(attrs, n.errorType.String(errorType(err)))
	}
	return named(attrs)
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

// socketAttributes names an address a connection is really made to or from,
// which is the intermediary's where one sits in between and the logical end's
// otherwise, under the keys naming that end of a session.
func socketAttributes(address net.Addr, host, port attribute.Key) []attribute.KeyValue {
	tcp, ok := address.(*net.TCPAddr)
	if !ok {
		return nil
	}
	return named([]attribute.KeyValue{
		host.String(tcp.IP.String()),
		port.Int(tcp.Port),
	})
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
