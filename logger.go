package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

const defaultLoggerUDPAddress = "127.0.0.1:5556"

// Logger is the slog.Logger an sshmux server logs sessions through, which the
// sinks are wrapped into: a UDP socket carrying JSON documents, an OpenTelemetry
// logger provider exporting over OTLP, or both. One convention names the
// attributes for all of them, and a record is built under it rather than
// rewritten on the way to each.
//
// It embeds the slog.Logger rather than hiding it, so that anything holding one
// logs through the standard interface, and only the shutdown is ours.
type Logger struct {
	*slog.Logger
	attrs    attributeNames
	provider *sdklog.LoggerProvider
	conn     net.Conn
}

func makeLogger(config LoggerConfig) (*Logger, error) {
	logger := &Logger{
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		attrs:  defaultAttributeNames,
	}
	if !config.Enabled {
		return logger, nil
	}
	names, err := conventionAttributeNames(config.Convention)
	if err != nil {
		return nil, err
	}
	logger.attrs = names

	res, err := otelResource(config.ServiceName, config.Attributes)
	if err != nil {
		return nil, err
	}

	udpAddress, deprecated, err := loggerUDPAddress(config)
	if err != nil {
		return nil, err
	}
	if udpAddress == "" && !config.OTLP.Enabled {
		return nil, errors.New("the logger is enabled but no sink is configured")
	}

	var handlers []slog.Handler
	if udpAddress != "" {
		conn, err := net.Dial("udp", udpAddress)
		if err != nil {
			return nil, fmt.Errorf("logger dial failed: %w", err)
		}
		logger.conn = conn
		handlers = append(handlers, jsonSink(conn, loggerShape(config.UDP.Shape, deprecated), names, res.Attributes()))
	}
	if config.OTLP.Enabled {
		provider, err := makeLoggerProvider(config, res, names)
		if err != nil {
			logger.closeConn()
			return nil, err
		}
		logger.provider = provider
		// OTLP carries the record's own fields as the data model's, so there is
		// no shape left for a sink to decide.
		handlers = append(handlers, otelslog.NewHandler(otelScopeName, otelslog.WithLoggerProvider(provider)))
	}

	if len(handlers) == 1 {
		logger.Logger = slog.New(handlers[0])
	} else {
		logger.Logger = slog.New(multiHandler(handlers))
	}
	return logger, nil
}

// loggerShape resolves the document a UDP sink writes. A configuration still
// using the deprecated endpoint keeps the shape it was already receiving,
// rather than being rewritten out from under it.
func loggerShape(configured LogRecordShape, deprecated bool) LogRecordShape {
	if configured != "" {
		return configured
	}
	if deprecated {
		return LogRecordShapeLegacy
	}
	return LogRecordShapeECS
}

// loggerUDPAddress resolves the UDP sink, accepting the deprecated
// `logger.endpoint` URL as well as the `logger.udp` group, and reporting which
// of the two named it. An empty address means the sink is off.
func loggerUDPAddress(config LoggerConfig) (string, bool, error) {
	if config.Endpoint != "" {
		if config.UDP.Enabled || config.UDP.Address != "" {
			return "", false, errors.New("only one of logger.endpoint and logger.udp can be set")
		}
		log.Println("warning: `logger.endpoint` is deprecated. Please use `logger.udp` instead.")
		endpoint, err := url.Parse(config.Endpoint)
		if err != nil {
			return "", false, err
		}
		if endpoint.Scheme != "udp" {
			return "", false, fmt.Errorf("unsupported logger endpoint: %s", config.Endpoint)
		}
		return endpoint.Host, true, nil
	}
	if !config.UDP.Enabled {
		return "", false, nil
	}
	return valueOrDefault(config.UDP.Address, defaultLoggerUDPAddress), false, nil
}

func makeLoggerProvider(config LoggerConfig, res *resource.Resource, names attributeNames) (*sdklog.LoggerProvider, error) {
	exporter, err := makeOTLPLogExporter(config.OTLP)
	if err != nil {
		return nil, err
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(eventNameProcessor{
			Processor: sdklog.NewBatchProcessor(exporter),
			name:      names.eventName,
		}),
	), nil
}

func makeOTLPLogExporter(config OTLPConfig) (sdklog.Exporter, error) {
	protocol, err := otlpProtocol(config.Protocol, envOTLPLogsProtocol)
	if err != nil {
		return nil, err
	}
	endpoint, err := otlpEndpoint(config, protocol)
	if err != nil {
		return nil, err
	}
	headers := otlpHeaders(config)
	timeout, hasTimeout := otlpTimeout(config)

	if protocol == "grpc" {
		var options []otlploggrpc.Option
		if endpoint != nil {
			options = append(options, otlploggrpc.WithEndpointURL(endpoint.String()))
		}
		if len(headers) > 0 {
			options = append(options, otlploggrpc.WithHeaders(headers))
		}
		if hasTimeout {
			options = append(options, otlploggrpc.WithTimeout(timeout))
		}
		return otlploggrpc.New(context.Background(), options...)
	}

	var options []otlploghttp.Option
	if endpoint != nil {
		// A configured endpoint is a signal-specific one, so it is used as-is,
		// the same way OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is. Only the generic
		// OTEL_EXPORTER_OTLP_ENDPOINT is a base URL that `/v1/logs` is appended
		// to, which the exporter handles itself.
		options = append(options, otlploghttp.WithEndpointURL(endpoint.String()))
	}
	if len(headers) > 0 {
		options = append(options, otlploghttp.WithHeaders(headers))
	}
	if hasTimeout {
		options = append(options, otlploghttp.WithTimeout(timeout))
	}
	return otlploghttp.New(context.Background(), options...)
}

// Shutdown flushes pending records and closes the sinks.
func (l *Logger) Shutdown(ctx context.Context) {
	if l.provider != nil {
		if err := l.provider.Shutdown(ctx); err != nil {
			log.Printf("Error on logger shutdown: %s\n", err)
		}
		l.provider = nil
	}
	l.closeConn()
}

func (l *Logger) closeConn() {
	if l.conn != nil {
		l.conn.Close()
		l.conn = nil
	}
}

// sessionAttributes names one finished connection, for a caller to log through
// the standard slog interface. They are named under the logger's convention as
// they are built, so that no sink has to rewrite a record to name it its own
// way.
//
// err is whatever ended the session, if anything. The outcome is not read from
// it but from whether the session was established, which is the question a
// record of one answers.
func (l *Logger) sessionAttributes(info connectionInfo, err error, connect, disconnect time.Time) []slog.Attr {
	names := l.attrs
	attrs := []slog.Attr{
		slog.String(string(names.eventName), sessionEndEventName),
		slog.String(string(names.eventKind), "event"),
		slog.Any(string(names.eventCategory), []string{"network"}),
		slog.Any(string(names.eventType), []string{"connection", "end"}),
	}
	// The class of whatever ended it is the one the metrics record, so that a
	// failure is called the same thing whichever signal reports it.
	attrs = append(attrs, slogAttributes(names.sessionOutcomeAttributes(info.Established, err))...)
	attrs = append(attrs,
		// ECS dates are UTC, so the local zone must not leak into the record.
		slog.Time(string(names.eventStart), connect.UTC()),
		slog.Time(string(names.eventEnd), disconnect.UTC()),
		slog.Int64(string(names.eventDuration), disconnect.Sub(connect).Nanoseconds()),
		slog.Time(string(names.sshmuxHandshakeStart), info.HandshakeStart.UTC()),
		slog.Time(string(names.sshmuxHandshakeEnd), info.HandshakeEnd.UTC()),
	)
	// The connection is named by the same builder the spans are built from.
	attrs = append(attrs, slogAttributes(names.connectionAttributes(info))...)
	// A span names its peer without ambiguity because its kind says which end
	// that is. One record covers both of a session's connections, so it names
	// each of them rather than either as the peer.
	attrs = append(attrs, slogAttributes(socketAttributes(info.ClientPeer,
		names.sshmuxDownstreamAddress, names.sshmuxDownstreamPort))...)
	attrs = append(attrs, slogAttributes(socketAttributes(info.UpstreamPeer,
		names.sshmuxUpstreamAddress, names.sshmuxUpstreamPort))...)
	return attrs
}

// slogAttributes renders OpenTelemetry attributes as their slog equivalents.
func slogAttributes(attrs []attribute.KeyValue) []slog.Attr {
	rendered := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		rendered = append(rendered, slogAttribute(attr))
	}
	return rendered
}

// slogAttribute renders an OpenTelemetry attribute as its slog equivalent.
func slogAttribute(attr attribute.KeyValue) slog.Attr {
	key := string(attr.Key)
	switch attr.Value.Type() {
	case attribute.BOOL:
		return slog.Bool(key, attr.Value.AsBool())
	case attribute.INT64:
		return slog.Int64(key, attr.Value.AsInt64())
	case attribute.FLOAT64:
		return slog.Float64(key, attr.Value.AsFloat64())
	case attribute.STRING:
		return slog.String(key, attr.Value.AsString())
	default:
		return slog.Any(key, attr.Value.AsInterface())
	}
}

// The classes of event a record is one of. The conventions define both for a
// session, and require the session's own identifier alongside either.
const (
	sessionStartEventName = "session.start"
	sessionEndEventName   = "session.end"
)

// sessionStartAttributes names a session that has begun, which is as much of
// the connection as is known once its SSH transport is up: no user has been
// authenticated yet, and no backend named.
func (l *Logger) sessionStartAttributes(info connectionInfo, start time.Time) []slog.Attr {
	names := l.attrs
	attrs := []slog.Attr{
		slog.String(string(names.eventName), sessionStartEventName),
		slog.String(string(names.eventKind), "event"),
		slog.Any(string(names.eventCategory), []string{"network"}),
		slog.Any(string(names.eventType), []string{"connection", "start"}),
		slog.Time(string(names.eventStart), start.UTC()),
	}
	attrs = append(attrs, slogAttributes(names.connectionAttributes(info))...)
	return append(attrs, slogAttributes(socketAttributes(info.ClientPeer,
		names.sshmuxDownstreamAddress, names.sshmuxDownstreamPort))...)
}

// eventNameProcessor moves the class of event a record is into the field the
// data model keeps it in, out of the attribute a logging library has to carry
// it in for want of a way to reach that field. Records reach the exporter
// through it, so what leaves over OTLP is the event the record describes
// itself as, rather than one a collector has still to be told to promote.
type eventNameProcessor struct {
	sdklog.Processor
	name attribute.Key
}

func (p eventNameProcessor) OnEmit(ctx context.Context, record *sdklog.Record) error {
	if record.EventName() == "" {
		var name string
		kept := make([]attribute.KeyValue, 0, record.AttributesLen())
		record.WalkAttributes(func(attr attribute.KeyValue) bool {
			if attr.Key == p.name {
				name = attr.Value.AsString()
			} else {
				kept = append(kept, attr)
			}
			return true
		})
		if name != "" {
			record.SetEventName(name)
			record.SetAttributes(kept...)
		}
	}
	return p.Processor.OnEmit(ctx, record)
}

// jsonSink writes each record to conn as one JSON document per datagram, in
// the shape asked for. The attributes are named by the convention whichever
// document they are written into; what a shape decides is the document around
// them, and whether it has a place for the resource.
func jsonSink(conn net.Conn, shape LogRecordShape, names attributeNames, resource []attribute.KeyValue) slog.Handler {
	switch shape {
	case LogRecordShapeLegacy:
		return legacyHandler{Handler: slog.NewJSONHandler(conn, nil), attrs: names}
	case LogRecordShapeOTel:
		return otelShapeHandler{out: conn, resource: resource, attrs: names}
	default:
		return slog.NewJSONHandler(conn, &slog.HandlerOptions{ReplaceAttr: ecsBuiltins})
	}
}

// ecsBuiltins names the record's own fields as the Elastic Common Schema does.
// Its dates are UTC, which the record's time is not until it is written as one.
func ecsBuiltins(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return attr
	}
	switch attr.Key {
	case slog.TimeKey:
		return slog.Time("@timestamp", attr.Value.Time().UTC())
	case slog.LevelKey:
		attr.Key = "log.level"
	case slog.MessageKey:
		attr.Key = "message"
	}
	return attr
}

// otelShapeHandler writes each record as one line of the OpenTelemetry Logs
// Data Model's JSON serialization, the shape the file exporter writes, so that
// a datagram carries what an OTLP export of the same record would.
// See https://opentelemetry.io/docs/specs/otel/protocol/file-exporter.
type otelShapeHandler struct {
	out      io.Writer
	resource []attribute.KeyValue
	attrs    attributeNames
	bound    []slog.Attr
	groups   []string
}

// The document, named as the serialization names it rather than as sshmux
// would, since it is the wire format that is being reproduced.
type (
	otelDocument struct {
		ResourceLogs []otelResourceLogs `json:"resourceLogs"`
	}
	otelResourceLogs struct {
		Resource  otelLogResource `json:"resource"`
		ScopeLogs []otelScopeLogs `json:"scopeLogs"`
	}
	otelLogResource struct {
		Attributes []otelKeyValue `json:"attributes,omitempty"`
	}
	otelScopeLogs struct {
		Scope      otelScope       `json:"scope"`
		LogRecords []otelLogRecord `json:"logRecords"`
	}
	otelScope struct {
		Name string `json:"name,omitempty"`
	}
	otelLogRecord struct {
		EventName      string         `json:"eventName,omitempty"`
		TimeUnixNano   string         `json:"timeUnixNano,omitempty"`
		SeverityNumber int            `json:"severityNumber"`
		SeverityText   string         `json:"severityText"`
		Body           otelValue      `json:"body"`
		Attributes     []otelKeyValue `json:"attributes,omitempty"`
		TraceID        string         `json:"traceId,omitempty"`
		SpanID         string         `json:"spanId,omitempty"`
	}
	otelKeyValue struct {
		Key   string    `json:"key"`
		Value otelValue `json:"value"`
	}
	otelValue struct {
		StringValue *string    `json:"stringValue,omitempty"`
		BoolValue   *bool      `json:"boolValue,omitempty"`
		IntValue    *string    `json:"intValue,omitempty"`
		DoubleValue *float64   `json:"doubleValue,omitempty"`
		ArrayValue  *otelArray `json:"arrayValue,omitempty"`
	}
	otelArray struct {
		Values []otelValue `json:"values"`
	}
)

// Enabled matches what the other shapes inherit from slog's JSON handler,
// which records at Info and above unless it is given a level of its own.
func (h otelShapeHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h otelShapeHandler) Handle(ctx context.Context, record slog.Record) error {
	entry := otelLogRecord{
		SeverityNumber: int(otelSeverity(record.Level)),
		SeverityText:   record.Level.String(),
		Body:           otelStringValue(record.Message),
	}
	// A record with no time of its own leaves the field out, rather than
	// writing the zero time as a moment before the epoch.
	if !record.Time.IsZero() {
		entry.TimeUnixNano = strconv.FormatInt(record.Time.UnixNano(), 10)
	}
	// The span the record is logged against, which is what correlates it with
	// a trace the same way the OTLP exporter does.
	if span := trace.SpanContextFromContext(ctx); span.IsValid() {
		entry.TraceID = span.TraceID().String()
		entry.SpanID = span.SpanID().String()
	}
	for _, attr := range h.bound {
		entry.Attributes = appendOTelAttr(entry.Attributes, h.groups, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		// The document has a field for this one, which is where the conventions
		// say it belongs wherever there is one.
		if attr.Key == string(h.attrs.eventName) && len(h.groups) == 0 {
			entry.EventName = attr.Value.String()
			return true
		}
		entry.Attributes = appendOTelAttr(entry.Attributes, h.groups, attr)
		return true
	})

	document, err := json.Marshal(otelDocument{ResourceLogs: []otelResourceLogs{{
		Resource: otelLogResource{Attributes: otelAttributes(h.resource)},
		ScopeLogs: []otelScopeLogs{{
			Scope:      otelScope{Name: otelScopeName},
			LogRecords: []otelLogRecord{entry},
		}},
	}}})
	if err != nil {
		return err
	}
	_, err = h.out.Write(append(document, '\n'))
	return err
}

func (h otelShapeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.bound = append(slices.Clip(h.bound), attrs...)
	return h
}

func (h otelShapeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h.groups = append(slices.Clip(h.groups), name)
	return h
}

// appendOTelAttr writes one attribute out, under the groups it was opened in.
// The serialization has no nesting for those, so they become a dotted prefix,
// which is how the names sshmux gives an attribute are spelled anyway.
//
// The rules a handler observes are slog.Handler's: an attribute that is wholly
// zero is ignored, an empty group is ignored, and a group with no name of its
// own has its members written where it stands.
func appendOTelAttr(into []otelKeyValue, groups []string, attr slog.Attr) []otelKeyValue {
	if attr.Equal(slog.Attr{}) {
		return into
	}
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		members := value.Group()
		if len(members) == 0 {
			return into
		}
		if attr.Key != "" {
			groups = append(slices.Clone(groups), attr.Key)
		}
		for _, member := range members {
			into = appendOTelAttr(into, groups, member)
		}
		return into
	}
	key := attr.Key
	if len(groups) > 0 {
		key = strings.Join(append(slices.Clone(groups), key), ".")
	}
	return append(into, otelKeyValue{Key: key, Value: otelSlogValue(value)})
}

// otelAttributes renders a resource's attributes as the document holds them.
func otelAttributes(attrs []attribute.KeyValue) []otelKeyValue {
	out := make([]otelKeyValue, 0, len(attrs))
	for _, attr := range attrs {
		out = append(out, otelKeyValue{Key: string(attr.Key), Value: otelSlogValue(slogAttribute(attr).Value)})
	}
	return out
}

// otelSlogValue renders a value as the serialization's AnyValue, which wraps it
// in the name of its type and writes a 64-bit integer as a string. Times become
// nanoseconds since the epoch, as the OTLP bridge renders them, so that both
// sinks carry one record's attribute alike.
func otelSlogValue(value slog.Value) otelValue {
	switch value.Kind() {
	case slog.KindBool:
		boolean := value.Bool()
		return otelValue{BoolValue: &boolean}
	case slog.KindInt64:
		return otelIntValue(value.Int64())
	case slog.KindUint64:
		return otelIntValue(int64(value.Uint64()))
	case slog.KindFloat64:
		number := value.Float64()
		return otelValue{DoubleValue: &number}
	case slog.KindDuration:
		return otelIntValue(value.Duration().Nanoseconds())
	case slog.KindTime:
		return otelIntValue(value.Time().UnixNano())
	case slog.KindString:
		return otelStringValue(value.String())
	case slog.KindAny:
		if values, ok := value.Any().([]string); ok {
			array := otelArray{Values: make([]otelValue, 0, len(values))}
			for _, member := range values {
				array.Values = append(array.Values, otelStringValue(member))
			}
			return otelValue{ArrayValue: &array}
		}
	}
	return otelStringValue(value.String())
}

func otelStringValue(text string) otelValue { return otelValue{StringValue: &text} }

func otelIntValue(number int64) otelValue {
	text := strconv.FormatInt(number, 10)
	return otelValue{IntValue: &text}
}

// otelSeverity maps a slog level onto the data model's severity numbers, the
// way the OTLP bridge does, so that one record reads alike from either sink.
func otelSeverity(level slog.Level) otellog.Severity {
	const offset = slog.Level(otellog.SeverityDebug) - slog.LevelDebug
	return otellog.Severity(level + offset)
}

// sessionFields is the part of a record the legacy shape is built from, held
// under the names the convention gave them, so that the shape can be written
// from whatever the record turned out to carry.
type sessionFields map[string]slog.Value

// readSessionFields keeps the fields the legacy shape is written from, and
// only those. The shape is frozen permanently: it is read by consumers written
// against what sshmux wrote before it followed a schema, and gains no field it
// did not already have, so anything the record grows in future is left here
// for the sinks that follow a schema.
func readSessionFields(record slog.Record, names attributeNames) sessionFields {
	fields := sessionFields{}
	record.Attrs(func(attr slog.Attr) bool {
		switch attr.Key {
		case string(names.eventName),
			string(names.clientAddress), string(names.clientPort),
			string(names.serverAddress), string(names.serverPort), string(names.sessionID),
			string(names.userName), string(names.eventOutcome), string(names.errorType),
			string(names.sshmuxHandshakeStart), string(names.eventEnd):
			fields[attr.Key] = attr.Value
		}
		return true
	})
	return fields
}

// unixTime reads a time field as the legacy shape wrote times. The kind is
// checked because the record may be one this package did not build.
func (f sessionFields) unixTime(key string) (int64, bool) {
	value, ok := f[key]
	if !ok || value.Kind() != slog.KindTime {
		return 0, false
	}
	return value.Time().Unix(), true
}

// hostPort rejoins an address that the schema splits in two.
func (f sessionFields) hostPort(host, port string) (string, bool) {
	value, ok := f[host]
	if !ok {
		return "", false
	}
	number, ok := f[port]
	if !ok || number.Kind() != slog.KindInt64 {
		return value.String(), true
	}
	return joinHostPort(value.String(), int(number.Int64())), true
}

// legacyAttributes renders the record in the shape sshmux wrote before it
// followed a schema: the times collapse to Unix seconds, the addresses rejoin
// into `host:port`, and the outcome becomes a boolean that is simply absent on
// a session that never started. Only what the record carried is written, and a
// record carrying none of the fields above is not a session, so it is left
// with nothing but its message.
func (f sessionFields) legacyAttributes(names attributeNames) []slog.Attr {
	// The shape describes a session that has ended, which is the only event
	// sshmux wrote when it was the only shape. Anything else is left with
	// nothing but its message, rather than written as a session it is not.
	if f[string(names.eventName)].String() != sessionEndEventName {
		return nil
	}
	var attrs []slog.Attr
	if session, ok := f[string(names.sessionID)]; ok {
		attrs = append(attrs, slog.String("session_id", session.String()))
	}
	if connect, ok := f.unixTime(string(names.sshmuxHandshakeStart)); ok {
		attrs = append(attrs, slog.Int64("connect_time", connect))
	}
	if remote, ok := f.hostPort(string(names.clientAddress), string(names.clientPort)); ok {
		attrs = append(attrs, slog.String("remote_ip", remote))
	}
	attrs = append(attrs, slog.String("client_type", "SSH"))
	if disconnect, ok := f.unixTime(string(names.eventEnd)); ok {
		attrs = append(attrs, slog.Int64("disconnect_time", disconnect))
	}
	// The shape has written these where establishing the session returned no
	// error, which is not the same as where the session was established: one
	// that came up and then failed has never been written as authenticated.
	if _, failed := f[string(names.errorType)]; failed {
		return attrs
	}
	if f[string(names.eventOutcome)].String() != "success" {
		return attrs
	}
	if user, ok := f[string(names.userName)]; ok {
		attrs = append(attrs, slog.String("username", user.String()))
	}
	// The backend the auth API named, as `remote_ip` is the client the PROXY
	// protocol header claims: both ends of the shape are the logical ones.
	if host, ok := f.hostPort(string(names.serverAddress), string(names.serverPort)); ok {
		attrs = append(attrs, slog.String("host_ip", host))
	}
	return append(attrs, slog.Bool("authenticated", true))
}

// legacyHandler writes the record in the legacy shape, on the way to the sink
// behind it.
type legacyHandler struct {
	slog.Handler
	attrs attributeNames
}

func (h legacyHandler) Handle(ctx context.Context, record slog.Record) error {
	translated := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	translated.AddAttrs(readSessionFields(record, h.attrs).legacyAttributes(h.attrs)...)
	return h.Handler.Handle(ctx, translated)
}

func (h legacyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return legacyHandler{Handler: h.Handler.WithAttrs(attrs), attrs: h.attrs}
}

func (h legacyHandler) WithGroup(name string) slog.Handler {
	return legacyHandler{Handler: h.Handler.WithGroup(name), attrs: h.attrs}
}

func joinHostPort(host string, port int) string {
	if host == "" || port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// multiHandler forwards each record to every sink, so that the UDP and OTLP
// sinks can run side by side during a migration.
type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range m {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, handler := range m {
		if !handler.Enabled(ctx, record.Level) {
			continue
		}
		// Each handler may retain the record, so hand out a copy.
		if err := handler.Handle(ctx, record.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make(multiHandler, len(m))
	for i, handler := range m {
		next[i] = handler.WithAttrs(attrs)
	}
	return next
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	next := make(multiHandler, len(m))
	for i, handler := range m {
		next[i] = handler.WithGroup(name)
	}
	return next
}
