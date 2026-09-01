package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// udpSink listens for JSON log records on an ephemeral port.
func udpSink(t *testing.T) (string, chan map[string]any) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	records := make(chan map[string]any, 8)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var record map[string]any
			if json.Unmarshal(buf[:n], &record) == nil {
				select {
				case records <- record:
				default:
				}
			}
		}
	}()
	return conn.LocalAddr().String(), records
}

// logSessionRecord logs one session record the way the server does, through the
// standard slog interface.
// A test session's SSH transport comes up a second after the connection is
// accepted and its handshake concludes a second after that, so that the three
// moments a record carries are three distinct whole seconds and a value read
// from the wrong one is visible.
const (
	testTransportSetup = time.Second
	testHandshake      = time.Second
	// Long enough for the handshake above to have finished inside it.
	testSessionLength = 3 * time.Second
)

func logSessionRecord(logger *Logger, info connectionInfo, connect, disconnect time.Time) {
	logFailedSessionRecord(logger, info, nil, connect, disconnect)
}

func logFailedSessionRecord(logger *Logger, info connectionInfo, err error, connect, disconnect time.Time) {
	if info.HandshakeStart.IsZero() {
		info.HandshakeStart = connect.Add(testTransportSetup)
		info.HandshakeEnd = info.HandshakeStart.Add(testHandshake)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "SSH proxy session",
		logger.sessionAttributes(info, err, connect, disconnect)...)
}

// awaitEventRecord reads until a record of the named class arrives, so that a
// test can ignore what the server reports of itself around the session it drove.
func awaitEventRecord(t *testing.T, records chan map[string]any, event string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case record := <-records:
			if record["otel.event.name"] == event {
				return record
			}
		case <-deadline:
			t.Fatalf("no %s record arrived", event)
			return nil
		}
	}
}

func awaitRecord(t *testing.T, records chan map[string]any) map[string]any {
	t.Helper()
	select {
	case record := <-records:
		return record
	case <-time.After(5 * time.Second):
		t.Fatal("no log record arrived")
		return nil
	}
}

func shutdownLogger(t *testing.T, logger *Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	logger.Shutdown(ctx)
}

func TestLoggerDisabled(t *testing.T) {
	logger, err := makeLogger(LoggerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// Logging through a disabled logger must be safe and silent.
	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))
	shutdownLogger(t, logger)
}

func TestLoggerWithoutSink(t *testing.T) {
	if _, err := makeLogger(LoggerConfig{Enabled: true}); err == nil {
		t.Fatal("an enabled logger with no sink should fail to start")
	}
}

func TestLoggerUDPSink(t *testing.T) {
	address, records := udpSink(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled: true,
		UDP:     LoggerUDPConfig{Enabled: true, Address: address, Shape: LogRecordShapeECS},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownLogger(t, logger)

	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))
	record := awaitRecord(t, records)
	if record["message"] != "SSH proxy session" || record["user.name"] != "vlab" {
		t.Errorf("record = %v", record)
	}
}

// TestLoggerDeprecatedEndpoint checks that the pre-existing `logger.endpoint`
// spelling keeps working, and keeps writing the fields it always did.
func TestLoggerDeprecatedEndpoint(t *testing.T) {
	address, records := udpSink(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled:  true,
		Endpoint: "udp://" + address,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownLogger(t, logger)

	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))
	record := awaitRecord(t, records)
	if record["username"] != "vlab" || record["client_type"] != "SSH" {
		t.Errorf("record = %v, want the legacy fields", record)
	}
}

func TestLoggerUDPAddressErrors(t *testing.T) {
	cases := []struct {
		name   string
		config LoggerConfig
	}{
		{"both spellings", LoggerConfig{
			Enabled:  true,
			Endpoint: "udp://127.0.0.1:5556",
			UDP:      LoggerUDPConfig{Enabled: true, Address: "127.0.0.1:5556"},
		}},
		{"unsupported scheme", LoggerConfig{Enabled: true, Endpoint: "tcp://127.0.0.1:5556"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := loggerUDPAddress(tc.config); err == nil {
				t.Fatal("loggerUDPAddress() error = nil, want an error")
			}
		})
	}
}

func TestLoggerOTLPExport(t *testing.T) {
	server, requests := otlpTestCollector(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled: true,
		OTLP: OTLPConfig{
			Enabled:  true,
			Endpoint: server.URL + "/v1/logs",
			Headers:  []HTTPHeaderConfig{{Name: "Authorization", Value: "ApiKey 12345678"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))

	// Shutdown flushes the batch processor, so an export must have happened.
	shutdownLogger(t, logger)
	if path := awaitExport(t, requests).Path; path != "/v1/logs" {
		t.Fatalf("OTLP request path = %q, want %q", path, "/v1/logs")
	}
}

// TestLoggerBothSinks covers the migration case, where records have to reach
// the existing UDP collector and an OTLP one at the same time.
func TestLoggerBothSinks(t *testing.T) {
	address, records := udpSink(t)
	server, requests := otlpTestCollector(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled: true,
		UDP:     LoggerUDPConfig{Enabled: true, Address: address, Shape: LogRecordShapeECS},
		OTLP: OTLPConfig{
			Enabled: true, Endpoint: server.URL + "/v1/logs",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := logger.Handler().(multiHandler); !ok {
		t.Fatalf("handler = %T, want a multiHandler", logger.Handler())
	}

	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))
	if record := awaitRecord(t, records); record["user.name"] != "vlab" {
		t.Errorf("UDP record = %v", record)
	}
	shutdownLogger(t, logger)
	awaitExport(t, requests)
}

// TestOTLPRecordEnvelope checks what carries a record's time, level and message
// over OTLP. They are fields of the log data model rather than attributes, so
// no convention renames them and a collector reads them the same way whichever
// one is configured.
func TestOTLPRecordEnvelope(t *testing.T) {
	server, requests := otlpLogCollector(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled:    true,
		Convention: AttributeConventionECS,
		OTLP: OTLPConfig{
			Enabled:  true,
			Endpoint: server.URL + "/v1/logs",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	logSessionRecord(logger, testSession, time.Unix(1700000000, 0), time.Unix(1700000090, 0))
	shutdownLogger(t, logger)

	record := awaitLogRecord(t, requests)
	if body := record.GetBody().GetStringValue(); body != "SSH proxy session" {
		t.Errorf("body = %q, want the message", body)
	}
	if severity := record.GetSeverityNumber(); severity != logspb.SeverityNumber_SEVERITY_NUMBER_INFO {
		t.Errorf("severity number = %v, want INFO", severity)
	}
	if text := record.GetSeverityText(); text != "INFO" {
		t.Errorf("severity text = %q, want %q", text, "INFO")
	}
	if record.GetTimeUnixNano() == 0 {
		t.Error("the record carries no timestamp")
	}

	keys := map[string]bool{}
	for _, attr := range record.GetAttributes() {
		keys[attr.GetKey()] = true
	}
	// The envelope must not be duplicated into the attributes, under slog's
	// names for them or any other.
	for _, key := range []string{"time", "level", "msg", "@timestamp", "log.level", "message"} {
		if keys[key] {
			t.Errorf("%q is an attribute, want it carried by the record itself", key)
		}
	}
	// The bridge cannot reach the record's own EventName field, so the class of
	// event is carried as an attribute and promoted on the way to the exporter.
	if name := record.GetEventName(); name != "session.end" {
		t.Errorf("event name = %q, want the class promoted to the field", name)
	}
	if keys["otel.event.name"] {
		t.Errorf("otel.event.name is still an attribute; got %v", slices.Sorted(maps.Keys(keys)))
	}
	// The attributes, unlike the envelope, are the convention's to name.
	if !keys["network.protocol"] {
		t.Errorf(`no "network.protocol" attribute; got %v`, slices.Sorted(maps.Keys(keys)))
	}
}

// otlpLogCollector accepts OTLP/HTTP exports and keeps their decoded records.
func otlpLogCollector(t *testing.T) (*httptest.Server, chan *logspb.LogRecord) {
	t.Helper()
	records := make(chan *logspb.LogRecord, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var export collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &export); err != nil {
			return
		}
		for _, resource := range export.GetResourceLogs() {
			for _, scope := range resource.GetScopeLogs() {
				for _, record := range scope.GetLogRecords() {
					select {
					case records <- record:
					default:
					}
				}
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, records
}

func awaitLogRecord(t *testing.T, records chan *logspb.LogRecord) *logspb.LogRecord {
	t.Helper()
	select {
	case record := <-records:
		return record
	case <-time.After(5 * time.Second):
		t.Fatal("no OTLP log record arrived")
		return nil
	}
}

func TestMakeOTLPLogExporterErrors(t *testing.T) {
	cases := []struct {
		name   string
		config OTLPConfig
	}{
		{"bad scheme", OTLPConfig{Enabled: true, Endpoint: "udp://127.0.0.1:4318"}},
		{"unknown protocol", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4318", Protocol: "thrift"}},
		{"grpc with path", OTLPConfig{Enabled: true, Endpoint: "http://127.0.0.1:4317/v1/logs", Protocol: "grpc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := makeOTLPLogExporter(tc.config); err == nil {
				t.Fatal("makeOTLPLogExporter() error = nil, want an error")
			}
		})
	}
}

// TestLoggerOTLPProtocolFromEnvironment checks that the log exporter reads its
// own signal-specific variable rather than another signal's.
func TestLoggerOTLPProtocolFromEnvironment(t *testing.T) {
	t.Setenv(envOTLPMetricsProtocol, "grpc")
	protocol, err := otlpProtocol("", envOTLPLogsProtocol)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "http/protobuf" {
		t.Fatalf("log protocol = %q, want it unaffected by the metrics variable", protocol)
	}

	t.Setenv(envOTLPLogsProtocol, "grpc")
	if protocol, err = otlpProtocol("", envOTLPLogsProtocol); err != nil || protocol != "grpc" {
		t.Fatalf("log protocol = %q (%v), want grpc", protocol, err)
	}
}

// loggingServer starts a server whose session records go to the returned sink.
func loggingServer(t *testing.T) (*Server, chan map[string]any) {
	t.Helper()
	address, records := udpSink(t)
	sshmux, err := makeServer(Config{
		Address: "127.0.0.1:0",
		SSH:     SSHConfig{HostKeys: []SSHKeyConfig{{Path: "fixtures/ssh_host_ed25519_key"}}},
		Auth:    AuthConfig{Endpoint: "http://127.0.0.1:5000", Version: "v1"},
		Logger: LoggerConfig{
			Enabled: true,
			UDP:     LoggerUDPConfig{Enabled: true, Address: address, Shape: LogRecordShapeECS},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sshmux.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sshmux.Shutdown)
	return sshmux, records
}

// TestServerLogsNothingBeforeHandshake covers a connection that goes away
// before the SSH transport is up. `sshmux.connections` counts it, but there is
// no session to write a record about, and the sinks have never been sent one.
func TestServerLogsNothingBeforeHandshake(t *testing.T) {
	sshmux, records := loggingServer(t)

	conn, err := net.Dial("tcp", sshmux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// The server reports itself starting, which is not a session record.
	for {
		select {
		case record := <-records:
			if record["otel.event.name"] == "session.end" {
				t.Errorf("a record was written for a connection that never started a session: %v", record)
			}
			continue
		case <-time.After(time.Second):
		}
		return
	}
}

// TestServerLifecycleRecords covers what a server reports of itself, which is
// what tells a collector it is running at all: nothing else says so, and the
// records for the traffic through it cannot.
func TestServerLifecycleRecords(t *testing.T) {
	sshmux, records := loggingServer(t)

	started := awaitEventRecord(t, records, "sshmux.server.start")
	if started["message"] != "sshmux started" {
		t.Errorf("message = %v", started["message"])
	}
	if started["log.level"] != "INFO" {
		t.Errorf("log.level = %v, want a record like any other", started["log.level"])
	}
	// The address it was reached at, which is a port the configuration did not
	// name: the fixture asks for one and is given whichever was free. sshmux is
	// the server of this one, as the backend is of a session.
	if started["server.address"] != "127.0.0.1" {
		t.Errorf("server.address = %v", started["server.address"])
	}
	if port, ok := started["server.port"].(float64); !ok || port == 0 {
		t.Errorf("server.port = %v, want the port it listens on", started["server.port"])
	}

	sshmux.Shutdown()
	stopped := awaitEventRecord(t, records, "sshmux.server.stop")
	if stopped["message"] != "sshmux stopped" {
		t.Errorf("message = %v", stopped["message"])
	}
	// The listener is closed by the time this is reported, and still names the
	// address it was reached at while it was open.
	if stopped["server.address"] != started["server.address"] || stopped["server.port"] != started["server.port"] {
		t.Errorf("stopped at %v:%v, want the address it started on",
			stopped["server.address"], stopped["server.port"])
	}
	// Each names how long its own event took, not how long the service ran.
	for _, record := range []map[string]any{started, stopped} {
		if took, ok := record["event.duration"].(float64); !ok || took <= 0 {
			t.Errorf("event.duration = %v on %v, want what the event took",
				record["event.duration"], record["otel.event.name"])
		}
	}
}

// TestLogRecordServiceError covers what the service says about itself: an error
// it carried on from, named by the class the metrics classify one by and the
// text ECS names, at a level that says it is not a session.
func TestLogRecordServiceError(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	logger.LogAttrs(context.Background(), slog.LevelError,
		"sshmux could not accept a connection", logger.errorAttributes(os.ErrDeadlineExceeded)...)

	record := awaitRecord(t, records)
	if record["message"] != "sshmux could not accept a connection" {
		t.Errorf("message = %v", record["message"])
	}
	if record["log.level"] != "ERROR" {
		t.Errorf("log.level = %v, want an error", record["log.level"])
	}
	if record["error.type"] != "timeout" {
		t.Errorf("error.type = %v, want the class the metrics use", record["error.type"])
	}
	if record["exception.message"] != os.ErrDeadlineExceeded.Error() {
		t.Errorf("exception.message = %v", record["exception.message"])
	}
	// It is not a session, so it says nothing of one.
	for _, key := range []string{"otel.event.name", "session.id", "event.outcome"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want nothing of a session", key, value)
		}
	}
}

// TestServerLoggerWiring drives a connection past the SSH transport and checks
// the session record reaches the sink.
func TestServerLoggerWiring(t *testing.T) {
	sshmux, records := loggingServer(t)

	// The client authenticates as this user before the auth API refuses it.
	client, err := ssh.Dial("tcp", sshmux.Addr().String(), &ssh.ClientConfig{
		User:            "vlab",
		Auth:            []ssh.AuthMethod{ssh.Password("nope")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
	}

	started := awaitEventRecord(t, records, "session.start")
	if _, ok := started["user.name"]; ok {
		t.Errorf("user.name = %v, want nobody authenticated yet", started["user.name"])
	}
	if _, ok := started["session.id"].(string); !ok {
		t.Errorf("session.id = %v, want the session it identifies", started["session.id"])
	}

	record := awaitEventRecord(t, records, "session.end")
	if record["user.name"] != "vlab" {
		t.Errorf("user.name = %v, want the name the client offered", record["user.name"])
	}
	if protocol, _ := record["network.protocol.name"].(string); protocol != "ssh" {
		t.Errorf("network.protocol.name = %v", record["network.protocol.name"])
	}
	if start, _ := record["event.start"].(string); !strings.HasSuffix(start, "Z") {
		t.Errorf("event.start = %v, want it in UTC", record["event.start"])
	}
}

// testSession is the connection the record assertions are built from.
var testSession = connectionInfo{
	Username:              "vlab",
	UpstreamHost:          "10.0.0.7",
	UpstreamPort:          22,
	SessionID:             "c3NobXV4LXRlc3Qtc2Vzc2lvbg==",
	DownstreamAuthMethods: []string{"publickey", "keyboard-interactive"},
	UpstreamAuthMethods:   []string{"publickey"},
	UpstreamPeer:          &net.TCPAddr{IP: net.IPv4(192, 0, 2, 200), Port: 2222},
	ClientHost:            "192.0.2.10",
	ClientPort:            54321,
	ClientPeer:            &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000},
	ProtocolVersion:       "2.0",
	Established:           true,
}

// loggerWithShape returns a logger writing JSON documents of the given shape,
// with attributes named by the given convention, to a UDP sink.
func loggerWithShape(t *testing.T, convention AttributeConvention, shape LogRecordShape) (*Logger, chan map[string]any) {
	t.Helper()
	address, records := udpSink(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled:    true,
		Convention: convention,
		UDP:        LoggerUDPConfig{Enabled: true, Address: address, Shape: shape},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shutdownLogger(t, logger) })
	return logger, records
}

func logTestSession(t *testing.T, logger *Logger) {
	t.Helper()
	connect := time.Unix(1700000000, 0)
	logSessionRecord(logger, testSession, connect, connect.Add(90*time.Second))
}

func TestLogRecordDefaultConvention(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	want := map[string]any{
		"message":                   "SSH proxy session",
		"log.level":                 "INFO",
		"client.address":            "192.0.2.10",
		"client.port":               float64(54321),
		"server.address":            "10.0.0.7",
		"server.port":               float64(22),
		"user.name":                 "vlab",
		"sshmux.downstream.address": "198.51.100.7",
		"sshmux.downstream.port":    float64(40000),
		"sshmux.upstream.address":   "192.0.2.200",
		"sshmux.upstream.port":      float64(2222),
		"network.protocol.name":     "ssh",
		"network.protocol.version":  "2.0",
		"event.outcome":             "success",
		"event.kind":                "event",
		"event.duration":            float64(90 * time.Second),
	}
	for key, value := range want {
		if record[key] != value {
			t.Errorf("%s = %v, want %v", key, record[key], value)
		}
	}
	if value, ok := record["error.type"]; ok {
		t.Errorf("error.type = %v, want nothing to classify on a session that started", value)
	}
	// The handshake's own span sits inside the connection's, so the record
	// carries both ends of it rather than one.
	if record["sshmux.handshake.start"] != "2023-11-14T22:13:21Z" {
		t.Errorf("sshmux.handshake.start = %v", record["sshmux.handshake.start"])
	}
	if record["sshmux.handshake.end"] != "2023-11-14T22:13:22Z" {
		t.Errorf("sshmux.handshake.end = %v", record["sshmux.handshake.end"])
	}
	// ECS dates are UTC, whatever the host's zone.
	if record["event.start"] != "2023-11-14T22:13:20Z" {
		t.Errorf("event.start = %v, want it in UTC", record["event.start"])
	}
	if record["event.end"] != "2023-11-14T22:14:50Z" {
		t.Errorf("event.end = %v, want it in UTC", record["event.end"])
	}
}

// TestLogRecordECSConvention checks the two attributes ECS spells differently.
// It names the application protocol without the namespace the semantic
// conventions put it in, and has nothing for the version.
func TestLogRecordECSConvention(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionECS, LogRecordShapeECS)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	if record["network.protocol"] != "ssh" {
		t.Errorf("network.protocol = %v, want the ECS spelling", record["network.protocol"])
	}
	if record["event.action"] != "session.end" {
		t.Errorf("event.action = %v, want the ECS name for the class of event", record["event.action"])
	}
	if _, ok := record["otel.event.name"]; ok {
		t.Error("otel.event.name is written under the ECS convention")
	}
	if _, ok := record["network.protocol.name"]; ok {
		t.Error("network.protocol.name is written under the ECS convention")
	}
	if _, ok := record["network.protocol.version"]; ok {
		t.Error("network.protocol.version is written, which ECS does not name")
	}
	// Everything the two conventions share is left alone.
	for key, value := range map[string]any{
		"client.address": "192.0.2.10",
		"user.name":      "vlab",
		"event.outcome":  "success",
	} {
		if record[key] != value {
			t.Errorf("%s = %v, want %v", key, record[key], value)
		}
	}
}

func TestLogRecordLegacyShape(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	want := map[string]any{
		"msg": "SSH proxy session",
		// connect_time is when the SSH transport came up, which is what this
		// shape has always written, not when the connection was accepted.
		"connect_time":    float64(1700000001),
		"disconnect_time": float64(1700000090),
		// remote_ip is the client the PROXY protocol header claims, not the
		// hop it arrived through, which the shape has no name for.
		"remote_ip":   "192.0.2.10:54321",
		"client_type": "SSH",
		"username":    "vlab",
		// host_ip is the backend the auth API named, as remote_ip is the client
		// the header claims: both ends of this shape are the logical ones, and
		// the hop the connection really ends at is 192.0.2.200:2222.
		"host_ip":       "10.0.0.7:22",
		"authenticated": true,
		// The session an auth request can be joined to a record by.
		"session_id": "c3NobXV4LXRlc3Qtc2Vzc2lvbg==",
	}
	for key, value := range want {
		if record[key] != value {
			t.Errorf("%s = %v, want %v", key, record[key], value)
		}
	}
	// The schema's names must be gone, not merely supplemented.
	for _, key := range []string{"client.address", "server.address", "user.name", "event.outcome", "event.start", "session.id"} {
		if _, ok := record[key]; ok {
			t.Errorf("%s is still present in the legacy shape", key)
		}
	}
}

// TestLogRecordErrorType covers a session that never started, which the record
// classifies the same way the metrics classify it.
func TestLogRecordErrorType(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, connectionInfo{ClientHost: "192.0.2.10", ClientPort: 54321},
		os.ErrDeadlineExceeded, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if record["error.type"] != "timeout" {
		t.Errorf("error.type = %v, want the class the metrics record", record["error.type"])
	}
	if record["event.outcome"] != "failure" {
		t.Errorf("event.outcome = %v", record["event.outcome"])
	}
}

// TestLogRecordEstablishedWithError covers the one case where the two questions
// a record answers disagree: the session was established, so its outcome is a
// success, and something still went wrong, so the class of it is recorded.
func TestLogRecordEstablishedWithError(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, testSession, os.ErrDeadlineExceeded, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if record["event.outcome"] != "success" {
		t.Errorf("event.outcome = %v, want the session it established", record["event.outcome"])
	}
	if record["error.type"] != "timeout" {
		t.Errorf("error.type = %v, want what went wrong recorded alongside", record["error.type"])
	}
	// The legacy shape answers it the way it always has, which is whether
	// establishing the session returned an error, not whether one was reached.
	legacy, legacyRecords := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logFailedSessionRecord(legacy, testSession, os.ErrDeadlineExceeded, connect, connect.Add(testSessionLength))
	written := awaitRecord(t, legacyRecords)
	for _, key := range []string{"authenticated", "username", "host_ip"} {
		if value, ok := written[key]; ok {
			t.Errorf("%s = %v, want the shape to write it only where establishing succeeded", key, value)
		}
	}
	if written["remote_ip"] != "192.0.2.10:54321" {
		t.Errorf("remote_ip = %v, want the record still written", written["remote_ip"])
	}
}

// TestLegacyShapeIgnoresTheError checks that a class the shape never had stays
// out of it, as everything added to the record hereafter must.
func TestLegacyShapeIgnoresTheError(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, connectionInfo{ClientHost: "192.0.2.10", ClientPort: 54321},
		os.ErrDeadlineExceeded, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if value, ok := record["error.type"]; ok {
		t.Errorf("error.type = %v, want it left out of a frozen shape", value)
	}
	if record["remote_ip"] != "192.0.2.10:54321" {
		t.Errorf("remote_ip = %v, want the record still written", record["remote_ip"])
	}
}

// TestLegacyShapeBracketsTheTransport checks which of the times the shape
// writes: it has always started where the SSH transport came up, where the
// record starts at the connection that carried it being accepted.
func TestLegacyShapeBracketsTheTransport(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	if record["connect_time"] != float64(1700000001) {
		t.Errorf("connect_time = %v, want the transport coming up", record["connect_time"])
	}
	// The accept time is on the record under the schema's name for it, and is
	// not what this field has ever held.
	if record["connect_time"] == float64(1700000000) {
		t.Error("connect_time is the time the connection was accepted")
	}
}

// TestLogRecordSessionStart covers the event a session reports when its SSH
// transport comes up: it identifies the session and names what is known of the
// connection by then, which is neither a user nor a backend.
func TestLogRecordSessionStart(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	start := time.Unix(1700000000, 0)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "SSH proxy session started",
		logger.sessionStartAttributes(connectionInfo{
			SessionID:       "c3NobXV4LXRlc3Qtc2Vzc2lvbg==",
			ClientHost:      "192.0.2.10",
			ClientPort:      54321,
			ClientPeer:      &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000},
			ProtocolVersion: "2.0",
		}, start)...)

	record := awaitRecord(t, records)
	want := map[string]any{
		"otel.event.name":           "session.start",
		"session.id":                "c3NobXV4LXRlc3Qtc2Vzc2lvbg==",
		"event.start":               "2023-11-14T22:13:20Z",
		"event.kind":                "event",
		"network.protocol.name":     "ssh",
		"network.protocol.version":  "2.0",
		"client.address":            "192.0.2.10",
		"sshmux.downstream.address": "198.51.100.7",
	}
	for key, value := range want {
		if record[key] != value {
			t.Errorf("%s = %v, want %v", key, record[key], value)
		}
	}
	// Nothing is known of either yet, and the session has not ended.
	for _, key := range []string{"user.name", "server.address", "event.end", "event.duration", "event.outcome"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want it unknown when a session begins", key, value)
		}
	}
}

// TestLegacyShapeWritesOnlyTheSessionEnd checks that the shape keeps to the one
// event it has a document for, rather than writing every event as a session.
func TestLegacyShapeWritesOnlyTheSessionEnd(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	start := time.Unix(1700000000, 0)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "SSH proxy session started",
		logger.sessionStartAttributes(testSession, start)...)

	record := awaitRecord(t, records)
	if record["msg"] != "SSH proxy session started" {
		t.Errorf("msg = %v, want the record still written", record["msg"])
	}
	for _, key := range []string{"session_id", "connect_time", "remote_ip", "client_type", "host_ip"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want no session document for an event that is not one", key, value)
		}
	}
}

// TestServiceErrorsReachTheConsole covers the console keeping what the service
// has to say about itself, whether a sink is configured or not, where a session
// that ran to its end is left to the sinks by the level.
func TestServiceErrorsReachTheConsole(t *testing.T) {
	var console strings.Builder
	logger, err := makeLoggerWithBase(LoggerConfig{},
		slog.New(slog.NewTextHandler(&console, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAttrs(context.Background(), slog.LevelError,
		"sshmux could not accept a connection", logger.errorAttributes(os.ErrDeadlineExceeded)...)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "SSH proxy session",
		logger.sessionAttributes(testSession, nil, time.Unix(1700000000, 0), time.Unix(1700000001, 0))...)

	written := console.String()
	if !strings.Contains(written, "sshmux could not accept a connection") {
		t.Errorf("console = %q, want the error it carried on from", written)
	}
	if !strings.Contains(written, "error.type=timeout") {
		t.Errorf("console = %q, want the class the metrics use", written)
	}
	if strings.Contains(written, "SSH proxy session") {
		t.Errorf("console = %q, want a session left to the sinks", written)
	}
}

// TestLogRecordAuthenticated covers what authenticated each side of a session,
// which one exchange cannot say: a key accepted before challenges is one method
// and the challenges another, and sshmux authenticates to the backend besides.
func TestLogRecordAuthenticated(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	downstream, _ := record["sshmux.downstream.auth.methods"].([]any)
	if len(downstream) != 2 || downstream[0] != "publickey" || downstream[1] != "keyboard-interactive" {
		t.Errorf("downstream = %v, want both, in the order they authenticated", record["sshmux.downstream.auth.methods"])
	}
	upstream, _ := record["sshmux.upstream.auth.methods"].([]any)
	if len(upstream) != 1 || upstream[0] != "publickey" {
		t.Errorf("upstream = %v, want the key sshmux was given", record["sshmux.upstream.auth.methods"])
	}
	// What each was answered with belongs to the request that answered it.
	if value, ok := record["sshmux.auth.status"]; ok {
		t.Errorf("sshmux.auth.status = %v, want it left to the request it answered", value)
	}
}

// TestLogRecordAuthenticatedByNothing covers a session that authenticated on
// neither side, which names no method rather than naming what it tried.
func TestLogRecordAuthenticatedByNothing(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, connectionInfo{ClientHost: "192.0.2.10", ClientPort: 54321},
		io.EOF, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	for _, key := range []string{"sshmux.downstream.auth.methods", "sshmux.upstream.auth.methods"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want nothing where nothing authenticated", key, value)
		}
	}
}

// TestLogRecordUpstreamRole covers the label the auth API put on an upstream,
// which the record carries because the API said it and no address reveals it,
// and which a session it labelled none on leaves out.
func TestLogRecordUpstreamRole(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	recovering := testSession
	recovering.UpstreamRole = "recovery"
	connect := time.Unix(1700000000, 0)
	logSessionRecord(logger, recovering, connect, connect.Add(testSessionLength))

	if record := awaitRecord(t, records); record["sshmux.upstream.role"] != "recovery" {
		t.Errorf("sshmux.upstream.role = %v, want what the API answered", record["sshmux.upstream.role"])
	}

	logSessionRecord(logger, testSession, connect, connect.Add(testSessionLength))
	if record := awaitRecord(t, records); record["sshmux.upstream.role"] != nil {
		t.Errorf("sshmux.upstream.role = %v, want nothing where the API named none", record["sshmux.upstream.role"])
	}
}

// TestLogRecordUpstreamUsername covers the account a session reached, which is
// the client's own unless the auth API chose another and is named either way.
func TestLogRecordUpstreamUsername(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	chosen := testSession
	chosen.UpstreamUsername = "ubuntu"
	connect := time.Unix(1700000000, 0)
	logSessionRecord(logger, chosen, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if record["sshmux.upstream.username"] != "ubuntu" {
		t.Errorf("sshmux.upstream.username = %v, want the account the API chose", record["sshmux.upstream.username"])
	}
	if record["user.name"] != "vlab" {
		t.Errorf("user.name = %v, want the user who connected", record["user.name"])
	}
}

// TestLogRecordEndedBy covers which of a session's two connections ended it,
// the ordinary answer being the client and the interesting one the backend
// going away under an established session.
func TestLogRecordEndedBy(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	connect := time.Unix(1700000000, 0)

	dropped := testSession
	dropped.EndedBy = "upstream"
	logSessionRecord(logger, dropped, connect, connect.Add(testSessionLength))
	record := awaitRecord(t, records)
	if record["event.reason"] != "upstream" {
		t.Errorf("event.reason = %v, want the backend that went away", record["event.reason"])
	}
	// It ended as an established session all the same: how one ends is not
	// whether it happened.
	if record["event.outcome"] != "success" {
		t.Errorf("event.outcome = %v, want the session it was", record["event.outcome"])
	}

	// A session sshmux closed itself, as it does for every one still running
	// when it shuts down, is neither peer's doing.
	stopped := testSession
	stopped.EndedBy = "proxy"
	logSessionRecord(logger, stopped, connect, connect.Add(testSessionLength))
	if record := awaitRecord(t, records); record["event.reason"] != "proxy" {
		t.Errorf("event.reason = %v, want sshmux itself", record["event.reason"])
	}

	// A session that never reached the pipe has no answer to give.
	logSessionRecord(logger, testSession, connect, connect.Add(testSessionLength))
	if record := awaitRecord(t, records); record["event.reason"] != nil {
		t.Errorf("event.reason = %v, want nothing where no session was piped", record["event.reason"])
	}
}

// TestLegacyShapeIgnoresTheSockets checks that the addresses sshmux is really
// connected to and from reach the schema's sinks without reaching this one,
// whose fields are fixed.
func TestLegacyShapeIgnoresTheSockets(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	for _, key := range []string{
		"sshmux.downstream.address", "sshmux.downstream.port",
		"sshmux.upstream.address", "sshmux.upstream.port",
		"otel.event.name", "eventName",
	} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want a shape that never had it to leave it out", key, value)
		}
	}
	if record["remote_ip"] != "192.0.2.10:54321" {
		t.Errorf("remote_ip = %v, want the client the header claims", record["remote_ip"])
	}
	if record["host_ip"] != "10.0.0.7:22" {
		t.Errorf("host_ip = %v, want the backend the auth API named", record["host_ip"])
	}
}

// TestLogRecordUnestablished checks the record a connection that never
// authenticated produces: an outcome, but no user or server.
func TestLogRecordUnestablished(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, connectionInfo{ClientHost: "192.0.2.10", ClientPort: 54321},
		io.EOF, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if record["event.outcome"] != "failure" {
		t.Errorf("event.outcome = %v, want failure", record["event.outcome"])
	}
	if record["client.address"] != "192.0.2.10" {
		t.Errorf("client.address = %v", record["client.address"])
	}
	for _, key := range []string{"user.name", "server.address", "server.port"} {
		if _, ok := record[key]; ok {
			t.Errorf("%s is present for a session that never started", key)
		}
	}
}

// TestLegacyShapeUnestablished checks the legacy record of a connection
// that never started, which the old code never wrote at all.
func TestLegacyShapeUnestablished(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	connect := time.Unix(1700000000, 0)
	logFailedSessionRecord(logger, connectionInfo{ClientHost: "192.0.2.10", ClientPort: 54321},
		io.EOF, connect, connect.Add(testSessionLength))

	record := awaitRecord(t, records)
	if record["remote_ip"] != "192.0.2.10:54321" {
		t.Errorf("remote_ip = %v", record["remote_ip"])
	}
	for _, key := range []string{"username", "host_ip", "authenticated"} {
		if _, ok := record[key]; ok {
			t.Errorf("%s is present for a session that never started", key)
		}
	}
}

// TestLegacyShapeIsFrozen checks that the shape takes no field it was not
// defined with: an attribute it has no name for is left out rather than
// carried through, and a record that is not a session is given none of a
// session's fields.
func TestLegacyShapeIsFrozen(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "listening",
		slog.String("address", "0.0.0.0:8022"))

	record := awaitRecord(t, records)
	// The shape gains no field, so an attribute it has no name for is left out
	// rather than carried through.
	if value, ok := record["address"]; ok {
		t.Errorf("address = %v, want a field the shape never had left out", value)
	}
	// Nor is the session shape invented for a record that has none of it,
	// which would date it to the zero time.
	for _, key := range []string{"connect_time", "disconnect_time", "remote_ip", "client_type"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want no session shape on a record that is not one", key, value)
		}
	}
	if record["msg"] != "listening" {
		t.Errorf("msg = %v, want the message to survive", record["msg"])
	}
}

func TestLegacyWritesOnlyTheFieldsPresent(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeLegacy)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "SSH proxy session",
		slog.String("otel.event.name", "session.end"),
		slog.String("client.address", "192.0.2.10"),
		slog.String("event.outcome", "failure"))

	record := awaitRecord(t, records)
	if record["remote_ip"] != "192.0.2.10" {
		t.Errorf("remote_ip = %v", record["remote_ip"])
	}
	if record["client_type"] != "SSH" {
		t.Errorf("client_type = %v, want the record read as a session", record["client_type"])
	}
	for _, key := range []string{"connect_time", "disconnect_time"} {
		if value, ok := record[key]; ok {
			t.Errorf("%s = %v, want it left out when the record has no such time", key, value)
		}
	}
}

func TestLoggerShape(t *testing.T) {
	cases := []struct {
		name       string
		configured LogRecordShape
		deprecated bool
		want       LogRecordShape
	}{
		{"what is configured", LogRecordShapeOTel, false, LogRecordShapeOTel},
		{"ECS where none is configured", "", false, LogRecordShapeECS},
		{"legacy for the deprecated endpoint", "", true, LogRecordShapeLegacy},
		{"configured over the deprecated endpoint", LogRecordShapeECS, true, LogRecordShapeECS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loggerShape(tc.configured, tc.deprecated); got != tc.want {
				t.Fatalf("loggerShape() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLogRecordShapeParsing(t *testing.T) {
	for _, name := range []string{"", "otel", "ecs", "legacy"} {
		var shape LogRecordShape
		if err := shape.UnmarshalText([]byte(name)); err != nil {
			t.Errorf("UnmarshalText(%q) = %v", name, err)
		}
	}
	var shape LogRecordShape
	if err := shape.UnmarshalText([]byte("syslog")); err == nil {
		t.Error("an unknown shape should be rejected")
	}
	// A shape is not a convention: the one the signals share never named a
	// document, and must not start now.
	var convention AttributeConvention
	if err := convention.UnmarshalText([]byte("legacy")); err == nil {
		t.Error("the convention must not accept a shape's name")
	}
}

// TestOTelShape checks the document the OpenTelemetry Logs Data Model names,
// which nests the record under a resource and a scope, wraps each value in the
// name of its type, and writes 64-bit integers as strings.
func TestOTelShape(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeOTel)
	logTestSession(t, logger)

	entry, attrs, resource := readOTelDocument(t, awaitRecord(t, records))

	if attrs["session.id"]["stringValue"] != "c3NobXV4LXRlc3Qtc2Vzc2lvbg==" {
		t.Errorf("session.id = %v, want the identity the event requires", attrs["session.id"])
	}
	if entry["eventName"] != "session.end" {
		t.Errorf("eventName = %v, want the class of event the record is", entry["eventName"])
	}
	if _, ok := attrs["otel.event.name"]; ok {
		t.Error("otel.event.name is an attribute, which is for documents without the field")
	}
	if body, _ := entry["body"].(map[string]any); body["stringValue"] != "SSH proxy session" {
		t.Errorf("body = %v, want the message wrapped as a string", entry["body"])
	}
	if entry["severityText"] != "INFO" {
		t.Errorf("severityText = %v", entry["severityText"])
	}
	if entry["severityNumber"] != float64(9) {
		t.Errorf("severityNumber = %v, want INFO", entry["severityNumber"])
	}
	if _, ok := entry["timeUnixNano"].(string); !ok {
		t.Errorf("timeUnixNano = %v, want nanoseconds as a string", entry["timeUnixNano"])
	}
	// slog's own spellings belong to no shape, and the record's fields are not
	// attributes here either.
	for _, key := range []string{"time", "level", "msg", "@timestamp", "message"} {
		if _, ok := entry[key]; ok {
			t.Errorf("%s is a field of the record, which the model does not have", key)
		}
	}

	if attrs["network.protocol.name"]["stringValue"] != "ssh" {
		t.Errorf("network.protocol.name = %v", attrs["network.protocol.name"])
	}
	// A 64-bit integer is a string, and a time is one of nanoseconds, as the
	// OTLP bridge renders them.
	if attrs["client.port"]["intValue"] != "54321" {
		t.Errorf("client.port = %v, want an integer written as a string", attrs["client.port"])
	}
	if attrs["event.start"]["intValue"] != "1700000000000000000" {
		t.Errorf("event.start = %v, want nanoseconds since the epoch", attrs["event.start"])
	}
	// A list is wrapped rather than written as a bare JSON array.
	values, _ := attrs["event.type"]["arrayValue"].(map[string]any)
	if list, _ := values["values"].([]any); len(list) != 2 {
		t.Errorf("event.type = %v, want the two ECS categories", attrs["event.type"])
	}

	// The resource the OTLP sink exports is carried here too, the shape having
	// somewhere to put it.
	if resource["service.name"]["stringValue"] != "sshmux" {
		t.Errorf("service.name = %v", resource["service.name"])
	}
}

// readOTelDocument unwraps the one record a datagram holds, returning its own
// fields, its attributes and the resource's, each keyed by name.
func readOTelDocument(t *testing.T, document map[string]any) (entry map[string]any, attrs, resource map[string]map[string]any) {
	t.Helper()
	resourceLogs, _ := document["resourceLogs"].([]any)
	if len(resourceLogs) != 1 {
		t.Fatalf("%d resourceLogs, want 1: %v", len(resourceLogs), document)
	}
	first, _ := resourceLogs[0].(map[string]any)
	res, _ := first["resource"].(map[string]any)
	scopeLogs, _ := first["scopeLogs"].([]any)
	if len(scopeLogs) != 1 {
		t.Fatalf("%d scopeLogs, want 1: %v", len(scopeLogs), document)
	}
	scope, _ := scopeLogs[0].(map[string]any)
	if name, _ := scope["scope"].(map[string]any); name["name"] != otelScopeName {
		t.Errorf("scope = %v, want the instrumentation scope", scope["scope"])
	}
	logRecords, _ := scope["logRecords"].([]any)
	if len(logRecords) != 1 {
		t.Fatalf("%d logRecords, want 1: %v", len(logRecords), document)
	}
	entry, _ = logRecords[0].(map[string]any)
	return entry, otelKeyValues(entry["attributes"]), otelKeyValues(res["attributes"])
}

func otelKeyValues(list any) map[string]map[string]any {
	pairs, _ := list.([]any)
	out := make(map[string]map[string]any, len(pairs))
	for _, pair := range pairs {
		attr, _ := pair.(map[string]any)
		key, _ := attr["key"].(string)
		value, _ := attr["value"].(map[string]any)
		out[key] = value
	}
	return out
}

// TestOTelShapePromotesEitherConventionsName checks that the class of event
// reaches the document's own field whichever attribute the convention carried
// it in, since the field is the document's and the attribute is the
// convention's.
func TestOTelShapePromotesEitherConventionsName(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionECS, LogRecordShapeOTel)
	logTestSession(t, logger)

	entry, attrs, _ := readOTelDocument(t, awaitRecord(t, records))
	if entry["eventName"] != "session.end" {
		t.Errorf("eventName = %v, want the class promoted out of event.action", entry["eventName"])
	}
	for _, key := range []string{"event.action", "otel.event.name"} {
		if _, ok := attrs[key]; ok {
			t.Errorf("%s is an attribute, which is for documents without the field", key)
		}
	}
}

// TestECSShapeKeepsTheConvention checks that a shape names the document and
// the convention names the attributes, without either deciding the other.
func TestECSShapeKeepsTheConvention(t *testing.T) {
	logger, records := loggerWithShape(t, AttributeConventionDefault, LogRecordShapeECS)
	logTestSession(t, logger)

	record := awaitRecord(t, records)
	if _, ok := record["@timestamp"].(string); !ok {
		t.Errorf("@timestamp = %v, want the ECS spelling", record["@timestamp"])
	}
	// The document is ECS while the attributes stay under the conventions the
	// logger was configured with.
	if record["network.protocol.name"] != "ssh" {
		t.Errorf("network.protocol.name = %v, want the convention to still name it", record["network.protocol.name"])
	}
	// This document has no field for the event's class, which is what the
	// attribute is for.
	if record["otel.event.name"] != "session.end" {
		t.Errorf("otel.event.name = %v, want the class carried as an attribute", record["otel.event.name"])
	}
}

// TestOTelShapeFollowsTheHandlerRules covers the rules slog.Handler asks a
// handler to observe, which this one writes the document itself rather than
// inheriting from slog's own.
func TestOTelShapeFollowsTheHandlerRules(t *testing.T) {
	address, records := udpSink(t)
	logger, err := makeLogger(LoggerConfig{
		Enabled: true,
		UDP:     LoggerUDPConfig{Enabled: true, Address: address, Shape: LogRecordShapeOTel},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Shutdown(context.Background()) })

	logger.LogAttrs(context.Background(), slog.LevelInfo, "rules",
		slog.Attr{},
		slog.Group("named", slog.String("inside", "yes")),
		slog.Group("", slog.String("inlined", "yes")),
		slog.Group("empty"),
	)

	_, attrs, _ := readOTelDocument(t, awaitRecord(t, records))
	if _, ok := attrs["named.inside"]; !ok {
		t.Errorf("a named group was not written under its name; got %v", attrs)
	}
	if _, ok := attrs["inlined"]; !ok {
		t.Errorf("a group with no name was not inlined; got %v", attrs)
	}
	for _, key := range []string{"", ".inlined", "empty"} {
		if _, ok := attrs[key]; ok {
			t.Errorf("%q was written, want it dropped; got %v", key, attrs)
		}
	}
}

// TestUDPSinkLevelIsTheSameWhateverTheShape checks that what a sink records is
// the shape's business only as far as the document goes, since one of them
// writes the document rather than inheriting it.
func TestUDPSinkLevelIsTheSameWhateverTheShape(t *testing.T) {
	for _, shape := range []LogRecordShape{LogRecordShapeOTel, LogRecordShapeECS, LogRecordShapeLegacy} {
		t.Run(string(shape), func(t *testing.T) {
			address, records := udpSink(t)
			logger, err := makeLogger(LoggerConfig{
				Enabled: true,
				UDP:     LoggerUDPConfig{Enabled: true, Address: address, Shape: shape},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { logger.Shutdown(context.Background()) })

			logger.LogAttrs(context.Background(), slog.LevelDebug, "below the level")
			logger.LogAttrs(context.Background(), slog.LevelInfo, "at the level")

			if message := recordMessage(t, shape, awaitRecord(t, records)); message != "at the level" {
				t.Errorf("the first record written says %q, want the one at Info", message)
			}
		})
	}
}

// recordMessage reads the message out of a record, from wherever its shape
// writes it.
func recordMessage(t *testing.T, shape LogRecordShape, record map[string]any) string {
	t.Helper()
	switch shape {
	case LogRecordShapeOTel:
		entry, _, _ := readOTelDocument(t, record)
		body, _ := entry["body"].(map[string]any)
		message, _ := body["stringValue"].(string)
		return message
	case LogRecordShapeECS:
		message, _ := record["message"].(string)
		return message
	default:
		message, _ := record["msg"].(string)
		return message
	}
}
