# sshmux

`sshmux` is a new, simple implementation of SSH reverse proxy. `sshmux` was initially developed for Vlab, while we'd like to expand its usage to cover more scenarios.

## Build, Run and Test

`sshmux` requires a Go 1.25+ toolchain to build. You can use `go build` or `make` to get the `sshmux` binary directly in the directory.

You can run the built binary with `./sshmux`. Note that you'll need to provide a valid configuration file as described [here](#config).

You can perform unit tests with `go test` or `make test`. Enable verbose logging with `go test -v`.

## Config

`sshmux` requires a TOML configuration file to start up. By default it will look at `/etc/sshmux/config.toml`, but you can also specify a custom configuration by passing `-c path/to/config.toml` in the command line arguments. An [example](etc/config.example.toml) file is provided.

The sections below will introduce available options for `sshmux`:

### General Settings

General settings configure the `sshmux` service. They are top-level settings in the TOML file.

| Key       | Type     | Description                                     | Required | Example          |
| --------- | -------- | ----------------------------------------------- | -------- | ---------------- |
| `address` | `string` | TCP host and port that `sshmux` will listen on. | Yes      | `"0.0.0.0:8022"` |

### SSH Settings

SSH settings configure the integrated SSH server in `sshmux`. They are grouped under `ssh` in the TOML file.

| Key                         | Type       | Description                                                                          | Required | Example                                            |
| --------------------------- | ---------- | ------------------------------------------------------------------------------------ | -------- | -------------------------------------------------- |
| `banner`                    | `string`   | SSH banner to send to downstream.                                                    | No       | `"Welcome to Vlab\n"`                              |
| `host-keys`                 | `[]SSHKey` | Paths to SSH host key files with which `sshmux` identifies itself.                   | Yes      | See [`fixtures/config.toml`](fixtures/config.toml) |
| `handshake-timeout-seconds` | `uint`     | Deadline for the complete downstream SSH handshake and authentication. Defaults to 30 seconds. | No | `30`                                           |
| `upstream-timeout-seconds`  | `uint`     | Deadline for connecting to and authenticating with the upstream SSH server. Defaults to 30 seconds. | No | `30`                                      |

### Auth Settings

Auth settings configures the authentication and authorization API used by `sshmux`. They are grouped under `auth` in the TOML file.

| Key               | Type           | Description                                                               | Required | Example                                            |
| ----------------- | -------------- | ------------------------------------------------------------------------- | -------- | -------------------------------------------------- |
| `endpoint`        | `string`       | Endpoint URL that `sshmux` will use for authentication and authorization. | Yes      | `"http://127.0.0.1:5000/ssh"`                      |
| `version`         | `string`       | Auth endpoint API version (`"legacy"`, `"v1"`). Defaults to `"legacy"`.   | No       | `"v1"`                                             |
| `headers`         | `[]HTTPHeader` | Extra HTTP headers to send to API server.                                 | No       | See [`fixtures/config.toml`](fixtures/config.toml) |
| `timeout-seconds` | `uint`         | Timeout for a complete authentication API request. Defaults to 30 seconds. | No      | `30`                                               |

#### Legacy Auth Settings

The following settings are only used by `legacy` auth APIs. They are also grouped under `auth` in the TOML file.

| Key                        | Type       | Description                                                 | Required                        | Example                      |
| -------------------------- | ---------- | ----------------------------------------------------------- | ------------------------------- | ---------------------------- |
| `token`                    | `string`   | Token used to authenticate with the API endpoint.           | If `auth.version` is `"legacy"` | `"long-and-random-token"`    |
| `all-username-nopassword`  | `bool`     | If set to `true`, no users will be asked for UNIX password. | No                              | `true`                       |
| `usernames-nopassword`     | `[]string` | Usernames that won't be asked for UNIX password.            | No                              | `["vlab", "ubuntu", "root"]` |
| `invalid-usernames`        | `[]string` | Usernames that are known to be invalid.                     | No                              | `["user"]`                   |
| `invalid-username-message` | `string`   | Message to display when the requested username is invalid.  | No                              | `"Invalid username %s."`     |

#### Recovery Settings

Recovery settings configures Vlab recovery service support of `sshmux` for `legacy` auth APIs. They are grouped under `recovery` in the TOML file.

| Key         | Type       | Description                                           | Required | Example                   |
| ----------- | ---------- | ----------------------------------------------------- | -------- | ------------------------- |
| `address`   | `string`   | SSH host and port of the recovery server.             | No       | `"172.30.0.101:2222"`     |
| `usernames` | `[]string` | Usernames dedicated to the recovery server.           | No       | `["recovery", "console"]` |
| `token`     | `string`   | Token used to authenticate with the recovery backend. | No       | `"long-and-random-token"` |

### Logger Settings

Logger settings configure the session logging of `sshmux`, which is described under [Logs](#logs). They are grouped under `logger` in the TOML file. At least one of `logger.udp` and `logger.otlp` must be enabled when `logger.enabled` is `true`.

| Key            | Type                  | Description                                                                                | Required | Example                              |
| -------------- | --------------------- | ------------------------------------------------------------------------------------------ | -------- | ------------------------------------ |
| `enabled`      | `bool`                | Whether the logger is enabled. Defaults to `false`.                                        | No       | `true`                               |
| `convention`   | `string`              | Schema the attributes are named after, `"default"` or `"ecs"`. Defaults to `"default"`. See [Attribute Conventions](#attribute-conventions). | No | `"ecs"` |
| `service-name` | `string`              | Value of the `service.name` resource attribute. Defaults to `"sshmux"`.                    | No       | `"sshmux-vlab"`                      |
| `attributes`   | `[]ResourceAttribute` | Extra resource attributes attached to every record.                                        | No       | `[{ name = "env", value = "prod" }]` |

`service-name` and `attributes` fall back to `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`, and describe the resource. The OTLP sink always carries it, and over UDP only the `otel` shape has anywhere to put it.

The convention names the attributes for both sinks alike. What differs between them is the document those attributes are written into, which OTLP defines for itself and `logger.udp.shape` decides for a datagram, so a collector that parses the existing fields can keep receiving them while an OTLP one is given the schema.

> [!NOTE]
> `logger.endpoint` is deprecated in favour of `logger.udp`. A `udp://host:port` URL still works and is equivalent to setting `logger.udp.address`, but the two cannot be combined. A configuration still using it defaults that sink to the `legacy` shape, so its collector keeps receiving the document it already parses.

#### Logger UDP Settings

The UDP sink writes one JSON document per datagram. It is configured under `logger.udp` in the TOML file.

| Key       | Type     | Description                                                            | Required | Example            |
| --------- | -------- | ---------------------------------------------------------------------- | -------- | ------------------ |
| `enabled` | `bool`   | Whether the UDP sink is enabled. Defaults to `false`.                  | No       | `true`             |
| `address` | `string` | UDP host and port to send records to. Defaults to `"127.0.0.1:5556"`.  | No       | `"127.0.0.1:5556"` |
| `shape`   | `string` | Document each datagram is written as, `"ecs"`, `"otel"` or `"legacy"`. Defaults to `"ecs"`, or to `"legacy"` where `logger.endpoint` is set. | No | `"otel"` |

A shape decides what a transport does not define for itself: the document a datagram holds, and what the record's own time, level and message are called inside it. The attributes are named by `logger.convention` whichever document holds them, so the two never contend.

| Shape    | Time                          | Level                               | Message   | Defined by                                                                              |
| -------- | ----------------------------- | ----------------------------------- | --------- | --------------------------------------------------------------------------------------- |
| `ecs`    | `@timestamp`, ISO 8601 in UTC | `log.level`                         | `message` | the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)     |
| `otel`   | `timeUnixNano`                | `severityNumber` and `severityText` | `body`    | the [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model) |
| `legacy` | `time`                        | `level`                             | `msg`     | [sshmux's `legacy` shape](#the-legacy-shape)                                            |

`otel` writes the JSON serialization of the data model, as the [file exporter](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/#examples) writes it, so a datagram carries what an OTLP export of the same record would. Each holds one record, and the fields with nothing to say are left out of it: the dropped-attribute counts, the observed timestamp, the trace flags, and the schema URLs. It is also the only shape with somewhere to put the resource, so the only one `logger.service-name` and `logger.attributes` reach over UDP; the other two write one flat object per datagram.

> [!IMPORTANT]
> **`otel` is a shape for keeping the OpenTelemetry data model, rarely for reporting logs.** The record nests under a resource and a scope, every value is wrapped in the name of its type, and the resource repeats on each datagram where a file of them would amortize it. That makes it roughly two and a half times the size of the same record in `ecs`, past the payload a standard Ethernet frame carries, so each datagram is fragmented across two IP packets and losing either loses the record.
>
> It costs nothing over the loopback address the sink defaults to, where the MTU is far larger. Sending it across a network is better done by pointing the sink at a shipper on the same host and letting that forward — or by `logger.otlp`, which is what carrying these records over a network is for.

A shape names the document alone, so `shape = "ecs"` under the default `convention` produces one that is ECS where a pipeline reads it — `@timestamp`, `log.level` and `message` — while the attributes inside keep their semantic convention names, which such a pipeline has no mappings for and stores as custom fields. Set `logger.convention` to `"ecs"` alongside it where the tooling expects a document that is ECS throughout.

##### The `legacy` Shape

`sshmux` wrote a shape of its own before it followed a schema, which `logger.udp.shape` still writes as `legacy`. It is a different document rather than a different spelling of one: the values change along with the names, and two attributes are joined into each address.

| Attribute                             | `legacy`                                                    |
| ------------------------------------- | ----------------------------------------------------------- |
| `session.id`                          | `session_id`                                                |
| `client.address`, `client.port`       | `remote_ip`, as `host:port`                                 |
| `server.address`, `server.port`       | `host_ip`, as `host:port`                                   |
| `user.name`                           | `username`                                                  |
| `network.protocol.name`               | `client_type`, always `SSH`                                 |
| `sshmux.handshake.start`, `event.end` | `connect_time`, `disconnect_time`, as Unix seconds          |
| `event.outcome`, `error.type`         | `authenticated`, and absent where establishing returned an error |

Both of its addresses are the logical ends: `remote_ip` is the client the [PROXY protocol](#proxy-protocol-settings) header claims, and `host_ip` the backend the auth API named. Where a hop sits on either side, the address the connection really ends at is `sshmux.downstream.*` or `sshmux.upstream.*`, which this shape has no name for.

This shape is frozen. It gains no field beyond the table above, whatever else a record comes to carry, so that the consumers written against it keep reading exactly what they always have. A field it has no name for is left out, and a record other than `session.end`, the only event `sshmux` had when this was its only shape, is written without the shape at all.

#### Logger OTLP Settings

The OTLP exporter for logs is configured under `logger.otlp`, whose keys are described in [OTLP Settings](#otlp-settings). Records are exported to the `/v1/logs` path, and read `OTEL_EXPORTER_OTLP_LOGS_*` for the settings left out of the file.

### Metrics Settings

Metrics settings configure the [OpenTelemetry](https://opentelemetry.io) metrics of `sshmux`, which are described under [Metrics](#metrics). They are grouped under `metrics` in the TOML file. At least one of `metrics.otlp` and `metrics.prometheus` must be enabled when `metrics.enabled` is `true`.

| Key                | Type          | Description                                                                                                   | Required | Example                              |
| ------------------ | ------------- | ------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------ |
| `enabled`          | `bool`        | Whether metrics collection is enabled. Defaults to `false`.                                                   | No       | `true`                               |
| `convention`       | `string`      | Schema the attributes are named after, `"default"` or `"ecs"`. Defaults to `"default"`. See [Attribute Conventions](#attribute-conventions). | No | `"ecs"`     |
| `service-name`     | `string`      | Value of the `service.name` resource attribute. Defaults to `"sshmux"`.                                       | No       | `"sshmux-vlab"`                      |
| `attributes`       | `[]Attribute` | Extra resource attributes attached to every metric, e.g. to tag the deployment environment.                   | No       | `[{ name = "env", value = "prod" }]` |
| `interval-seconds` | `uint`        | Interval at which metrics are pushed to the OTLP endpoint. Defaults to 60 seconds.                            | No       | `60`                                 |
| `connection-grouping` | `bool`     | Whether the connection metrics carry the `user.name`, `server.address` and `server.port` dimensions. Defaults to `true`. See [Connection Grouping](#connection-grouping). | No | `false` |

`Attribute` is a table with a `name` and a `value`, both `string`s.

Settings left out of the TOML file fall back to the standard OpenTelemetry environment variables, and then to the default, giving a precedence of **configuration file > environment > default**. This applies per setting, so configuring one key does not stop the environment from supplying another. Here, `service-name` and `attributes` fall back to `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`, and `interval-seconds` to `OTEL_METRIC_EXPORT_INTERVAL`.

`OTEL_SDK_DISABLED` and `OTEL_METRICS_EXPORTER` are **not** used: `metrics.enabled` and the two `enabled` keys under it are the only switches that decide what runs.

#### Metrics OTLP Settings

The OTLP exporter for metrics is configured under `metrics.otlp`, whose keys are described in [OTLP Settings](#otlp-settings). Metrics are exported to the `/v1/metrics` path, and read `OTEL_EXPORTER_OTLP_METRICS_*` for the settings left out of the file.

#### Prometheus Settings

Prometheus settings configure the Prometheus scrape endpoint. They are grouped under `metrics.prometheus` in the TOML file.

| Key       | Type     | Description                                                              | Required | Example              |
| --------- | -------- | ------------------------------------------------------------------------ | -------- | -------------------- |
| `enabled` | `bool`   | Whether the Prometheus endpoint is enabled. Defaults to `false`.         | No       | `true`               |
| `address` | `string` | TCP host and port to serve metrics on. Defaults to `"127.0.0.1:9100"`.   | No       | `"127.0.0.1:9100"`   |
| `path`    | `string` | HTTP path to serve metrics on. Defaults to `"/metrics"`.                 | No       | `"/metrics"`         |
| `translation-strategy` | `string` | How OTLP names are rendered for Prometheus. One of `"UnderscoreEscapingWithSuffixes"` (default), `"NoUTF8EscapingWithSuffixes"` or `"NoTranslation"`. | No | `"NoTranslation"` |

See the [OpenTelemetry Collector's Prometheus exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/prometheusexporter/README.md) for what each translation strategy does.

### Tracer Settings

Tracer settings configure the [OpenTelemetry](https://opentelemetry.io) tracing of `sshmux`, which is described under [Tracing](#tracing). They are grouped under `tracer` in the TOML file.

| Key            | Type                      | Description                                                                                | Required | Example                              |
| -------------- | ------------------------- | ------------------------------------------------------------------------------------------ | -------- | ------------------------------------ |
| `enabled`      | `bool`                    | Whether tracing is enabled. Defaults to `false`.                                           | No       | `true`                               |
| `convention`   | `string`                  | Schema the attributes are named after, `"default"` or `"ecs"`. Defaults to `"default"`. See [Attribute Conventions](#attribute-conventions). | No | `"ecs"` |
| `service-name` | `string`                  | Value of the `service.name` resource attribute. Defaults to `"sshmux"`.                    | No       | `"sshmux-vlab"`                      |
| `attributes`   | `[]ResourceAttribute`     | Extra resource attributes attached to every span.                                          | No       | `[{ name = "env", value = "prod" }]` |
| `sample-ratio` | `float`                   | Fraction of traces to record, between 0 and 1. Defaults to recording every trace.          | No       | `0.25`                               |
| `propagation`  | `bool`                    | Whether auth API requests carry trace context. Defaults to `true`. See [Tracing](#tracing). | No      | `false`                              |

Settings left out of the TOML file fall back to the standard OpenTelemetry environment variables, so precedence is configuration file, then environment, then default. Here `service-name` and `attributes` fall back to `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`, and `sample-ratio` to `OTEL_TRACES_SAMPLER` with `OTEL_TRACES_SAMPLER_ARG`.

#### Tracer OTLP Settings

The OTLP exporter for traces is configured under `tracer.otlp`, whose keys are described in [OTLP Settings](#otlp-settings). Spans are exported to the `/v1/traces` path, and read `OTEL_EXPORTER_OTLP_TRACES_*` for the settings left out of the file. Unlike metrics, there is no scrape endpoint: spans are only ever pushed.

### OTLP Settings

OTLP settings configure an OTLP push exporter. They are grouped per signal, under `logger.otlp`, `metrics.otlp` and `tracer.otlp` in the TOML file.

| Key               | Type           | Description                                                                                                                  | Required                      | Example                     |
| ----------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | --------------------------- |
| `enabled`         | `bool`         | Whether the OTLP exporter is enabled. Defaults to `false`.                                                                   | No                            | `true`                      |
| `protocol`        | `string`       | OTLP transport to use, either `"http"` or `"grpc"`. Defaults to `"http"`.                                                    | No                            | `"grpc"`                    |
| `endpoint`        | `string`       | Endpoint URL of the OTLP collector, used exactly as written. Defaults to `https://localhost:4318/v1/<signal>` for `http`, and `https://localhost:4317` for `grpc`. | No | `"http://127.0.0.1:4318/v1/metrics"` |
| `headers`         | `[]HTTPHeader` | Extra headers (gRPC metadata for `grpc`) to send to the collector, e.g. for authentication.                                  | No                            | See [`etc/config.example.toml`](etc/config.example.toml) |
| `timeout-seconds` | `uint`         | Timeout for a single export request. Defaults to 10 seconds.                                                                 | No                            | `10`                        |

`"http/protobuf"` is accepted as a synonym for `"http"`, since that is the spelling the OpenTelemetry specification uses for `OTEL_EXPORTER_OTLP_PROTOCOL`. The specification's third value, `"http/json"`, is not supported.

For `http`, `endpoint` is a signal-specific endpoint and is used exactly as written, like `OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT`; only the generic `OTEL_EXPORTER_OTLP_ENDPOINT` is a base URL that the signal path is appended to. Spell the path out: `"http://127.0.0.1:4318"` posts to the collector's root, and a gateway documented as `"https://otlp.example.com/otlp"` has to be configured as `"https://otlp.example.com/otlp/v1/metrics"`.

A `grpc` `endpoint` must not carry a path.

Each key above may be left out and supplied by an environment variable instead:

| Key               | Environment variable                                                  |
| ----------------- | --------------------------------------------------------------------- |
| `protocol`        | `OTEL_EXPORTER_OTLP_<SIGNAL>_PROTOCOL`, `OTEL_EXPORTER_OTLP_PROTOCOL` |
| `endpoint`        | `OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `headers`         | `OTEL_EXPORTER_OTLP_<SIGNAL>_HEADERS`, `OTEL_EXPORTER_OTLP_HEADERS`   |
| `timeout-seconds` | `OTEL_EXPORTER_OTLP_<SIGNAL>_TIMEOUT`, `OTEL_EXPORTER_OTLP_TIMEOUT`   |

Where two are listed, the signal-specific one takes precedence. The exporters read further variables that have no equivalent in the TOML file, such as `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_INSECURE` and the `OTEL_EXPORTER_OTLP_CERTIFICATE` family; those are always honoured.

### PROXY Protocol Settings

PROXY protocol settings configures [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) support in `sshmux`. They are grouped under `proxy-protocol` in the TOML file.

| Key        | Type       | Description                                                     | Required | Example                         |
| ---------- | ---------- | --------------------------------------------------------------- | -------- | ------------------------------- |
| `enabled`  | `bool`     | Whether PROXY protocol support is enabled. Defaults to `false`. | No       | `true`                          |
| `hosts`    | `[]string` | Host names from which PROXY protocol is allowed.                | No       | `["nginx.local", "127.0.0.22"]` |
| `networks` | `[]string` | Network CIDRs from which PROXY protocol is allowed.             | No       | `["10.10.0.0/24"]`              |

## Attribute Conventions

`logger.convention`, `metrics.convention` and `tracer.convention` select how each attribute is named:

| Value     | Resolves each attribute against                                                                          |
| --------- | -------------------------------------------------------------------------------------------------------- |
| `default` | the [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/), then the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html), then `sshmux` |
| `ecs`     | the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html), then `sshmux`       |

They differ in the following attributes:

| Attribute            | `default`                  | `ecs`              |
| -------------------- | -------------------------- | ------------------ |
| Application protocol | `network.protocol.name`    | `network.protocol` |
| Its version          | `network.protocol.version` | dropped            |
| Class of event       | `otel.event.name`          | `event.action`     |
| What an error said   | `exception.message`        | `error.message`    |
| Its underlying type  | `exception.type`           | dropped            |

### Error Classes

`error.type` names what went wrong, on a record, a span and a metric alike, and its values are a closed set so that a label cannot be blown up by whatever a client sends. Each is a condition with an answer of its own:

| Value         | What it was                                                               |
| ------------- | ------------------------------------------------------------------------- |
| `eof`         | a peer closed in order, having said nothing more                          |
| `reset`       | a peer went away mid-stream                                               |
| `timeout`     | a deadline passed, whether `sshmux`'s own or a request's                  |
| `canceled`    | the context was cancelled, which is `sshmux` shutting down                |
| `closed`      | the socket was already closed                                             |
| `refused`     | nothing was listening at the address                                      |
| `unreachable` | no route reached it                                                       |
| `dns`         | a name did not resolve                                                    |
| `in_use`      | the address to listen on was somebody else's                              |
| `exhausted`   | file descriptors ran out                                                  |
| `not_found`   | a file the configuration named is not there                               |
| `permission`  | a file the configuration named cannot be read                             |
| `other`       | anything else, which the error's own message describes on a record        |

## Logs

`sshmux` writes two records per session, through the sinks configured in the [Logger Settings](#logger-settings). Both sinks can be enabled at once, so an OTLP collector can be introduced alongside an existing UDP one.

Each record is one of the two [session events](https://opentelemetry.io/docs/specs/semconv/general/session/) the semantic conventions define, and carries the `session.id` they require, which is the SSH session identifier the auth API is told as `session_id`. Over OTLP and in an `otel` document the class is the record's own event name, rather than the attribute each convention [names it in](#attribute-conventions).

`session.start` is written once the SSH transport is up, which is where a session is first identified. It carries what is known of the connection by then, which is neither a user, none having authenticated yet, nor a backend, none having been named. `session.end` is written when the connection closes, and is what the rest of this section describes.

A `session.end` record names the connection with the attributes the spans carry, `network.protocol.name`, `network.protocol.version`, `user.name`, `client.address`, `client.port`, `server.address` and `server.port`, and leaves out the ones whose values a connection never reached. To those it adds the event: `event.start` and `event.end`, the UTC times the connection was accepted and ended, `event.duration` in nanoseconds, `event.outcome`, which is `success` where the session was established and `failure` otherwise, `error.type` where something went wrong, naming one of the [error classes](#error-classes), and the ECS categorization `event.kind`, `event.category` and `event.type`, fixed at `event`, `network`, and `connection` with `end`.

It names `sshmux.handshake.start` and `sshmux.handshake.end`, the moments the downstream handshake and the upstream dial began and concluded, which [`sshmux.handshake.duration`](#exported-metrics) measures between. They bracket the session within the connection that `event.start` and `event.end` bracket, the gap before the first being the SSH transport coming up, and the end of them being where a session that came up began being proxied.

Where a session was piped, `event.reason` names what ended it: `downstream` where the client disconnected, which is how a session ordinarily ends, `upstream` where the backend went away under one, and `proxy` where `sshmux` closed the connection itself, as it does for every session still running when it shuts down. However one ended, it happened, so `event.outcome` stays `success`: how a session ended is not whether it did.

It also names the two connections a session is actually made of, against the logical ends above: `sshmux.downstream.address` and `sshmux.downstream.port` for the address the client connected from, and `sshmux.upstream.address` and `sshmux.upstream.port` for the one the upstream connection ends at. Where a [PROXY protocol](#proxy-protocol-settings) hop sits on either side, these are the hop's, while `client.address` is the client the header claims and `server.address` is the backend the auth API named. A span says which end it means by its kind, but one record covers both connections, so `network.peer.address` would not say.

The names above are the `default` convention's, which `ecs` renames as described under [Attribute Conventions](#attribute-conventions). The OTLP sink carries them as the log record's attributes, alongside the resource named by `logger.service-name` and `logger.attributes`, and carries the record's own time, level and message as the fields the data model has for them. The UDP sink writes one JSON document per datagram, in the shape [`logger.udp.shape`](#logger-udp-settings) asks for. Under the default shape and convention, abbreviated to a few of its attributes:

```console
$ socat UDP-LISTEN:5556 STDOUT
{"@timestamp":"2026-08-28T03:41:12.664Z","log.level":"INFO","message":"SSH proxy session","otel.event.name":"session.end","event.outcome":"success","network.protocol.name":"ssh","session.id":"3q2+7w==","network.protocol.version":"2.0","user.name":"vlab","client.address":"127.0.0.1","client.port":50227}
```

The document is ECS where a pipeline reads it, while the attributes keep the names above; set `logger.convention` to `"ecs"` alongside the shape for one that is [ECS throughout](#logger-udp-settings). The same record under `shape = "otel"`, which is [larger than a datagram wants to be](#logger-udp-settings):

```console
$ socat UDP-LISTEN:5556 STDOUT
{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"sshmux"}}]},"scopeLogs":[{"scope":{"name":"github.com/USTC-vlab/sshmux"},"logRecords":[{"eventName":"session.end","timeUnixNano":"1756352472664000000","severityNumber":9,"severityText":"INFO","body":{"stringValue":"SSH proxy session"},"attributes":[{"key":"event.outcome","value":{"stringValue":"success"}},{"key":"network.protocol.name","value":{"stringValue":"ssh"}},{"key":"session.id","value":{"stringValue":"3q2+7w=="}},{"key":"network.protocol.version","value":{"stringValue":"2.0"}},{"key":"user.name","value":{"stringValue":"vlab"}},{"key":"client.address","value":{"stringValue":"127.0.0.1"}},{"key":"client.port","value":{"intValue":"50227"}}],"traceId":"7a1e0dd3f9ee40a1b2c3d4e5f6a7b8c9","spanId":"3fbc2d1e4a5b6c7d"}]}]}]}
```

A connection that fails before the transport is up is counted by `sshmux.connections` without either record being written for it. A handshake that fails afterwards still ends its session, and is recorded with the fields known at that point.

A session ending is not among the errors: a client saying it is done is how sessions end, and `event.reason` says so on the record instead.

The errors `sshmux` carries on from go to the sinks as well: a connection it could not accept, a Prometheus endpoint that stopped serving, an exporter that would not shut down. Each is a record at `ERROR` naming one of the [error classes](#error-classes) as `error.type`, with what the error said and what it was beside it, and none of them says anything of a session. Every record is offered to standard error as well as to the sinks, whether one is configured or not: an operator watching the service should not have to run a collector to see it fail. What separates them is the level, the terminal taking `WARN` and above — so these errors reach it and a session that ran to its end does not.

Three things reach the terminal alone, no sink being up to carry them: what `sshmux` says about its configuration, before there is a logger to say it through; an error shutting the logger down, it being the last thing torn down so that the others can report through it; and a session whose pipe failed, which is about one session rather than about the service. All three are written the same way as the rest, so a terminal reads one shape throughout.

## Metrics

`sshmux` reports its own behaviour as [OpenTelemetry](https://opentelemetry.io) metrics, which are turned on and pointed at a collector through the [Metrics Settings](#metrics-settings).

### Exported Metrics

The metric names below are the OpenTelemetry ones. The Prometheus endpoint renders them with `.` replaced by `_`, a `_total` suffix on counters and the unit appended to durations, e.g. `sshmux.session.duration` is exposed as `sshmux_session_duration_seconds`.

| Name                         | Type            | Unit           | Attributes                                     | Description                                                       |
| ---------------------------- | --------------- | -------------- | ---------------------------------------------- | ----------------------------------------------------------------- |
| `sshmux.connections`         | Counter         | `{connection}` | —                                              | Connections accepted by `sshmux`.                                 |
| `sshmux.connections.active`  | UpDownCounter   | `{connection}` | —                                              | Connections currently being served.                               |
| `sshmux.sessions`            | Counter         | `{session}`    | `event.outcome`, `error.type`, [connection grouping](#connection-grouping) | Finished SSH proxy sessions.          |
| `sshmux.session.duration`    | Histogram       | `s`            | `event.outcome`, `error.type`, [connection grouping](#connection-grouping) | Session lifetime, from accept to close. |
| `sshmux.handshake.duration`  | Histogram       | `s`            | `event.outcome`, `error.type`, [connection grouping](#connection-grouping) | Downstream handshake and authentication latency. |
| `sshmux.auth.requests`       | Counter         | `{request}`    | `event.outcome`, `error.type`, `sshmux.auth.method`, `sshmux.auth.status` | Requests sent to the auth API.         |
| `sshmux.auth.duration`       | Histogram       | `s`            | `event.outcome`, `error.type`, `sshmux.auth.method`, `sshmux.auth.status` | Auth API request latency.              |
| `sshmux.upstream.connections` | Counter        | `{connection}` | `event.outcome`, `error.type`                  | Connection attempts to upstream SSH servers.                      |

`event.outcome` is either `success` or `failure`. On failure, `error.type` classifies the error as one of the [error classes](#error-classes), which are a closed set so that a misbehaving client cannot blow up the time series cardinality.

For `sshmux.sessions` and `sshmux.session.duration`, `event.outcome` reports whether the session was *established*: an SSH client ends a healthy session by disconnecting, so how a session terminated once it was up is not counted against it. Use `sshmux.handshake.duration` to tell apart where an unestablished session failed.

### Connection Grouping

`sshmux.sessions`, `sshmux.session.duration` and `sshmux.handshake.duration` are grouped by:

| Attribute          | Description                                                                          |
| ------------------ | ------------------------------------------------------------------------------------ |
| `user.name`        | Username the client authenticated as.                                                |
| `server.address`   | Backend host, as returned by the auth API and before any PROXY protocol override.    |
| `server.port`      | Backend port, from the same response.                                                |

Each is recorded as `unknown` when it is not yet known, which is the case for a connection that failed before its first auth request or before the auth API answered.

`sshmux.connections` and `sshmux.connections.active` are recorded when a connection is accepted, before any of them is known, so they carry no grouping.

Setting `metrics.connection-grouping` to `false` drops both dimensions, leaving one series per outcome.

> [!IMPORTANT]
> **Turn the grouping off once your user base approaches 2000.** Since users normally map one-to-one onto backends, the two dimensions together produce roughly one time series per user, and that count only ever grows, because the metrics are cumulative. The OpenTelemetry SDK caps each instrument at 2000 series by default: past the cap, measurements do not stop being recorded, but they collapse into a single series marked `otel.metric.overflow="true"`, and which users kept a series of their own comes down to whoever connected first after startup. Grouped metrics are therefore only meaningful below the cap.
>
> The `OTEL_GO_X_CARDINALITY_LIMIT` environment variable raises the cap if you would rather keep the grouping, at the cost of memory that grows with your user count. There is no TOML equivalent, because raising it is rarely the right answer.

## Tracing

`sshmux` records a span for each stage of a connection, which are turned on and pointed at a collector through the [Tracer Settings](#tracer-settings).

| Span                    | Kind       | Parent                  | Attributes                                                   | Covers                                                    |
| ----------------------- | ---------- | ----------------------- | ------------------------------------------------------------ | --------------------------------------------------------- |
| `establish ssh session` | `server`   | —                       | Connection, peer                                             | Accepting the connection through to a session that is up. |
| `ssh handshake`         | `internal` | `establish ssh session` | Connection                                                   | The downstream handshake and authentication.              |
| `authenticate user`     | `client`   | `ssh handshake`         | `server.*`, peer, `sshmux.auth.method`, `sshmux.auth.status` | One request to the auth API.                              |
| `connect upstream`      | `client`   | `ssh handshake`         | `server.*`, peer                                             | Dialling the backend.                                     |

The connection attributes are `session.id`, `network.protocol.name`, `network.protocol.version`, `user.name`, `client.address`, `client.port`, `server.address` and `server.port`, naming the session, the client that connected and the backend the auth API picked. Those are the logical ends, the ones behind any intermediary. A span's peer, `network.peer.address` and `network.peer.port`, is the address at the other end of the network connection the span itself covers, which its kind fixes — the client that reached `sshmux` for a server span, the service called for a client span, and neither for an internal one. It differs from the logical end where a PROXY protocol hop sits in between, and is missing only from a dial that never connected.

The kinds are also what a collector builds a service graph from: `sshmux` serves the session, and calls the auth API and the backend on its behalf.

The session span ends once the session is established, not when it closes: a session stays up for as long as the client is connected, and a span left open that long is never exported. How long a session lived is reported by `sshmux.session.duration` instead.

An attribute is left off while its value is unknown, rather than recorded as `unknown` the way the metrics do. A span whose step failed records the error and is marked with an error status.

Requests to the auth API carry the `authenticate user` span as a W3C `traceparent` header, so an auth server that is itself instrumented continues the same trace. Set `tracer.propagation` to `false` to stop sending it.

## Auth API

`sshmux` uses a RESTful API to perform authentication and authorization for a user.

### `POST /v1/auth/:username`

#### Input

| Key               | Type                  | Description                                                                                    | Position | Required |
| ----------------- | --------------------- | ---------------------------------------------------------------------------------------------- | -------- | -------- |
| `username`        | `string`              | SSH user name. Usually the one for logging into the target server.                             | Path     | Yes      |
| `client_address`  | `string`              | Address of the SSH client as `host:port`. Reflects the original client under PROXY protocol.   | Body     | Yes      |
| `client_version`  | `string`              | SSH client identification string, e.g. `"SSH-2.0-OpenSSH_9.9"`.                                | Body     | Yes      |
| `session_id`      | `string`              | Base64-encoded SSH session ID, unique per connection and stable across its auth requests.      | Body     | Yes      |
| `method`          | `string`              | SSH authentication method. Usually one of `"none"`, `"publickey"` or `"keyboard-interactive"`. | Body     | Yes      |
| `public_key`      | `string`              | User public key, serialized in OpenSSH format. Kept on later requests once accepted.           | Body     | No       |
| `payload`         | `Map<string, string>` | Authentication payload constructed from interactive input.                                     | Body     | No       |

#### Output: `200 OK`

| Key              | Type                        | Description                                                                           | Required |
| ---------------- | --------------------------- | ------------------------------------------------------------------------------------- | -------- |
| `upstream`       | [`Upstream`](#upstream)     | SSH upstream information.                                                             | Yes, unless `challenges` is set |
| `challenges`     | [`[]Challenge`](#challenge) | Challenges for extra inputs from user. Only applicable to `publickey` authentication. | No       |
| `proxy`          | [`Proxy`](#proxy)           | PROXY protocol configuration.                                                         | No       |

Returning `challenges` instead of `upstream` partially accepts the `publickey`
authentication: `sshmux` reports partial success to the user and sends them to
`keyboard-interactive`, the only method that can answer the challenges. Every
other authentication request is rejected until such a request arrives, at which
point the challenges are presented and their answers are sent back as `payload`
of a new `keyboard-interactive` request, carrying over the accepted `public_key`.
Further rounds of challenges are then requested with
[`401 Not Authorized`](#output-401-not-authorized) as usual.

Returning `200 OK` with neither `upstream` nor `challenges`, or returning
`challenges` for an authentication method other than `publickey`, is an error
and disconnects the user.

##### `Upstream`

| Key           | Type     | Description                                                                 | Required |
| ------------- | -------- | --------------------------------------------------------------------------- | -------- |
| `host`        | `string` | Host name or IP of upstream SSH server.                                     | Yes      |
| `port`        | `uint`   | Port number of upstream SSH server. Defaults to `22`.                       | No       |
| `username`    | `string` | User name for upstream SSH authentication. Defaults to the downstream user name. | No  |
| `private_key` | `string` | Private key for authenticating with upstream, serialized in OpenSSH format. | No       |
| `certificate` | `string` | Certificate for authenticating with upstream, serialized in OpenSSH format. | No       |
| `password`    | `string` | Password for authenticating with upstream.                                  | No       |

##### `Proxy`

| Key           | Type     | Description                                                                         | Required |
| ------------- | -------- | ----------------------------------------------------------------------------------- | -------- |
| `host`        | `string` | Host name or IP of the proxy server. Defaults to `upstream.host`.                   | No       |
| `port`        | `uint`   | Port number of the proxy server. Defaults to `upstream.port`.                       | No       |
| `protocol`    | `string` | PROXY protocol version to use. Must be one of `"v1"` or `"v2"`. Defaults to `"v2"`. | No       |

#### Output: `401 Not Authorized`

| Key          | Type                        | Description                                                                                      | Required |
| ------------ | --------------------------- | ------------------------------------------------------------------------------------------------ | -------- |
| `challenges` | [`[]Challenge`](#challenge) | Challenges for extra inputs from user. Only applicable to `keyboard-interactive` authentication. | Yes      |

Returning `401 Not Authorized` no `challenges`, or returning `challenges` for an
authentication method other than `keyboard-interactive`, is an error and
disconnects the user.

##### `Challenge`

| Key           | Type                                  | Description                        | Required |
| ------------- | ------------------------------------- | ---------------------------------- | -------- |
| `instruction` | `string`                              | Instruction for the challenge.     | Yes      |
| `fields`      | [`[]ChallengeField`](#challengefield) | Requested fields by the challenge. | No       |

##### `ChallengeField`

| Key      | Type     | Description                                                | Required |
| -------- | -------- | ---------------------------------------------------------- | -------- |
| `key`    | `string` | Key to set the user input on.                              | Yes      |
| `prompt` | `string` | Prompt for the input field.                                | Yes      |
| `secret` | `bool`   | Whether to treat the input as secret. Defaults to `false`. | No       |

#### Output: `403 Forbidden`

| Key       | Type                  | Description               | Required |
| --------- | --------------------- | ------------------------- | -------- |
| `failure` | [`Failure`](#failure) | Auth failure information. | No       |

##### `Failure`

| Key          | Type     | Description                                                                 | Required |
| ------------ | -------- | --------------------------------------------------------------------------- | -------- |
| `message`    | `string` | Message from the server to describe the failure.                            | Yes      |
| `disconnect` | `string` | Whether to disconnect the downstream user. Defaults to `false`.             | No       |
| `reason`     | `uint`   | SSH disconnect reason code. Defaults to `11` (`DISCONNECT_BY_APPLICATION`). | No       |
