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
| `handshake-timeout-seconds` | `uint`     | Deadline for the complete downstream SSH handshake and authentication. Defaults to 30 seconds. | No | `30` |
| `upstream-timeout-seconds`  | `uint`     | Deadline for connecting to and authenticating with the upstream SSH server. Defaults to 30 seconds. | No | `30` |

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

Logger settings configures the logger behavior of `sshmux`. They are grouped under `logger` in the TOML file.

| Key        | Type     | Description                                                                   | Required                      | Example                  |
| ---------- | -------- | ----------------------------------------------------------------------------- | ----------------------------- | ------------------------ |
| `enabled`  | `bool`   | Whether the logger is enabled. Defaults to `false`.                           | No                            | `true`                   |
| `endpoint` | `string` | Endpoint URL that `sshmux` will log onto. Only `udp` scheme is supported now. | If `logger.enabled` is `true` | `"udp://127.0.0.1:5556"` |

### Metrics Settings

Metrics settings configure the [OpenTelemetry](https://opentelemetry.io) metrics of `sshmux`, which are described under [Metrics](#metrics). They are grouped under `metrics` in the TOML file. At least one of `metrics.otlp` and `metrics.prometheus` must be enabled when `metrics.enabled` is `true`.

| Key                | Type          | Description                                                                                                   | Required | Example                              |
| ------------------ | ------------- | ------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------ |
| `enabled`          | `bool`        | Whether metrics collection is enabled. Defaults to `false`.                                                   | No       | `true`                               |
| `service-name`     | `string`      | Value of the `service.name` resource attribute. Defaults to `"sshmux"`.                                       | No       | `"sshmux-vlab"`                      |
| `attributes`       | `[]Attribute` | Extra resource attributes attached to every metric, e.g. to tag the deployment environment.                   | No       | `[{ name = "env", value = "prod" }]` |
| `interval-seconds` | `uint`        | Interval at which metrics are pushed to the OTLP endpoint. Defaults to 60 seconds.                            | No       | `60`                                 |

`Attribute` is a table with a `name` and a `value`, both `string`s.

Settings left out of the TOML file fall back to the standard OpenTelemetry environment variables, and then to the default, giving a precedence of **configuration file > environment > default**. This applies per setting, so configuring one key does not stop the environment from supplying another. Here, `service-name` and `attributes` fall back to `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`, and `interval-seconds` to `OTEL_METRIC_EXPORT_INTERVAL`.

`OTEL_SDK_DISABLED` and `OTEL_METRICS_EXPORTER` are **not** used: `metrics.enabled` and the two `enabled` keys under it are the only switches that decide what runs.

#### OTLP Settings

OTLP settings configure the OTLP push exporter. They are grouped under `metrics.otlp` in the TOML file.

| Key               | Type           | Description                                                                                                                  | Required                      | Example                     |
| ----------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | --------------------------- |
| `enabled`         | `bool`         | Whether the OTLP exporter is enabled. Defaults to `false`.                                                                   | No                            | `true`                      |
| `protocol`        | `string`       | OTLP transport to use, either `"http"` or `"grpc"`. Defaults to `"http"`.                                                    | No                            | `"grpc"`                    |
| `endpoint`        | `string`       | Endpoint URL of the OTLP collector. Defaults to `https://localhost:4318/v1/metrics` for `http`, and `https://localhost:4317` for `grpc` | No                 | `"http://127.0.0.1:4318/v1/metrics"` |
| `headers`         | `[]HTTPHeader` | Extra headers (gRPC metadata for `grpc`) to send to the collector, e.g. for authentication.                                  | No                            | See [`etc/config.example.toml`](etc/config.example.toml) |
| `timeout-seconds` | `uint`         | Timeout for a single export request. Defaults to 10 seconds.                                                                 | No                            | `10`                        |

`"http/protobuf"` is accepted as a synonym for `"http"`, since that is the spelling the OpenTelemetry specification uses for `OTEL_EXPORTER_OTLP_PROTOCOL`. The specification's third value, `"http/json"`, is not supported.

For `http`, `endpoint` is a signal-specific endpoint and is used exactly as written, like `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`; only the generic `OTEL_EXPORTER_OTLP_ENDPOINT` is a base URL that `/v1/metrics` is appended to. Spell the path out: `"http://127.0.0.1:4318"` posts to the collector's root, and a gateway documented as `"https://otlp.example.com/otlp"` has to be configured as `"https://otlp.example.com/otlp/v1/metrics"`.

A `grpc` `endpoint` must not carry a path.

Each key above may be left out and supplied by an environment variable instead:

| Key               | Environment variable                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `protocol`        | `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL`, `OTEL_EXPORTER_OTLP_PROTOCOL` |
| `endpoint`        | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `headers`         | `OTEL_EXPORTER_OTLP_METRICS_HEADERS`, `OTEL_EXPORTER_OTLP_HEADERS`   |
| `timeout-seconds` | `OTEL_EXPORTER_OTLP_METRICS_TIMEOUT`, `OTEL_EXPORTER_OTLP_TIMEOUT`   |

Where two are listed, the signal-specific one takes precedence. The exporters read further variables that have no equivalent in the TOML file, such as `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_INSECURE` and the `OTEL_EXPORTER_OTLP_CERTIFICATE` family; those are always honoured.

#### Prometheus Settings

Prometheus settings configure the Prometheus scrape endpoint. They are grouped under `metrics.prometheus` in the TOML file.

| Key       | Type     | Description                                                              | Required | Example              |
| --------- | -------- | ------------------------------------------------------------------------ | -------- | -------------------- |
| `enabled` | `bool`   | Whether the Prometheus endpoint is enabled. Defaults to `false`.         | No       | `true`               |
| `address` | `string` | TCP host and port to serve metrics on. Defaults to `"127.0.0.1:9100"`.   | No       | `"127.0.0.1:9100"`   |
| `path`    | `string` | HTTP path to serve metrics on. Defaults to `"/metrics"`.                 | No       | `"/metrics"`         |

### PROXY Protocol Settings

PROXY protocol settings configures [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) support in `sshmux`. They are grouped under `proxy-protocol` in the TOML file.

| Key        | Type       | Description                                                     | Required | Example                         |
| ---------- | ---------- | --------------------------------------------------------------- | -------- | ------------------------------- |
| `enabled`  | `bool`     | Whether PROXY protocol support is enabled. Defaults to `false`. | No       | `true`                          |
| `hosts`    | `[]string` | Host names from which PROXY protocol is allowed.                | No       | `["nginx.local", "127.0.0.22"]` |
| `networks` | `[]string` | Network CIDRs from which PROXY protocol is allowed.             | No       | `["10.10.0.0/24"]`              |

## Metrics

`sshmux` reports its own behaviour as [OpenTelemetry](https://opentelemetry.io) metrics, which are turned on and pointed at a collector through the [Metrics Settings](#metrics-settings).

### Exported Metrics

The metric names below are the OpenTelemetry ones. The Prometheus endpoint renders them with `.` replaced by `_`, a `_total` suffix on counters and the unit appended to durations, e.g. `sshmux.session.duration` is exposed as `sshmux_session_duration_seconds`.

| Name                         | Type            | Unit           | Attributes                                     | Description                                                       |
| ---------------------------- | --------------- | -------------- | ---------------------------------------------- | ----------------------------------------------------------------- |
| `sshmux.connections`         | Counter         | `{connection}` | —                                              | Connections accepted by `sshmux`.                                 |
| `sshmux.connections.active`  | UpDownCounter   | `{connection}` | —                                              | Connections currently being served.                               |
| `sshmux.sessions`            | Counter         | `{session}`    | `result`, `error.type`                         | Finished SSH proxy sessions.                              |
| `sshmux.session.duration`    | Histogram       | `s`            | `result`, `error.type`                         | Session lifetime, from accept to close.                   |
| `sshmux.handshake.duration`  | Histogram       | `s`            | `result`, `error.type`                         | Downstream handshake and authentication latency.          |
| `sshmux.auth.requests`       | Counter         | `{request}`    | `result`, `error.type`, `auth.method`, `auth.status` | Requests sent to the auth API.                              |
| `sshmux.auth.duration`       | Histogram       | `s`            | `result`, `error.type`, `auth.method`, `auth.status` | Auth API request latency.                                   |
| `sshmux.upstream.connections`| Counter         | `{connection}` | `result`, `error.type`                         | Connection attempts to upstream SSH servers.                      |

`result` is either `success` or `failure`. On failure, `error.type` classifies the error as one of `eof`, `timeout`, `canceled`, `closed` or `other`. These sets are deliberately closed, so that a misbehaving client cannot blow up the time series cardinality.

For `sshmux.sessions` and `sshmux.session.duration`, `result` reports whether the session was *established*: an SSH client ends a healthy session by disconnecting, so how a session terminated once it was up is not counted against it. Use `sshmux.handshake.duration` to tell apart where an unestablished session failed.

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
