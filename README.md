# sshmux

`sshmux` is a new, simple implementation of SSH reverse proxy. `sshmux` was initially developed for Vlab, while we'd like to expand its usage to cover more scenarios.

## Build, Run and Test

`sshmux` requires a Go 1.21+ toolchain to build. You can use `go build` or `make` to get the `sshmux` binary directly in the directory.

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

| Key         | Type       | Description                                                        | Required | Example                                            |
| ----------- | ---------- | ------------------------------------------------------------------ | -------- | -------------------------------------------------- |
| `banner`    | `string`   | SSH banner to send to downstream.                                  | No       | `"Welcome to Vlab\n"`                              |
| `host-keys` | `[]SSHKey` | Paths to SSH host key files with which `sshmux` identifies itself. | Yes      | See [`fixtures/config.toml`](fixtures/config.toml) |

### Auth Settings

Auth settings configures the authentication and authorization API used by `sshmux`. They are grouped under `auth` in the TOML file.

| Key        | Type           | Description                                                                | Required | Example                                            |
| ---------- | -------------- | -------------------------------------------------------------------------- | -------- | -------------------------------------------------- |
| `endpoint` | `string`       | Endpoint URL that `sshmux` will use for authentication and authorization.  | Yes      | `"http://127.0.0.1:5000/ssh"`                      |
| `version`  | `string`       | Auth endpoint API version (`"legacy"`, `"v1"`). Defaults to `"legacy"`.    | No       | `"v1"`                                             |
| `headers`  | `[]HTTPHeader` | Extra HTTP headers to send to API server.                                  | No       | See [`fixtures/config.toml`](fixtures/config.toml) |

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

### PROXY Protocol Settings

PROXY protocol settings configures [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) support in `sshmux`. They are grouped under `proxy-protocol` in the TOML file.

| Key        | Type       | Description                                                     | Required | Example                         |
| ---------- | ---------- | --------------------------------------------------------------- | -------- | ------------------------------- |
| `enabled`  | `bool`     | Whether PROXY protocol support is enabled. Defaults to `false`. | No       | `true`                          |
| `hosts`    | `[]string` | Host names from which PROXY protocol is allowed.                | No       | `["nginx.local", "127.0.0.22"]` |
| `networks` | `[]string` | Network CIDRs from which PROXY protocol is allowed.             | No       | `["10.10.0.0/24"]`              |

## Auth API

`sshmux` uses a RESTful API to perform authentication and authorization for a user.

### `POST /v1/auth/:username`

#### Input

| Key               | Type                  | Description                                                                                    | Position | Required |
| ----------------- | --------------------- | ---------------------------------------------------------------------------------------------- | -------- | -------- |
| `username`        | `string`              | SSH user name. Usually the one for logging into the target server.                             | Path     | Yes      |
| `method`          | `string`              | SSH authentication method. Usually one of `"none"`, `"publickey"` or `"keyboard-interactive"`. | Body     | Yes      |
| `public_key`      | `string`              | User public key, serialized in OpenSSH format.                                                 | Body     | No       |
| `payload`         | `Map<string, string>` | Authentication payload constructed from interactive input.                                     | Body     | No       |

#### Output: `200 OK`

| Key              | Type                    | Description                   | Required |
| ---------------- | ----------------------- | ----------------------------- | -------- |
| `upstream`       | [`Upstream`](#upstream) | SSH upstream information.     | Yes      |
| `proxy`          | [`Proxy`](#proxy)       | PROXY protocol configuration. | No       |

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
