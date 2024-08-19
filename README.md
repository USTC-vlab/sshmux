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

| Key                        | Type       | Description                                                                | Required | Example                       |
| -------------------------- | ---------- | -------------------------------------------------------------------------- | -------- | ----------------------------- |
| `endpoint`                 | `string`   | Endpoint URL that `sshmux` will use for authentication and authorization.  | Yes      | `"http://127.0.0.1:5000/ssh"` |
| `token`                    | `string`   | Token used to authenticate with the API endpoint.                          | Yes      | `"long-and-random-token"`     |
| `all-username-nopassword`  | `bool`     | If set to `true`, no users will be asked for UNIX password.                | No       | `true`                        |
| `usernames-nopassword`     | `[]string` | Usernames that won't be asked for UNIX password.                           | No       | `["vlab", "ubuntu", "root"]`  |
| `invalid-usernames`        | `[]string` | Usernames that are known to be invalid.                                    | No       | `["user"]`                    |
| `invalid-username-message` | `string`   | Message to display when the requested username is invalid.                 | No       | `"Invalid username %s."`      |

### Logger Settings

Logger settings configures the logger behavior of `sshmux`. They are grouped under `logger` in the TOML file.

| Key        | Type     | Description                                                                   | Required               | Example                  |
| ---------- | -------- | ----------------------------------------------------------------------------- | ---------------------- | ------------------------ |
| `enabled`  | `bool`   | Whether the logger is enabled. Defaults to `false`.                           | No                     | `true`                   |
| `endpoint` | `string` | Endpoint URL that `sshmux` will log onto. Only `udp` scheme is supported now. | If `enabled` is `true` | `"udp://127.0.0.1:5556"` |

### PROXY Protocol Settings

PROXY protocol settings configures [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) support in `sshmux`. They are grouped under `proxy-protocol` in the TOML file.

| Key        | Type       | Description                                                     | Required | Example                         |
| ---------- | ---------- | --------------------------------------------------------------- | -------- | ------------------------------- |
| `enabled`  | `bool`     | Whether PROXY protocol support is enabled. Defaults to `false`. | No       | `true`                          |
| `hosts`    | `[]string` | Host names from which PROXY protocol is allowed.                | No       | `["nginx.local", "127.0.0.22"]` |
| `networks` | `[]string` | Network CIDRs from which PROXY protocol is allowed.             | No       | `["10.10.0.0/24"]`              |

### Recovery Settings

Recovery settings configures Vlab recovery service support of `sshmux`. They are grouped under `recovery` in the TOML file.

| Key         | Type       | Description                                           | Required | Example                   |
| ----------- | ---------- | ----------------------------------------------------- | -------- | ------------------------- |
| `address`   | `string`   | SSH host and port of the recovery server.             | No       | `"172.30.0.101:2222"`     |
| `usernames` | `[]string` | Usernames dedicated to the recovery server.           | No       | `["recovery", "console"]` |
| `token`     | `string`   | Token used to authenticate with the recovery backend. | No       | `"long-and-random-token"` |

## API server

`sshmux` requires an API server to perform authentication and authorization for a user.

The API accepts JSON input with the following keys:

| Key               | Type     | Description                                                                                              |
| ----------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `auth_type`       | `string` | The authentication type. Always set to `"key"` at the moment.                                            |
| `username`        | `string` | Vlab username. Omitted if the user is authenticating with public key.                                    |
| `password`        | `string` | Vlab password. Omitted if the user is authenticating with public key.                                    |
| `public_key_type` | `string` | SSH public key type. Omitted if the user is authenticating with username and password.                   |
| `public_key_data` | `string` | Base64-encoded SSH public key payload. Omitted if the user is authenticating with username and password. |
| `unix_username`   | `string` | UNIX username the user is requesting access to.                                                          |
| `token`           | `string` | Token used to authenticate the `sshmux` instance.                                                        |

The API responds with JSON output with the following keys:

| Key              | Type      | Description                                                                                                      |
| ---------------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| `status`         | `string`  | The authentication status. Should be `"ok"` if the user is authorized.                                           |
| `address`        | `string`  | TCP host and port of the downstream SSH server the user is requesting for.                                       |
| `private_key`    | `string`  | SSH private key to authenticate for the downstream.                                                              |
| `cert`           | `string`  | The certificate associated with the SSH private key.                                                             |
| `vmid`           | `integer` | ID of the requested VM. Only used for recovery access.                                                           |
| `proxy_protocol` | `integer` | PROXY protocol version to use for the downstream. Should be `1`, `2` or omitted (which disables PROXY protocol). |

Note that if the user is not authorized, the API server should return a `status` other than `"ok"`, and other keys can be safely ommitted.
