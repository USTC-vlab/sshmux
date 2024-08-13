# sshmux

`sshmux` is a new, simple implementation of SSH reverse proxy. `sshmux` was initially developed for Vlab, while we'd like to expand its usage to cover more scenarios.

## Build, Run and Test

`sshmux` requires a Go 1.21+ toolchain to build. You can use `go build` or `make` to get the `sshmux` binary directly in the directory.

You can run the built binary with `./sshmux`. Note that you'll need to provide a valid configuration file as described [here](#config).

You can perform unit tests with `go test` or `make test`. Enable verbose logging with `go test -v`.

## Config

`sshmux` requires a JSON configuration file to start up. By default it will look at `/etc/sshmux/config.json`, but you can also specify a custom configuration by passing `-c path/to/config.json` in the command line arguments. An [example](etc/config.example.json) file is provided.

The table below shows the available options for `sshmux`:

| Key                            | Type       | Description                                                                                                                         | Required | Example                            |
| ------------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------- |
| `address`                      | `string`   | TCP host and port that `sshmux` will listen on.                                                                                     | `true`   | `"0.0.0.0:8022"`                   |
| `host-keys`                    | `[]string` | Paths to SSH host key files with which `sshmux` identifies itself.                                                                  | `true`   | `["/sshmux/ssh_host_ed25519_key"]` |
| `api`                          | `string`   | HTTP address that `sshmux` shall interact with.                                                                                     | `true`   | `"http://127.0.0.1:5000/ssh"`      |
| `token`                        | `string`   | Token used to authenticate with the API endpoint.                                                                                   | `true`   | `"long-and-random-token"`          |
| `banner`                       | `string`   | SSH banner to send to downstream.                                                                                                   | `false`  | `"Welcome to Vlab\n"`              |
| `logger`                       | `string`   | UDP host and port that `sshmux` send log messages to.                                                                               | `false`  | `"127.0.0.1:5556"`                 |
| `proxy-protocol-allowed-cidrs` | `[]string` | CIDRs from which [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) is allowed. | `false`  | `["127.0.0.22/32"]`                |

### Advanced Config

The table below shows extra options for `sshmux`, mainly for authentication with Vlab backends:

| Key                        | Type       | Description                                                                | Example                      |
| -------------------------- | ---------- | -------------------------------------------------------------------------- | ---------------------------- |
| `recovery-token`           | `string`   | Token used to authenticate with the recovery backend. Defaults to `token`. | `"long-and-random-token"`    |
| `recovery-server`          | `string`   | SSH host and port of the recovery server.                                  | `"172.30.0.101:2222"`        |
| `recovery-username`        | `[]string` | Usernames dedicated to the recovery server.                                | `["recovery", "console"]`    |
| `all-username-nopassword`  | `bool`     | If set to `true`, no users will be asked for UNIX password.                | `true`                       |
| `username-nopassword`      | `[]string` | Usernames that won't be asked for UNIX password.                           | `["vlab", "ubuntu", "root"]` |
| `invalid-username`         | `[]string` | Usernames that are known to be invalid.                                    | `["user"]`                   |
| `invalid-username-message` | `string`   | Message to display when the requested username is invalid.                 | `"Invalid username %s."`     |

All of these options can be omitted, if the corresponding feature is not intended to be used.

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
