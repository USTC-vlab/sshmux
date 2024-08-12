# sshmux

`sshmux` is a new, simple implementation of SSH reverse proxy. `sshmux` was initially developed for Vlab, while we'd like to expand its usage to cover more scenarios.

## Build, Run and Test

`sshmux` requires a Go 1.21+ toolchain to build. You can use `go build -ldflags='-s -w'` or `make all` to get the `sshmux` binary directly in the directory.

You can run the binary with `./sshmux`. Note that you'll need to provide a valid configuration file as described [here](#config).

You can perform the unit test with `go test` or `make test`. Enable verbose logging with `go test -v`.

## Config

`sshmux` requires a JSON configuration file to start up. By default it will look at `/etc/sshmux/config.json`, but you can also specify a custom configuration by passing `-c path/to/config.json` in the command line arguments. An example [`config.example.json`](config.example.json) file is provided.

The table below shows the available options for `sshmux`:

| Key         | Type       | Description                                                        | Required | Example                            |
|-------------|------------|--------------------------------------------------------------------|----------|------------------------------------|
| `address`   | `string`   | TCP host and port that `sshmux` will listen on.                    | `true`   | `"0.0.0.0:8022"`                   |
| `api`       | `string`   | HTTP address that `sshmux` shall interact with.                    | `true`   | `"http://127.0.0.1:5000/ssh"`      |
| `banner`    | `string`   | SSH banner to send to downstream.                                  | `false`  | `"Welcome to Vlab\n"`              |
| `logger`    | `string`   | UDP host and port that `sshmux` send log messages to.              | `false`  | `"127.0.0.1:5556"`                 |
| `host-keys` | `[]string` | Paths to SSH host key files with which `sshmux` identifies itself. | `true`   | `["/sshmux/ssh_host_ed25519_key"]` |
| `proxy-protocol-allowed-cidrs` | `[]string` | CIDRs for which [PROXY protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address) is allowed. | `false` | `["127.0.0.22/32"]` |

### Advanced Config

The table below shows extra options for `sshmux`, mainly for authentication with Vlab backends:

| Key                        | Type       | Description                                                      | Example                      |
|----------------------------|------------|------------------------------------------------------------------|------------------------------|
| `token`                    | `string`   | Token used to authenticate with the recovery backend.            | `"long-and-random-token"`    |
| `recovery-server`          | `string`   | SSH host and port of the recovery server.                        | `"172.30.0.101:2222"`        |
| `recovery-username`        | `[]string` | Usernames dedicated to the recovery server.                      | `["recovery", "console"]`    |
| `all-username-nopassword`  | `bool`     | If set to `true`, all users will not be asked for UNIX password. | `true`                       |
| `username-nopassword`      | `[]string` | Usernames that won't be asked for UNIX password.                 | `["vlab", "ubuntu", "root"]` |
| `invalid-username`         | `[]string` | Usernames that are known to be invalid.                          | `["user"]`                   |
| `invalid-username-message` | `string`   | Message to display when the requested username is invalid.       | `"Invalid username %s."`     |
