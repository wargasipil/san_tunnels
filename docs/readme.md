# san_tunnels

TCP tunnelling over Connect RPC or WebSocket, used to carry SSH sessions to
hosts that run no SSH daemon and expose no ports.

One static Go binary, two roles. On the target, `san_tunnels server` runs an
agent with an SSH server compiled into it that never binds a socket. On the
entry host, `san_tunnels client proxy` is an `ssh` ProxyCommand. The SSH
session is encrypted end to end between your `ssh` and the agent, so whatever
carries the tunnel in between moves ciphertext it cannot read.

```
ssh box-01
  └─ ProxyCommand: san_tunnels client proxy box-01
       └─ Connect/HTTP2 or WebSocket/HTTP1.1, TLS + bearer token
            └─ agent: stream → net.Conn → embedded SSH server → PTY + shell
```

> **Status: pre-production.** Working and tested end to end against the real
> OpenSSH client, but read [Security](#security) before exposing an agent —
> **an agent started without `--token` authenticates nobody**, and see
> [Limitations](#limitations) for what is not built yet.

---

## Install

Requires Go 1.26+.

```sh
bash build.sh        # or: pwsh build.ps1
```

Both scripts run `go vet`, the tests, and then build for Windows and Linux,
stamping the version into the binary:

```
bin/san_tunnels.exe   # windows/amd64
bin/san_tunnels       # linux/amd64
```

Copy the one binary to the target host. Nothing else is installed there — no
`openssh-server`, no system service, no open port.

---

## Quickstart

### 1. On the target host

Authorize the key you will connect with, then run the agent:

```sh
san_tunnels server authorize "$(cat ~/.ssh/id_ed25519.pub)"

san_tunnels server \
  --listen 0.0.0.0:8443 \
  --tls-cert /etc/san_tunnels/cert.pem \
  --tls-key  /etc/san_tunnels/key.pem \
  --token-file /etc/san_tunnels/token
```

The agent generates and persists its SSH host key on first run. Print its
fingerprint so you can verify it from the entry host:

```sh
san_tunnels server hostkey
```

### 2. On the entry host

Write `~/.config/san_tunnels/config.json` (`%AppData%\san_tunnels\config.json`
on Windows):

```json
{
  "agents": {
    "box-01": {
      "url": "https://box-01.example:8443",
      "token": "the-same-token",
      "user": "deploy"
    }
  }
}
```

Prove the path works before involving `ssh`, which fails far less clearly:

```sh
san_tunnels client check box-01
# ok: box-01 is reachable and the path is full-duplex
```

### 3. Wire it into ssh

```sh
san_tunnels client config box-01 >> ~/.ssh/config
```

That prints, rather than edits, because `~/.ssh/config` is yours and OpenSSH
resolves keywords first-match-wins:

```
Host box-01
  ProxyCommand san_tunnels client proxy %h
  User deploy
```

Then `ssh box-01` works normally. On first connection, verify the fingerprint
`ssh` shows against the `server hostkey` output above — after that it is
pinned in `known_hosts`, which is what stops anything in the middle
substituting its own key.

---

## Configuration

### Agent

| Flag | Default | Notes |
|---|---|---|
| `--listen` | `:8443` | **All interfaces.** Bind to a specific address if you can. |
| `--tls-cert`, `--tls-key` | — | Required unless `--h2c`. |
| `--h2c` | off | Cleartext HTTP/2. Only behind an L4 proxy terminating TLS, or on a trusted network. Mutually exclusive with `--tls-cert`. |
| `--token` | — | Bearer token. `$SAN_TUNNELS_TOKEN`. **Read [Security](#security) before omitting.** |
| `--token-file` | — | Same, from a file. Mutually exclusive with `--token`. Prefer this: flags are visible in `ps`. |
| `--host-key` | `<config dir>/san_tunnels/host_key` | Generated on first run, then persisted. |
| `--authorized-keys` | `<config dir>/san_tunnels/authorized_keys` | Ours, not the system's — the agent does not inherit `~/.ssh/authorized_keys`. |
| `--shell` | `$SHELL`, else `/bin/sh`; `%COMSPEC%`, else `cmd.exe` on Windows | |
| `--endpoint` | — | `name=host:port`, repeatable. See [Endpoints](#endpoints). |
| `--ws-origin` | — | Browser origin allowed to open a WebSocket. Repeatable. Empty means same-origin only. |

Subcommands: `server authorize <line \| ->`, `server hostkey`,
`server endpoints`.

### Client

Config file: `--config`, `$SAN_TUNNELS_CONFIG`, else
`<user config dir>/san_tunnels/config.json`.

```json
{
  "agents": {
    "box-01": {
      "url": "https://box-01.example:8443",
      "token": "…",
      "user": "deploy",
      "transport": "ws",
      "insecure": false
    }
  }
}
```

| Key | Meaning |
|---|---|
| `url` | `http`/`https`. Rewritten to `ws`/`wss` automatically on the WebSocket transport. |
| `token` | Bearer token. Overridable per run with `--token` / `$SAN_TUNNELS_TOKEN`. |
| `user` | SSH user written into the generated `ssh` config block. |
| `transport` | `connect` (default) or `ws`. See [Transports](#transports). |
| `insecure` | Skip TLS verification. **Development only.** |

Commands: `client proxy <name>`, `client config <name>`, `client check <name>`,
`client list`. Global `--log-level` (`debug`/`info`/`warn`/`error`,
`$SAN_TUNNELS_LOG_LEVEL`) — always to stderr, never stdout.

---

## Transports

Two doors onto the same agent. They diverge only in how they produce a
`net.Conn`; everything below that is shared.

| | `connect` (default) | `ws` |
|---|---|---|
| Wire | Connect RPC over HTTP/2 | WebSocket over HTTP/1.1 |
| Path | `/san.tunnels.v1.TunnelService/…` | `/ws`, `/ws/ping` |
| Survives h2-downgrading proxies | no — **hangs silently** | yes |
| Keepalives | free (`http2.Transport` pings) | **none yet** — idle tunnels get reaped |
| Half-close | native | via a `close-write` control frame |
| `client check` proves | reachability, token, **and duplex** | reachability and token only |

**Use `connect` unless something in the path breaks it.** One port serves
both: Go's TLS server advertises `h2` and `http/1.1` via ALPN and each client
picks what it needs.

Switch per agent with `"transport": "ws"`, or per run:

```sh
san_tunnels client proxy --transport ws box-01
```

**There is no automatic fallback**, deliberately. The h2 failure mode is a
silent hang rather than an error, so detecting it costs a timeout on every
connection — and routing around a misconfigured proxy quietly leaves it broken
for everything else behind it. `client check` fails loudly instead and names
both the infrastructure fix and the `--transport ws` escape hatch.

### When you need `ws`

Anything that speaks HTTP/2 to the client and HTTP/1.1 to the agent: nginx
`proxy_pass` (use `grpc_pass`), an AWS ALB whose target group is not HTTP2 or
gRPC, `ingress-nginx` without
`nginx.ingress.kubernetes.io/backend-protocol: "GRPC"`. An AWS NLB is L4 and
passes through cleanly; Envoy and Traefik handle gRPC natively.

Fixing the path is better than switching transport where you can. An L4
passthrough keeps every property intact.

---

## Endpoints

The client asks for an endpoint **by name**, never by address. The agent
resolves the name against its allowlist, so a token holder cannot pivot to
arbitrary hosts.

- `shell` — reserved, always present, handled in-process by the embedded SSH
  server. No socket is opened.
- anything from `--endpoint name=host:port` — dials that TCP address.

```sh
san_tunnels server --endpoint postgres=127.0.0.1:5432 --endpoint redis=127.0.0.1:6379
san_tunnels server endpoints    # list the allowlist
```

```sh
# tunnel Postgres to a local port
san_tunnels client proxy --endpoint postgres box-01
```

> ⚠️ **TCP endpoints are protected by the bearer token alone.** Unlike `shell`,
> they do not pass through SSH authentication. See [Security](#security).

---

## Security

Two independent layers, deliberately:

| | Transport | Session |
|---|---|---|
| Crypto | TLS (or `wss`) | SSH |
| Credential | bearer token | SSH public key vs the agent's `authorized_keys` |
| Decides | who may **open a tunnel** | who gets a **shell** |
| Key material | `--tls-cert` / `--tls-key` | ed25519 host key, generated on first run |

Because the SSH session is encrypted end to end, anything forwarding the
tunnel — a proxy, a load balancer, a future hub — moves ciphertext. Host-key
pinning via `known_hosts` is what stops it substituting its own key, so
**verify the fingerprint on first connect**. TLS still matters: it protects the
bearer token and the connection metadata, which sit outside the SSH layer.

### ⚠️ Always set a token

`--token` / `--token-file` is optional, and when it is omitted the agent
**accepts every request without authentication**. There is currently no
startup warning for this.

For `shell` that is partly covered — SSH key auth still stands between a
caller and a prompt. **For TCP endpoints there is no second layer at all**: an
agent with `--endpoint postgres=…` and no token is an open proxy to that
service for anyone who can reach the listener. Combined with `--listen`
defaulting to all interfaces, one forgotten flag is enough.

Until a startup check exists, treat the token as mandatory whenever the agent
is reachable by anything you do not control.

### Other operational notes

- Prefer `--token-file` over `--token`: command-line flags are visible in `ps`.
- `--insecure` disables TLS verification. Development only; never in a config
  file that ships anywhere.
- Rotating the SSH host key means editing it out of every client's
  `known_hosts`. There is no `hostkey --rotate` yet; delete the file and
  restart to regenerate.
- There is no rate limiting on token or key attempts, and no cap on concurrent
  tunnels.

---

## Troubleshooting

**`ssh` hangs with no output, no error.** The classic h2 downgrade. Run
`san_tunnels client check <name>` — it turns the hang into a message naming
the cause and the fix. Then either repair the path or switch to
`--transport ws`.

**`505 HTTP Version Not Supported`.** The agent received HTTP/1.1 on a Connect
path. Something in front of it is downgrading; this is the loud version of the
hang above, and it means the assertion is doing its job.

**`endpoint "x" is not in the allowlist`.** Add `--endpoint x=host:port` to the
agent, or check for a typo. `server endpoints` lists what is configured.

**`ssh` reports a bad packet length or protocol mismatch.** Something wrote to
`client proxy`'s stdout, which carries tunnel bytes only. All logging must go
to stderr; if you have wrapped the command in a script, check it is not
echoing.

**A `ws` tunnel dies after about a minute of idle.** Known gap — no WebSocket
keepalives yet. A middlebox is reaping the idle connection. Run `tmux` on the
target, or use the `connect` transport where h2 pings handle it.

**`unable to authenticate`.** The key is not in the agent's `authorized_keys`,
which is *not* the system one. Add it with `server authorize`.

---

## Development

```sh
go test ./...                                   # all tests
go test ./internal/agent -run TestSSHSession -v # one test, both transports
bash build.sh                                   # vet + test + build both targets
```

End-to-end tests run against a real OpenSSH client and are parameterized over
both transports — `TestSSHSessionThroughTunnel/connect` and `/ws` are separate
subtests. Anything touching the transport seam should stay in that matrix.

Regenerating protobuf/Connect code after editing `protos/`:

```sh
buf generate
```

### Layout

```
protos/san/tunnels/v1/tunnel.proto   TunnelService: Forward + Ping
gen/                                 buf output
cmd/san_tunnels/main.go              urfave/cli v3 tree
internal/streamconn/                 net.Conn over stream callbacks
internal/wsconn/                     net.Conn over a WebSocket + framing convention
internal/agent/                      keys, sshd, service, ws, http
internal/client/                     client, ws, proxy, config
```

The seam worth knowing: `Service.Handle(ctx, endpoint, conn, ack)` takes an
open `net.Conn` and routes it. Nothing below it — the SSH server, the key
handling, the allowlist, the CLI — knows which transport produced the conn.
Adding a transport means writing an adapter that reaches that function, not
touching anything underneath it.

---

## Limitations

Not built yet, in rough order of how likely you are to hit them:

- **No `scp` / `sftp`.** No SFTP subsystem is registered, so file transfer does
  not work. Interactive sessions and `ssh host cmd` do.
- **No WebSocket keepalives.** Idle `ws` tunnels get reaped by middleboxes at
  60s or less.
- **No startup check for a missing token.** See [Security](#security).
- **Targets must be directly reachable.** The entry host dials the target. If
  your targets sit behind NAT this does not work yet — it needs the hub design
  sketched in the spec, which is an open decision, not an implementation gap.
- **No session resumption.** A dropped connection kills the session; run `tmux`
  on the target.
- **No `hostkey --rotate`.**
- **No metrics.** Nothing to alert on.
- **Shutdown does not close WebSocket tunnels** — hijacked connections outlive
  a graceful restart.

---

## See also

Design rationale, protocol detail, and the reasoning behind the choices above:
[`docs/external_repo/san_tunnels.md`](../../../../docs/external_repo/san_tunnels.md)
in the parent repository. This file is the operator's reference; that one is
the argument.
