# ech-tls-tunnel

A SIP003 plugin for [shadowsocks](https://shadowsocks.org/) that wraps
each stream in a WebSocket-over-TLS connection on port 443, with the
TLS handshake protected by **ECH** (Encrypted Client Hello). To passive
observers the connection looks like a TLS request to a benign public
name; the real tunnel domain is encrypted inside the ECH-protected
ClientHelloInner.

- Auto-issues and renews a Let's Encrypt cert via **TLS-ALPN-01**, on
  the same port-443 listener — no port 80 needed.
- Stealth: probes that don't hit the secret WebSocket path get a fake
  nginx 404, indistinguishable from a default nginx install.
- Single config surface: every option lives in `SS_PLUGIN_OPTIONS`.
  No YAML, no separate config file.

## What's in this repo

| | |
|---|---|
| `src/server.rs` + `src/client.rs` | event loops |
| `src/tls_server.rs` + `src/tls_client.rs` | BoringSSL wrappers |
| `src/ws.rs` | WebSocket ↔ AsyncRead/Write adapter |
| `src/acme.rs` + `src/challenge.rs` | TLS-ALPN-01 issuance + renewal |
| `src/ech.rs` | HPKE keygen, ECHConfig (un)marshaling, FFI |
| `src/sip003.rs` + `src/config.rs` | SIP003 env / plugin options |
| `tests/sip003_e2e.rs` | full localhost test against `shadowsocks-rust` |

## Install

Pick a release binary from the
[Releases page](https://github.com/shadowsocks/ech-tls-tunnel/releases),
extract, and put `ech-tls-tunnel` somewhere on `PATH`:

```sh
# Linux x86_64
curl -L https://github.com/shadowsocks/ech-tls-tunnel/releases/latest/download/ech-tls-tunnel-linux-amd64.tar.gz | tar xz
sudo mv ech-tls-tunnel /usr/local/bin/

# macOS arm64
curl -L https://github.com/shadowsocks/ech-tls-tunnel/releases/latest/download/ech-tls-tunnel-darwin-arm64.tar.gz | tar xz
sudo mv ech-tls-tunnel /usr/local/bin/
```

Or build from source:

```sh
cargo install --git https://github.com/shadowsocks/ech-tls-tunnel
```

## Quick start

### 1. Server side (VPS, port 443 free, A record points at it)

```sh
# Generate the HPKE keypair + ECHConfigList
sudo mkdir -p /var/lib/ech-tls-tunnel
ech-tls-tunnel ech-gen-keys \
    --public-name front.example.com \
    --out /var/lib/ech-tls-tunnel/ech

# Run ssserver with the plugin
ssserver \
    -s 0.0.0.0:443 \
    -k '<password>' \
    -m aes-128-gcm \
    --plugin ech-tls-tunnel \
    --plugin-opts "mode=server;\
domain=tunnel.example.com;\
path=/ws-tunnel-CHANGE-ME;\
acme_email=admin@example.com;\
acme_cache=/var/lib/ech-tls-tunnel/acme;\
ech_public_name=front.example.com;\
ech_key=/var/lib/ech-tls-tunnel/ech/ech.key"
```

The first run blocks on the ACME order; subsequent runs reuse the
cached cert and renew transparently.

### 2. Client side (any device)

Copy the base64 `ECHConfigList` printed by `ech-gen-keys` (or the
contents of `/var/lib/ech-tls-tunnel/ech/ech.config_list` after
base64-encoding) and pass it as `ech_config=`:

```sh
sslocal \
    -b 127.0.0.1:1080 \
    -s tunnel.example.com:443 \
    -k '<password>' \
    -m aes-128-gcm \
    --protocol socks \
    --plugin ech-tls-tunnel \
    --plugin-opts "mode=client;\
sni=tunnel.example.com;\
path=/ws-tunnel-CHANGE-ME;\
ech_config=<paste base64 ECHConfigList here>"
```

Now `127.0.0.1:1080` is a SOCKS5 proxy whose traffic looks (to anyone
on the wire) like an HTTPS connection to `front.example.com`.

## Plugin options reference

### Common

| Key | Default | Notes |
|---|---|---|
| `mode` | (required) | `server` or `client` |
| `path` | (required) | Secret WS path, must start with `/`. Anything else gets fake nginx 404. |
| `fast_open` | `false` | Enable TCP Fast Open on listener and outgoing connections. Linux benefits most. |

### Server-only

| Key | Default | Notes |
|---|---|---|
| `domain` | (required) | Real tunnel domain — inner SNI; appears as a SAN on the production cert. |
| `cert` + `key` | — | Static cert/key on disk. Mutually exclusive with `acme_email`. |
| `acme_email` | — | Contact email; enables ACME (Let's Encrypt) via TLS-ALPN-01. |
| `acme_cache` | `/var/lib/ech-tls-tunnel/acme` | Where the ACME account + cert live across restarts. |
| `acme_staging` | `false` | Use Let's Encrypt staging — set `true` while testing to avoid rate limits. |
| `ech_public_name` | — | Outer SNI advertised to public observers. Required (with `ech_key`) to enable ECH. |
| `ech_key` | — | Path to the HPKE private key from `ech-gen-keys`. |
| `server_name` | `nginx/1.24.0` | Value of the `Server` header in fake-404 responses. |

### Client-only

| Key | Default | Notes |
|---|---|---|
| `sni` | (required) | Real upstream hostname — sent as inner SNI inside the ECH-protected ClientHello. |
| `ech_config` | — | Base64 ECHConfigList from the server. Either this or `ech_config_file`. |
| `ech_config_file` | — | Path to a binary ECHConfigList file (alternative to `ech_config`). |
| `ca_file` | — | Pin to a specific CA bundle (PEM). Mutually exclusive with `insecure`. |
| `insecure` | `false` | DEV/TEST ONLY — skip cert verification. |

## CLI subcommands

```
ech-tls-tunnel ech-gen-keys --public-name <NAME> --out <DIR>
```

Generates an HPKE X25519 keypair, writes `ech.key` (binary private
key) and `ech.config_list` (binary ECHConfigList) under `<DIR>`, and
prints the base64 ConfigList ready to paste into the client's
`ech_config=` plugin option.

## Running under systemd (Linux)

The plugin itself is a child process of `ssserver` — write the
systemd unit for `ssserver`, not the plugin:

```ini
# /etc/systemd/system/ssserver-ech.service
[Unit]
Description=Shadowsocks server with ech-tls-tunnel plugin
After=network.target

[Service]
ExecStart=/usr/local/bin/ssserver \
    -s 0.0.0.0:443 \
    -k YOUR_PASSWORD \
    -m aes-128-gcm \
    --plugin /usr/local/bin/ech-tls-tunnel \
    --plugin-opts "mode=server;domain=tunnel.example.com;path=/ws-secret;acme_email=admin@example.com;ech_public_name=front.example.com;ech_key=/var/lib/ech-tls-tunnel/ech/ech.key"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ssserver-ech
```

## How it works

```
sslocal ──TCP──▶ ech-tls-tunnel (client mode) ──TLS+ECH+WS──▶ ech-tls-tunnel (server mode) ──TCP──▶ ssserver
                                                  │
                                                  ▼
                              ACME (TLS-ALPN-01 on the same port 443)
```

- TLS termination uses BoringSSL via the `boring`/`tokio-boring`
  crates from Cloudflare. BoringSSL's mature ECH support
  (`SSL_marshal_ech_config`, `SSL_ECH_KEYS_*`,
  `SSL_set1_ech_config_list`) is what makes server-side ECH possible
  in pure Rust today.
- The ACME flow (instant-acme) uses TLS-ALPN-01: when the ACME server
  validates a domain, it offers ALPN `acme-tls/1`. A
  `ChallengeStore` keyed by the SAN being validated lets the
  ALPN-select callback hot-swap the active SSL_CTX to a self-signed
  cert carrying `SHA-256(keyAuthorization)` in the `acmeIdentifier`
  extension. After validation, the entry is removed and traffic
  resumes on the production cert.
- Cert renewals hot-swap the production `SslAcceptor` via `arc-swap`;
  in-flight connections keep the old cert, new ones get the renewed.

## Threat model

In scope: passive DPI, SNI-based blocking, basic active probing
(connecting to your IP and inspecting the response).

Out of scope: traffic-analysis attacks (packet sizes, timing),
GFW-style replay-and-correlate, host compromise.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --lib --tests       # 58 tests, end-to-end against shadowsocks-rust
```

The full e2e test (`tests/sip003_e2e.rs`) requires `ssserver`,
`sslocal`, and `curl` on `PATH`; it skips with a clear message
otherwise.

See [`docs/PRD.md`](docs/PRD.md), [`docs/ROADMAP.md`](docs/ROADMAP.md),
and [`docs/TODO.md`](docs/TODO.md) for the design.

## License

MIT.
