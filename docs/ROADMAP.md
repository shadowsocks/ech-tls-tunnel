# Roadmap

## v0.1 — TLS+WS tunnel, no ECH yet

- SIP003 env-var parsing.
- Config builder over `SS_PLUGIN_OPTIONS` (no separate config file).
- TFO listener/connect (lifted from `https_proxy`).
- Stealth fake-nginx 404 (lifted from `https_proxy`).
- BoringSSL server with **static cert/key files** (no ACME yet).
- BoringSSL client with **CA file** trust path.
- WS upgrade (server) and WS handshake (client).
- `bidi-copy` between WS payload and the SIP003 upstream/downstream TCP.
- `tests/sip003_e2e.rs` — full localhost e2e with `shadowsocks-rust`
  ssserver/sslocal + curl + in-process echo server.

**Definition of done**: e2e test green on macOS and Linux CI.

## v0.2 — ACME (TLS-ALPN-01)

- `instant-acme` integration: account registration, order, **TLS-ALPN-01**
  challenge, finalize, persistence under `cache_dir`.
- BoringSSL ALPN-select callback that swaps to a per-domain challenge
  `SslContext` when ALPN `acme-tls/1` is offered.
- Challenge-cert builder using `rcgen`'s
  `CustomExtension::new_acme_identifier`.
- Hot reload of the production cert into the running `SslAcceptor` via
  `arc-swap`.
- Background renewal task (24h timer, <30d remaining triggers renew).
- Multi-SAN cert covering both `domain` and `ech.public_name`.
- `tests/acme.rs` integration test against
  [Pebble](https://github.com/letsencrypt/pebble) on `127.0.0.1`.

**Definition of done**: VPS smoke test against Let's Encrypt staging
succeeds end-to-end on port 443 alone; `curl https://<domain>/` returns
fake nginx 404.

## v0.3 — ECH

- HPKE keypair generation (`hpke` crate).
- ECHConfigList encode/decode per draft-ietf-tls-esni-22.
- `ech gen-keys` CLI subcommand: writes private key + ConfigList,
  prints base64 blob.
- Server: `SSL_CTX_set1_ech_keys` via `boring-sys` FFI.
- Client: `SSL_set1_ech_config_list` per connection.
- E2e test extended to assert ECH path is exercised (synthetic check
  via outer SNI = `public_name`).

**Definition of done**: Wireshark capture on a real VPS shows outer
SNI = `public_name`, ECHClientHello extension present.

## v0.4 — Polish

- Structured logging with redaction of secret material.
- `systemd` install/uninstall subcommands (Linux, lifted from
  `https_proxy`).
- Linux ARM64 + AMD64 release artifacts; macOS ARM64 dev build.
- README with end-to-end deployment recipe (DNS, ACME, ECH ConfigList
  sharing, ssserver invocation).

## v1.0 — Out of beta

- Documented threat model and limitations.
- A real test in CI that runs `shadowsocks-rust` + this plugin against
  a self-signed cert.
- Versioned config schema (rejects unknown keys with a clear error).

## Future (post-1.0, not committed)

- DNS-01 ACME for hosts where port 80 isn't available.
- DNS HTTPS-record helper to publish the ECH ConfigList.
- Multiplexed mode (1 WS for many ss streams) — open question whether
  the latency/jitter tradeoff is worth it.
- ss-libev compatibility test in CI.
