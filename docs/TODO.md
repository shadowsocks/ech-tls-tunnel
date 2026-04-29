# TODO

Each item maps to a small, mergeable PR. Strikethrough as completed.

## v0.1 — TLS+WS tunnel (no ECH)

- [ ] Branch `feature/sip003-skeleton`. `cargo init`, MIT license,
      `.gitignore`, baseline `Cargo.toml`.
- [ ] Lift `src/net.rs` (TFO listener/connect) from `../https_proxy`,
      adjust crate name, add a unit test that round-trips a TFO listen.
- [ ] Lift `src/stealth.rs` from `../https_proxy`, add a unit test
      that asserts `fake_404()` returns 404 + `Server` header.
- [ ] `src/sip003.rs` — `SipEnv::from_env()` and option parser; unit
      test with a synthetic env.
- [ ] `src/config.rs` — `Config`, `ServerCfg`, `ClientCfg`, `ServerTls`
      enum (`Acme | Static`), `ClientTrust` enum. Round-trip tests for
      the two example YAMLs.
- [ ] `src/tls_server.rs` — BoringSSL `SslAcceptor` from static
      `cert_file` + `key_file`. ALPN h2 + http/1.1. Wrapped in
      `ArcSwap` for future hot-reload.
- [ ] `src/tls_client.rs` — `SslConnector` with `ClientTrust` choice.
- [ ] `src/ws.rs` — server-side upgrade (hyper `on_upgrade` →
      `tokio_tungstenite::WebSocketStream::from_raw_socket`) and
      client-side `client_async`. Adapter mapping WS Binary frames ↔
      `AsyncRead+AsyncWrite`.
- [ ] `src/server.rs` — accept loop, hyper service, dispatch on
      `cfg.ws_path`, fake 404 otherwise, `copy_bidirectional` to the
      SIP003 upstream.
- [ ] `src/client.rs` — accept loop from ss-local, dial upstream,
      TLS+WS, `copy_bidirectional`.
- [ ] `src/cli.rs` — `clap` subcommands `run-server`, `run-client`,
      `ech gen-keys` (gen-keys is a stub here, real impl in v0.3).
- [ ] `src/main.rs` — default branch reads SS_* env and dispatches.
      Subcommands for standalone runs.
- [ ] `tests/sip003_e2e.rs` — full e2e test (see Verification section
      of the plan). Skips with a clear message if `ssserver`,
      `sslocal`, or `curl` are missing.
- [ ] CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test`,
      `cargo test --test sip003_e2e` on Linux runner that installs
      `shadowsocks-rust`.

## v0.2 — ACME (TLS-ALPN-01)

- [ ] `src/acme.rs` skeleton: `instant-acme` account creation, order,
      finalize, persistence (`account.json`, `cert.pem`, `key.pem`
      under `cache_dir`).
- [ ] `ChallengeStore` (`RwLock<HashMap<String, Arc<SslContext>>>`)
      shared with `tls_server`.
- [ ] Challenge-cert builder via
      `rcgen::CustomExtension::new_acme_identifier` (SHA-256 of
      keyAuthorization, OID 1.3.6.1.5.5.7.1.31).
- [ ] BoringSSL ALPN-select callback in `tls_server.rs`: detect
      `acme-tls/1`, look up challenge cert by SNI, `SSL_set_SSL_CTX`
      swap, return `acme-tls/1`. Unit test the callback with
      synthetic inputs.
- [ ] TLS-ALPN-01 flow in `acme.rs`: install challenge → notify ACME →
      poll → remove challenge → finalize → install new cert via
      `arc-swap`.
- [ ] Renewal task (24h tick, renew when <30d remaining).
- [ ] `tests/acme.rs` — drive a full issuance against
      [Pebble](https://github.com/letsencrypt/pebble) on `127.0.0.1`
      (Pebble installed by CI; skip locally if absent).
- [ ] Smoke test against Let's Encrypt **staging** on a VPS.
- [ ] Doc: deployment recipe (single port, no port 80 needed).

## v0.3 — ECH

- [ ] `src/ech.rs` — HPKE keygen (X25519/HKDF-SHA256/ChaCha20Poly1305),
      ECHConfig builder, ECHConfigList serializer (draft-22 wire
      format), file I/O.
- [ ] CLI `ech gen-keys --public-name … --out …` writes files +
      prints base64 blob.
- [ ] Server: wire `SSL_CTX_set1_ech_keys` via `boring-sys` FFI.
- [ ] Client: wire `SSL_set1_ech_config_list` per connection.
- [ ] E2e test extended: outer SNI assertion via a tiny TLS sniffer in
      the test (or by inspecting the hello captured at the upstream
      side).
- [ ] VPS smoke + Wireshark capture review.

## v0.4 — Polish

- [ ] Structured logs with secret redaction.
- [ ] systemd install/uninstall subcommands (Linux).
- [ ] Release artifacts: linux-amd64, linux-arm64, darwin-arm64.
- [ ] README rewrite with deployment recipe.

## Backlog / not v1

- [ ] DNS-01 ACME challenge.
- [ ] DNS HTTPS-record helper to publish the ECH ConfigList.
- [ ] Multiplexed mode (1 WS many ss streams).
- [ ] ss-libev compatibility CI lane.
