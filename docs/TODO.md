# TODO

Each item maps to a small, mergeable PR.

## v0.1 — TLS+WS tunnel (no ECH) ✅

- [x] `feature/sip003-skeleton` — crate scaffold + docs
- [x] Lift `src/net.rs` (TFO listener/connect) from `../https_proxy`
      with a unit test
- [x] Lift `src/stealth.rs` from `../https_proxy` with a unit test
- [x] `src/sip003.rs` — `SipEnv::from_env()` and the SIP003 plugin-options
      parser (escape-aware; first-`=`-wins for base64-friendly values)
- [x] `src/config.rs` — `Config::from_options(&PluginOptions)` builds
      `ServerCfg` / `ClientCfg` directly from `SS_PLUGIN_OPTIONS`. No
      YAML, no separate config file.
- [x] `src/tls_server.rs` — BoringSSL `SslAcceptor` from static
      `cert_file` + `key_file`, ALPN h2 + http/1.1, ArcSwap for
      hot-reload
- [x] `src/tls_client.rs` — `SslConnector` honoring all three
      `ClientTrust` modes (system roots, ca_file, insecure)
- [x] `src/ws.rs` — WebSocket byte-stream adapter
- [x] `src/server.rs` + `src/client.rs` — event loops with
      `copy_bidirectional`
- [x] `src/main.rs` — SIP003 dispatch + clap subcommands
- [x] `tests/sip003_e2e.rs` — full e2e against `shadowsocks-rust` +
      `curl`, all on `127.0.0.1`. Skips with a clear message when
      external binaries are missing.
- [x] CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test`
      with shadowsocks-rust installed on Linux + macOS

## v0.2 — ACME (TLS-ALPN-01) ✅

- [x] `src/acme.rs` — `instant-acme` flow: account, order,
      finalize, persistence under `cache_dir`
- [x] `ChallengeStore` (`RwLock<HashMap<String, Arc<SslContext>>>`)
      shared with `tls_server`
- [x] Challenge-cert builder via
      `rcgen::CustomExtension::new_acme_identifier`
- [x] BoringSSL ALPN-select callback in `tls_server.rs`: detect
      `acme-tls/1`, look up challenge cert by SNI, `SSL_set_SSL_CTX`
      swap, return `acme-tls/1`
- [x] TLS-ALPN-01 flow in `acme.rs`: install challenge → notify ACME →
      poll → remove challenge → finalize → install new cert via
      `arc-swap`
- [x] Renewal task (24h tick, renew when <30d remaining)
- [ ] `tests/acme.rs` against [Pebble](https://github.com/letsencrypt/pebble)
      (follow-up — needs Pebble in CI)
- [x] Doc: deployment recipe (single port, no port 80 needed) — see README.md

## v0.3 — ECH ✅

- [x] `src/ech.rs` — HPKE keygen (X25519/HKDF-SHA256), ECHConfig
      builder via BoringSSL `SSL_marshal_ech_config`, ECHConfigList
      serialization, file I/O
- [x] CLI `ech-gen-keys --public-name … --out …` writes files +
      prints base64 blob
- [x] Server: wire `SSL_CTX_set1_ech_keys` via `boring-sys` FFI
- [x] Client: wire `SSL_set1_ech_config_list` per connection
- [x] E2e test extended: ECH path actually wired through real
      shadowsocks-rust ssserver/sslocal (`sip003_full_pipeline_with_ech`)
- [ ] VPS smoke + Wireshark capture review (manual, follow-up)

## Post-v0.4 — Client browser fingerprint ✅

- [x] `src/fingerprint.rs` — `FingerprintParams` + 6 profile constants
      (Chrome, Firefox, Safari, iOS, Android, Edge) + `random` weighted
- [x] `fingerprint=` plugin option on the client side
- [x] Applied via boring's `set_cipher_list` / `set_curves_list` /
      `set_grease_enabled` / `set_permute_extensions` /
      `set_sigalgs_list`
- [x] Profiles ported from `metacubex/utls` `u_parrots.go` (via
      mihomo-rust's port)
- [x] e2e test runs the non-ECH path with `fingerprint=chrome`
      through real `sslocal`

## v0.4 — Polish ✅

- [x] README rewrite with deployment recipe
- [x] LICENSE (MIT)
- [x] Release workflow: linux-amd64, linux-arm64, darwin-arm64
      via `.github/workflows/release.yml`
- [x] systemd documentation (sample unit in README — the unit lives
      around `ssserver`, not the plugin, so a runtime subcommand
      would be the wrong abstraction)
- [x] Structured logs already use `tracing` throughout; no
      secret-bearing fields are logged

## Backlog / not v1

- [ ] `tests/acme.rs` against Pebble (live ACME issuance)
- [ ] DNS-01 ACME challenge
- [ ] DNS HTTPS-record helper to publish the ECH ConfigList
- [ ] Multiplexed mode (1 WS, many ss streams)
- [ ] ss-libev compatibility CI lane
