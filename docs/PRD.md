# ech-tls-tunnel — Product Requirements

## Problem

Shadowsocks traffic on the public internet is fingerprintable: even with an
encrypted payload, the TCP-level handshake, packet sizes, and timing make
it detectable to active probers and DPI. A common defense is to wrap the
shadowsocks stream in an ordinary-looking TLS+WebSocket flow on port 443
so the connection looks like a generic HTTPS website. But the TLS
ClientHello itself still leaks the destination via SNI, and SNI is
increasingly inspected and blocked.

## Solution

A SIP003-compatible plugin (Rust) that wraps each shadowsocks stream in a
WebSocket tunnel over TLS, with the TLS handshake protected by ECH
(Encrypted Client Hello). To external observers the connection looks
like a TLS request to a benign public name (e.g. `front.example.com`);
the real tunnel domain is encrypted inside the ECH-wrapped inner
ClientHello.

## Goals

- **G1**: One-binary deployment. The same binary runs as both the
  server-side and client-side plugin; mode is selected by an option key.
- **G2**: Drop-in SIP003 plugin compatible with `ssserver` / `sslocal`
  from `shadowsocks-rust` (and `ss-libev` as a stretch).
- **G3**: Auto-TLS via ACME / Let's Encrypt using **TLS-ALPN-01**
  (RFC 8737), so issuance and renewal happen on the existing port-443
  listener with no port 80 dependency. No manual cert copying for
  production.
- **G4**: ECH enabled for every connection in the standard configuration.
- **G5**: Stealth: HTTPS probes that don't hit the secret WS path get a
  fake nginx 404, indistinguishable from a stock nginx default.
- **G6**: Localhost end-to-end test using real `shadowsocks-rust`,
  self-signed cert, and `curl`. Reproducible without VPS access.
- **G7**: No separate config file. The plugin reads everything it needs
  from `SS_PLUGIN_OPTIONS`. This keeps deployment to one shadowsocks
  config edit and removes a class of "where does the config live"
  questions.

## Non-goals (v1)

- Multiplexing many shadowsocks connections in a single WebSocket.
- DNS HTTPS-record auto-publication of the ECH ConfigList.
- DoH-based ConfigList retrieval on the client.
- DNS-01 ACME challenge.
- TUI setup wizard.

## Users

- **Operator** of a single VPS who wants `ssserver + plugin` running
  behind one DNS record and a Let's Encrypt cert.
- **End user** running `sslocal + plugin` on macOS / Linux / Android
  (Android delivered later via a separate packaging effort).

## Success metrics

- `tests/sip003_e2e.rs` passes locally and in CI.
- Manual VPS test: `curl --socks5-hostname` over the tunnel succeeds;
  Wireshark capture shows outer SNI = `public_name`, ECHClientHello
  extension present, real domain not in cleartext.
- p50 added latency vs direct TLS+WS (no ECH): <5 ms localhost,
  <15 ms WAN.

## Threat model

- **In scope**: passive DPI, SNI-based blocking, basic active probing
  (an attacker that connects to the IP and inspects the response).
- **Out of scope**: traffic-analysis attacks (packet timing/sizes),
  GFW-style replay-and-correlate, compromise of the VPS.

## Constraints

- Pure-Rust where practical, with one carve-out: BoringSSL via `boring`
  + `tokio-boring` for the TLS layer, because rustls server-side ECH is
  not yet stable. ACME stays pure Rust via `instant-acme`.
- TLS-ALPN-01 challenges share the main port-443 listener via
  BoringSSL's ALPN-select callback (`SSL_set_SSL_CTX`); no second port.
- Single-process: no external broker, no shared state across instances.
