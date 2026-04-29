//! ech-tls-tunnel: SIP003 plugin that wraps shadowsocks streams in
//! WebSocket-over-TLS with ECH-protected handshakes and ACME auto-renewal.
//!
//! See `docs/PRD.md` for the high-level design and `docs/ROADMAP.md` for
//! the milestone breakdown.

pub mod net;
pub mod sip003;
pub mod stealth;
