//! Shared QUIC / HTTP-3 plumbing for the `quiche`-backed transport.
//!
//! This module holds everything the server ([`crate::h3_server`]) and
//! client ([`crate::h3_client`]) event loops have in common:
//!
//! - building a [`quiche::Config`] from the project's existing BoringSSL
//!   cert/key (and ECH) wiring, via
//!   [`quiche::Config::with_boring_ssl_ctx_builder`];
//! - [`StreamState`], the per-stream send/receive bookkeeping;
//! - [`QuicStream`], an `AsyncRead + AsyncWrite` adapter over a single
//!   HTTP/3 request stream so the tunnels can reuse
//!   [`tokio::io::copy_bidirectional`] exactly like the WS path; and
//! - the [`pump_inbound`] / [`pump_outbound`] / [`flush_packets`] helpers
//!   that ferry bytes between `quiche` and the [`QuicStream`] channels.
//!
//! ## ECH on the HTTP/3 path
//!
//! ECH works here exactly as it does on TCP. `quiche` has no ECH API of
//! its own, but with its default `boringssl-boring-crate` feature
//! `quiche::Connection` implements `AsMut<boring::ssl::SslRef>`, and it
//! does not start the TLS handshake until the first
//! `Connection::send` — so there is a window after `quiche::connect`
//! in which the ClientHello has not been built yet.
//! [`install_client_ech`] uses that window to apply the client's
//! ECHConfigList via `SSL_set1_ech_config_list`, the same call
//! [`crate::tls_client`] makes on the TCP path. The QUIC Initial then
//! carries an ECHClientHello whose outer SNI is only the cover
//! `public_name`. Server-side, [`server_config`] installs the ECH keys
//! on the QUIC `SSL_CTX`.
//!
//! One TCP-only knob remains: `reject_non_ech`. [`crate::server`]
//! enforces it by peeking at the cleartext TCP ClientHello *before*
//! completing a handshake, so a probe never sees the production cert.
//! A QUIC Initial is encrypted under keys derived from its own DCID, so
//! the equivalent peek is impossible — [`crate::h3_server`] can only
//! check `SSL_ech_accepted` once the handshake (and therefore the
//! certificate) is already on the wire. It still drops those
//! connections, but on this transport that hides the tunnel, not the
//! cert.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod};
use boring::x509::X509;
use bytes::{Buf, Bytes};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::PollSender;

use crate::config::{ClientCfg, ClientTrust};
use crate::ech::{self, EchServerKey};

/// HTTP/3 ALPN token. QUIC mandates exactly one application protocol.
const H3_ALPN: &[&[u8]] = &[b"h3"];

/// Conservative QUIC datagram size that survives common MTUs without PMTU
/// discovery surprises. Matches the value used by `quiche`'s own examples.
pub const MAX_DATAGRAM_SIZE: usize = 1350;

/// Idle timeout for QUIC connections (ms). Kept generous so a quiet but
/// live tunnel isn't torn down between bursts.
const MAX_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Connection- and stream-level flow control windows. The connection
/// window bounds total in-flight bytes; the per-stream window bounds a
/// single tunnel. Together with the bounded inbound channel these provide
/// backpressure toward the peer.
const INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;
const INITIAL_MAX_STREAM_DATA: u64 = 4 * 1024 * 1024;
const MAX_STREAMS_BIDI: u64 = 256;
const MAX_STREAMS_UNI: u64 = 32;

/// Buffer size for a single `recv_body` read.
const RECV_CHUNK: usize = 16 * 1024;

/// Depth of a stream's QUIC→app channel, in [`RECV_CHUNK`]-sized chunks.
/// Bounds how much a slow tunnel peer can make an event loop buffer
/// before [`pump_inbound`] stops draining `quiche` and the QUIC
/// flow-control window closes behind it.
pub const INBOUND_CHANNEL_CAP: usize = 32;

/// A freshly generated random source connection ID.
pub fn random_scid() -> [u8; quiche::MAX_CONN_ID_LEN] {
    let mut id = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill(&mut id[..]);
    id
}

fn apply_common(config: &mut quiche::Config) {
    config.set_max_idle_timeout(MAX_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);
}

/// Build the server-side BoringSSL context from in-memory PEM material,
/// installing ECH keys when configured. No ALPN is set here — `quiche`
/// pins the QUIC ALPN itself via [`quiche::Config::set_application_protos`].
fn server_ssl_ctx(
    cert_pem: &str,
    key_pem: &str,
    ech: Option<&crate::config::ServerEch>,
) -> Result<SslContextBuilder> {
    let mut b = SslContextBuilder::new(SslMethod::tls()).context("init SslContextBuilder")?;
    let mut x509s = X509::stack_from_pem(cert_pem.as_bytes()).context("parse cert chain pem")?;
    let mut iter = x509s.drain(..);
    let leaf = iter.next().ok_or_else(|| anyhow!("empty cert chain"))?;
    b.set_certificate(&leaf).context("set leaf cert")?;
    for ca in iter {
        b.add_extra_chain_cert(ca).context("add chain cert")?;
    }
    let pkey = PKey::private_key_from_pem(key_pem.as_bytes()).context("parse private key pem")?;
    b.set_private_key(&pkey).context("set private key")?;
    b.check_private_key().context("cert/key pair check")?;

    if let Some(cfg) = ech {
        let key = EchServerKey::read_from(&cfg.key_file)
            .with_context(|| format!("read ECH key {}", cfg.key_file.display()))?;
        key.install_on_ctx_builder(&b)?;
        tracing::info!(
            "HTTP/3 ECH keys installed (public_name={})",
            key.public_name()
        );
    }
    Ok(b)
}

/// Build a server [`quiche::Config`] for HTTP/3 from PEM cert material.
pub fn server_config(
    cert_pem: &str,
    key_pem: &str,
    ech: Option<&crate::config::ServerEch>,
) -> Result<quiche::Config> {
    let ctx = server_ssl_ctx(cert_pem, key_pem, ech)?;
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ctx)
        .map_err(|e| anyhow!("quiche server config: {e}"))?;
    config
        .set_application_protos(H3_ALPN)
        .map_err(|e| anyhow!("set h3 ALPN: {e}"))?;
    config.verify_peer(false);
    apply_common(&mut config);
    Ok(config)
}

/// Build a client [`quiche::Config`] honoring the [`ClientTrust`] mode.
pub fn client_config(cfg: &ClientCfg) -> Result<quiche::Config> {
    let mut b = SslContextBuilder::new(SslMethod::tls()).context("init SslContextBuilder")?;
    let verify = match &cfg.trust {
        ClientTrust::SystemRoots => {
            b.set_default_verify_paths()
                .context("set default verify paths")?;
            true
        }
        ClientTrust::CaFile(path) => {
            let pem =
                std::fs::read(path).with_context(|| format!("read ca file {}", path.display()))?;
            let cert = X509::from_pem(&pem).context("parse ca pem")?;
            b.cert_store_mut()
                .add_cert(cert)
                .context("add ca cert to store")?;
            true
        }
        ClientTrust::InsecureSkipVerify => false,
    };

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, b)
        .map_err(|e| anyhow!("quiche client config: {e}"))?;
    config
        .set_application_protos(H3_ALPN)
        .map_err(|e| anyhow!("set h3 ALPN: {e}"))?;
    config.verify_peer(verify);
    apply_common(&mut config);
    Ok(config)
}

/// Apply the client's ECHConfigList to a freshly created
/// [`quiche::Connection`], before its first `send` builds the
/// ClientHello. No-op when ECH isn't configured.
///
/// Must be called between [`quiche::connect`] and the first
/// [`flush_packets`]; afterwards the ClientHello is already encoded and
/// the call would be silently too late.
pub fn install_client_ech(conn: &mut quiche::Connection, cfg: &ClientCfg) -> Result<()> {
    let Some(src) = &cfg.ech else { return Ok(()) };
    let list = ech::load_client_config_list(src)?;
    ech::install_client_ech_config_list(conn.as_mut(), &list)
        .context("install client ECH config list on QUIC connection")?;
    tracing::debug!("HTTP/3 ECHClientHello armed ({} bytes)", list.len());
    Ok(())
}

/// HTTP/3 settings shared by both roles. Extended CONNECT is advertised so
/// the WebSocket-over-HTTP/3 (RFC 9220) bootstrap is available.
pub fn h3_config() -> Result<quiche::h3::Config> {
    let mut h3 = quiche::h3::Config::new().map_err(|e| anyhow!("h3 config: {e}"))?;
    h3.enable_extended_connect(true);
    Ok(h3)
}

/// An app→QUIC message destined for a particular stream, produced by a
/// [`QuicStream`] (or the bridge task on teardown) and consumed by the
/// owning event loop.
pub enum StreamOut {
    /// Payload bytes to forward as an HTTP/3 DATA frame.
    Data(Bytes),
    /// The local write side closed; finish the stream.
    Fin,
    /// The bridge task finished entirely; the loop may drop the stream.
    Closed,
}

/// A routed [`StreamOut`]. `key` identifies the QUIC connection (the
/// server multiplexes many); the client uses a single connection and
/// ignores it.
pub struct Egress {
    pub key: Vec<u8>,
    pub stream_id: u64,
    pub out: StreamOut,
}

/// Per-stream send/receive state owned by an event loop.
pub struct StreamState {
    /// QUIC→app delivery. `None` once EOF has been signalled (peer fin or
    /// teardown).
    inbound_tx: Option<mpsc::Sender<Bytes>>,
    /// Set when an `Event::Data` (or `Finished`) arrives; drives
    /// [`pump_inbound`]. Cleared once `recv_body` drains to `Done`.
    readable: bool,
    /// app→QUIC bytes not yet accepted by `send_body` (flow-control blocked).
    pending: VecDeque<Bytes>,
    /// A fin is owed once `pending` drains.
    fin_pending: bool,
    fin_sent: bool,
    /// The bridge task has finished; [`reap_streams`] may drop this
    /// stream once everything queued has been handed to `quiche`.
    closed: bool,
}

impl StreamState {
    /// A tunnel stream wired to `inbound_tx` (QUIC→app).
    pub fn tunnel(inbound_tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            inbound_tx: Some(inbound_tx),
            readable: false,
            pending: VecDeque::new(),
            fin_pending: false,
            fin_sent: false,
            closed: false,
        }
    }

    pub fn mark_readable(&mut self) {
        self.readable = true;
    }

    /// Apply an outbound message produced by the [`QuicStream`].
    pub fn queue(&mut self, out: StreamOut) {
        match out {
            StreamOut::Data(b) => self.pending.push_back(b),
            StreamOut::Fin => self.fin_pending = true,
            StreamOut::Closed => self.closed = true,
        }
    }
}

/// Read all currently-available body bytes for readable streams into their
/// inbound channels, applying backpressure: a full channel leaves the data
/// in `quiche` (so the QUIC flow-control window stops opening) and the
/// stream stays `readable` for a later retry.
pub fn pump_inbound(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    streams: &mut std::collections::HashMap<u64, StreamState>,
) {
    let mut buf = [0u8; RECV_CHUNK];
    for (&sid, st) in streams.iter_mut() {
        if !st.readable {
            continue;
        }
        let Some(tx) = st.inbound_tx.clone() else {
            st.readable = false;
            continue;
        };
        loop {
            match tx.try_reserve() {
                Ok(permit) => match h3.recv_body(conn, sid, &mut buf) {
                    Ok(n) => permit.send(Bytes::copy_from_slice(&buf[..n])),
                    Err(quiche::h3::Error::Done) => {
                        st.readable = false;
                        if conn.stream_finished(sid) {
                            st.inbound_tx = None; // EOF to the bridge
                        }
                        break;
                    }
                    Err(_) => {
                        st.readable = false;
                        st.inbound_tx = None;
                        break;
                    }
                },
                // Channel full: keep `readable`, retry when the bridge drains.
                Err(mpsc::error::TrySendError::Full(())) => break,
                // Bridge gone: stop reading this stream.
                Err(mpsc::error::TrySendError::Closed(())) => {
                    st.readable = false;
                    st.inbound_tx = None;
                    let _ = conn.stream_shutdown(sid, quiche::Shutdown::Read, 0);
                    break;
                }
            }
        }
    }
}

/// Flush each stream's queued app→QUIC bytes (and any owed fin) via
/// `send_body`, retrying partial / flow-control-blocked writes later.
pub fn pump_outbound(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    streams: &mut std::collections::HashMap<u64, StreamState>,
) {
    for (&sid, st) in streams.iter_mut() {
        while let Some(front) = st.pending.front_mut() {
            match h3.send_body(conn, sid, &front[..], false) {
                Ok(n) if n == front.len() => {
                    st.pending.pop_front();
                }
                Ok(n) => {
                    front.advance(n);
                    break; // stream send buffer full
                }
                Err(quiche::h3::Error::Done) => break,
                Err(_) => {
                    st.pending.clear();
                    st.fin_sent = true;
                    break;
                }
            }
        }
        if st.pending.is_empty() && st.fin_pending && !st.fin_sent {
            match h3.send_body(conn, sid, &[], true) {
                Ok(_) => st.fin_sent = true,
                Err(quiche::h3::Error::Done) => {}
                Err(_) => st.fin_sent = true,
            }
        }
    }
}

/// Drop streams whose bridge task has finished and whose queued bytes
/// have all been handed to `quiche`. A stream that never got to send its
/// fin (the bridge aborted mid-copy) is reset instead, so the peer isn't
/// left waiting on a half-open tunnel.
///
/// Call after [`pump_outbound`], which is what clears `pending` and sets
/// the fin as sent.
pub fn reap_streams(
    conn: &mut quiche::Connection,
    streams: &mut std::collections::HashMap<u64, StreamState>,
) {
    streams.retain(|&sid, st| {
        let drained = st.pending.is_empty() && (!st.fin_pending || st.fin_sent);
        if !st.closed || !drained {
            return true;
        }
        if !st.fin_sent {
            let _ = conn.stream_shutdown(sid, quiche::Shutdown::Write, 0);
        }
        if !conn.stream_finished(sid) {
            let _ = conn.stream_shutdown(sid, quiche::Shutdown::Read, 0);
        }
        false
    });
}

/// Drain all of `quiche`'s queued datagrams to the socket. When `connected`
/// the socket is already `connect()`ed to the peer (client side); otherwise
/// each datagram is sent to the address `quiche` reports (server side).
pub async fn flush_packets(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    connected: bool,
) -> std::io::Result<()> {
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((n, info)) => {
                if connected {
                    socket.send(&out[..n]).await?;
                } else {
                    socket.send_to(&out[..n], info.to).await?;
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => {
                return Err(std::io::Error::other(format!("quiche send: {e}")));
            }
        }
    }
}

/// `AsyncRead + AsyncWrite` view of one HTTP/3 request stream, backed by
/// channels to the owning event loop. Mirrors [`crate::ws::WsByteStream`]
/// so the tunnels can drive it with [`tokio::io::copy_bidirectional`].
pub struct QuicStream {
    key: Vec<u8>,
    stream_id: u64,
    rx: mpsc::Receiver<Bytes>,
    rx_buf: Bytes,
    rx_eof: bool,
    read_credit: Arc<Notify>,
    tx: PollSender<Egress>,
    shutdown_sent: bool,
}

impl QuicStream {
    /// `rx` carries QUIC→app bytes; `egress` carries app→QUIC messages back
    /// to the loop; `read_credit` wakes the loop after the adapter frees a
    /// slot in `rx` so it can resume reading flow-control-blocked data.
    pub fn new(
        key: Vec<u8>,
        stream_id: u64,
        rx: mpsc::Receiver<Bytes>,
        read_credit: Arc<Notify>,
        egress: mpsc::Sender<Egress>,
    ) -> Self {
        Self {
            key,
            stream_id,
            rx,
            rx_buf: Bytes::new(),
            rx_eof: false,
            read_credit,
            tx: PollSender::new(egress),
            shutdown_sent: false,
        }
    }

    /// The [`StreamOut::Closed`] message the bridge task owes the event
    /// loop once it is done with this stream. Sending it is what lets
    /// [`reap_streams`] drop the loop's [`StreamState`]; without it the
    /// entry leaks until the whole connection goes away.
    pub fn close_notice(&self) -> Egress {
        Egress {
            key: self.key.clone(),
            stream_id: self.stream_id,
            out: StreamOut::Closed,
        }
    }
}

/// Run a tunnel: copy bytes both ways between one HTTP/3 stream and its
/// local peer (the `ssserver` socket on the server, the `sslocal` socket
/// on the client), then tell the owning event loop the stream is done.
///
/// This is the HTTP/3 analogue of the `copy_bidirectional` call the
/// WebSocket path makes in [`crate::server`] / [`crate::client`].
pub async fn bridge<S>(mut stream: QuicStream, mut peer: S, egress: mpsc::Sender<Egress>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let close = stream.close_notice();
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut peer).await {
        tracing::debug!("h3 stream {}: bidi-copy ended: {e:#}", close.stream_id);
    }
    // Drop first: the loop must see the fin `poll_shutdown` queued before
    // it sees the close notice, and dropping releases the inbound channel.
    drop(stream);
    let _ = egress.send(close).await;
}

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn broken_pipe() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "quic event loop gone")
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.rx_buf.is_empty() {
                let n = buf.remaining().min(this.rx_buf.len());
                buf.put_slice(&this.rx_buf[..n]);
                this.rx_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.rx_eof {
                return Poll::Ready(Ok(())); // EOF
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => {
                    this.read_credit.notify_one();
                    this.rx_buf = b;
                }
                Poll::Ready(None) => {
                    this.rx_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Err(broken_pipe()));
        }
        match this.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Egress {
                    key: this.key.clone(),
                    stream_id: this.stream_id,
                    out: StreamOut::Data(Bytes::copy_from_slice(buf)),
                };
                this.tx.send_item(msg).map_err(|_| broken_pipe())?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(broken_pipe())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        match this.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Egress {
                    key: this.key.clone(),
                    stream_id: this.stream_id,
                    out: StreamOut::Fin,
                };
                let _ = this.tx.send_item(msg);
                this.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                this.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
