//! Client-side HTTP/3 event loop: accept plain TCP from `sslocal`, open
//! one QUIC stream per connection against the upstream, pipe the payload
//! bytes through.
//!
//! This is the QUIC sibling of [`crate::client`], selected with
//! `transport=h3`. The visible difference from the TCP path is
//! multiplexing: every accepted `sslocal` connection becomes a stream on
//! a *single* QUIC connection, so only the first one pays for a
//! handshake and a stalled stream can't head-of-line-block the others.
//!
//! ## Shape of the loop
//!
//! `quiche` state lives in one task ([`session`]), which owns the UDP
//! socket, the [`quiche::Connection`], and the HTTP/3 connection. The
//! accept loop asks it for a stream over an `mpsc` and gets a
//! [`quic::QuicStream`] back; from there the bridge task drives
//! `copy_bidirectional` exactly as the WebSocket path does.
//!
//! A session lasts as long as the QUIC connection does. If it dies —
//! idle timeout, network change, the server going away — the streams on
//! it see EOF and the next accepted connection starts a fresh session.
//! Connecting is lazy: nothing is dialled until `sslocal` hands us
//! something to carry.
//!
//! ECH applies here just as it does on TCP; see the [`crate::quic`]
//! module docs for how it reaches `quiche`'s BoringSSL handshake.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quiche::h3::{Header, NameValue};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, warn};

use crate::config::ClientCfg;
use crate::net;
use crate::quic::{self, Egress, QuicStream, StreamState};

/// Bound on queued app→QUIC messages across all streams of a session.
const EGRESS_CHANNEL_CAP: usize = 256;

/// Bound on accepted-but-not-yet-opened connections.
const OPEN_CHANNEL_CAP: usize = 64;

/// Parked sleep duration when the connection has no timer armed.
const IDLE_TICK: Duration = Duration::from_secs(3600);

/// How long a QUIC handshake may take before we give up on the session.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Sent on requests so the traffic reads like a browser opening a
/// WebSocket rather than a bespoke client. The TCP path gets its
/// equivalent shaping from `fingerprint=`, which doesn't apply here.
const USER_AGENT: &[u8] =
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
      Chrome/131.0.0.0 Safari/537.36";

/// A request from the accept loop for one new tunnel stream.
struct OpenReq {
    reply: oneshot::Sender<Opened>,
}

/// A stream the session opened, plus the egress handle its bridge task
/// needs to report the stream finished.
struct Opened {
    stream: QuicStream,
    egress: mpsc::Sender<Egress>,
}

/// Bind, accept, and serve until the listener errors.
///
/// `listen_addr` is the loopback bind for `sslocal`; `upstream_addr` is
/// the public plugin endpoint, reached over UDP rather than TCP here.
pub async fn run(listen_addr: &str, upstream_addr: &str, cfg: ClientCfg) -> Result<()> {
    let listener = net::create_listener(listen_addr, cfg.fast_open).await?;
    let cfg = Arc::new(cfg);

    let (open_tx, open_rx) = mpsc::channel::<OpenReq>(OPEN_CHANNEL_CAP);
    tokio::spawn(manager(upstream_addr.to_string(), cfg.clone(), open_rx));

    tracing::info!("listening on {listen_addr} (http/3 upstream {upstream_addr})");
    loop {
        let (mut tcp_in, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error: {e:#}");
                continue;
            }
        };
        let open_tx = open_tx.clone();

        tokio::spawn(async move {
            let (reply, rx) = oneshot::channel();
            if open_tx.send(OpenReq { reply }).await.is_err() {
                warn!("{peer}: h3 session manager gone");
                return;
            }
            // The sender is dropped without a reply when the session
            // failed to come up or the connection died first.
            let Ok(Opened { stream, egress }) = rx.await else {
                warn!("{peer}: no h3 stream available");
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_in).await;
                return;
            };
            quic::bridge(stream, tcp_in, egress).await;
        });
    }
}

/// Own the upstream connection across its lifetime, reconnecting on the
/// next demand after one dies.
async fn manager(upstream: String, cfg: Arc<ClientCfg>, mut open_rx: mpsc::Receiver<OpenReq>) {
    // Nothing is dialled until there is traffic to carry, so an idle
    // plugin holds no QUIC connection open.
    while let Some(first) = open_rx.recv().await {
        match session(&upstream, &cfg, first, &mut open_rx).await {
            Ok(()) => debug!("h3 session to {upstream} ended"),
            Err(e) => warn!("h3 session to {upstream}: {e:#}"),
        }
    }
}

/// Establish one QUIC connection and run it until it closes, serving
/// stream-open requests for as long as it lives.
async fn session(
    upstream: &str,
    cfg: &ClientCfg,
    first: OpenReq,
    open_rx: &mut mpsc::Receiver<OpenReq>,
) -> Result<()> {
    let peer = tokio::net::lookup_host(upstream)
        .await
        .with_context(|| format!("resolve {upstream}"))?
        .next()
        .ok_or_else(|| anyhow!("{upstream} resolved to no addresses"))?;

    let bind: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().expect("literal addr")
    } else {
        "[::]:0".parse().expect("literal addr")
    };
    let socket = UdpSocket::bind(bind).await.context("bind udp")?;
    socket
        .connect(peer)
        .await
        .with_context(|| format!("connect udp {peer}"))?;
    let local = socket.local_addr().context("udp local_addr")?;

    let mut config = quic::client_config(cfg)?;
    let scid_bytes = quic::random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut quic_conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)
        .map_err(|e| anyhow!("quiche::connect: {e}"))?;

    // Must happen before the first flush: that is what builds the
    // ClientHello the ECH extension has to be part of.
    quic::install_client_ech(&mut quic_conn, cfg)?;

    let mut buf = vec![0u8; 65535];
    quic::flush_packets(&mut quic_conn, &socket, true).await?;
    handshake(&mut quic_conn, &socket, &mut buf, peer, local).await?;
    debug!(
        "h3 connected to {peer} (ech={})",
        crate::ech::ech_accepted(quic_conn.as_mut())
    );

    let h3_cfg = quic::h3_config()?;
    let mut h3 = quiche::h3::Connection::with_transport(&mut quic_conn, &h3_cfg)
        .map_err(|e| anyhow!("h3 init: {e}"))?;

    let (egress_tx, mut egress_rx) = mpsc::channel::<Egress>(EGRESS_CHANNEL_CAP);
    let read_credit = Arc::new(Notify::new());
    let mut streams: HashMap<u64, StreamState> = HashMap::new();

    let mut pending = Some(first);
    loop {
        // Extended CONNECT is a SETTINGS-gated capability, so requests
        // wait for the server's SETTINGS to arrive. Everything else in
        // the loop keeps running while that happens.
        if let Some(req) = pending.take() {
            if h3.extended_connect_enabled_by_peer() {
                open_stream(
                    &mut quic_conn,
                    &mut h3,
                    cfg,
                    &mut streams,
                    &egress_tx,
                    &read_credit,
                    req,
                );
            } else {
                pending = Some(req);
            }
        }

        let next_timeout = quic_conn.timeout();
        let accepting = pending.is_none();

        tokio::select! {
            res = socket.recv(&mut buf) => {
                let len = res.context("udp recv")?;
                let info = quiche::RecvInfo { from: peer, to: local };
                if let Err(e) = quic_conn.recv(&mut buf[..len], info) {
                    debug!("quiche recv: {e}");
                }
            }

            // Disabled while a request is parked waiting for SETTINGS,
            // so requests are served strictly in arrival order.
            Some(req) = open_rx.recv(), if accepting => {
                pending = Some(req);
            }

            Some(msg) = egress_rx.recv() => {
                if let Some(st) = streams.get_mut(&msg.stream_id) {
                    st.queue(msg.out);
                }
            }

            _ = read_credit.notified() => {}

            _ = tokio::time::sleep(next_timeout.unwrap_or(IDLE_TICK)) => {
                quic_conn.on_timeout();
            }
        }

        poll_h3(&mut quic_conn, &mut h3, &mut streams);
        quic::pump_inbound(&mut quic_conn, &mut h3, &mut streams);
        quic::pump_outbound(&mut quic_conn, &mut h3, &mut streams);
        quic::reap_streams(&mut quic_conn, &mut streams);
        quic::flush_packets(&mut quic_conn, &socket, true).await?;

        if quic_conn.is_closed() {
            // Dropping `streams` here is what gives every live bridge
            // task its EOF; the next open request starts a new session.
            if let Some(e) = quic_conn.peer_error() {
                debug!("peer closed connection: code {}", e.error_code);
            }
            return Ok(());
        }
    }
}

/// Drive the connection until the TLS handshake completes.
async fn handshake(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    buf: &mut [u8],
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    while !conn.is_established() {
        let next_timeout = conn.timeout();
        tokio::select! {
            res = socket.recv(buf) => {
                let len = res.context("udp recv during handshake")?;
                let info = quiche::RecvInfo { from: peer, to: local };
                if let Err(e) = conn.recv(&mut buf[..len], info) {
                    debug!("quiche recv during handshake: {e}");
                }
            }
            _ = tokio::time::sleep(next_timeout.unwrap_or(IDLE_TICK)) => conn.on_timeout(),
            _ = tokio::time::sleep_until(deadline) => {
                bail!("quic handshake to {peer} timed out after {HANDSHAKE_TIMEOUT:?}");
            }
        }
        quic::flush_packets(conn, socket, true).await?;

        if conn.is_closed() {
            // A rejected ECHConfigList lands here too: BoringSSL fails
            // the handshake rather than falling back in the clear.
            bail!(
                "quic handshake to {peer} failed (peer_error={:?})",
                conn.peer_error().map(|e| e.error_code)
            );
        }
    }
    Ok(())
}

/// Send one WebSocket Extended CONNECT (RFC 9220) request and hand the
/// resulting stream to the waiting accept task.
fn open_stream(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    cfg: &ClientCfg,
    streams: &mut HashMap<u64, StreamState>,
    egress_tx: &mpsc::Sender<Egress>,
    read_credit: &Arc<Notify>,
    req: OpenReq,
) {
    let headers = [
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"websocket"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", cfg.sni.as_bytes()),
        Header::new(b":path", cfg.ws_path.as_bytes()),
        Header::new(b"sec-websocket-version", b"13"),
        Header::new(b"user-agent", USER_AGENT),
    ];

    let sid = match h3.send_request(conn, &headers, false) {
        Ok(sid) => sid,
        Err(e) => {
            // Dropping `req.reply` is the accept task's signal to close
            // the `sslocal` connection it was holding.
            warn!("h3 send_request: {e}");
            return;
        }
    };

    let (inbound_tx, inbound_rx) = mpsc::channel(quic::INBOUND_CHANNEL_CAP);
    streams.insert(sid, StreamState::tunnel(inbound_tx));

    // The connection key is only meaningful to the server, which
    // multiplexes many; here there is exactly one.
    let stream = QuicStream::new(
        Vec::new(),
        sid,
        inbound_rx,
        read_credit.clone(),
        egress_tx.clone(),
    );
    let opened = Opened {
        stream,
        egress: egress_tx.clone(),
    };
    if req.reply.send(opened).is_err() {
        // The accept task gave up while we were opening; don't leave a
        // half-open stream on the wire.
        debug!("h3 stream {sid}: requester vanished");
        streams.remove(&sid);
        let _ = conn.stream_shutdown(sid, quiche::Shutdown::Write, 0);
        let _ = conn.stream_shutdown(sid, quiche::Shutdown::Read, 0);
        return;
    }
    debug!("h3 stream {sid} opened");
}

/// Drain `quiche`'s HTTP/3 event queue.
fn poll_h3(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    streams: &mut HashMap<u64, StreamState>,
) {
    loop {
        match h3.poll(conn) {
            Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                if !is_success(&list) {
                    // Wrong path, server not configured for the tunnel,
                    // a real 404 from a real web server: all the same
                    // to us. Drop the stream so the bridge sees EOF.
                    warn!("h3 stream {sid}: upstream refused CONNECT");
                    streams.remove(&sid);
                    let _ = conn.stream_shutdown(sid, quiche::Shutdown::Read, 0);
                }
            }
            Ok((sid, quiche::h3::Event::Data)) => {
                if let Some(st) = streams.get_mut(&sid) {
                    st.mark_readable();
                }
            }
            Ok((sid, quiche::h3::Event::Finished)) => {
                if let Some(st) = streams.get_mut(&sid) {
                    st.mark_readable();
                }
            }
            Ok((sid, quiche::h3::Event::Reset(code))) => {
                debug!("h3 stream {sid} reset by peer (code {code})");
                streams.remove(&sid);
            }
            Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
            Ok((_, quiche::h3::Event::GoAway)) => {
                debug!("h3 GOAWAY from peer");
            }
            Err(quiche::h3::Error::Done) => return,
            Err(e) => {
                debug!("h3 poll: {e}");
                return;
            }
        }
    }
}

/// Whether a response header list carries a 2xx `:status`.
fn is_success(list: &[Header]) -> bool {
    list.iter()
        .find(|h| h.name() == b":status")
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|v| v.parse::<u16>().ok())
        .is_some_and(|s| (200..300).contains(&s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_success_accepts_2xx_only() {
        let ok = [Header::new(b":status", b"200")];
        assert!(is_success(&ok));

        let created = [Header::new(b":status", b"204")];
        assert!(is_success(&created));

        let not_found = [
            Header::new(b":status", b"404"),
            Header::new(b"server", b"nginx/1.24.0"),
        ];
        assert!(!is_success(&not_found));

        let redirect = [Header::new(b":status", b"301")];
        assert!(!is_success(&redirect));
    }

    #[test]
    fn is_success_rejects_missing_or_malformed_status() {
        assert!(!is_success(&[]));
        assert!(!is_success(&[Header::new(b"server", b"nginx")]));
        assert!(!is_success(&[Header::new(b":status", b"abc")]));
    }
}
