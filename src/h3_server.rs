//! Server-side HTTP/3 event loop: terminate QUIC+TLS on a UDP socket,
//! accept the WebSocket Extended CONNECT (RFC 9220) on the secret path,
//! and pipe each stream's payload bytes to the loopback `ssserver`.
//!
//! This is the QUIC sibling of [`crate::server`]. Same contract, same
//! stealth behaviour: a request that doesn't hit `ws_path` gets the
//! nginx-shaped 404 from [`crate::stealth`], so the listener looks like
//! an HTTP/3 web server with nothing on it.
//!
//! ## Shape of the loop
//!
//! One task owns the UDP socket and every live [`quiche::Connection`];
//! `quiche` is not `Sync` and its connection state must be touched from
//! a single place. Per-stream tunnels run as their own tasks and talk to
//! this loop over channels: [`quic::QuicStream`] carries QUIC→app bytes
//! in on an `mpsc` and app→QUIC bytes back out as [`quic::Egress`]
//! messages tagged with the connection key and stream ID.
//!
//! ## Certificates
//!
//! [`CertSource`] holds the live PEM material behind an `ArcSwap`, the
//! same hot-swap shape [`crate::tls_server::TlsServer`] uses for the TCP
//! acceptor, so an ACME renewal reaches the QUIC listener too. Rebuilding
//! a [`quiche::Config`] means re-parsing the chain, so the loop caches
//! one and only rebuilds when the generation counter moves.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use quiche::h3::{Header, NameValue};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::config::{ServerCfg, ServerTls};
use crate::ech;
use crate::net;
use crate::quic::{self, Egress, QuicStream, StreamState};
use crate::stealth::FAKE_404_BODY;

/// Bound on queued app→QUIC messages across all streams of the listener.
const EGRESS_CHANNEL_CAP: usize = 256;

/// Parked sleep duration when no connection has a timer armed.
const IDLE_TICK: Duration = Duration::from_secs(3600);

/// The cert/key PEM the QUIC listener is currently serving, plus a
/// generation counter so the loop can tell when it has to rebuild its
/// [`quiche::Config`].
struct Pem {
    generation: u64,
    cert_pem: String,
    key_pem: String,
}

/// Hot-swappable cert material for the HTTP/3 listener.
///
/// [`crate::server`] owns one of these and calls [`CertSource::swap`]
/// whenever it installs new ACME material, mirroring what it does to the
/// TCP acceptor via [`crate::tls_server::TlsServer::swap`].
pub struct CertSource {
    current: ArcSwap<Pem>,
    next_generation: AtomicU64,
}

impl std::fmt::Debug for CertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertSource").finish_non_exhaustive()
    }
}

impl CertSource {
    pub fn new(cert_pem: String, key_pem: String) -> Self {
        Self {
            current: ArcSwap::from_pointee(Pem {
                generation: 0,
                cert_pem,
                key_pem,
            }),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Read the PEM files named by a [`ServerTls::Static`] config.
    pub fn from_static_cfg(cfg: &ServerCfg) -> Result<Self> {
        let ServerTls::Static {
            cert_file,
            key_file,
        } = &cfg.tls
        else {
            return Err(anyhow!(
                "from_static_cfg called with tls=acme; seed from the ACME material instead"
            ));
        };
        let cert_pem = std::fs::read_to_string(cert_file)
            .with_context(|| format!("read cert {}", cert_file.display()))?;
        let key_pem = std::fs::read_to_string(key_file)
            .with_context(|| format!("read key {}", key_file.display()))?;
        Ok(Self::new(cert_pem, key_pem))
    }

    /// Publish new material. Connections already established keep the
    /// cert they handshook with; the next one picks this up.
    pub fn swap(&self, cert_pem: String, key_pem: String) {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.current.store(Arc::new(Pem {
            generation,
            cert_pem,
            key_pem,
        }));
    }
}

/// Everything a connection needs from the listener that isn't its own
/// QUIC state. Held by the loop and handed to the per-connection
/// servicing helpers by reference.
struct Ctx {
    cfg: Arc<ServerCfg>,
    upstream: Arc<str>,
    egress_tx: mpsc::Sender<Egress>,
    /// Woken by a [`QuicStream`] after it frees a slot in its inbound
    /// channel, so the loop retries reads it had to leave in `quiche`.
    read_credit: Arc<Notify>,
    h3_cfg: quiche::h3::Config,
}

/// One live QUIC connection and the tunnels running on it.
struct Conn {
    quic: quiche::Connection,
    /// `None` until the TLS handshake completes.
    h3: Option<quiche::h3::Connection>,
    streams: HashMap<u64, StreamState>,
}

/// The cached [`quiche::Config`] and the cert generation it was built from.
struct CachedConfig {
    generation: u64,
    config: quiche::Config,
}

/// Bind the UDP socket and serve until it errors.
///
/// `listen_addr` is the same `host:port` [`crate::server`] binds on TCP;
/// `upstream_addr` is the loopback `ssserver`.
pub async fn run(
    listen_addr: &str,
    upstream_addr: &str,
    cfg: Arc<ServerCfg>,
    certs: Arc<CertSource>,
) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("bind udp {listen_addr}"))?;
    let local = socket.local_addr().context("udp local_addr")?;

    let (egress_tx, mut egress_rx) = mpsc::channel::<Egress>(EGRESS_CHANNEL_CAP);
    let ctx = Ctx {
        cfg,
        upstream: Arc::<str>::from(upstream_addr),
        egress_tx,
        read_credit: Arc::new(Notify::new()),
        h3_cfg: quic::h3_config()?,
    };

    let mut conns: HashMap<Vec<u8>, Conn> = HashMap::new();
    let mut cached: Option<CachedConfig> = None;
    // Sized for a full-MTU datagram rather than our own send limit —
    // peers are free to send us more than `MAX_DATAGRAM_SIZE`.
    let mut buf = vec![0u8; 65535];
    let mut scratch = [0u8; quic::MAX_DATAGRAM_SIZE];

    tracing::info!("http/3 listening on {listen_addr} (udp)");
    loop {
        let next_timeout = conns.values().filter_map(|c| c.quic.timeout()).min();

        tokio::select! {
            res = socket.recv_from(&mut buf) => {
                let (len, from) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("udp recv error: {e:#}");
                        continue;
                    }
                };
                let key = match route_packet(
                    &mut buf[..len],
                    from,
                    local,
                    &mut conns,
                    &mut cached,
                    &certs,
                    &ctx,
                    &socket,
                    &mut scratch,
                )
                .await
                {
                    Some(k) => k,
                    None => continue,
                };
                if let Some(c) = conns.get_mut(&key) {
                    service(&key, c, &ctx, &socket, local).await;
                }
            }

            Some(msg) = egress_rx.recv() => {
                let key = msg.key.clone();
                if let Some(c) = conns.get_mut(&key) {
                    if let Some(st) = c.streams.get_mut(&msg.stream_id) {
                        st.queue(msg.out);
                    }
                    service(&key, c, &ctx, &socket, local).await;
                }
            }

            _ = ctx.read_credit.notified() => {
                // We don't know which connection freed a slot, so retry
                // every one. Cheap relative to the syscalls involved and
                // this listener carries tens of connections, not
                // thousands.
                for (key, c) in conns.iter_mut() {
                    let key = key.clone();
                    service(&key, c, &ctx, &socket, local).await;
                }
            }

            _ = tokio::time::sleep(next_timeout.unwrap_or(IDLE_TICK)) => {
                for (key, c) in conns.iter_mut() {
                    c.quic.on_timeout();
                    let key = key.clone();
                    service(&key, c, &ctx, &socket, local).await;
                }
            }
        }

        conns.retain(|_, c| {
            if c.quic.is_closed() {
                debug!("h3 connection closed: {:?}", c.quic.stats());
            }
            // Dropping the connection drops its `StreamState`s, whose
            // inbound senders are what the bridge tasks see EOF on.
            !c.quic.is_closed()
        });
    }
}

/// Feed one received datagram to the connection it belongs to, creating
/// that connection if this is a fresh Initial. Returns the key of the
/// connection that now needs servicing, or `None` if the packet was
/// handled standalone (version negotiation) or dropped.
#[allow(clippy::too_many_arguments)]
async fn route_packet(
    pkt: &mut [u8],
    from: SocketAddr,
    local: SocketAddr,
    conns: &mut HashMap<Vec<u8>, Conn>,
    cached: &mut Option<CachedConfig>,
    certs: &CertSource,
    ctx: &Ctx,
    socket: &UdpSocket,
    scratch: &mut [u8],
) -> Option<Vec<u8>> {
    let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
        Ok(h) => h,
        // Not a QUIC packet, or a truncated one. Silence is the same
        // thing a closed UDP port with a firewall in front of it does.
        Err(e) => {
            debug!("{from}: undecodable quic header: {e}");
            return None;
        }
    };

    let mut key = hdr.dcid.to_vec();
    if !conns.contains_key(&key) {
        if hdr.ty != quiche::Type::Initial {
            debug!("{from}: {:?} packet for unknown connection", hdr.ty);
            return None;
        }
        if !quiche::version_is_supported(hdr.version) {
            match quiche::negotiate_version(&hdr.scid, &hdr.dcid, scratch) {
                Ok(n) => {
                    if let Err(e) = socket.send_to(&scratch[..n], from).await {
                        warn!("{from}: send version negotiation: {e:#}");
                    }
                }
                Err(e) => debug!("{from}: negotiate_version: {e}"),
            }
            return None;
        }

        // No stateless Retry: `quiche` already enforces the RFC 9000
        // 3x anti-amplification limit before address validation, which
        // is the property Retry would otherwise buy us here.
        let config = match ensure_config(cached, certs, &ctx.cfg) {
            Ok(c) => c,
            Err(e) => {
                warn!("build quic server config: {e:#}");
                return None;
            }
        };
        let scid_bytes = quic::random_scid();
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);
        let quic_conn = match quiche::accept(&scid, None, local, from, config) {
            Ok(c) => c,
            Err(e) => {
                debug!("{from}: quiche::accept: {e}");
                return None;
            }
        };
        // Subsequent packets from this peer carry our SCID as their
        // DCID, so that is what we key the map on.
        key = scid.to_vec();
        conns.insert(
            key.clone(),
            Conn {
                quic: quic_conn,
                h3: None,
                streams: HashMap::new(),
            },
        );
        debug!("{from}: new h3 connection");
    }

    let c = conns.get_mut(&key)?;
    let info = quiche::RecvInfo { from, to: local };
    if let Err(e) = c.quic.recv(pkt, info) {
        debug!("{from}: quiche recv: {e}");
    }
    Some(key)
}

/// Rebuild the [`quiche::Config`] if the cert material has rotated, then
/// hand back the cached one.
fn ensure_config<'a>(
    cached: &'a mut Option<CachedConfig>,
    certs: &CertSource,
    cfg: &ServerCfg,
) -> Result<&'a mut quiche::Config> {
    let pem = certs.current.load_full();
    if !matches!(cached.as_ref(), Some(c) if c.generation == pem.generation) {
        let config = quic::server_config(&pem.cert_pem, &pem.key_pem, cfg.ech.as_ref())?;
        *cached = Some(CachedConfig {
            generation: pem.generation,
            config,
        });
        tracing::info!("http/3 cert material generation {} live", pem.generation);
    }
    Ok(&mut cached
        .as_mut()
        .expect("cached config populated above")
        .config)
}

/// Bring one connection up to date: finish the handshake bookkeeping,
/// drain HTTP/3 events, move bytes in both directions, and flush
/// whatever `quiche` wants on the wire.
async fn service(key: &[u8], c: &mut Conn, ctx: &Ctx, socket: &UdpSocket, local: SocketAddr) {
    if c.h3.is_none() && (c.quic.is_established() || c.quic.is_in_early_data()) {
        if !ech_ok(c, ctx) {
            // Silent drop, as close as QUIC gets to the TCP path's
            // RST. Note this only hides the tunnel: by now the
            // certificate has already gone out in the handshake.
            debug!("dropped non-ECH h3 handshake");
            let _ = c.quic.close(false, 0x0, b"");
            let _ = quic::flush_packets(&mut c.quic, socket, false).await;
            return;
        }
        match quiche::h3::Connection::with_transport(&mut c.quic, &ctx.h3_cfg) {
            Ok(h3) => c.h3 = Some(h3),
            Err(e) => {
                debug!("h3 init: {e}");
                let _ = c.quic.close(true, 0x105 /* H3_INTERNAL_ERROR */, b"");
            }
        }
    }

    if let Some(h3) = c.h3.as_mut() {
        poll_h3(key, &mut c.quic, h3, &mut c.streams, ctx, local);
        quic::pump_inbound(&mut c.quic, h3, &mut c.streams);
        quic::pump_outbound(&mut c.quic, h3, &mut c.streams);
        quic::reap_streams(&mut c.quic, &mut c.streams);
    }

    if let Err(e) = quic::flush_packets(&mut c.quic, socket, false).await {
        warn!("h3 flush: {e:#}");
    }
}

/// Enforce `reject_non_ech` on the HTTP/3 path.
///
/// Unlike the TCP listener this can only run *after* the handshake, so
/// it cannot keep the production cert away from a probe — see the
/// [`crate::quic`] module docs. It still refuses to tunnel for a client
/// that didn't use ECH.
fn ech_ok(c: &mut Conn, ctx: &Ctx) -> bool {
    if ctx.cfg.ech.is_none() || !ctx.cfg.reject_non_ech {
        return true;
    }
    ech::ech_accepted(c.quic.as_mut())
}

/// Drain `quiche`'s HTTP/3 event queue for one connection.
fn poll_h3(
    key: &[u8],
    quic: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    streams: &mut HashMap<u64, StreamState>,
    ctx: &Ctx,
    local: SocketAddr,
) {
    loop {
        match h3.poll(quic) {
            Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                handle_headers(key, sid, &list, quic, h3, streams, ctx, local);
            }
            Ok((sid, quiche::h3::Event::Data)) => match streams.get_mut(&sid) {
                Some(st) => st.mark_readable(),
                // Body on a stream we already answered (the 404 path).
                // Stop the peer from buffering more of it.
                None => {
                    let _ = quic.stream_shutdown(sid, quiche::Shutdown::Read, 0);
                }
            },
            // `pump_inbound` turns the resulting `Done` from `recv_body`
            // plus `stream_finished` into EOF for the bridge task.
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

/// Decide what a request is: the tunnel, or a probe that gets the 404.
#[allow(clippy::too_many_arguments)]
fn handle_headers(
    key: &[u8],
    sid: u64,
    list: &[Header],
    quic: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    streams: &mut HashMap<u64, StreamState>,
    ctx: &Ctx,
    local: SocketAddr,
) {
    let mut method: &[u8] = b"";
    let mut path: &[u8] = b"";
    let mut protocol: &[u8] = b"";
    for h in list {
        match h.name() {
            b":method" => method = h.value(),
            b":path" => path = h.value(),
            b":protocol" => protocol = h.value(),
            _ => {}
        }
    }

    // RFC 9220 WebSocket bootstrap on the secret path. Anything else —
    // a plain GET, the right path with the wrong method, a scan — looks
    // to the peer like a static web server with no such file.
    let is_tunnel =
        method == b"CONNECT" && protocol == b"websocket" && path == ctx.cfg.ws_path.as_bytes();
    if !is_tunnel {
        send_fake_404(sid, quic, h3, &ctx.cfg.server_name);
        return;
    }

    let resp = [
        Header::new(b":status", b"200"),
        Header::new(b"server", ctx.cfg.server_name.as_bytes()),
    ];
    if let Err(e) = h3.send_response(quic, sid, &resp, false) {
        debug!("h3 stream {sid}: send 200: {e}");
        let _ = quic.stream_shutdown(sid, quiche::Shutdown::Write, 0);
        return;
    }

    let (inbound_tx, inbound_rx) = mpsc::channel(quic::INBOUND_CHANNEL_CAP);
    streams.insert(sid, StreamState::tunnel(inbound_tx));

    let stream = QuicStream::new(
        key.to_vec(),
        sid,
        inbound_rx,
        ctx.read_credit.clone(),
        ctx.egress_tx.clone(),
    );
    let egress = ctx.egress_tx.clone();
    let upstream = ctx.upstream.clone();
    let fast_open = ctx.cfg.fast_open;
    tokio::spawn(async move {
        match net::connect(&upstream, fast_open).await {
            Ok(up) => quic::bridge(stream, up, egress).await,
            Err(e) => {
                warn!("dial upstream {upstream}: {e:#}");
                let close = stream.close_notice();
                drop(stream);
                let _ = egress.send(close).await;
            }
        }
    });
    debug!(
        "h3 stream {sid} tunnelling to {} (via {local})",
        ctx.upstream
    );
}

/// Answer with the same nginx-shaped 404 the HTTP/1.1 listener serves.
fn send_fake_404(
    sid: u64,
    quic: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    server_name: &str,
) {
    let len = FAKE_404_BODY.len().to_string();
    let resp = [
        Header::new(b":status", b"404"),
        Header::new(b"server", server_name.as_bytes()),
        Header::new(b"content-type", b"text/html"),
        Header::new(b"content-length", len.as_bytes()),
    ];
    if let Err(e) = h3.send_response(quic, sid, &resp, false) {
        debug!("h3 stream {sid}: send 404 headers: {e}");
        return;
    }
    // A body this small always fits the initial stream window, so there
    // is no partial-write case worth carrying state for.
    if let Err(e) = h3.send_body(quic, sid, FAKE_404_BODY.as_bytes(), true) {
        debug!("h3 stream {sid}: send 404 body: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_pems() -> (String, String) {
        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".to_string()]).unwrap();
        (kp.cert.pem(), kp.key_pair.serialize_pem())
    }

    fn base_cfg(dir: &std::path::Path, cert: &str, key: &str) -> ServerCfg {
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");
        std::fs::write(&cert_file, cert).unwrap();
        std::fs::write(&key_file, key).unwrap();
        ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file,
                key_file,
            },
            ech: None,
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: true,
        }
    }

    #[test]
    fn cert_source_reads_static_pems() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_pems();
        let cfg = base_cfg(dir.path(), &cert, &key);
        let src = CertSource::from_static_cfg(&cfg).unwrap();
        let pem = src.current.load_full();
        assert_eq!(pem.generation, 0);
        assert_eq!(pem.cert_pem, cert);
        assert_eq!(pem.key_pem, key);
    }

    #[test]
    fn cert_source_rejects_acme_config() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_pems();
        let mut cfg = base_cfg(dir.path(), &cert, &key);
        cfg.tls = ServerTls::Acme {
            email: "a@b.c".into(),
            staging: true,
            cache_dir: dir.path().to_path_buf(),
        };
        let err = CertSource::from_static_cfg(&cfg).unwrap_err();
        assert!(format!("{err:#}").contains("acme"), "got: {err:#}");
    }

    #[test]
    fn swap_bumps_generation_and_forces_config_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_pems();
        let cfg = base_cfg(dir.path(), &cert, &key);
        let src = CertSource::from_static_cfg(&cfg).unwrap();

        let mut cached: Option<CachedConfig> = None;
        ensure_config(&mut cached, &src, &cfg).unwrap();
        assert_eq!(cached.as_ref().unwrap().generation, 0);

        // Same generation: the cached config is reused as-is.
        ensure_config(&mut cached, &src, &cfg).unwrap();
        assert_eq!(cached.as_ref().unwrap().generation, 0);

        let (cert2, key2) = cert_pems();
        src.swap(cert2, key2);
        ensure_config(&mut cached, &src, &cfg).unwrap();
        assert_eq!(cached.as_ref().unwrap().generation, 1);
    }
}
