//! Server-side event loop: terminate TLS, accept WebSocket Upgrade on
//! the secret path, and pipe the payload bytes to the loopback
//! `ssserver`.

use std::convert::Infallible;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

use crate::acme;
use crate::challenge::ChallengeStore;
use crate::config::{ServerCfg, ServerTls};
use crate::net;
use crate::stealth;
use crate::tls_server::TlsServer;
use crate::ws::WsByteStream;

/// Bind, accept, and serve until the listener errors. `listen_addr` is
/// the public bind address (server-side: `SS_REMOTE_HOST:SS_REMOTE_PORT`),
/// `upstream_addr` is the loopback `ssserver` listener
/// (`SS_LOCAL_HOST:SS_LOCAL_PORT`).
pub async fn run(listen_addr: &str, upstream_addr: &str, cfg: ServerCfg) -> Result<()> {
    let challenges = Arc::new(ChallengeStore::new());
    let tls = Arc::new(build_tls_server(&cfg, challenges.clone()).await?);
    let listener = net::create_listener(listen_addr, cfg.fast_open).await?;
    let cfg = Arc::new(cfg);
    let upstream = Arc::<str>::from(upstream_addr);

    tracing::info!("listening on {listen_addr}");
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error: {e:#}");
                continue;
            }
        };
        let tls = tls.clone();
        let cfg = cfg.clone();
        let upstream = upstream.clone();

        tokio::spawn(async move {
            let stream = match tls.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("{peer}: tls handshake: {e:#}");
                    return;
                }
            };
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let cfg = cfg.clone();
                let upstream = upstream.clone();
                async move { handle_request(req, cfg, upstream).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                debug!("{peer}: http: {e:#}");
            }
        });
    }
}

async fn handle_request(
    mut req: Request<Incoming>,
    cfg: Arc<ServerCfg>,
    upstream: Arc<str>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != cfg.ws_path || !is_ws_upgrade(&req) {
        return Ok(stealth::fake_404(&cfg.server_name));
    }

    let key = match req.headers().get(header::SEC_WEBSOCKET_KEY) {
        Some(k) => k.clone(),
        None => return Ok(stealth::fake_404(&cfg.server_name)),
    };

    let accept_value = match HeaderValue::from_str(&derive_accept_key(key.as_bytes())) {
        Ok(v) => v,
        Err(_) => return Ok(stealth::fake_404(&cfg.server_name)),
    };

    // Capture the upgrade future *before* the spawn / before `req` drops —
    // this is the canonical hyper 1.x pattern (matches hyper-tungstenite).
    let on_upgrade = hyper::upgrade::on(&mut req);
    let fast_open = cfg.fast_open;
    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!("upgrade failed: {e:#}");
                return;
            }
        };
        let io = TokioIo::new(upgraded);
        let ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
        let mut wsbs = WsByteStream::new(ws);

        let mut up = match net::connect(&upstream, fast_open).await {
            Ok(s) => s,
            Err(e) => {
                warn!("dial upstream {upstream}: {e:#}");
                return;
            }
        };

        if let Err(e) = copy_bidirectional(&mut wsbs, &mut up).await {
            debug!("bidi-copy ended: {e:#}");
        }
    });

    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept_value)
        .body(Full::new(Bytes::new()))
        .expect("static 101 response is valid"))
}

/// Build a [`TlsServer`] from the config, dispatching on
/// [`ServerTls::Static`] vs [`ServerTls::Acme`]. The ACME path may
/// block on a network roundtrip to issue/refresh the cert.
async fn build_tls_server(cfg: &ServerCfg, challenges: Arc<ChallengeStore>) -> Result<TlsServer> {
    match &cfg.tls {
        ServerTls::Static { .. } => TlsServer::build_static_with(cfg, challenges),
        ServerTls::Acme {
            email,
            staging,
            cache_dir,
        } => {
            let mut domains: Vec<&str> = vec![cfg.domain.as_str()];
            if let Some(ech) = &cfg.ech {
                if !ech.public_name.is_empty() && ech.public_name != cfg.domain {
                    domains.push(ech.public_name.as_str());
                }
            }
            let cert = match acme::load_cached(cache_dir) {
                Some(c) => {
                    tracing::info!("using cached cert from {}", cache_dir.display());
                    c
                }
                None => {
                    tracing::info!("issuing new cert via ACME (TLS-ALPN-01) for {domains:?}");
                    acme::issue(
                        &domains,
                        email,
                        *staging,
                        cache_dir,
                        None,
                        challenges.clone(),
                    )
                    .await?
                }
            };
            let server = TlsServer::build_from_pem_with(&cert.cert_pem, &cert.key_pem, challenges)?;
            Ok(server)
        }
    }
}

fn is_ws_upgrade(req: &Request<Incoming>) -> bool {
    let upgrade_match = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    let connection_match = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        });

    upgrade_match && connection_match
}
