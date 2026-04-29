//! Client-side event loop: accept plain TCP from `sslocal`, dial the
//! upstream over TLS+WS, pipe the payload bytes through.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::copy_bidirectional;
use tokio_tungstenite::client_async;
use tracing::{debug, warn};

use crate::config::ClientCfg;
use crate::net;
use crate::tls_client::TlsClient;
use crate::ws::WsByteStream;

/// Bind, accept, and serve until the listener errors. `listen_addr` is
/// the loopback bind for `sslocal` (`SS_LOCAL_HOST:SS_LOCAL_PORT`);
/// `upstream_addr` is the public ssserver/plugin endpoint
/// (`SS_REMOTE_HOST:SS_REMOTE_PORT`).
pub async fn run(listen_addr: &str, upstream_addr: &str, cfg: ClientCfg) -> Result<()> {
    let tls = Arc::new(TlsClient::build(&cfg)?);
    let listener = net::create_listener(listen_addr, cfg.fast_open).await?;
    let cfg = Arc::new(cfg);
    let upstream = Arc::<str>::from(upstream_addr);

    tracing::info!("listening on {listen_addr}");
    loop {
        let (mut tcp_in, peer) = match listener.accept().await {
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
            let tcp_up = match net::connect(&upstream, cfg.fast_open).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("{peer}: dial {upstream}: {e:#}");
                    return;
                }
            };
            let tls_up = match tls.connect(&cfg.sni, tcp_up).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("{peer}: tls handshake: {e:#}");
                    return;
                }
            };

            let url = format!("wss://{}{}", cfg.sni, cfg.ws_path);
            let (ws, _resp) = match client_async(url, tls_up).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("{peer}: ws upgrade: {e:#}");
                    return;
                }
            };
            let mut wsbs = WsByteStream::new(ws);

            if let Err(e) = copy_bidirectional(&mut tcp_in, &mut wsbs).await {
                debug!("{peer}: bidi-copy ended: {e:#}");
            }
        });
    }
}
