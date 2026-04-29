//! BoringSSL-backed TLS server for the static-cert deployment path.
//!
//! For v0.1 this loads a PEM cert + key from the paths in
//! [`ServerTls::Static`] and exposes a hot-swappable [`TlsServer`] handle
//! so the upcoming ACME renewal task (v0.2) can replace the cert without
//! dropping in-flight connections.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::config::{ServerCfg, ServerTls};

/// Live TLS acceptor backed by BoringSSL. The inner [`SslAcceptor`] sits
/// behind `ArcSwap` so the ACME task can hot-swap it on cert renewal.
pub struct TlsServer {
    acceptor: Arc<ArcSwap<SslAcceptor>>,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer").finish_non_exhaustive()
    }
}

impl TlsServer {
    /// Build from a [`ServerCfg`] whose `tls` is [`ServerTls::Static`].
    /// (Acme support arrives in v0.2.)
    pub fn build_static(cfg: &ServerCfg) -> Result<Self> {
        let (cert_file, key_file) = match &cfg.tls {
            ServerTls::Static {
                cert_file,
                key_file,
            } => (cert_file, key_file),
            ServerTls::Acme { .. } => {
                return Err(anyhow!(
                    "build_static called with tls=acme; use the v0.2 ACME path"
                ))
            }
        };
        let acceptor = build_acceptor_from_pem(cert_file, key_file)?;
        Ok(Self {
            acceptor: Arc::new(ArcSwap::from_pointee(acceptor)),
        })
    }

    /// Perform the TLS handshake on an accepted TCP stream.
    pub async fn accept(&self, tcp: TcpStream) -> Result<SslStream<TcpStream>> {
        let acceptor = self.acceptor.load_full();
        tokio_boring::accept(&acceptor, tcp)
            .await
            .map_err(|e| anyhow!("tls handshake: {e}"))
    }

    /// Replace the active acceptor (used by the ACME renewal task).
    pub fn swap(&self, new: SslAcceptor) {
        self.acceptor.store(Arc::new(new));
    }
}

fn build_acceptor_from_pem(cert: &Path, key: &Path) -> Result<SslAcceptor> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .context("init SslAcceptorBuilder")?;
    b.set_certificate_chain_file(cert)
        .with_context(|| format!("load cert {}", cert.display()))?;
    b.set_private_key_file(key, SslFiletype::PEM)
        .with_context(|| format!("load key {}", key.display()))?;
    b.check_private_key().context("cert/key pair check")?;
    b.set_alpn_protos(&alpn_wire(&[b"h2", b"http/1.1"]))
        .context("set ALPN")?;
    Ok(b.build())
}

/// Encode an ALPN protocol list as length-prefixed concatenation:
/// `0x02 'h' '2' 0x08 'h' 't' 't' 'p' '/' '1' '.' '1'`.
pub(crate) fn alpn_wire(protos: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protos.iter().map(|p| p.len() + 1).sum());
    for p in protos {
        out.push(p.len() as u8);
        out.extend_from_slice(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerEch, ServerTls};
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use boring::x509::X509;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_cert() -> (String, String) {
        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".to_string()]).unwrap();
        (kp.cert.pem(), kp.key_pair.serialize_pem())
    }

    fn write_pems(
        dir: &Path,
        cert_pem: &str,
        key_pem: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, cert_pem).unwrap();
        std::fs::write(&key, key_pem).unwrap();
        (cert, key)
    }

    fn server_cfg(cert_path: std::path::PathBuf, key_path: std::path::PathBuf) -> ServerCfg {
        ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path,
                key_file: key_path,
            },
            ech: None::<ServerEch>,
            server_name: "nginx/1.24.0".into(),
        }
    }

    #[tokio::test]
    async fn handshake_round_trips_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = test_cert();
        let (cert_path, key_path) = write_pems(dir.path(), &cert_pem, &key_pem);
        let server = TlsServer::build_static(&server_cfg(cert_path, key_path)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = server.accept(tcp).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.shutdown().await.ok();
        });

        // Client side: trust only the test cert.
        let mut cb = SslConnector::builder(SslMethod::tls_client()).unwrap();
        cb.cert_store_mut()
            .add_cert(X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        cb.set_verify(SslVerifyMode::PEER);
        let connector = cb.build();
        let cfg = connector.configure().unwrap();

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = tokio_boring::connect(cfg, "tunnel.local", tcp)
            .await
            .unwrap();
        tls.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn build_static_rejects_acme_config() {
        let cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws".into(),
            fast_open: false,
            tls: ServerTls::Acme {
                email: "x@example.com".into(),
                staging: true,
                cache_dir: "/tmp".into(),
            },
            ech: None,
            server_name: "nginx/1.24.0".into(),
        };
        let err = TlsServer::build_static(&cfg).unwrap_err();
        assert!(format!("{err:#}").contains("ACME"));
    }

    #[tokio::test]
    async fn swap_replaces_active_acceptor() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = test_cert();
        let (cert_path, key_path) = write_pems(dir.path(), &cert_pem, &key_pem);
        let server =
            TlsServer::build_static(&server_cfg(cert_path.clone(), key_path.clone())).unwrap();

        // Build a second acceptor and swap it in.
        let new_acceptor = build_acceptor_from_pem(&cert_path, &key_path).unwrap();
        server.swap(new_acceptor);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            server.accept(tcp).await.unwrap();
        });

        let mut cb = SslConnector::builder(SslMethod::tls_client()).unwrap();
        cb.cert_store_mut()
            .add_cert(X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        cb.set_verify(SslVerifyMode::PEER);
        let cfg = cb.build().configure().unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let _ = tokio_boring::connect(cfg, "tunnel.local", tcp)
            .await
            .unwrap();

        task.await.unwrap();
    }
}
