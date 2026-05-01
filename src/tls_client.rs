//! BoringSSL-backed TLS client.
//!
//! Builds an [`SslConnector`] honoring the three [`ClientTrust`] modes:
//! the system root store, an explicit CA bundle on disk, or
//! verification disabled (dev/test only).

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::X509;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::config::{ClientCfg, ClientEch, ClientTrust};
use crate::ech;
use crate::fingerprint;
use crate::tls_server::alpn_wire;

pub struct TlsClient {
    connector: Arc<SslConnector>,
    /// Binary ECHConfigList to apply per-connection. `None` disables ECH.
    ech_config_list: Option<Vec<u8>>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient").finish_non_exhaustive()
    }
}

impl TlsClient {
    pub fn build(cfg: &ClientCfg) -> Result<Self> {
        let mut b = SslConnector::builder(SslMethod::tls_client()).context("init SslConnector")?;
        match &cfg.trust {
            ClientTrust::SystemRoots => {
                // BoringSSL's `set_default_verify_paths` honors
                // SSL_CERT_FILE / SSL_CERT_DIR and the platform default
                // (e.g. /etc/ssl/certs on Linux). Operators on systems
                // without one can switch to `ca_file=<path>`.
                b.set_default_verify_paths()
                    .context("set default verify paths")?;
            }
            ClientTrust::CaFile(path) => {
                let pem = std::fs::read(path)
                    .with_context(|| format!("read ca file {}", path.display()))?;
                let cert = X509::from_pem(&pem).context("parse ca pem")?;
                b.cert_store_mut()
                    .add_cert(cert)
                    .context("add ca cert to store")?;
                b.set_verify(SslVerifyMode::PEER);
            }
            ClientTrust::InsecureSkipVerify => {
                b.set_verify(SslVerifyMode::NONE);
            }
        }
        b.set_alpn_protos(&alpn_wire(&[b"h2", b"http/1.1"]))
            .context("set ALPN")?;

        // Browser-fingerprint shaping (a.k.a. uTLS / impersonation).
        // Applied AFTER ALPN so that the GREASE / permute behaviour is
        // determined by the chosen profile.
        if let Some(name) = &cfg.fingerprint {
            let params = fingerprint::resolve(name).ok_or_else(|| {
                anyhow!("unknown fingerprint {name:?} (config validation should have caught this)")
            })?;
            fingerprint::apply(&mut b, &params)
                .with_context(|| format!("apply fingerprint {name:?}"))?;
            tracing::info!("client TLS fingerprint: {name}");
        }

        let ech_config_list = match &cfg.ech {
            None => None,
            Some(ClientEch::Inline(b64)) => Some(ech::decode_config_list_b64(b64)?),
            Some(ClientEch::File(path)) => Some(
                std::fs::read(path)
                    .with_context(|| format!("read ECH config list {}", path.display()))?,
            ),
        };

        Ok(Self {
            connector: Arc::new(b.build()),
            ech_config_list,
        })
    }

    /// Open a TLS connection over an already-connected TCP stream.
    /// `sni` is the server name presented in the (inner) ClientHello and
    /// used for hostname verification when trust isn't
    /// `InsecureSkipVerify`. When ECH is enabled the outer SNI is
    /// derived from the configured `public_name` inside the
    /// ECHConfigList.
    pub async fn connect(&self, sni: &str, tcp: TcpStream) -> Result<SslStream<TcpStream>> {
        let cfg = self.connector.configure().context("configure handshake")?;
        match &self.ech_config_list {
            None => tokio_boring::connect(cfg, sni, tcp)
                .await
                .map_err(|e| anyhow!("tls handshake: {e}")),
            Some(list) => {
                let mut ssl = cfg
                    .into_ssl(sni)
                    .context("ConnectConfiguration::into_ssl")?;
                ech::install_client_ech_config_list(&mut ssl, list)
                    .context("install client ECH config list")?;
                tokio_boring::SslStreamBuilder::new(ssl, tcp)
                    .connect()
                    .await
                    .map_err(|e| anyhow!("tls handshake (ECH): {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientEch, ServerCfg, ServerEch, ServerTls};
    use crate::tls_server::TlsServer;
    use std::path::Path;
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

    /// Spin up a `TlsServer` on a fresh `127.0.0.1:0` port. The spawned
    /// task echoes one 5-byte payload back to the client and then exits.
    async fn spawn_echo_server(server: TlsServer) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = server.accept(tcp).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.shutdown().await.ok();
        });
        addr
    }

    fn server_with_cert(
        dir: &Path,
        cert_pem: &str,
        key_pem: &str,
    ) -> (TlsServer, std::path::PathBuf) {
        let (cert_path, key_path) = write_pems(dir, cert_pem, key_pem);
        let cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: None::<ServerEch>,
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
        };
        let server = TlsServer::build_static(&cfg).unwrap();
        (server, cert_path)
    }

    fn client_cfg(trust: ClientTrust) -> ClientCfg {
        ClientCfg {
            sni: "tunnel.local".into(),
            ws_path: "/ws".into(),
            fast_open: false,
            ech: None::<ClientEch>,
            trust,
            fingerprint: None,
        }
    }

    #[tokio::test]
    async fn ca_file_trust_handshake_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = test_cert();
        let (server, cert_path) = server_with_cert(dir.path(), &cert_pem, &key_pem);
        let addr = spawn_echo_server(server).await;

        let client = TlsClient::build(&client_cfg(ClientTrust::CaFile(cert_path))).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = client.connect("tunnel.local", tcp).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test]
    async fn insecure_skip_verify_accepts_unknown_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = test_cert();
        let (server, _cert_path) = server_with_cert(dir.path(), &cert_pem, &key_pem);
        let addr = spawn_echo_server(server).await;

        // Note: NOT loading the cert into the client's trust store.
        let client = TlsClient::build(&client_cfg(ClientTrust::InsecureSkipVerify)).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = client.connect("tunnel.local", tcp).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test]
    async fn ca_file_trust_rejects_untrusted_cert() {
        // Server uses cert A; client trusts ONLY cert B (a different one).
        let dir = tempfile::tempdir().unwrap();
        let (cert_a_pem, key_a_pem) = test_cert();
        let (server, _) = server_with_cert(dir.path(), &cert_a_pem, &key_a_pem);
        let addr = spawn_echo_server(server).await;

        let other_cert_pem = test_cert().0;
        let other_path = dir.path().join("other.pem");
        std::fs::write(&other_path, &other_cert_pem).unwrap();

        let client = TlsClient::build(&client_cfg(ClientTrust::CaFile(other_path))).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = client
            .connect("tunnel.local", tcp)
            .await
            .expect_err("handshake should reject untrusted cert");
        // BoringSSL's error message varies by version; just confirm it failed.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tls handshake"),
            "expected tls handshake error, got {msg}"
        );
    }

    #[tokio::test]
    async fn system_roots_builds_successfully() {
        // We can't test SystemRoots end-to-end on loopback (the test
        // cert isn't in the system store), so just assert the builder
        // accepts the trust mode without error.
        let _ = TlsClient::build(&client_cfg(ClientTrust::SystemRoots)).unwrap();
    }
}
