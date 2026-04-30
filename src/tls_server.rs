//! BoringSSL-backed TLS server.
//!
//! Loads the production cert/key (from disk for `ServerTls::Static`,
//! from ACME for `ServerTls::Acme`), wraps the resulting `SslAcceptor`
//! in `ArcSwap` so the renewal task can hot-swap on cert refresh, and
//! installs an ALPN-select callback that lets TLS-ALPN-01 challenges
//! share the same listener as production traffic.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use boring::ssl::{AlpnError, NameType, SslAcceptor, SslContextBuilder, SslFiletype, SslMethod};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::challenge::ChallengeStore;
use crate::config::{ServerCfg, ServerEch, ServerTls};
use crate::ech::EchServerKey;

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
    /// Build with a default empty `ChallengeStore`. Convenient for
    /// callers that won't ever serve TLS-ALPN-01.
    pub fn build_static(cfg: &ServerCfg) -> Result<Self> {
        Self::build_static_with(cfg, Arc::new(ChallengeStore::new()))
    }

    /// Build from `ServerTls::Static`, with an explicit `ChallengeStore`
    /// shared with the ACME flow.
    pub fn build_static_with(cfg: &ServerCfg, challenges: Arc<ChallengeStore>) -> Result<Self> {
        let (cert_file, key_file) = match &cfg.tls {
            ServerTls::Static {
                cert_file,
                key_file,
            } => (cert_file, key_file),
            ServerTls::Acme { .. } => {
                return Err(anyhow!(
                    "build_static called with tls=acme; use the ACME path"
                ))
            }
        };
        let acceptor = build_acceptor_from_pem(cert_file, key_file, challenges, cfg.ech.as_ref())?;
        Ok(Self {
            acceptor: Arc::new(ArcSwap::from_pointee(acceptor)),
        })
    }

    /// Build from cert/key already in memory (PEM strings) plus a
    /// `ChallengeStore`. Used by the ACME path which has just received
    /// a freshly-issued cert. Reads ECH config from `cfg.ech` if any.
    pub fn build_from_pem_with(
        cfg: &ServerCfg,
        cert_pem: &str,
        key_pem: &str,
        challenges: Arc<ChallengeStore>,
    ) -> Result<Self> {
        let acceptor =
            build_acceptor_from_pem_strs_pub(cert_pem, key_pem, challenges, cfg.ech.as_ref())?;
        Ok(Self {
            acceptor: Arc::new(ArcSwap::from_pointee(acceptor)),
        })
    }

    /// Build a bootstrap acceptor with a self-signed throwaway cert as
    /// the default. The ALPN+SNI callbacks still consult `challenges`,
    /// so TLS-ALPN-01 validation works while the real ACME-issued cert
    /// is being fetched. Real clients see an untrusted cert until the
    /// production cert is swapped in.
    pub fn build_bootstrap_with(cfg: &ServerCfg, challenges: Arc<ChallengeStore>) -> Result<Self> {
        let kp = rcgen::generate_simple_self_signed(vec![cfg.domain.clone()])
            .context("generate bootstrap self-signed cert")?;
        let cert_pem = kp.cert.pem();
        let key_pem = kp.key_pair.serialize_pem();
        let acceptor =
            build_acceptor_from_pem_strs_pub(&cert_pem, &key_pem, challenges, cfg.ech.as_ref())?;
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

fn build_acceptor_from_pem(
    cert: &Path,
    key: &Path,
    challenges: Arc<ChallengeStore>,
    ech: Option<&ServerEch>,
) -> Result<SslAcceptor> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .context("init SslAcceptorBuilder")?;
    b.set_certificate_chain_file(cert)
        .with_context(|| format!("load cert {}", cert.display()))?;
    b.set_private_key_file(key, SslFiletype::PEM)
        .with_context(|| format!("load key {}", key.display()))?;
    b.check_private_key().context("cert/key pair check")?;
    install_alpn_callback(&mut b, challenges)?;
    install_ech_if_configured(&b, ech)?;
    Ok(b.build())
}

/// Crate-public variant so [`crate::server`] can build a fresh acceptor
/// from a freshly-issued ACME cert and hot-swap it via [`TlsServer::swap`].
pub(crate) fn build_acceptor_from_pem_strs_pub(
    cert_pem: &str,
    key_pem: &str,
    challenges: Arc<ChallengeStore>,
    ech: Option<&ServerEch>,
) -> Result<SslAcceptor> {
    build_acceptor_from_pem_strs(cert_pem, key_pem, challenges, ech)
}

fn build_acceptor_from_pem_strs(
    cert_pem: &str,
    key_pem: &str,
    challenges: Arc<ChallengeStore>,
    ech: Option<&ServerEch>,
) -> Result<SslAcceptor> {
    use boring::pkey::PKey;
    use boring::x509::X509;

    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .context("init SslAcceptorBuilder")?;
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
    install_alpn_callback(&mut b, challenges)?;
    install_ech_if_configured(&b, ech)?;
    Ok(b.build())
}

/// Read the HPKE keypair from `ech.key_file` and install it on the
/// builder via `SSL_CTX_set1_ech_keys`. No-op when ECH isn't
/// configured.
fn install_ech_if_configured(
    b: &boring::ssl::SslContextBuilder,
    ech: Option<&ServerEch>,
) -> Result<()> {
    let Some(cfg) = ech else { return Ok(()) };
    let key = EchServerKey::read_from(&cfg.key_file)
        .with_context(|| format!("read ECH key {}", cfg.key_file.display()))?;
    if key.public_name() != cfg.public_name {
        tracing::warn!(
            "ECH public_name mismatch: stored={:?}, config={:?}",
            key.public_name(),
            cfg.public_name
        );
    }
    key.install_on_ctx_builder(b)?;
    tracing::info!("ECH enabled (public_name={})", key.public_name());
    Ok(())
}

/// Install the ALPN-select callback that:
///   1. If the client offers `acme-tls/1` AND we have a matching
///      challenge installed for the SNI, swap the SSL context to the
///      challenge cert and negotiate `acme-tls/1`.
///   2. Otherwise, pick the first match from `["h2", "http/1.1"]`.
fn install_alpn_callback(b: &mut SslContextBuilder, challenges: Arc<ChallengeStore>) -> Result<()> {
    b.set_alpn_protos(&alpn_wire(&[b"h2", b"http/1.1"]))
        .context("set ALPN protos")?;
    b.set_alpn_select_callback(move |ssl, client_protos| {
        let mut iter = AlpnIter::new(client_protos);
        let mut offered_acme = false;
        let mut first_h2: Option<&[u8]> = None;
        let mut first_h11: Option<&[u8]> = None;
        for proto in iter.by_ref() {
            if proto == b"acme-tls/1" {
                offered_acme = true;
            } else if proto == b"h2" && first_h2.is_none() {
                first_h2 = Some(proto);
            } else if proto == b"http/1.1" && first_h11.is_none() {
                first_h11 = Some(proto);
            }
        }

        if offered_acme {
            let sni = ssl.servername(NameType::HOST_NAME).map(str::to_string);
            if let Some(sni) = sni {
                if let Some(ctx) = challenges.get(&sni) {
                    if ssl.set_ssl_context(&ctx).is_ok() {
                        // `b"acme-tls/1"` is &'static, valid for any 'a.
                        return Ok(b"acme-tls/1");
                    }
                }
            }
            return Err(AlpnError::ALERT_FATAL);
        }

        if let Some(p) = first_h2 {
            return Ok(p);
        }
        if let Some(p) = first_h11 {
            return Ok(p);
        }
        Err(AlpnError::NOACK)
    });
    Ok(())
}

/// Iterator over ALPN protocol entries in the wire format
/// (length-prefixed, concatenated).
struct AlpnIter<'a> {
    remaining: &'a [u8],
}

impl<'a> AlpnIter<'a> {
    fn new(s: &'a [u8]) -> Self {
        Self { remaining: s }
    }
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining.is_empty() {
            return None;
        }
        let len = self.remaining[0] as usize;
        if len == 0 || self.remaining.len() < 1 + len {
            return None;
        }
        let proto = &self.remaining[1..1 + len];
        self.remaining = &self.remaining[1 + len..];
        Some(proto)
    }
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
        let new_acceptor = build_acceptor_from_pem(
            &cert_path,
            &key_path,
            Arc::new(crate::challenge::ChallengeStore::new()),
            None,
        )
        .unwrap();
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
