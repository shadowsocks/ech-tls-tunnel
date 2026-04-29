//! Loopback end-to-end test for `server::run` + `client::run`.
//!
//! Wires up the server and client event loops on `127.0.0.1` with a
//! self-signed cert, then verifies bytes round-trip from a "fake
//! sslocal" → client loop → TLS+WS → server loop → "fake ssserver".
//! No external binaries — `tests/sip003_e2e.rs` (PR#6) is the version
//! that drives the real `shadowsocks-rust` ssserver/sslocal.

use std::path::PathBuf;
use std::time::Duration;

use ech_tls_tunnel::client;
use ech_tls_tunnel::config::{ClientCfg, ClientTrust, ServerCfg, ServerTls};
use ech_tls_tunnel::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Hard deadline for every test in this file.
const TEST_TIMEOUT: Duration = Duration::from_secs(600);

async fn within_deadline<F, T>(label: &'static str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(TEST_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{label} timed out after {:?}", TEST_TIMEOUT))
}

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for_ready(addr: &str) {
    for _ in 0..40 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server at {addr} did not become ready");
}

fn write_pems(dir: &std::path::Path, cert_pem: &str, key_pem: &str) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    (cert, key)
}

#[tokio::test]
async fn full_loop_round_trips_payload() {
    within_deadline("full_loop_round_trips_payload", async {
        // ── 1. echo server (stand-in for ssserver) ────────────────────────
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // ── 2. self-signed cert ───────────────────────────────────────────
        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_pems(dir.path(), &kp.cert.pem(), &kp.key_pair.serialize_pem());

        // ── 3. server loop on the public-side port ────────────────────────
        let tunnel_port = pick_port();
        let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
        let server_cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws-test".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: None,
            server_name: "nginx/1.24.0".into(),
        };
        let server_listen = tunnel_addr.clone();
        let echo_str = echo_addr.to_string();
        tokio::spawn(async move {
            let _ = server::run(&server_listen, &echo_str, server_cfg).await;
        });
        wait_for_ready(&tunnel_addr).await;

        // ── 4. client loop on the loopback-side port ──────────────────────
        let local_port = pick_port();
        let local_addr = format!("127.0.0.1:{local_port}");
        let client_cfg = ClientCfg {
            sni: "tunnel.local".into(),
            ws_path: "/ws-test".into(),
            fast_open: false,
            ech: None,
            trust: ClientTrust::CaFile(cert_path),
            fingerprint: None,
        };
        let client_listen = local_addr.clone();
        let client_upstream = tunnel_addr.clone();
        tokio::spawn(async move {
            let _ = client::run(&client_listen, &client_upstream, client_cfg).await;
        });
        wait_for_ready(&local_addr).await;

        // ── 5. drive: simulate sslocal opening a connection through us ────
        let mut sock = TcpStream::connect(&local_addr).await.unwrap();
        sock.write_all(b"ping").await.unwrap();
        sock.flush().await.unwrap();
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // larger payload to stress framing
        let big: Vec<u8> = (0..256_000).map(|i| (i % 251) as u8).collect();
        sock.write_all(&big).await.unwrap();
        sock.flush().await.unwrap();
        let mut got = vec![0u8; big.len()];
        sock.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
    })
    .await
}

#[tokio::test]
async fn unmatched_path_serves_fake_404() {
    within_deadline("unmatched_path_serves_fake_404", async {
        // Stand-up a server (no real upstream needed for this test).
        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_pems(dir.path(), &kp.cert.pem(), &kp.key_pair.serialize_pem());

        let tunnel_port = pick_port();
        let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
        let server_cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws-secret".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: None,
            server_name: "nginx/1.24.0".into(),
        };
        let listen = tunnel_addr.clone();
        tokio::spawn(async move {
            // upstream addr is irrelevant — we never hit the upgrade path
            let _ = server::run(&listen, "127.0.0.1:1", server_cfg).await;
        });
        wait_for_ready(&tunnel_addr).await;

        // Probe the wrong path with curl-equivalent (boring TLS client +
        // raw HTTP/1 request). Expect 404 with the fake nginx Server header.
        use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
        use boring::x509::X509;

        let mut cb = SslConnector::builder(SslMethod::tls_client()).unwrap();
        cb.cert_store_mut()
            .add_cert(X509::from_pem(kp.cert.pem().as_bytes()).unwrap())
            .unwrap();
        cb.set_verify(SslVerifyMode::PEER);
        let connector = cb.build();

        let tcp = TcpStream::connect(&tunnel_addr).await.unwrap();
        let mut tls = tokio_boring::connect(connector.configure().unwrap(), "tunnel.local", tcp)
            .await
            .unwrap();

        tls.write_all(b"GET / HTTP/1.1\r\nHost: tunnel.local\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tls.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 404"),
            "expected 404, got: {resp}"
        );
        // Hyper lowercases header names on the wire (HTTP/1.1 spec is
        // case-insensitive). Match that.
        let lc = resp.to_ascii_lowercase();
        assert!(
            lc.contains("server: nginx/1.24.0"),
            "expected fake nginx Server header, got: {resp}"
        );
    })
    .await
}
