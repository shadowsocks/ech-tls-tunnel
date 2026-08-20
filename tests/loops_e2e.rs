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
use ech_tls_tunnel::config::{
    ClientCfg, ClientEch, ClientTrust, ServerCfg, ServerEch, ServerTls, Transport,
};
use ech_tls_tunnel::ech::{encode_config_list_b64, EchServerKey};
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

/// The HTTP/3 listener binds UDP on the same port the TCP one uses, but
/// from its own task — so `wait_for_ready` (which only proves the TCP
/// side is up) isn't enough. Poll until the UDP port is taken.
async fn wait_for_udp_ready(addr: &str) {
    for _ in 0..40 {
        if std::net::UdpSocket::bind(addr).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("http/3 listener at {addr} did not bind udp");
}

/// Drive one round-trip plus a 256 KB payload through an already-running
/// client loop, the same exercise the TCP test does.
async fn assert_round_trips(local_addr: &str) {
    let mut sock = TcpStream::connect(local_addr).await.unwrap();
    sock.write_all(b"ping").await.unwrap();
    sock.flush().await.unwrap();
    let mut buf = [0u8; 4];
    sock.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let big: Vec<u8> = (0..256_000).map(|i| (i % 251) as u8).collect();
    sock.write_all(&big).await.unwrap();
    sock.flush().await.unwrap();
    let mut got = vec![0u8; big.len()];
    sock.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big);
}

/// Spawn the echo server that stands in for `ssserver`.
async fn spawn_echo() -> std::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
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
    addr
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
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: false,
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
            transport: ech_tls_tunnel::config::Transport::Tcp,
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
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: false,
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

/// The HTTP/3 sibling of `full_loop_round_trips_payload`: same payload,
/// same assertions, but carried over QUIC with `http3=true` /
/// `transport=h3` instead of TLS+WebSocket over TCP.
#[tokio::test]
async fn http3_loop_round_trips_payload() {
    within_deadline("http3_loop_round_trips_payload", async {
        let echo_addr = spawn_echo().await;

        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_pems(dir.path(), &kp.cert.pem(), &kp.key_pair.serialize_pem());

        let tunnel_port = pick_port();
        let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
        let server_cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws-h3".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: None,
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: true,
        };
        let server_listen = tunnel_addr.clone();
        let echo_str = echo_addr.to_string();
        tokio::spawn(async move {
            let _ = server::run(&server_listen, &echo_str, server_cfg).await;
        });
        wait_for_ready(&tunnel_addr).await;
        wait_for_udp_ready(&tunnel_addr).await;

        let local_port = pick_port();
        let local_addr = format!("127.0.0.1:{local_port}");
        let client_cfg = ClientCfg {
            sni: "tunnel.local".into(),
            ws_path: "/ws-h3".into(),
            fast_open: false,
            ech: None,
            trust: ClientTrust::CaFile(cert_path),
            fingerprint: None,
            transport: Transport::H3,
        };
        let client_listen = local_addr.clone();
        let client_upstream = tunnel_addr.clone();
        tokio::spawn(async move {
            let _ = client::run(&client_listen, &client_upstream, client_cfg).await;
        });
        wait_for_ready(&local_addr).await;

        assert_round_trips(&local_addr).await;
    })
    .await
}

/// ECH over QUIC: the server publishes ECH keys on the HTTP/3 `SSL_CTX`
/// and rejects handshakes without ECH (`reject_non_ech`), so a payload
/// only round-trips if the client's ECHClientHello actually reached
/// `quiche`'s BoringSSL handshake.
#[tokio::test]
async fn http3_loop_round_trips_payload_with_ech() {
    within_deadline("http3_loop_round_trips_payload_with_ech", async {
        let echo_addr = spawn_echo().await;

        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_pems(dir.path(), &kp.cert.pem(), &kp.key_pair.serialize_pem());

        // ECH keypair: `cover.example` is the only name a passive
        // observer gets to see in the QUIC Initial.
        let ech_key = EchServerKey::generate("cover.example").unwrap();
        let ech_key_path = dir.path().join("ech.key");
        ech_key.write_to(&ech_key_path).unwrap();
        let config_list_b64 = encode_config_list_b64(&ech_key.marshal_config_list().unwrap());

        let tunnel_port = pick_port();
        let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
        let server_cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws-h3-ech".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: Some(ServerEch {
                public_name: "cover.example".into(),
                key_file: ech_key_path,
            }),
            acme_cover_san: false,
            // The HTTP/3 listener enforces this via `SSL_ech_accepted`
            // after the handshake, so a non-ECH client gets dropped
            // before it can tunnel anything.
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: true,
        };
        let server_listen = tunnel_addr.clone();
        let echo_str = echo_addr.to_string();
        tokio::spawn(async move {
            let _ = server::run(&server_listen, &echo_str, server_cfg).await;
        });
        wait_for_ready(&tunnel_addr).await;
        wait_for_udp_ready(&tunnel_addr).await;

        let local_port = pick_port();
        let local_addr = format!("127.0.0.1:{local_port}");
        let client_cfg = ClientCfg {
            sni: "tunnel.local".into(),
            ws_path: "/ws-h3-ech".into(),
            fast_open: false,
            ech: Some(ClientEch::Inline(config_list_b64)),
            trust: ClientTrust::CaFile(cert_path),
            fingerprint: None,
            transport: Transport::H3,
        };
        let client_listen = local_addr.clone();
        let client_upstream = tunnel_addr.clone();
        tokio::spawn(async move {
            let _ = client::run(&client_listen, &client_upstream, client_cfg).await;
        });
        wait_for_ready(&local_addr).await;

        assert_round_trips(&local_addr).await;
    })
    .await
}

/// Regression test for `send_request` backpressure. `MAX_STREAMS_BIDI`
/// caps concurrent QUIC streams at 256, and a QUIC stream can also be
/// momentarily out of send capacity — both surface as `StreamBlocked` /
/// `StreamLimit` from `send_request`. Those are retryable, not fatal;
/// treating them as fatal dropped connections under concurrency.
///
/// Drives 400 concurrent connections through one QUIC connection, which
/// is comfortably past the 256 limit.
#[tokio::test]
async fn http3_concurrent_streams_exceed_stream_limit() {
    within_deadline("http3_concurrent_streams_exceed_stream_limit", async {
        let echo_addr = spawn_echo().await;

        let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_pems(dir.path(), &kp.cert.pem(), &kp.key_pair.serialize_pem());

        let tunnel_port = pick_port();
        let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
        let server_cfg = ServerCfg {
            domain: "tunnel.local".into(),
            ws_path: "/ws-h3-many".into(),
            fast_open: false,
            tls: ServerTls::Static {
                cert_file: cert_path.clone(),
                key_file: key_path,
            },
            ech: None,
            acme_cover_san: true,
            reject_non_ech: true,
            server_name: "nginx/1.24.0".into(),
            http3: true,
        };
        let server_listen = tunnel_addr.clone();
        let echo_str = echo_addr.to_string();
        tokio::spawn(async move {
            let _ = server::run(&server_listen, &echo_str, server_cfg).await;
        });
        wait_for_ready(&tunnel_addr).await;
        wait_for_udp_ready(&tunnel_addr).await;

        let local_port = pick_port();
        let local_addr = format!("127.0.0.1:{local_port}");
        let client_cfg = ClientCfg {
            sni: "tunnel.local".into(),
            ws_path: "/ws-h3-many".into(),
            fast_open: false,
            ech: None,
            trust: ClientTrust::CaFile(cert_path),
            fingerprint: None,
            transport: Transport::H3,
        };
        let client_listen = local_addr.clone();
        let client_upstream = tunnel_addr.clone();
        tokio::spawn(async move {
            let _ = client::run(&client_listen, &client_upstream, client_cfg).await;
        });
        wait_for_ready(&local_addr).await;

        const N: usize = 400;
        let mut tasks = Vec::with_capacity(N);
        for i in 0..N {
            let addr = local_addr.clone();
            tasks.push(tokio::spawn(async move {
                let mut sock = TcpStream::connect(&addr).await?;
                let msg = format!("{i:04}");
                sock.write_all(msg.as_bytes()).await?;
                sock.flush().await?;
                let mut buf = [0u8; 4];
                sock.read_exact(&mut buf).await?;
                assert_eq!(&buf, msg.as_bytes(), "stream {i} echoed wrong bytes");
                Ok::<(), std::io::Error>(())
            }));
        }

        let mut failed = 0;
        for (i, t) in tasks.into_iter().enumerate() {
            match t.await.expect("task panicked") {
                Ok(()) => {}
                Err(e) => {
                    failed += 1;
                    if failed <= 3 {
                        eprintln!("stream {i} failed: {e}");
                    }
                }
            }
        }
        assert_eq!(failed, 0, "{failed}/{N} concurrent h3 streams failed");
    })
    .await
}
