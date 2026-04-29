//! Full SIP003 end-to-end test against shadowsocks-rust.
//!
//! Spawns `ssserver` and `sslocal` (from the `shadowsocks-rust`
//! distribution) as subprocesses, each with our plugin binary attached
//! via `--plugin`. Drives traffic with `curl --socks5-hostname` against
//! an in-process echo HTTP server. Self-signed cert, all on
//! `127.0.0.1`.
//!
//! Skips cleanly with a clear message if `ssserver`, `sslocal`, or
//! `curl` aren't on `PATH`.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Hard deadline for the e2e test.
const TEST_TIMEOUT: Duration = Duration::from_secs(600);

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn precondition() -> Option<String> {
    for tool in ["ssserver", "sslocal", "curl"] {
        if which::which(tool).is_err() {
            return Some(format!(
                "{tool} not on PATH; install shadowsocks-rust + curl to run this test"
            ));
        }
    }
    None
}

async fn wait_for_ready(addr: &str) {
    for _ in 0..80 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("listener at {addr} did not become ready");
}

/// Tiny HTTP/1.1 echo server: responds `200 OK` with body `echo:<path>`.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let body = format!("echo:{path}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sip003_full_pipeline_with_shadowsocks_rust() {
    tokio::time::timeout(
        TEST_TIMEOUT,
        sip003_full_pipeline_with_shadowsocks_rust_inner(),
    )
    .await
    .expect("sip003_e2e timed out after 10 minutes");
}

async fn sip003_full_pipeline_with_shadowsocks_rust_inner() {
    if let Some(reason) = precondition() {
        eprintln!("SKIP sip003_e2e: {reason}");
        return;
    }

    // The plugin binary built by `cargo test` (cargo sets this env var
    // for integration tests so we don't have to re-invoke cargo).
    let plugin_path: PathBuf = env!("CARGO_BIN_EXE_ech-tls-tunnel").into();
    assert!(
        plugin_path.exists(),
        "plugin binary missing at {}",
        plugin_path.display()
    );

    // ── self-signed cert ──────────────────────────────────────────────
    let kp = rcgen::generate_simple_self_signed(vec!["tunnel.local".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, kp.cert.pem()).unwrap();
    std::fs::write(&key_path, kp.key_pair.serialize_pem()).unwrap();

    // ── echo server (the "destination" for curl traffic) ─────────────
    let echo_addr = spawn_echo_server().await;

    // ── ports for the public tunnel and the local SOCKS5 ─────────────
    let tunnel_port = pick_port();
    let local_port = pick_port();

    // ── ssserver + plugin ────────────────────────────────────────────
    let ssserver_opts = format!(
        "mode=server;domain=tunnel.local;path=/ws-test;cert={};key={}",
        cert_path.display(),
        key_path.display()
    );
    let _ssserver = ChildGuard(Some(
        Command::new("ssserver")
            .args([
                "-s",
                &format!("127.0.0.1:{tunnel_port}"),
                "-k",
                "testpass-12345",
                "-m",
                "aes-128-gcm",
                "--plugin",
                plugin_path.to_str().unwrap(),
                "--plugin-opts",
                &ssserver_opts,
            ])
            .spawn()
            .expect("spawn ssserver"),
    ));

    wait_for_ready(&format!("127.0.0.1:{tunnel_port}")).await;

    // ── sslocal + plugin ─────────────────────────────────────────────
    let sslocal_opts = format!(
        "mode=client;sni=tunnel.local;path=/ws-test;ca_file={}",
        cert_path.display()
    );
    let _sslocal = ChildGuard(Some(
        Command::new("sslocal")
            .args([
                "-b",
                &format!("127.0.0.1:{local_port}"),
                "-s",
                &format!("127.0.0.1:{tunnel_port}"),
                "-k",
                "testpass-12345",
                "-m",
                "aes-128-gcm",
                "--protocol",
                "socks",
                "--plugin",
                plugin_path.to_str().unwrap(),
                "--plugin-opts",
                &sslocal_opts,
            ])
            .spawn()
            .expect("spawn sslocal"),
    ));

    wait_for_ready(&format!("127.0.0.1:{local_port}")).await;
    // sslocal sometimes accepts on its SOCKS port a beat before the
    // plugin upstream listener is ready; small extra grace.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── drive traffic with curl through the SOCKS5 entrypoint ────────
    let url = format!("http://{}/hello", echo_addr);
    let out = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--socks5-hostname",
            &format!("127.0.0.1:{local_port}"),
            &url,
        ])
        .output()
        .expect("run curl");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "curl failed: status={:?}\nstdout: {}\nstderr: {}",
        out.status,
        stdout,
        stderr
    );
    assert_eq!(
        stdout.trim(),
        "echo:/hello",
        "unexpected response body: stdout={stdout:?} stderr={stderr:?}"
    );
}
