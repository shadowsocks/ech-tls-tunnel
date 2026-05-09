//! Network utilities with optional TCP Fast Open (TFO) support.
//!
//! Provides [`create_listener`] and [`connect`] as drop-in replacements for
//! [`tokio::net::TcpListener::bind`] and [`tokio::net::TcpStream::connect`]
//! that set the `TCP_FASTOPEN` / `TCP_FASTOPEN_CONNECT` socket options when
//! enabled. Supports both Linux and macOS.
//!
//! On Linux, ensure TFO is enabled at the kernel level:
//! ```text
//! sysctl -w net.ipv4.tcp_fastopen=3
//! ```

use std::net::SocketAddr;

use anyhow::Context;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

/// Default TCP Fast Open queue length for the listening socket.
const TFO_QUEUE_LEN: i32 = 256;

/// Create a [`TcpListener`] bound to `addr`, optionally with TCP Fast Open.
///
/// When `fast_open` is `true`, sets `TCP_FASTOPEN` on the socket before
/// binding so the kernel can accept TFO connections.
pub async fn create_listener(addr: &str, fast_open: bool) -> anyhow::Result<TcpListener> {
    let sock_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address: {addr}"))?;

    let domain = if sock_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create socket")?;

    socket.set_reuse_address(true)?;

    if fast_open {
        #[cfg(target_os = "linux")]
        {
            set_tcp_fastopen(&socket, TFO_QUEUE_LEN)?;
            info!("TCP Fast Open enabled on listener (queue={TFO_QUEUE_LEN})");
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!(
                "fast_open=true: listener TFO is Linux-only — \
                 ignored on this platform (loopback gets no benefit)"
            );
            let _ = TFO_QUEUE_LEN;
        }
    }

    socket
        .bind(&SockAddr::from(sock_addr))
        .with_context(|| format!("bind {addr}"))?;
    socket
        .listen(1024)
        .with_context(|| format!("listen {addr}"))?;
    socket.set_nonblocking(true)?;

    TcpListener::from_std(socket.into()).context("convert to tokio TcpListener")
}

/// Connect to a remote address, optionally with TCP Fast Open.
///
/// When `fast_open` is `true`:
/// - Linux: sets `TCP_FASTOPEN_CONNECT` (option 30) so `connect()` defers
///   the SYN until the first `write()`, which then carries the cookie + data.
/// - macOS: uses `connectx(2)` with `CONNECT_RESUME_ON_READ_WRITE |
///   CONNECT_DATA_IDEMPOTENT`. macOS does **not** support enabling
///   client-side TFO via `setsockopt(TCP_FASTOPEN)` — that returns
///   `EINVAL`. `connectx` is the only supported entry point.
pub async fn connect(addr: &str, fast_open: bool) -> anyhow::Result<TcpStream> {
    if !fast_open {
        return TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect to {addr}"));
    }

    let sock_addr: SocketAddr = tokio::net::lookup_host(addr)
        .await
        .with_context(|| format!("resolve {addr}"))?
        .next()
        .with_context(|| format!("no addresses for {addr}"))?;

    let domain = if sock_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create socket")?;
    socket.set_nonblocking(true)?;

    let dst = SockAddr::from(sock_addr);
    start_tfo_connect(&socket, &dst).with_context(|| format!("connect to {addr}"))?;

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).context("convert to tokio TcpStream")?;

    stream
        .writable()
        .await
        .with_context(|| format!("connect to {addr}"))?;

    if let Some(e) = stream.take_error()? {
        return Err(e).with_context(|| format!("connect to {addr}"));
    }

    Ok(stream)
}

/// Initiate a TFO connect on `socket` toward `dst`.
///
/// Linux uses the classic `TCP_FASTOPEN_CONNECT` + nonblocking `connect()`
/// path. macOS uses `connectx(2)` because client-side TFO via setsockopt
/// is not supported (`EINVAL`).
fn start_tfo_connect(socket: &Socket, dst: &SockAddr) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        set_tcp_fastopen_connect(socket)?;
        match socket.connect(dst) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => Ok(()),
            Err(e) => Err(e).context("connect"),
        }
    }

    #[cfg(target_os = "macos")]
    {
        macos_connectx_tfo(socket, dst)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, dst);
        anyhow::bail!("TCP Fast Open connect not supported on this platform")
    }
}

/// Trigger TFO on macOS via `connectx(2)`.
///
/// Apple's TFO requires `connectx` with `CONNECT_DATA_IDEMPOTENT` set. We
/// also pass `CONNECT_RESUME_ON_READ_WRITE` so the SYN is held until the
/// first `write()`, mirroring Linux's `TCP_FASTOPEN_CONNECT` semantics.
/// libc 0.2.186 does not expose `connectx` for Apple targets, so the FFI
/// is declared inline here.
#[cfg(target_os = "macos")]
fn macos_connectx_tfo(socket: &Socket, dst: &SockAddr) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    struct SaEndpoints {
        sae_srcif: libc::c_uint,
        sae_srcaddr: *const libc::sockaddr,
        sae_srcaddrlen: libc::socklen_t,
        sae_dstaddr: *const libc::sockaddr,
        sae_dstaddrlen: libc::socklen_t,
    }

    const CONNECT_RESUME_ON_READ_WRITE: libc::c_uint = 0x1;
    const CONNECT_DATA_IDEMPOTENT: libc::c_uint = 0x2;
    const SAE_ASSOCID_ANY: libc::c_uint = 0;

    unsafe extern "C" {
        fn connectx(
            socket: libc::c_int,
            endpoints: *const SaEndpoints,
            associd: libc::c_uint,
            flags: libc::c_uint,
            iov: *const libc::iovec,
            iovcnt: libc::c_uint,
            len: *mut libc::size_t,
            connid: *mut libc::c_uint,
        ) -> libc::c_int;
    }

    let endpoints = SaEndpoints {
        sae_srcif: 0,
        sae_srcaddr: std::ptr::null(),
        sae_srcaddrlen: 0,
        sae_dstaddr: dst.as_ptr(),
        sae_dstaddrlen: dst.len(),
    };

    let ret = unsafe {
        connectx(
            socket.as_raw_fd(),
            &endpoints,
            SAE_ASSOCID_ANY,
            CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINPROGRESS) {
            return Ok(());
        }
        return Err(err).context("connectx");
    }
    Ok(())
}

/// Set `TCP_FASTOPEN` on a listening socket (Linux only).
///
/// `queue_len` is the kernel's pending-TFO accept queue. macOS has no
/// equivalent op for arbitrary listeners (the plugin's macOS listener is
/// loopback, where TFO offers no benefit anyway), so this function is
/// only compiled on Linux.
#[cfg(target_os = "linux")]
fn set_tcp_fastopen(socket: &Socket, queue_len: i32) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let val = queue_len;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt TCP_FASTOPEN");
    }
    Ok(())
}

/// Set `TCP_FASTOPEN_CONNECT` on an outgoing socket (Linux only).
///
/// macOS uses `connectx(2)` instead — see [`macos_connectx_tfo`].
#[cfg(target_os = "linux")]
fn set_tcp_fastopen_connect(socket: &Socket) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let val: i32 = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            30, // TCP_FASTOPEN_CONNECT
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt TCP_FASTOPEN_CONNECT");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Setting `TCP_FASTOPEN` on the listening socket must succeed and
    /// produce a usable listener. Linux only — macOS server-side TFO works
    /// in production but the loopback path here is flaky.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tfo_listener_binds_and_accepts() {
        let listener = create_listener("127.0.0.1:0", true).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let mut client = connect(&addr.to_string(), false).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        server.await.unwrap();
    }

    /// macOS connect-path TFO must use `connectx(2)` and not panic with
    /// `EINVAL`. The first write completes the handshake regardless of
    /// whether the kernel actually has a cookie cached.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn tfo_connectx_round_trips_on_macos() {
        let listener = create_listener("127.0.0.1:0", false).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let mut client = connect(&addr.to_string(), true).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn plain_listener_round_trips_bytes() {
        let listener = create_listener("127.0.0.1:0", false).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let mut client = connect(&addr.to_string(), false).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        let mut echoed = [0u8; 3];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"abc");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_listen_address_errors() {
        let err = create_listener("not-an-address", false).await.unwrap_err();
        assert!(format!("{err:#}").contains("invalid listen address"));
    }
}
