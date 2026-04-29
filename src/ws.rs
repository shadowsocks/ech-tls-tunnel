//! WebSocket byte-stream adapter.
//!
//! Wraps a [`WebSocketStream`] so that it implements
//! `AsyncRead + AsyncWrite`, letting [`tokio::io::copy_bidirectional`]
//! shovel raw bytes between a WS connection and a plain TCP socket
//! (the SIP003 upstream/downstream).
//!
//! - Writes become Binary frames.
//! - Reads concatenate Binary and Text frame payloads (shadowsocks data
//!   is binary; we accept Text purely to avoid breaking on a peer that
//!   misuses it).
//! - Pings are auto-ponged inside `tungstenite`.
//! - A Close frame from the peer surfaces as EOF on the read side.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

pin_project! {
    /// `AsyncRead + AsyncWrite` wrapper around a [`WebSocketStream`].
    pub struct WsByteStream<S> {
        #[pin]
        inner: WebSocketStream<S>,
        read_buf: Bytes,
        eof: bool,
    }
}

impl<S> WsByteStream<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
            eof: false,
        }
    }

    pub fn into_inner(self) -> WebSocketStream<S> {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                *this.read_buf = this.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }
            if *this.eof {
                return Poll::Ready(Ok(())); // EOF
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    *this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        *this.read_buf = Bytes::from(data);
                    }
                    Message::Text(s) => {
                        *this.read_buf = Bytes::from(s.into_bytes());
                    }
                    Message::Close(_) => {
                        *this.eof = true;
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        // tungstenite handles ping replies; just keep reading.
                    }
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_err(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io_err(e))),
            Poll::Ready(Ok(())) => {}
        }
        let msg = Message::Binary(buf.to_vec());
        this.inner.as_mut().start_send(msg).map_err(io_err)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx).map_err(io_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        this.inner.poll_close(cx).map_err(io_err)
    }
}

fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> std::io::Error {
    std::io::Error::other(e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{accept_async, client_async};

    /// Spin up a TCP listener, accept one connection, run the WS
    /// handshake on each side, and return both ends wrapped in
    /// [`WsByteStream`].
    async fn ws_pair() -> (
        WsByteStream<TcpStream>, // client
        WsByteStream<TcpStream>, // server
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.unwrap();
            WsByteStream::new(ws)
        });
        let url = format!("ws://{addr}/ws");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (ws, _resp) = client_async(&url, tcp).await.unwrap();
        let server = server_handle.await.unwrap();
        (WsByteStream::new(ws), server)
    }

    #[tokio::test]
    async fn small_payload_round_trips_both_directions() {
        let (mut client, mut server) = ws_pair().await;

        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server.write_all(b"world").await.unwrap();
        server.flush().await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn one_megabyte_round_trips() {
        let (mut client, mut server) = ws_pair().await;
        let payload: Vec<u8> = (0..1_000_000).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let server_task = tokio::spawn(async move {
            let mut got = vec![0u8; payload_clone.len()];
            server.read_exact(&mut got).await.unwrap();
            // echo back to exercise the other direction
            server.write_all(&got).await.unwrap();
            server.flush().await.unwrap();
            got
        });

        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        let received_at_server = server_task.await.unwrap();
        assert_eq!(received_at_server, payload);
    }

    #[tokio::test]
    async fn shutdown_propagates_eof() {
        let (mut client, mut server) = ws_pair().await;

        // Client closes after writing.
        client.write_all(b"bye").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);

        // Server reads the bytes, then sees EOF.
        let mut buf = [0u8; 3];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"bye");
        let n = server.read(&mut [0u8; 16]).await.unwrap();
        assert_eq!(n, 0);
    }
}
