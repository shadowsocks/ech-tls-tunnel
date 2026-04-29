//! Stealth layer that hides the tunnel from probes and scanners.
//!
//! HTTPS requests that don't hit the secret WebSocket path receive an
//! nginx-style 404, making the listener indistinguishable from a
//! misconfigured static-file web server.

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;

/// Build a fake 404 response mimicking nginx.
///
/// The response sets `Server: <server_name>` and an HTML body identical
/// to the one nginx serves for a missing page.
pub fn fake_404(server_name: &str) -> Response<Full<Bytes>> {
    let body = concat!(
        "<html>\r\n",
        "<head><title>404 Not Found</title></head>\r\n",
        "<body>\r\n",
        "<center><h1>404 Not Found</h1></center>\r\n",
        "<hr><center>nginx/1.24.0</center>\r\n",
        "</body>\r\n",
        "</html>\r\n",
    );

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Server", server_name)
        .header("Content-Type", "text/html")
        .header("Content-Length", body.len().to_string())
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn fake_404_has_status_server_and_nginx_body() {
        let resp = fake_404("nginx/1.24.0");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("Server").unwrap().to_str().unwrap(),
            "nginx/1.24.0"
        );
        assert_eq!(
            resp.headers()
                .get("Content-Type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/html"
        );

        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&collected).unwrap();
        assert!(body.contains("<h1>404 Not Found</h1>"));
        assert!(body.contains("nginx/1.24.0"));
    }

    #[tokio::test]
    async fn fake_404_server_header_is_configurable() {
        let resp = fake_404("Apache/2.4.58 (Ubuntu)");
        assert_eq!(
            resp.headers().get("Server").unwrap().to_str().unwrap(),
            "Apache/2.4.58 (Ubuntu)"
        );
    }
}
