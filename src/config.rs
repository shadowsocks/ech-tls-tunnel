//! Plugin configuration, derived entirely from `SS_PLUGIN_OPTIONS`.
//!
//! No YAML, no separate config file — everything the plugin needs is
//! one option-string set by `ssserver` / `sslocal`. This keeps the
//! deployment story tiny: paste a single line into the shadowsocks
//! config and you're done.
//!
//! # Option keys
//!
//! Common (both modes):
//! - `mode=server|client` (required)
//! - `path=/<ws-path>` (required, must start with `/`)
//! - `fast_open=true|false` (default `false`)
//!
//! Server (`mode=server`):
//! - `domain=<real-domain>` (required, inner SNI / cert SAN)
//! - `cert=<path>` + `key=<path>` (static cert/key on disk) — or —
//! - `acme_email=<addr>` (auto cert via Let's Encrypt)
//! - `acme_cache=<dir>` (default `/var/lib/ech-tls-tunnel/acme`)
//! - `acme_staging=true|false` (default `false`)
//! - `acme_cover_san=true|false` (default `true`) — include
//!   `ech_public_name` as a SAN on the ACME cert. Set to `false` when
//!   the cover name is a domain you don't own (e.g. `www.baidu.com`)
//!   so the order only requests a cert for `domain`.
//! - `ech_public_name=<name>` + `ech_key=<path>` (both required for ECH)
//! - `reject_non_ech=true|false` (default `true`, only meaningful when
//!   ECH is enabled) — TCP-RST any inbound TLS handshake that lacks
//!   the ECH extension (and isn't an ACME `acme-tls/1` validator), so
//!   active probes don't observe the production cert.
//! - `server_name=<header value>` (default `nginx/1.24.0`)
//!
//! Client (`mode=client`):
//! - `sni=<real-domain>` (required, inner SNI / Host)
//! - `ech_config=<base64>` — or — `ech_config_file=<path>` (enables ECH)
//! - `ca_file=<path>` (override default trust store)
//! - `insecure=true` (DEV/TEST ONLY — disable verification)
//! - `fingerprint=<profile>` (TLS ClientHello shaping; one of
//!   `chrome|firefox|safari|ios|android|edge|random`)

use std::path::PathBuf;

use anyhow::{anyhow, Result};

use crate::sip003::{Mode, PluginOptions};

#[derive(Debug, Clone)]
pub enum Config {
    Server(ServerCfg),
    Client(ClientCfg),
}

impl Config {
    /// Build the full config from a parsed plugin-options string.
    pub fn from_options(opts: &PluginOptions) -> Result<Self> {
        match opts.mode()? {
            Mode::Server => Ok(Config::Server(ServerCfg::from_options(opts)?)),
            Mode::Client => Ok(Config::Client(ClientCfg::from_options(opts)?)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerCfg {
    /// Real tunnel domain (inner SNI; SAN on the production cert).
    pub domain: String,
    /// Secret WebSocket path; non-matching requests get a fake nginx 404.
    pub ws_path: String,
    /// TCP Fast Open on listener and outgoing connections.
    pub fast_open: bool,
    /// How the production TLS cert/key are obtained.
    pub tls: ServerTls,
    /// ECH HPKE keys; `None` disables ECH.
    pub ech: Option<ServerEch>,
    /// Include `ech_public_name` as a SAN on the ACME cert when distinct
    /// from `domain`. Set `false` when the cover name is a domain you
    /// don't own — ACME issuance would otherwise fail.
    pub acme_cover_san: bool,
    /// When ECH is enabled, drop (TCP-RST) inbound TLS handshakes that
    /// don't carry the ECH extension and aren't ACME validators.
    pub reject_non_ech: bool,
    /// `Server` header value for fake-404 responses.
    pub server_name: String,
}

#[derive(Debug, Clone)]
pub struct ClientCfg {
    /// Real upstream hostname (inner SNI / Host header).
    pub sni: String,
    /// WebSocket path on the upstream; must match the server's `path`.
    pub ws_path: String,
    /// TCP Fast Open on outgoing connections.
    pub fast_open: bool,
    /// ECH ConfigList for the upstream; `None` disables ECH.
    pub ech: Option<ClientEch>,
    /// Trust source for verifying the upstream cert.
    pub trust: ClientTrust,
    /// Browser-fingerprint profile for the TLS ClientHello.
    /// `None` = boring defaults; otherwise one of the names accepted by
    /// [`crate::fingerprint::resolve`].
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ServerTls {
    /// PEM cert/key on disk. Used for tests and the v0.1 path before
    /// ACME lands.
    Static {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    /// Auto-issued via Let's Encrypt (TLS-ALPN-01). Wired in v0.2.
    Acme {
        email: String,
        staging: bool,
        cache_dir: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct ServerEch {
    pub public_name: String,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ClientEch {
    /// Base64 ECHConfigList, pasted into the option string.
    Inline(String),
    /// Path to a binary ECHConfigList file.
    File(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub enum ClientTrust {
    /// webpki-roots / Mozilla root store.
    #[default]
    SystemRoots,
    /// Pin to a specific CA bundle.
    CaFile(PathBuf),
    /// Skip verification entirely. Dev/test only.
    InsecureSkipVerify,
}

impl ServerCfg {
    pub fn from_options(o: &PluginOptions) -> Result<Self> {
        let domain = required(o, "domain")?;
        let ws_path = ws_path(o)?;
        let fast_open = parse_bool(o, "fast_open")?.unwrap_or(false);
        let tls = build_server_tls(o)?;
        let ech = build_server_ech(o)?;
        let acme_cover_san = parse_bool(o, "acme_cover_san")?.unwrap_or(true);
        let reject_non_ech = parse_bool(o, "reject_non_ech")?.unwrap_or(true);
        let server_name = o
            .get("server_name")
            .map(str::to_string)
            .unwrap_or_else(|| "nginx/1.24.0".to_string());

        Ok(Self {
            domain,
            ws_path,
            fast_open,
            tls,
            ech,
            acme_cover_san,
            reject_non_ech,
            server_name,
        })
    }
}

impl ClientCfg {
    pub fn from_options(o: &PluginOptions) -> Result<Self> {
        let sni = required(o, "sni")?;
        let ws_path = ws_path(o)?;
        let fast_open = parse_bool(o, "fast_open")?.unwrap_or(false);
        let ech = build_client_ech(o)?;
        let trust = build_client_trust(o)?;
        let fingerprint = build_fingerprint(o)?;

        Ok(Self {
            sni,
            ws_path,
            fast_open,
            ech,
            trust,
            fingerprint,
        })
    }
}

fn build_fingerprint(o: &PluginOptions) -> Result<Option<String>> {
    let Some(raw) = o.get("fingerprint") else {
        return Ok(None);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    if crate::fingerprint::resolve(&normalized).is_none() {
        return Err(anyhow!(
            "unknown fingerprint {raw:?}; expected one of \
             chrome|firefox|safari|ios|android|edge|random \
             (or a versioned alias like chrome120, firefox120, safari16, ios14, android11, edge85)"
        ));
    }
    Ok(Some(normalized))
}

fn required(o: &PluginOptions, key: &str) -> Result<String> {
    o.get(key)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("plugin option `{key}` is required"))
}

fn ws_path(o: &PluginOptions) -> Result<String> {
    let p = required(o, "path")?;
    if !p.starts_with('/') {
        return Err(anyhow!("plugin option `path` must start with `/`: {p:?}"));
    }
    Ok(p)
}

fn parse_bool(o: &PluginOptions, key: &str) -> Result<Option<bool>> {
    match o.get(key) {
        None => Ok(None),
        Some("true" | "1" | "yes" | "on") => Ok(Some(true)),
        Some("false" | "0" | "no" | "off" | "") => Ok(Some(false)),
        Some(v) => Err(anyhow!(
            "plugin option `{key}` must be a boolean, got {v:?}"
        )),
    }
}

fn build_server_tls(o: &PluginOptions) -> Result<ServerTls> {
    let cert = o.get("cert");
    let key = o.get("key");
    let acme_email = o.get("acme_email");

    match (cert, key) {
        (Some(c), Some(k)) => {
            if acme_email.is_some() {
                return Err(anyhow!(
                    "static cert (`cert`/`key`) and `acme_email` are mutually exclusive"
                ));
            }
            Ok(ServerTls::Static {
                cert_file: PathBuf::from(c),
                key_file: PathBuf::from(k),
            })
        }
        (Some(_), None) => Err(anyhow!("plugin option `key` must accompany `cert`")),
        (None, Some(_)) => Err(anyhow!("plugin option `cert` must accompany `key`")),
        (None, None) => match acme_email {
            Some(email) => {
                let cache_dir = o
                    .get("acme_cache")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/var/lib/ech-tls-tunnel/acme"));
                let staging = parse_bool(o, "acme_staging")?.unwrap_or(false);
                Ok(ServerTls::Acme {
                    email: email.to_string(),
                    staging,
                    cache_dir,
                })
            }
            None => Err(anyhow!(
                "must provide either `cert`+`key` or `acme_email` for the server cert"
            )),
        },
    }
}

fn build_server_ech(o: &PluginOptions) -> Result<Option<ServerEch>> {
    match (o.get("ech_public_name"), o.get("ech_key")) {
        (None, None) => Ok(None),
        (Some(name), Some(key)) => Ok(Some(ServerEch {
            public_name: name.to_string(),
            key_file: PathBuf::from(key),
        })),
        (Some(_), None) => Err(anyhow!("`ech_public_name` requires `ech_key`")),
        (None, Some(_)) => Err(anyhow!("`ech_key` requires `ech_public_name`")),
    }
}

fn build_client_ech(o: &PluginOptions) -> Result<Option<ClientEch>> {
    match (o.get("ech_config"), o.get("ech_config_file")) {
        (None, None) => Ok(None),
        (Some(b64), None) => Ok(Some(ClientEch::Inline(b64.to_string()))),
        (None, Some(path)) => Ok(Some(ClientEch::File(PathBuf::from(path)))),
        (Some(_), Some(_)) => Err(anyhow!(
            "`ech_config` and `ech_config_file` are mutually exclusive"
        )),
    }
}

fn build_client_trust(o: &PluginOptions) -> Result<ClientTrust> {
    let ca = o.get("ca_file");
    let insecure = parse_bool(o, "insecure")?.unwrap_or(false);

    match (ca, insecure) {
        (Some(_), true) => Err(anyhow!(
            "`ca_file` and `insecure=true` are mutually exclusive"
        )),
        (Some(p), false) => Ok(ClientTrust::CaFile(PathBuf::from(p))),
        (None, true) => Ok(ClientTrust::InsecureSkipVerify),
        (None, false) => Ok(ClientTrust::SystemRoots),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(s: &str) -> PluginOptions {
        PluginOptions::parse(s).unwrap()
    }

    fn server_cfg(s: &str) -> ServerCfg {
        match Config::from_options(&opts(s)).unwrap() {
            Config::Server(s) => s,
            Config::Client(_) => panic!("expected server"),
        }
    }

    fn client_cfg(s: &str) -> ClientCfg {
        match Config::from_options(&opts(s)).unwrap() {
            Config::Client(c) => c,
            Config::Server(_) => panic!("expected client"),
        }
    }

    fn err_str(s: &str) -> String {
        format!("{:#}", Config::from_options(&opts(s)).unwrap_err())
    }

    #[test]
    fn server_minimum_static_cert() {
        let c = server_cfg(
            "mode=server;domain=tunnel.example.com;path=/ws;cert=/tmp/c.pem;key=/tmp/k.pem",
        );
        assert_eq!(c.domain, "tunnel.example.com");
        assert_eq!(c.ws_path, "/ws");
        assert!(!c.fast_open);
        assert_eq!(c.server_name, "nginx/1.24.0");
        assert!(c.ech.is_none());
        match c.tls {
            ServerTls::Static {
                cert_file,
                key_file,
            } => {
                assert_eq!(cert_file, PathBuf::from("/tmp/c.pem"));
                assert_eq!(key_file, PathBuf::from("/tmp/k.pem"));
            }
            ServerTls::Acme { .. } => panic!("expected static"),
        }
    }

    #[test]
    fn server_acme_with_defaults() {
        let c = server_cfg("mode=server;domain=tunnel.example.com;path=/ws;acme_email=a@b.c");
        match c.tls {
            ServerTls::Acme {
                email,
                staging,
                cache_dir,
            } => {
                assert_eq!(email, "a@b.c");
                assert!(!staging);
                assert_eq!(cache_dir, PathBuf::from("/var/lib/ech-tls-tunnel/acme"));
            }
            ServerTls::Static { .. } => panic!("expected acme"),
        }
    }

    #[test]
    fn server_acme_with_overrides() {
        let c = server_cfg(
            "mode=server;domain=t.x;path=/ws;acme_email=a@b.c;\
             acme_cache=/srv/acme;acme_staging=true",
        );
        match c.tls {
            ServerTls::Acme {
                staging, cache_dir, ..
            } => {
                assert!(staging);
                assert_eq!(cache_dir, PathBuf::from("/srv/acme"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn server_ech_pair_required_together() {
        assert!(
            err_str("mode=server;domain=t.x;path=/ws;cert=/c;key=/k;ech_public_name=front.x")
                .contains("ech_key")
        );
        assert!(
            err_str("mode=server;domain=t.x;path=/ws;cert=/c;key=/k;ech_key=/e.key")
                .contains("ech_public_name")
        );
    }

    #[test]
    fn server_acme_cover_san_default_true() {
        let c = server_cfg(
            "mode=server;domain=t.x;path=/ws;acme_email=a@b.c;\
             ech_public_name=front.x;ech_key=/e.key",
        );
        assert!(c.acme_cover_san);
    }

    #[test]
    fn server_acme_cover_san_opt_out() {
        let c = server_cfg(
            "mode=server;domain=t.x;path=/ws;acme_email=a@b.c;\
             ech_public_name=www.baidu.com;ech_key=/e.key;acme_cover_san=false",
        );
        assert!(!c.acme_cover_san);
    }

    #[test]
    fn server_reject_non_ech_default_true() {
        let c = server_cfg("mode=server;domain=t.x;path=/ws;cert=/c;key=/k");
        assert!(c.reject_non_ech);
    }

    #[test]
    fn server_reject_non_ech_opt_out() {
        let c = server_cfg("mode=server;domain=t.x;path=/ws;cert=/c;key=/k;reject_non_ech=false");
        assert!(!c.reject_non_ech);
    }

    #[test]
    fn server_ech_both_yields_some() {
        let c = server_cfg(
            "mode=server;domain=t.x;path=/ws;cert=/c;key=/k;\
             ech_public_name=front.x;ech_key=/e.key",
        );
        let ech = c.ech.expect("ech expected");
        assert_eq!(ech.public_name, "front.x");
        assert_eq!(ech.key_file, PathBuf::from("/e.key"));
    }

    #[test]
    fn server_static_and_acme_are_exclusive() {
        let err = err_str("mode=server;domain=t.x;path=/ws;cert=/c;key=/k;acme_email=a@b.c");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn server_missing_cert_or_acme_email_errors() {
        let err = err_str("mode=server;domain=t.x;path=/ws");
        assert!(err.contains("cert") || err.contains("acme_email"));
    }

    #[test]
    fn server_path_must_start_with_slash() {
        let err = err_str("mode=server;domain=t.x;path=ws;cert=/c;key=/k");
        assert!(err.contains("path") && err.contains('/'));
    }

    #[test]
    fn server_custom_server_name_and_fast_open() {
        let c = server_cfg(
            "mode=server;domain=t.x;path=/ws;cert=/c;key=/k;\
             server_name=Apache/2.4;fast_open=yes",
        );
        assert_eq!(c.server_name, "Apache/2.4");
        assert!(c.fast_open);
    }

    #[test]
    fn client_minimum() {
        let c = client_cfg("mode=client;sni=tunnel.example.com;path=/ws");
        assert_eq!(c.sni, "tunnel.example.com");
        assert_eq!(c.ws_path, "/ws");
        assert!(c.ech.is_none());
        assert!(matches!(c.trust, ClientTrust::SystemRoots));
    }

    #[test]
    fn client_ech_inline() {
        let c = client_cfg("mode=client;sni=t.x;path=/ws;ech_config=AAAAAA");
        match c.ech.unwrap() {
            ClientEch::Inline(b64) => assert_eq!(b64, "AAAAAA"),
            ClientEch::File(_) => panic!("expected inline"),
        }
    }

    #[test]
    fn client_ech_file() {
        let c = client_cfg("mode=client;sni=t.x;path=/ws;ech_config_file=/e.bin");
        match c.ech.unwrap() {
            ClientEch::File(p) => assert_eq!(p, PathBuf::from("/e.bin")),
            ClientEch::Inline(_) => panic!("expected file"),
        }
    }

    #[test]
    fn client_ech_inline_and_file_exclusive() {
        let err = err_str("mode=client;sni=t.x;path=/ws;ech_config=AAAA;ech_config_file=/e.bin");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn client_trust_ca_file() {
        let c = client_cfg("mode=client;sni=t.x;path=/ws;ca_file=/etc/ca.pem");
        assert!(
            matches!(c.trust, ClientTrust::CaFile(ref p) if p == &PathBuf::from("/etc/ca.pem"))
        );
    }

    #[test]
    fn client_trust_insecure() {
        let c = client_cfg("mode=client;sni=t.x;path=/ws;insecure=true");
        assert!(matches!(c.trust, ClientTrust::InsecureSkipVerify));
    }

    #[test]
    fn client_trust_ca_and_insecure_exclusive() {
        let err = err_str("mode=client;sni=t.x;path=/ws;ca_file=/etc/ca.pem;insecure=true");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn parse_bool_rejects_garbage() {
        let err = err_str("mode=server;domain=t.x;path=/ws;cert=/c;key=/k;fast_open=maybe");
        assert!(err.contains("boolean"));
    }

    #[test]
    fn client_fingerprint_recognized_names() {
        for fp in [
            "chrome",
            "Chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "random",
            "chrome120",
        ] {
            let c = client_cfg(&format!("mode=client;sni=t.x;path=/ws;fingerprint={fp}"));
            assert_eq!(c.fingerprint, Some(fp.to_ascii_lowercase()));
        }
    }

    #[test]
    fn client_fingerprint_default_is_none() {
        let c = client_cfg("mode=client;sni=t.x;path=/ws");
        assert!(c.fingerprint.is_none());
    }

    #[test]
    fn client_fingerprint_unknown_errors() {
        let err = err_str("mode=client;sni=t.x;path=/ws;fingerprint=netscape");
        assert!(
            err.contains("unknown fingerprint"),
            "expected unknown fingerprint error, got: {err}"
        );
    }
}
