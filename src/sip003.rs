//! SIP003 plugin protocol — env-var and plugin-options parsing.
//!
//! `ssserver` and `sslocal` invoke this binary with four required env
//! vars and an optional fifth:
//!
//! | name              | meaning                                       |
//! |-------------------|-----------------------------------------------|
//! | `SS_REMOTE_HOST`  | public address (ss-server) or upstream peer   |
//! | `SS_REMOTE_PORT`  | …                                             |
//! | `SS_LOCAL_HOST`   | loopback host where ss-{server,local} talks   |
//! | `SS_LOCAL_PORT`   | …                                             |
//! | `SS_PLUGIN_OPTIONS` | `key=val;key=val` (optional)                |
//!
//! Whether the plugin is acting as the server-side (in front of
//! `ssserver`) or the client-side (in front of `sslocal`) is conveyed
//! via the application-defined `mode=server|client` option.
//!
//! See <https://shadowsocks.org/doc/sip003.html>.

use std::collections::HashMap;
use std::env;

use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Server,
    Client,
}

/// Parsed view of the four `SS_*` address vars plus `SS_PLUGIN_OPTIONS`.
#[derive(Debug, Clone)]
pub struct SipEnv {
    pub remote_host: String,
    pub remote_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub options: PluginOptions,
}

impl SipEnv {
    /// Read the SIP003 env vars from the current process environment.
    pub fn from_env() -> Result<Self> {
        let mut map = HashMap::new();
        for key in [
            "SS_REMOTE_HOST",
            "SS_REMOTE_PORT",
            "SS_LOCAL_HOST",
            "SS_LOCAL_PORT",
            "SS_PLUGIN_OPTIONS",
        ] {
            if let Ok(v) = env::var(key) {
                map.insert(key.to_string(), v);
            }
        }
        Self::from_map(&map)
    }

    /// Parse from a map (used both by `from_env` and by tests).
    pub fn from_map(env: &HashMap<String, String>) -> Result<Self> {
        let remote_host = required(env, "SS_REMOTE_HOST")?;
        let remote_port = required(env, "SS_REMOTE_PORT")?
            .parse::<u16>()
            .context("SS_REMOTE_PORT must be a u16")?;
        let local_host = required(env, "SS_LOCAL_HOST")?;
        let local_port = required(env, "SS_LOCAL_PORT")?
            .parse::<u16>()
            .context("SS_LOCAL_PORT must be a u16")?;

        let options = match env.get("SS_PLUGIN_OPTIONS") {
            Some(s) => PluginOptions::parse(s).context("parse SS_PLUGIN_OPTIONS")?,
            None => PluginOptions::default(),
        };

        Ok(Self {
            remote_host,
            remote_port,
            local_host,
            local_port,
            options,
        })
    }

    /// Resolve the plugin's `(listen_addr, upstream_addr)` pair given the
    /// configured `mode`. Server-side plugins listen on REMOTE and dial
    /// LOCAL; client-side plugins do the opposite.
    pub fn endpoints(&self, mode: Mode) -> (String, String) {
        let remote = format!("{}:{}", self.remote_host, self.remote_port);
        let local = format!("{}:{}", self.local_host, self.local_port);
        match mode {
            Mode::Server => (remote, local),
            Mode::Client => (local, remote),
        }
    }
}

fn required(env: &HashMap<String, String>, key: &str) -> Result<String> {
    env.get(key)
        .cloned()
        .ok_or_else(|| anyhow!("missing required env var {key}"))
}

/// `SS_PLUGIN_OPTIONS` parsed into key→value pairs.
#[derive(Debug, Clone, Default)]
pub struct PluginOptions(HashMap<String, String>);

impl PluginOptions {
    /// Parse a SIP003 plugin-options string.
    ///
    /// - options are separated by `;`
    /// - each option is `key=value` or just `key` (value defaults to `""`)
    /// - backslash escapes `\;`, `\=`, and `\\` allow those literals
    ///   inside keys or values
    pub fn parse(s: &str) -> Result<Self> {
        let mut map = HashMap::new();

        for raw in split_unescaped(s, ';') {
            if raw.is_empty() {
                continue;
            }
            let pieces = split_unescaped(&raw, '=');
            let mut it = pieces.into_iter();
            let key = unescape(it.next().unwrap_or_default());
            let value = it.next().map(unescape).unwrap_or_default();
            if it.next().is_some() {
                return Err(anyhow!(
                    "plugin option {key:?} has more than one unescaped `=`"
                ));
            }
            if key.is_empty() {
                return Err(anyhow!("empty key in plugin options: {s:?}"));
            }
            map.insert(key, value);
        }

        Ok(Self(map))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Read `mode=server|client`. Errors if the option is missing or
    /// holds an unrecognized value.
    pub fn mode(&self) -> Result<Mode> {
        match self.get("mode") {
            Some("server") => Ok(Mode::Server),
            Some("client") => Ok(Mode::Client),
            Some(other) => Err(anyhow!(
                "plugin option `mode` must be `server` or `client`, got {other:?}"
            )),
            None => Err(anyhow!(
                "plugin option `mode` is required (set via SS_PLUGIN_OPTIONS)"
            )),
        }
    }
}

/// Split `s` on every unescaped occurrence of `delim`. Backslash escapes
/// the next character (the escape itself is preserved here; `unescape`
/// resolves it later).
fn split_unescaped(s: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            current.push(c);
            if let Some(next) = chars.next() {
                current.push(next);
            }
        } else if c == delim {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    out.push(current);
    out
}

/// Resolve `\;`, `\=`, `\\` (and `\<other>` → `<other>`) in `s`.
fn unescape(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parses_required_address_vars() {
        let env = env_map(&[
            ("SS_REMOTE_HOST", "0.0.0.0"),
            ("SS_REMOTE_PORT", "443"),
            ("SS_LOCAL_HOST", "127.0.0.1"),
            ("SS_LOCAL_PORT", "9000"),
            ("SS_PLUGIN_OPTIONS", "mode=server"),
        ]);
        let s = SipEnv::from_map(&env).unwrap();
        assert_eq!(s.remote_host, "0.0.0.0");
        assert_eq!(s.remote_port, 443);
        assert_eq!(s.local_host, "127.0.0.1");
        assert_eq!(s.local_port, 9000);
        assert_eq!(s.options.mode().unwrap(), Mode::Server);
    }

    #[test]
    fn missing_required_var_errors() {
        let env = env_map(&[
            ("SS_REMOTE_HOST", "0.0.0.0"),
            ("SS_REMOTE_PORT", "443"),
            // SS_LOCAL_HOST omitted
            ("SS_LOCAL_PORT", "9000"),
        ]);
        let err = SipEnv::from_map(&env).unwrap_err();
        assert!(format!("{err:#}").contains("SS_LOCAL_HOST"));
    }

    #[test]
    fn endpoints_swap_by_mode() {
        let env = env_map(&[
            ("SS_REMOTE_HOST", "1.2.3.4"),
            ("SS_REMOTE_PORT", "443"),
            ("SS_LOCAL_HOST", "127.0.0.1"),
            ("SS_LOCAL_PORT", "9000"),
        ]);
        let s = SipEnv::from_map(&env).unwrap();
        assert_eq!(
            s.endpoints(Mode::Server),
            ("1.2.3.4:443".to_string(), "127.0.0.1:9000".to_string())
        );
        assert_eq!(
            s.endpoints(Mode::Client),
            ("127.0.0.1:9000".to_string(), "1.2.3.4:443".to_string())
        );
    }

    #[test]
    fn plugin_options_basic() {
        let opts = PluginOptions::parse("mode=server;config=/etc/foo.yaml").unwrap();
        assert_eq!(opts.get("mode"), Some("server"));
        assert_eq!(opts.get("config"), Some("/etc/foo.yaml"));
        assert_eq!(opts.get("missing"), None);
    }

    #[test]
    fn plugin_options_value_less_key() {
        let opts = PluginOptions::parse("mode=server;ech;debug=true").unwrap();
        assert_eq!(opts.get("ech"), Some(""));
        assert!(opts.contains_key("ech"));
        assert_eq!(opts.get("debug"), Some("true"));
    }

    #[test]
    fn plugin_options_escapes_semicolon_and_equals() {
        let opts = PluginOptions::parse(r"path=/ws\;1;note=a\=b").unwrap();
        assert_eq!(opts.get("path"), Some("/ws;1"));
        assert_eq!(opts.get("note"), Some("a=b"));
    }

    #[test]
    fn plugin_options_double_backslash() {
        let opts = PluginOptions::parse(r"k=a\\b").unwrap();
        assert_eq!(opts.get("k"), Some(r"a\b"));
    }

    #[test]
    fn plugin_options_empty_string_is_empty_map() {
        let opts = PluginOptions::parse("").unwrap();
        assert!(opts.0.is_empty());
    }

    #[test]
    fn plugin_options_trailing_semicolon_is_ignored() {
        let opts = PluginOptions::parse("mode=server;").unwrap();
        assert_eq!(opts.get("mode"), Some("server"));
        assert_eq!(opts.0.len(), 1);
    }

    #[test]
    fn plugin_options_empty_key_errors() {
        let err = PluginOptions::parse("=value").unwrap_err();
        assert!(format!("{err:#}").contains("empty key"));
    }

    #[test]
    fn plugin_options_extra_unescaped_equals_errors() {
        let err = PluginOptions::parse("k=a=b").unwrap_err();
        assert!(format!("{err:#}").contains("more than one unescaped"));
    }

    #[test]
    fn mode_helper_rejects_unknown_value() {
        let opts = PluginOptions::parse("mode=middle").unwrap();
        let err = opts.mode().unwrap_err();
        assert!(format!("{err:#}").contains("server"));
    }

    #[test]
    fn mode_helper_requires_option() {
        let opts = PluginOptions::parse("config=/x.yaml").unwrap();
        assert!(opts.mode().is_err());
    }
}
