//! ECH (Encrypted Client Hello) — server keypair and ConfigList wiring.
//!
//! Server side: holds an HPKE X25519/HKDF-SHA256 keypair and the
//! `public_name` advertised in the cleartext ClientHello. Wraps
//! BoringSSL's `EVP_HPKE_KEY_*` and `SSL_*_ech_*` FFI from `boring-sys`,
//! which exposes the full ECH surface (`SSL_marshal_ech_config`,
//! `SSL_ECH_KEYS_*`, `SSL_CTX_set1_ech_keys`, `SSL_set1_ech_config_list`).
//!
//! Client side: a single helper that takes the binary ECHConfigList
//! (whether decoded from base64 or read from disk) and applies it to
//! a per-connection `SslRef` before the handshake.
//!
//! On-disk format for the server key (see [`EchServerKey::write_to`]):
//!
//! ```text
//! [u8 config_id]
//! [u16 BE name_len]
//! [name_len bytes UTF-8 public_name]
//! [32 bytes raw X25519 private key]
//! ```

use std::ffi::CString;
use std::path::Path;
use std::ptr::NonNull;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use boring::ssl::{SslContextBuilder, SslRef};
use foreign_types_shared::ForeignTypeRef;

const X25519_PRIVATE_KEY_LEN: usize = 32;
/// `0` lets BoringSSL pick the conventional max name length when
/// padding the ClientHelloInner.
const MAX_NAME_LENGTH: usize = 0;

/// Server-side ECH key material (HPKE X25519/HKDF-SHA256).
#[derive(Clone)]
pub struct EchServerKey {
    config_id: u8,
    public_name: String,
    private_key: [u8; X25519_PRIVATE_KEY_LEN],
}

impl std::fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchServerKey")
            .field("config_id", &self.config_id)
            .field("public_name", &self.public_name)
            .field("private_key", &"<32 bytes>")
            .finish()
    }
}

/// Owned wrapper around `EVP_HPKE_KEY` with proper Drop.
struct HpkeKey(NonNull<boring_sys::EVP_HPKE_KEY>);

impl HpkeKey {
    fn new() -> Result<Self> {
        unsafe {
            let p = boring_sys::EVP_HPKE_KEY_new();
            NonNull::new(p)
                .map(Self)
                .ok_or_else(|| anyhow::anyhow!("EVP_HPKE_KEY_new"))
        }
    }

    fn from_private(raw: &[u8]) -> Result<Self> {
        let key = Self::new()?;
        unsafe {
            let kem = boring_sys::EVP_hpke_x25519_hkdf_sha256();
            let rc = boring_sys::EVP_HPKE_KEY_init(key.0.as_ptr(), kem, raw.as_ptr(), raw.len());
            if rc != 1 {
                bail!("EVP_HPKE_KEY_init failed");
            }
        }
        Ok(key)
    }

    fn generate() -> Result<Self> {
        let key = Self::new()?;
        unsafe {
            let kem = boring_sys::EVP_hpke_x25519_hkdf_sha256();
            let rc = boring_sys::EVP_HPKE_KEY_generate(key.0.as_ptr(), kem);
            if rc != 1 {
                bail!("EVP_HPKE_KEY_generate failed");
            }
        }
        Ok(key)
    }

    fn private_bytes(&self) -> Result<[u8; X25519_PRIVATE_KEY_LEN]> {
        let mut out = [0u8; X25519_PRIVATE_KEY_LEN];
        let mut out_len: usize = 0;
        let rc = unsafe {
            boring_sys::EVP_HPKE_KEY_private_key(
                self.0.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                out.len(),
            )
        };
        if rc != 1 {
            bail!("EVP_HPKE_KEY_private_key failed");
        }
        if out_len != X25519_PRIVATE_KEY_LEN {
            bail!("unexpected HPKE private key length: {out_len}");
        }
        Ok(out)
    }
}

impl Drop for HpkeKey {
    fn drop(&mut self) {
        unsafe { boring_sys::EVP_HPKE_KEY_free(self.0.as_ptr()) }
    }
}

impl EchServerKey {
    /// Generate a fresh keypair with a random `config_id`.
    pub fn generate(public_name: &str) -> Result<Self> {
        if public_name.is_empty() {
            bail!("ECH public_name must be non-empty");
        }
        let key = HpkeKey::generate()?;
        Ok(Self {
            config_id: rand::random(),
            public_name: public_name.to_string(),
            private_key: key.private_bytes()?,
        })
    }

    pub fn config_id(&self) -> u8 {
        self.config_id
    }
    pub fn public_name(&self) -> &str {
        &self.public_name
    }

    /// Marshal a single ECHConfig (no list wrapper) via
    /// `SSL_marshal_ech_config`.
    pub fn marshal_config(&self) -> Result<Vec<u8>> {
        let key = HpkeKey::from_private(&self.private_key)?;
        let pn = CString::new(self.public_name.as_bytes()).context("public_name has NUL byte")?;
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            boring_sys::SSL_marshal_ech_config(
                &mut out,
                &mut out_len,
                self.config_id,
                key.0.as_ptr(),
                pn.as_ptr(),
                MAX_NAME_LENGTH,
            )
        };
        if rc != 1 || out.is_null() {
            if !out.is_null() {
                unsafe { boring_sys::OPENSSL_free(out as *mut _) };
            }
            bail!("SSL_marshal_ech_config failed");
        }
        let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { boring_sys::OPENSSL_free(out as *mut _) };
        Ok(bytes)
    }

    /// Wrap the single ECHConfig in a TLS-encoded ECHConfigList
    /// (`u16` length prefix + concatenated ECHConfigs).
    pub fn marshal_config_list(&self) -> Result<Vec<u8>> {
        let cfg = self.marshal_config()?;
        let len = u16::try_from(cfg.len()).context("ECHConfig too large for u16 length prefix")?;
        let mut out = Vec::with_capacity(2 + cfg.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&cfg);
        Ok(out)
    }

    /// Persist to disk in the format documented at the module level.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let pn = self.public_name.as_bytes();
        let nlen = u16::try_from(pn.len()).context("public_name too long")?;
        let mut buf = Vec::with_capacity(1 + 2 + pn.len() + X25519_PRIVATE_KEY_LEN);
        buf.push(self.config_id);
        buf.extend_from_slice(&nlen.to_be_bytes());
        buf.extend_from_slice(pn);
        buf.extend_from_slice(&self.private_key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, buf).with_context(|| format!("write {}", path.display()))
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let buf = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if buf.len() < 3 {
            bail!("ECH key file too short (got {} bytes)", buf.len());
        }
        let config_id = buf[0];
        let nlen = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let expected = 1 + 2 + nlen + X25519_PRIVATE_KEY_LEN;
        if buf.len() != expected {
            bail!(
                "ECH key file length mismatch: got {} bytes, expected {} (nlen={})",
                buf.len(),
                expected,
                nlen
            );
        }
        let public_name = std::str::from_utf8(&buf[3..3 + nlen])
            .context("public_name not valid UTF-8")?
            .to_string();
        let mut private_key = [0u8; X25519_PRIVATE_KEY_LEN];
        private_key.copy_from_slice(&buf[3 + nlen..]);
        Ok(Self {
            config_id,
            public_name,
            private_key,
        })
    }

    /// Install on an `SslContextBuilder` via
    /// `SSL_ECH_KEYS_new` + `SSL_ECH_KEYS_add` + `SSL_CTX_set1_ech_keys`.
    /// `is_retry_config = 1` so the public ECHConfig is included in the
    /// retry config list returned to clients with stale ConfigLists.
    pub fn install_on_ctx_builder(&self, b: &SslContextBuilder) -> Result<()> {
        let cfg_bytes = self.marshal_config()?;
        let key = HpkeKey::from_private(&self.private_key)?;
        unsafe {
            let keys = boring_sys::SSL_ECH_KEYS_new();
            if keys.is_null() {
                bail!("SSL_ECH_KEYS_new failed");
            }
            let rc = boring_sys::SSL_ECH_KEYS_add(
                keys,
                1,
                cfg_bytes.as_ptr(),
                cfg_bytes.len(),
                key.0.as_ptr(),
            );
            if rc != 1 {
                boring_sys::SSL_ECH_KEYS_free(keys);
                bail!("SSL_ECH_KEYS_add failed");
            }
            let rc = boring_sys::SSL_CTX_set1_ech_keys(b.as_ptr(), keys);
            // CTX took its own up_ref via set1_; release ours.
            boring_sys::SSL_ECH_KEYS_free(keys);
            if rc != 1 {
                bail!("SSL_CTX_set1_ech_keys failed");
            }
        }
        Ok(())
    }
}

/// Apply a binary ECHConfigList to a per-connection `SslRef` before the
/// handshake. The bytes are exactly what
/// [`EchServerKey::marshal_config_list`] produces on the server.
pub fn install_client_ech_config_list(ssl: &mut SslRef, list: &[u8]) -> Result<()> {
    let rc =
        unsafe { boring_sys::SSL_set1_ech_config_list(ssl.as_ptr(), list.as_ptr(), list.len()) };
    if rc != 1 {
        bail!("SSL_set1_ech_config_list failed");
    }
    Ok(())
}

/// Decode a base64 ECHConfigList string.
pub fn decode_config_list_b64(b64: &str) -> Result<Vec<u8>> {
    B64.decode(b64.trim())
        .context("decode ECHConfigList base64")
}

/// Encode bytes as base64 (canonical/standard alphabet, with padding).
pub fn encode_config_list_b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_marshal_then_load_round_trip() {
        let key = EchServerKey::generate("front.example.com").unwrap();
        let cfg = key.marshal_config().unwrap();
        assert!(!cfg.is_empty());

        let list = key.marshal_config_list().unwrap();
        assert_eq!(list.len(), 2 + cfg.len());
        assert_eq!(
            u16::from_be_bytes([list[0], list[1]]) as usize,
            cfg.len(),
            "u16 length prefix should equal ECHConfig length"
        );
    }

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ech.key");
        let key = EchServerKey::generate("front.example.com").unwrap();
        key.write_to(&path).unwrap();
        let loaded = EchServerKey::read_from(&path).unwrap();
        assert_eq!(loaded.config_id(), key.config_id());
        assert_eq!(loaded.public_name(), key.public_name());
        // Re-marshaling from the loaded key produces the same bytes as
        // marshaling from the original (deterministic given inputs).
        let a = key.marshal_config().unwrap();
        let b = loaded.marshal_config().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_public_name_rejected() {
        assert!(EchServerKey::generate("").is_err());
    }

    #[test]
    fn read_short_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"x").unwrap();
        assert!(EchServerKey::read_from(&path).is_err());
    }

    #[test]
    fn b64_round_trip() {
        let key = EchServerKey::generate("front.example.com").unwrap();
        let list = key.marshal_config_list().unwrap();
        let b64 = encode_config_list_b64(&list);
        let decoded = decode_config_list_b64(&b64).unwrap();
        assert_eq!(decoded, list);
    }
}
