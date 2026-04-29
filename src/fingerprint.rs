//! Client TLS fingerprint emulation (a.k.a. uTLS / browser-impersonation).
//!
//! By default `boring`'s `SslConnector` produces a recognizable
//! BoringSSL ClientHello: cipher order, curve order, sigalg order, and
//! the absence of GREASE all give it away. A DPI box keyed on JA3/JA4
//! can distinguish that from real browser traffic even after we wrap it
//! in WebSocket-over-TLS.
//!
//! This module ports mihomo-rust's profile-based approach: each profile
//! is a small bundle of OpenSSL-format strings + booleans that drive
//! the BoringSSL context-builder knobs:
//!
//! - `set_cipher_list` — TLS 1.2 cipher order (1.3 ciphers are
//!   BoringSSL-fixed and prepended).
//! - `set_curves_list` — named-group order.
//! - `set_grease_enabled` — RFC 8701 GREASE in ciphers, extensions, and
//!   groups; also enables ECH GREASE.
//! - `set_permute_extensions` — extension-order randomization
//!   (Chrome 106+).
//! - `set_sigalgs_list` — signature algorithm order.
//!
//! The profile constants below are taken from
//! `metacubex/utls`'s `u_parrots.go`.

use anyhow::{Context, Result};
use boring::ssl::SslConnectorBuilder;

/// All knobs the BoringSSL builder needs to mint a ClientHello that
/// looks like a particular browser/SDK.
#[derive(Clone, Copy)]
pub struct FingerprintParams {
    pub cipher_list: &'static str,
    pub curves_list: &'static str,
    pub grease: bool,
    pub permute_extensions: bool,
    pub sigalgs_list: &'static str,
}

/// Chrome 120.
/// Reference: utls `u_parrots.go` lines 665–736, HelloChrome_120.
pub const CHROME: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: true,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Firefox 120.
pub const FIREFOX: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384:P-521",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha256:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha256:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512",
};

/// Safari 16.
pub const SAFARI: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// iOS 14. Cipher list matches Safari 16; sigalgs differ.
pub const IOS: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Android 11 (OkHttp).
pub const ANDROID: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "P-256:X25519",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Edge 85 (Chrome 83 base — pre-permutation).
pub const EDGE: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Resolve a fingerprint name (lowercased ASCII) to its params. The
/// `random` keyword picks weighted-randomly among the most common
/// real-world distributions: chrome 6, safari 3, ios 2, firefox 1.
pub fn resolve(fp: &str) -> Option<FingerprintParams> {
    match fp {
        "chrome" | "chrome120" => Some(CHROME),
        "firefox" | "firefox120" => Some(FIREFOX),
        "safari" | "safari16" => Some(SAFARI),
        "ios" | "ios14" => Some(IOS),
        "android" | "android11" => Some(ANDROID),
        "edge" | "edge85" => Some(EDGE),
        "random" => Some(match rand::random::<u8>() % 12 {
            0..=5 => CHROME,
            6..=8 => SAFARI,
            9..=10 => IOS,
            _ => FIREFOX,
        }),
        _ => None,
    }
}

/// Apply a profile to an `SslConnectorBuilder`. Idempotent — the last
/// caller wins.
pub fn apply(b: &mut SslConnectorBuilder, p: &FingerprintParams) -> Result<()> {
    b.set_cipher_list(p.cipher_list)
        .context("set_cipher_list")?;
    b.set_curves_list(p.curves_list)
        .context("set_curves_list")?;
    b.set_sigalgs_list(p.sigalgs_list)
        .context("set_sigalgs_list")?;
    b.set_grease_enabled(p.grease);
    b.set_permute_extensions(p.permute_extensions);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_profiles() {
        for name in [
            "chrome",
            "chrome120",
            "firefox",
            "firefox120",
            "safari",
            "safari16",
            "ios",
            "ios14",
            "android",
            "android11",
            "edge",
            "edge85",
        ] {
            assert!(resolve(name).is_some(), "missing profile {name}");
        }
    }

    #[test]
    fn random_returns_a_profile() {
        for _ in 0..32 {
            assert!(resolve("random").is_some());
        }
    }

    #[test]
    fn unknown_returns_none() {
        assert!(resolve("netscape").is_none());
        assert!(resolve("").is_none());
    }
}
