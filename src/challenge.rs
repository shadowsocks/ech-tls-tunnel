//! In-process registry of active TLS-ALPN-01 challenge contexts.
//!
//! When [`crate::acme`] starts an ACME order, it generates a per-domain
//! self-signed cert that carries the SHA-256 of the key authorization in
//! the `acmeIdentifier` extension and installs it here keyed by the
//! domain. The TLS server's ALPN-select callback (in
//! [`crate::tls_server`]) consults this store on every handshake: if the
//! client offered ALPN `acme-tls/1` and the SNI matches an installed
//! entry, it hot-swaps the active `SslContext` to the challenge cert and
//! negotiates `acme-tls/1`. After the ACME server validates, the entry
//! is removed.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use boring::ssl::SslContext;

#[derive(Default)]
pub struct ChallengeStore {
    inner: RwLock<HashMap<String, Arc<SslContext>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, domain: impl Into<String>, ctx: SslContext) {
        self.inner
            .write()
            .unwrap()
            .insert(domain.into(), Arc::new(ctx));
    }

    pub fn remove(&self, domain: &str) {
        self.inner.write().unwrap().remove(domain);
    }

    pub fn get(&self, domain: &str) -> Option<Arc<SslContext>> {
        self.inner.read().unwrap().get(domain).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}

impl std::fmt::Debug for ChallengeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ChallengeStore").field("len", &n).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{SslContext, SslMethod};

    fn dummy_ctx() -> SslContext {
        SslContext::builder(SslMethod::tls()).unwrap().build()
    }

    #[test]
    fn install_get_remove() {
        let store = ChallengeStore::new();
        assert!(store.is_empty());
        store.install("a.example.com", dummy_ctx());
        assert_eq!(store.len(), 1);
        assert!(store.get("a.example.com").is_some());
        assert!(store.get("b.example.com").is_none());
        store.remove("a.example.com");
        assert!(store.is_empty());
    }

    #[test]
    fn install_replaces_existing() {
        let store = ChallengeStore::new();
        store.install("a.example.com", dummy_ctx());
        store.install("a.example.com", dummy_ctx()); // overwrite
        assert_eq!(store.len(), 1);
    }
}
