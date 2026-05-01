//! Minimal TLS ClientHello peeker used to drop non-ECH probes before
//! BoringSSL would otherwise terminate the handshake and reveal a
//! cert mismatch (cover name vs. real `domain`).
//!
//! Parses just enough of the record layer + handshake header to find
//! the extension list, then scans for:
//!
//! - `encrypted_client_hello` (ext type 0xfe0d) — a real client.
//! - `application_layer_protocol_negotiation` carrying `acme-tls/1`
//!   (RFC 8737) — Let's Encrypt validator. Must not be dropped or
//!   ACME issuance/renewal breaks.
//!
//! Returns [`ClientHelloKind::Other`] for anything else. The caller
//! is expected to RST the connection in that case.

const EXT_ECH: u16 = 0xfe0d;
const EXT_ALPN: u16 = 0x0010;
const ACME_ALPN: &[u8] = b"acme-tls/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloKind {
    /// Buffer doesn't contain a complete ClientHello yet; caller may
    /// read more bytes (up to its budget) before deciding.
    Incomplete,
    /// First byte isn't a TLS handshake record (0x16). Drop.
    NotTls,
    /// ClientHello carries the ECH extension or `acme-tls/1` ALPN.
    EchOrAcmeAlpn,
    /// Parsed a ClientHello, but it has neither signal. Drop.
    Other,
}

/// Classify the bytes at the start of a TCP connection. Never
/// allocates; bounded scan limited to one TLS record.
pub fn classify(buf: &[u8]) -> ClientHelloKind {
    let mut r = Reader::new(buf);

    // TLS record layer: type(1) version(2) length(2)
    let Some(record_type) = r.read_u8() else {
        return ClientHelloKind::Incomplete;
    };
    if record_type != 0x16 {
        return ClientHelloKind::NotTls;
    }
    if r.skip(2).is_none() {
        return ClientHelloKind::Incomplete;
    }
    let Some(record_len) = r.read_u16() else {
        return ClientHelloKind::Incomplete;
    };
    let Some(record) = r.read_slice(record_len as usize) else {
        return ClientHelloKind::Incomplete;
    };
    let mut r = Reader::new(record);

    // Handshake header: type(1) length(3)
    let Some(hs_type) = r.read_u8() else {
        return ClientHelloKind::Incomplete;
    };
    if hs_type != 0x01 {
        return ClientHelloKind::Other;
    }
    let Some(hs_len) = r.read_u24() else {
        return ClientHelloKind::Incomplete;
    };
    let Some(body) = r.read_slice(hs_len as usize) else {
        return ClientHelloKind::Incomplete;
    };
    let mut r = Reader::new(body);

    // ClientHello body, skipping past the fields we don't care about.
    if r.skip(2 + 32).is_none() {
        return ClientHelloKind::Incomplete;
    }
    let Some(sid_len) = r.read_u8() else {
        return ClientHelloKind::Incomplete;
    };
    if r.skip(sid_len as usize).is_none() {
        return ClientHelloKind::Incomplete;
    }
    let Some(cs_len) = r.read_u16() else {
        return ClientHelloKind::Incomplete;
    };
    if r.skip(cs_len as usize).is_none() {
        return ClientHelloKind::Incomplete;
    }
    let Some(comp_len) = r.read_u8() else {
        return ClientHelloKind::Incomplete;
    };
    if r.skip(comp_len as usize).is_none() {
        return ClientHelloKind::Incomplete;
    }
    let Some(ext_len) = r.read_u16() else {
        return ClientHelloKind::Other;
    };
    let Some(exts) = r.read_slice(ext_len as usize) else {
        return ClientHelloKind::Incomplete;
    };

    let mut r = Reader::new(exts);
    while !r.is_empty() {
        let Some(ext_type) = r.read_u16() else {
            return ClientHelloKind::Other;
        };
        let Some(ext_data_len) = r.read_u16() else {
            return ClientHelloKind::Other;
        };
        let Some(ext_data) = r.read_slice(ext_data_len as usize) else {
            return ClientHelloKind::Other;
        };
        if ext_type == EXT_ECH {
            return ClientHelloKind::EchOrAcmeAlpn;
        }
        if ext_type == EXT_ALPN && alpn_has_acme(ext_data) {
            return ClientHelloKind::EchOrAcmeAlpn;
        }
    }

    ClientHelloKind::Other
}

fn alpn_has_acme(ext_data: &[u8]) -> bool {
    let mut r = Reader::new(ext_data);
    let Some(list_len) = r.read_u16() else {
        return false;
    };
    let Some(list) = r.read_slice(list_len as usize) else {
        return false;
    };
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let Some(name_len) = r.read_u8() else {
            return false;
        };
        let Some(name) = r.read_slice(name_len as usize) else {
            return false;
        };
        if name == ACME_ALPN {
            return true;
        }
    }
    false
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        let s = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn read_u24(&mut self) -> Option<u32> {
        let s = self.buf.get(self.pos..self.pos + 3)?;
        self.pos += 3;
        Some(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(())
    }
    fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap an already-built handshake body in TLS record + handshake
    /// headers, then run classify on the result.
    fn classify_with_record(hs_body: &[u8]) -> ClientHelloKind {
        let mut hs = vec![0x01]; // ClientHello
        let len = hs_body.len() as u32;
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(hs_body);

        let mut record = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0 legacy
        let l = hs.len() as u16;
        record.extend_from_slice(&l.to_be_bytes());
        record.extend_from_slice(&hs);
        classify(&record)
    }

    fn build_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // 1 compression
        let mut exts = Vec::new();
        for (ty, data) in extensions {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        body
    }

    fn alpn_ext(names: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for n in names {
            list.push(n.len() as u8);
            list.extend_from_slice(n);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(list.len() as u16).to_be_bytes());
        out.extend_from_slice(&list);
        out
    }

    #[test]
    fn empty_is_incomplete() {
        assert_eq!(classify(&[]), ClientHelloKind::Incomplete);
    }

    #[test]
    fn non_handshake_record_is_not_tls() {
        assert_eq!(
            classify(&[0x17, 0x03, 0x03, 0, 1, 0]),
            ClientHelloKind::NotTls
        );
    }

    #[test]
    fn truncated_record_is_incomplete() {
        let hello = build_hello(&[(EXT_ECH, &[0u8; 4])]);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hello.len() as u16 + 4).to_be_bytes());
        record.push(0x01);
        record.extend_from_slice(&[
            (hello.len() >> 16) as u8,
            (hello.len() >> 8) as u8,
            hello.len() as u8,
        ]);
        record.extend_from_slice(&hello[..hello.len() / 2]);
        assert_eq!(classify(&record), ClientHelloKind::Incomplete);
    }

    #[test]
    fn ech_extension_passes() {
        let hello = build_hello(&[(EXT_ECH, &[0u8; 8])]);
        assert_eq!(classify_with_record(&hello), ClientHelloKind::EchOrAcmeAlpn);
    }

    #[test]
    fn acme_alpn_passes() {
        let alpn = alpn_ext(&[ACME_ALPN]);
        let hello = build_hello(&[(EXT_ALPN, &alpn)]);
        assert_eq!(classify_with_record(&hello), ClientHelloKind::EchOrAcmeAlpn);
    }

    #[test]
    fn ordinary_alpn_does_not_pass() {
        let alpn = alpn_ext(&[b"h2", b"http/1.1"]);
        let hello = build_hello(&[(EXT_ALPN, &alpn)]);
        assert_eq!(classify_with_record(&hello), ClientHelloKind::Other);
    }

    #[test]
    fn no_relevant_extensions_is_other() {
        let hello = build_hello(&[(0x002b, &[0x02, 0x03, 0x04])]); // supported_versions
        assert_eq!(classify_with_record(&hello), ClientHelloKind::Other);
    }
}
