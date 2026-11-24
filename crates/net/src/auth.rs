//! Identity and pairing.
//!
//! Both ends have a self-signed certificate. Trust is by SHA-256 fingerprint,
//! not by CA:
//! - the server requires a client certificate (mTLS) and authorizes it by
//!   fingerprint against its list of paired clients;
//! - the client pins the exact server certificate it learned while pairing.
//!
//! Pairing uses a one-time code shown on the server. The code is used as the
//! password of a SPAKE2 exchange, so a man in the middle cannot test guesses
//! offline. Each side then proves it derived the same key, bound to both
//! certificate fingerprints, which detects a MITM swapping certificates.

use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use quinn::rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use quinn::rustls::{self, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Hex SHA-256 of a certificate's DER.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Short form for logs and listings.
pub fn short_fp(fp: &str) -> &str {
    &fp[..fp.len().min(16)]
}

/// The certificate the peer presented on an established connection.
pub fn peer_cert(conn: &quinn::Connection) -> Option<CertificateDer<'static>> {
    conn.peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?
        .into_iter()
        .next()
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

/// Server side: require a client certificate, accept any, but still verify
/// the handshake signature so the client proves it holds the private key.
/// Authorization by fingerprint happens after the handshake.
#[derive(Debug)]
pub struct AnyClientCert(WebPkiSupportedAlgorithms);

impl AnyClientCert {
    pub fn new() -> Arc<Self> {
        Arc::new(AnyClientCert(algorithms()))
    }
}

impl ClientCertVerifier for AnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Client side: either require exactly the pinned server certificate, or
/// (pairing only) accept any certificate and remember it, so the pairing
/// exchange can bind it.
#[derive(Debug)]
pub struct ServerCert {
    pinned: Option<CertificateDer<'static>>,
    pub seen: Mutex<Option<CertificateDer<'static>>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCert {
    pub fn pinned(cert: CertificateDer<'static>) -> Arc<Self> {
        Arc::new(ServerCert { pinned: Some(cert), seen: Mutex::new(None), algs: algorithms() })
    }
    /// Trust on first use; only for the pairing connection, whose SPAKE2
    /// confirmation then authenticates the certificate.
    pub fn for_pairing() -> Arc<Self> {
        Arc::new(ServerCert { pinned: None, seen: Mutex::new(None), algs: algorithms() })
    }
}

impl ServerCertVerifier for ServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(p) = &self.pinned
            && p.as_ref() != end_entity.as_ref()
        {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        *self.seen.lock().unwrap() = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// Unambiguous alphabet (Crockford base32): no I, L, O, U.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh one-time code: 10 symbols (50 bits), shown as XXXXX-XXXXX.
pub fn new_pairing_code() -> Result<String> {
    let mut raw = [0u8; 10];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let s: String = raw.iter().map(|b| CODE_ALPHABET[(*b & 31) as usize] as char).collect();
    Ok(format!("{}-{}", &s[..5], &s[5..]))
}

/// Canonical form for comparison: upper case, separators dropped, and the
/// commonly confused letters mapped as Crockford base32 does.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

const SPAKE_ID: &[u8] = b"usbwire-pairing-v1";

/// One side of the SPAKE2 exchange.
pub struct Pairing(Spake2<Ed25519Group>);

impl Pairing {
    /// Returns the state and the message to send to the peer.
    pub fn start(code: &str) -> (Pairing, Vec<u8>) {
        let (s, msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(normalize_code(code)), &Identity::new(SPAKE_ID));
        (Pairing(s), msg)
    }

    /// Shared key; equal on both sides only if both used the same code.
    pub fn finish(self, peer_msg: &[u8]) -> Result<Vec<u8>> {
        self.0.finish(peer_msg).map_err(|e| anyhow::anyhow!("pairing exchange failed: {e:?}"))
    }
}

/// Key confirmation bound to both certificates.
pub fn confirmation(key: &[u8], role: &str, server_fp: &str, client_fp: &str) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(role.as_bytes());
    m.update(b"\0");
    m.update(server_fp.as_bytes());
    m.update(b"\0");
    m.update(client_fp.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Constant-time check of a peer's confirmation.
pub fn check_confirmation(key: &[u8], role: &str, server_fp: &str, client_fp: &str, got: &[u8]) -> Result<()> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(role.as_bytes());
    m.update(b"\0");
    m.update(server_fp.as_bytes());
    m.update(b"\0");
    m.update(client_fp.as_bytes());
    if m.verify_slice(got).is_err() {
        bail!("pairing confirmation mismatch (wrong code, or someone is intercepting the connection)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(server_code: &str, client_code: &str) -> Result<()> {
        let (s, s_msg) = Pairing::start(server_code);
        let (c, c_msg) = Pairing::start(client_code);
        let ks = s.finish(&c_msg)?;
        let kc = c.finish(&s_msg)?;
        let proof = confirmation(&ks, "server", "sfp", "cfp");
        check_confirmation(&kc, "server", "sfp", "cfp", &proof)?;
        let proof = confirmation(&kc, "client", "sfp", "cfp");
        check_confirmation(&ks, "client", "sfp", "cfp", &proof)
    }

    #[test]
    fn same_code_pairs() {
        let code = new_pairing_code().unwrap();
        assert_eq!(code.len(), 11);
        run(&code, &code.to_lowercase().replace('-', " ")).unwrap();
    }

    #[test]
    fn wrong_code_fails() {
        assert!(run("ABCDE-FGHJK", "ABCDE-FGHJM").is_err());
    }

    #[test]
    fn confirmation_is_bound_to_fingerprints() {
        let (s, s_msg) = Pairing::start("12345-67890");
        let (c, c_msg) = Pairing::start("12345-67890");
        let ks = s.finish(&c_msg).unwrap();
        let kc = c.finish(&s_msg).unwrap();
        let proof = confirmation(&ks, "server", "sfp", "cfp");
        // A MITM presenting its own certificate changes the fingerprint the client sees.
        assert!(check_confirmation(&kc, "server", "mitm", "cfp", &proof).is_err());
        // Roles are not interchangeable (no reflection).
        assert!(check_confirmation(&kc, "client", "sfp", "cfp", &proof).is_err());
    }

    #[test]
    fn normalize_maps_confusables() {
        assert_eq!(normalize_code("abcdo-il123"), "ABCD011123");
    }
}
