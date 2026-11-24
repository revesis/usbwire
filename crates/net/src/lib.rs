//! QUIC plumbing shared by server and client: framed streams, TLS setup, transport tuning.
//!
//! TLS: mutual, with self-signed certificates trusted by fingerprint; see [`auth`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};
use usbwire_proto::frame;

pub mod auth;

pub use quinn;

/// TLS server name the client expects; the certificate is pinned anyway.
pub const SERVER_NAME: &str = "usbwire";
pub const ALPN: &[u8] = b"usbwire/1";
pub const DEFAULT_PORT: u16 = 7443;

/// QUIC application close code: an ordinary hang-up (client exit, server
/// shutdown). A client may reconnect.
pub const CLOSE_NORMAL: u32 = 0;
/// QUIC application close code: the server closed this session because a
/// newer session of the same client took over its device. The client must
/// not reconnect, or two copies of it would take the device from each other
/// forever.
pub const CLOSE_SUPERSEDED: u32 = 2;
/// QUIC application close code: the client was revoked on the server
/// (`usbwire-server revoke`). It must not reconnect.
pub const CLOSE_REVOKED: u32 = 3;

/// Reads whole frames from a QUIC receive stream.
pub struct FrameReader {
    recv: RecvStream,
    buf: BytesMut,
}

impl FrameReader {
    pub fn new(recv: RecvStream) -> Self {
        Self { recv, buf: BytesMut::with_capacity(4096) }
    }

    /// Next message, or `None` when the peer finished the stream cleanly.
    pub async fn next<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        loop {
            if let Some(msg) = frame::decode(&mut self.buf)? {
                return Ok(Some(msg));
            }
            match self.recv.read_chunk(64 * 1024, true).await? {
                Some(chunk) => self.buf.extend_from_slice(&chunk.bytes),
                None if self.buf.is_empty() => return Ok(None),
                None => anyhow::bail!("stream ended inside a frame"),
            }
        }
    }
}

/// Writes one frame. QUIC has no Nagle: the packet leaves on the next
/// connection-driver poll.
pub async fn send<T: Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    let mut buf = BytesMut::new();
    frame::encode(msg, &mut buf)?;
    s.write_all(&buf).await?;
    Ok(())
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // Keep NAT bindings alive and notice dead peers quickly.
    // An outage shorter than the idle timeout is ridden out by QUIC itself
    // (it retransmits; nothing is lost). A longer one ends the connection and
    // the client reconnects, failing what was in flight. 10 s keeps that
    // blind window short, and lets the server free a vanished client's
    // device quickly; keep-alives every 2 s keep a quiet link from idling out.
    t.keep_alive_interval(Some(Duration::from_secs(2)));
    t.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    // Plenty of endpoint streams (a few per device).
    t.max_concurrent_bidi_streams(256u32.into());
    Arc::new(t)
}

pub type Identity = (CertificateDer<'static>, PrivateKeyDer<'static>);

/// Load this side's certificate and key from `dir`, creating them on first run.
pub fn load_or_create_identity(dir: &Path) -> Result<Identity> {
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    if !cert_path.exists() || !key_path.exists() {
        std::fs::create_dir_all(dir)?;
        let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
        std::fs::write(&cert_path, ck.cert.der())?;
        std::fs::write(&key_path, ck.signing_key.serialize_der())?;
    }
    let cert = CertificateDer::from(std::fs::read(&cert_path).context("reading cert.der")?);
    let key = PrivatePkcs8KeyDer::from(std::fs::read(&key_path).context("reading key.der")?);
    Ok((cert, key.into()))
}

/// Server config: requires a client certificate (authorized later by fingerprint).
pub fn server_config((cert, key): Identity) -> Result<quinn::ServerConfig> {
    let mut tls = quinn::rustls::ServerConfig::builder()
        .with_client_cert_verifier(auth::AnyClientCert::new())
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// Client config presenting our identity; the server certificate is checked
/// by `verifier` (pinned, or recorded during pairing).
pub fn client_config(verifier: Arc<auth::ServerCert>, (cert, key): Identity) -> Result<quinn::ClientConfig> {
    let mut tls = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}
