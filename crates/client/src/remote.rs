//! QUIC session with a usbwire server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info};
use usbwire_net::quinn::rustls::pki_types::CertificateDer;
use usbwire_net::auth::{self, Pairing, ServerCert};
use usbwire_net::{FrameReader, quinn, send};
use usbwire_proto::{
    AttachOk, Capabilities, Complete, Control, DevId, DeviceInfo, EpMsg, EpOpen, Hello, PROTOCOL_VERSION,
    Status, Submit, UrbId,
};

/// Everything the server sends on endpoint streams.
#[derive(Debug)]
pub enum EpEvent {
    Complete(Complete),
    Push { ep: u8, epoch: UrbId, data: Vec<u8> },
    Deferred { ep: u8, urb: UrbId, status: Status },
}

pub struct Remote {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    ctl: Mutex<(quinn::SendStream, FrameReader)>,
}

/// Open a QUIC connection presenting our identity, checking the server with `verifier`.
async fn dial(
    server: &str,
    verifier: Arc<ServerCert>,
    identity: usbwire_net::Identity,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let addr: SocketAddr = tokio::net::lookup_host(server)
        .await?
        .next()
        .with_context(|| format!("cannot resolve {server}"))?;
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(usbwire_net::client_config(verifier, identity)?);
    let conn = endpoint
        .connect(addr, usbwire_net::SERVER_NAME)?
        .await
        .with_context(|| format!("connecting to {server}"))?;
    Ok((endpoint, conn))
}

fn this_host() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "usbwire-client".into())
}

pub struct Paired {
    pub server_cert: CertificateDer<'static>,
    pub server_name: String,
    pub allowed: Vec<String>,
}

/// Pair with a server using the one-time code it displayed.
pub async fn pair(server: &str, identity: usbwire_net::Identity, code: &str) -> Result<Paired> {
    let client_fp = auth::fingerprint(&identity.0);
    let verifier = ServerCert::for_pairing();
    let (endpoint, conn) = dial(server, verifier.clone(), identity).await?;
    let server_cert = verifier.seen.lock().unwrap().clone().context("server sent no certificate")?;
    let server_fp = auth::fingerprint(&server_cert);

    let result: Result<Paired> = async {
        let (mut tx, rx) = conn.open_bi().await?;
        let mut rx = FrameReader::new(rx);
        let (spake, msg) = Pairing::start(code);
        send(&mut tx, &Control::Pair { client_name: this_host(), spake: msg }).await?;
        let (key, confirm) = match rx.next::<Control>().await? {
            Some(Control::PairStep { spake: server_msg, confirm }) => (spake.finish(&server_msg)?, confirm),
            Some(Control::Error { message, .. }) => bail!("{message}"),
            other => bail!("unexpected reply {other:?}"),
        };
        // Wrong code, or a man in the middle: stop before confirming anything.
        auth::check_confirmation(&key, "server", &server_fp, &client_fp, &confirm)?;
        let confirm = auth::confirmation(&key, "client", &server_fp, &client_fp);
        send(&mut tx, &Control::PairConfirm { confirm }).await?;
        match rx.next::<Control>().await? {
            Some(Control::PairOk { server_name, allowed }) => Ok(Paired { server_cert, server_name, allowed }),
            Some(Control::Error { message, .. }) => bail!("{message}"),
            other => bail!("unexpected reply {other:?}"),
        }
    }
    .await;
    conn.close(0u32.into(), b"paired");
    endpoint.wait_idle().await;
    result
}

impl Remote {
    pub async fn connect(
        server: &str,
        server_cert: CertificateDer<'static>,
        identity: usbwire_net::Identity,
        caps: Capabilities,
    ) -> Result<Self> {
        let t = Instant::now();
        let (endpoint, conn) = dial(server, ServerCert::pinned(server_cert), identity).await?;
        let (mut tx, rx) = conn.open_bi().await?;
        let mut rx = FrameReader::new(rx);
        let hello = Hello { version: PROTOCOL_VERSION, client_name: this_host(), caps };
        send(&mut tx, &Control::Hello(hello)).await?;
        match rx.next::<Control>().await? {
            Some(Control::HelloOk { server_name, .. }) => {
                info!("connected to {server_name} ({server}) in {:?}", t.elapsed())
            }
            Some(Control::Error { code, message }) => bail!("server refused ({code:?}): {message}"),
            other => bail!("handshake failed: {other:?}"),
        }
        Ok(Remote { endpoint, conn, ctl: Mutex::new((tx, rx)) })
    }

    async fn request(&self, msg: Control) -> Result<Control> {
        let mut ctl = self.ctl.lock().await;
        send(&mut ctl.0, &msg).await?;
        match ctl.1.next::<Control>().await? {
            Some(Control::Error { code, message }) => bail!("server error {code:?}: {message}"),
            Some(reply) => Ok(reply),
            None => bail!("server closed the control stream"),
        }
    }

    pub async fn list(&self) -> Result<Vec<DeviceInfo>> {
        match self.request(Control::ListDevices).await? {
            Control::DeviceList(l) => Ok(l),
            other => bail!("unexpected reply {other:?}"),
        }
    }

    pub async fn attach(&self, dev: DevId) -> Result<AttachOk> {
        match self.request(Control::Attach { dev }).await? {
            Control::AttachOk(a) => Ok(*a),
            other => bail!("unexpected reply {other:?}"),
        }
    }

    /// Close the connection so the server releases attached devices at once
    /// instead of after the idle timeout.
    pub async fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
        self.endpoint.wait_idle().await;
    }

    /// One control-stream round trip: the network + QUIC floor for any transfer.
    pub async fn ping(&self) -> Result<Duration> {
        let t = Instant::now();
        match self.request(Control::Ping { nonce: 7 }).await? {
            Control::Pong { .. } => Ok(t.elapsed()),
            other => bail!("unexpected reply {other:?}"),
        }
    }

    /// Endpoint streams for one attachment; completions from every endpoint
    /// arrive on `done`.
    pub fn endpoints(&self, dev: DevId, done: mpsc::UnboundedSender<EpEvent>) -> EpStreams {
        EpStreams { conn: self.conn.clone(), dev, streams: HashMap::new(), done }
    }
}

/// Lazily opened QUIC stream per endpoint address.
pub struct EpStreams {
    conn: quinn::Connection,
    dev: DevId,
    streams: HashMap<u8, quinn::SendStream>,
    done: mpsc::UnboundedSender<EpEvent>,
}

impl EpStreams {
    async fn stream(&mut self, ep: u8) -> Result<&mut quinn::SendStream> {
        if !self.streams.contains_key(&ep) {
            let (mut tx, rx) = self.conn.open_bi().await?;
            send(&mut tx, &EpOpen { dev: self.dev, ep }).await?;
            let done = self.done.clone();
            tokio::spawn(async move {
                let mut rx = FrameReader::new(rx);
                loop {
                    let ev = match rx.next::<EpMsg>().await {
                        Ok(Some(EpMsg::Complete(c))) => EpEvent::Complete(c),
                        Ok(Some(EpMsg::Push { epoch, data })) => EpEvent::Push { ep, epoch, data },
                        Ok(Some(EpMsg::DeferredError { urb, status })) => EpEvent::Deferred { ep, urb, status },
                        Ok(Some(other)) => {
                            debug!(ep, "ignoring {other:?}");
                            continue;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            debug!(ep, "endpoint stream: {e:#}");
                            break;
                        }
                    };
                    if done.send(ev).is_err() {
                        break;
                    }
                }
            });
            debug!(ep, "opened endpoint stream");
            self.streams.insert(ep, tx);
        }
        Ok(self.streams.get_mut(&ep).unwrap())
    }

    pub async fn submit(&mut self, ep: u8, s: Submit) -> Result<()> {
        let st = self.stream(ep).await?;
        send(st, &EpMsg::Submit(s)).await
    }

    pub async fn cancel(&mut self, ep: u8, urb: UrbId) -> Result<()> {
        let st = self.stream(ep).await?;
        send(st, &EpMsg::Cancel { urb }).await
    }
}
