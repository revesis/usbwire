//! The QUIC server: authentication, pairing, control and endpoint streams.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use usbwire_net::auth::{self, Pairing};
use usbwire_net::{FrameReader, quinn, send};
use usbwire_proto::{Capabilities, Control, EpOpen, ErrorCode, PROTOCOL_VERSION};

use crate::device::{OpenDevice, Refused, Registry, recover_from_journal};
use crate::endpoint;
use crate::state::{self, State};

struct Server {
    state: Arc<State>,
    registry: Arc<Registry>,
    fingerprint: String,
}

/// Serve until `shutdown` resolves, then close connections and give swapped
/// devices back to their drivers.
pub async fn run(state: Arc<State>, listen: Option<SocketAddr>, shutdown: impl Future<Output = ()>) -> Result<()> {
    recover_from_journal().await;
    let identity = usbwire_net::load_or_create_identity(&state.dir)?;
    let fingerprint = auth::fingerprint(&identity.0);
    let addr = match listen {
        Some(a) => a,
        None => state.config()?.listen,
    };
    let endpoint = quinn::Endpoint::server(usbwire_net::server_config(identity)?, addr)?;
    info!(state = %state.dir.display(), fingerprint = auth::short_fp(&fingerprint), "listening on {addr}");

    let srv = Arc::new(Server { registry: Registry::new(state.clone()), state, fingerprint });
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let srv = srv.clone();
                tokio::spawn(async move {
                    let remote = incoming.remote_address();
                    match srv.handle_connection(incoming).await {
                        Ok(()) => info!(%remote, "connection closed"),
                        Err(e) if is_normal_close(&e) => info!(%remote, "connection closed by client"),
                        Err(e) => warn!(%remote, "connection ended: {e:#}"),
                    }
                });
            }
            _ = &mut shutdown => break,
        }
    }

    info!("shutting down");
    endpoint.close(0u32.into(), b"server shutting down");
    let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
    srv.registry.restore_all().await;
    info!("stopped");
    Ok(())
}

type Attached = Arc<Mutex<HashMap<u32, Arc<OpenDevice>>>>;

fn error(code: ErrorCode, message: impl Into<String>) -> Control {
    Control::Error { code, message: message.into() }
}

impl Server {
    async fn handle_connection(self: Arc<Self>, incoming: quinn::Incoming) -> Result<()> {
        let conn = incoming.await?;
        let remote = conn.remote_address();
        let client_fp = auth::peer_cert(&conn)
            .map(|c| auth::fingerprint(&c))
            .context("client presented no certificate")?;
        let (mut ctl_tx, ctl_rx) = conn.accept_bi().await?;
        let mut ctl_rx = FrameReader::new(ctl_rx);

        let (client, caps) = match ctl_rx.next::<Control>().await? {
            Some(Control::Pair { client_name, spake }) => {
                let r = self.pair(&client_fp, &client_name, &spake, remote, ctl_tx, ctl_rx).await;
                // Let the client read the outcome and hang up first; dropping the
                // connection now would discard the reply.
                let _ = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
                return r;
            }
            Some(Control::Hello(h)) => {
                if h.version != PROTOCOL_VERSION {
                    let msg = format!("server speaks v{PROTOCOL_VERSION}, client v{}", h.version);
                    send(&mut ctl_tx, &error(ErrorCode::VersionMismatch, msg)).await?;
                    bail!("version mismatch");
                }
                let Some(client) = self.state.client(&client_fp)? else {
                    self.state.audit(&format!(
                        "rejected unpaired client fp={} name={:?} from {remote}",
                        auth::short_fp(&client_fp),
                        h.client_name
                    ));
                    let msg = "this client is not paired with the server: run `usbwire-server pair` on the server, then `usbwire-client pair` here";
                    send(&mut ctl_tx, &error(ErrorCode::NotPaired, msg)).await?;
                    let _ = ctl_tx.finish();
                    let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
                    bail!("unpaired client {}", auth::short_fp(&client_fp));
                };
                info!(client = %client.name, caps = ?h.caps, "hello");
                send(&mut ctl_tx, &Control::HelloOk { version: PROTOCOL_VERSION, server_name: hostname() }).await?;
                (client, h.caps)
            }
            other => bail!("expected Hello or Pair, got {other:?}"),
        };
        let who = format!("client={} fp={}", client.name, auth::short_fp(&client_fp));
        self.state.audit(&format!("session start {who} from {remote}"));

        let attached: Attached = Default::default();
        let ep_conn = conn.clone();
        let ep_attached = attached.clone();
        tokio::spawn(async move {
            while let Ok((tx, rx)) = ep_conn.accept_bi().await {
                let attached = ep_attached.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_endpoint_stream(tx, rx, attached, caps).await {
                        warn!("endpoint stream: {e:#}");
                    }
                });
            }
        });

        let result: Result<()> = async {
            while let Some(msg) = ctl_rx.next::<Control>().await? {
                let reply = match msg {
                    Control::ListDevices => Control::DeviceList(self.registry.list(&client.allow)?),
                    Control::Attach { dev } => match self.registry.attach(dev, &client, &conn).await {
                        Ok(open) => {
                            let reply = Control::AttachOk(Box::new(open.attach_ok(caps)));
                            let what = format!("{:04x}:{:04x}", open.info.vid, open.info.pid);
                            attached.lock().unwrap().insert(dev, Arc::new(open));
                            self.state.audit(&format!("attach {who} device={what}"));
                            info!(dev, client = %client.name, "attached {what}");
                            reply
                        }
                        Err(e) => {
                            self.state.audit(&format!("attach-refused {who} dev={dev}: {e:#}"));
                            warn!(dev, "attach refused: {e:#}");
                            match e.downcast_ref::<Refused>() {
                                Some(r) => error(r.0, r.1.clone()),
                                None => error(ErrorCode::Internal, format!("{e:#}")),
                            }
                        }
                    },
                    Control::Detach { dev } => {
                        if attached.lock().unwrap().remove(&dev).is_some() {
                            self.state.audit(&format!("detach {who} dev={dev}"));
                        }
                        continue;
                    }
                    Control::Ping { nonce } => Control::Pong { nonce },
                    other => {
                        warn!("unexpected control message {other:?}");
                        continue;
                    }
                };
                send(&mut ctl_tx, &reply).await?;
            }
            Ok(())
        }
        .await;
        self.state.audit(&format!("session end {who}"));
        result
    }

    /// One pairing attempt (see usbwire_net::auth for the scheme).
    async fn pair(
        &self,
        client_fp: &str,
        client_name: &str,
        client_msg: &[u8],
        remote: SocketAddr,
        mut tx: quinn::SendStream,
        mut rx: FrameReader,
    ) -> Result<()> {
        let attempt = format!("fp={} name={client_name:?} from {remote}", auth::short_fp(client_fp));
        let Some(pending) = self.state.pending_pairing()? else {
            self.state.audit(&format!("pair-refused (no open pairing) {attempt}"));
            let msg = "no pairing is open on the server: run `usbwire-server pair` there first";
            send(&mut tx, &error(ErrorCode::NotPaired, msg)).await?;
            return Ok(());
        };

        let (spake, server_msg) = Pairing::start(&pending.code);
        let key = spake.finish(client_msg)?;
        let confirm = auth::confirmation(&key, "server", &self.fingerprint, client_fp);
        send(&mut tx, &Control::PairStep { spake: server_msg, confirm }).await?;

        let verdict = match tokio::time::timeout(Duration::from_secs(30), rx.next::<Control>()).await {
            Ok(Ok(Some(Control::PairConfirm { confirm }))) => {
                auth::check_confirmation(&key, "client", &self.fingerprint, client_fp, &confirm)
            }
            // A client with the wrong code notices at PairStep and hangs up.
            _ => Err(anyhow::anyhow!("client did not confirm")),
        };
        if let Err(e) = verdict {
            self.state.pairing_failed()?;
            self.state.audit(&format!("pair-failed {attempt}: {e}"));
            let _ = send(&mut tx, &error(ErrorCode::Unauthorized, "pairing failed: wrong code")).await;
            return Ok(());
        }

        let name = if pending.name.is_empty() { client_name.to_string() } else { pending.name.clone() };
        self.state.add_client(state::Client {
            fingerprint: client_fp.into(),
            name: name.clone(),
            allow: pending.allow.clone(),
            paired_at: state::timestamp(),
        })?;
        self.state.end_pairing();
        self.state.audit(&format!("paired client={name} allow={:?} {attempt}", pending.allow));
        info!(client = %name, "paired");
        send(&mut tx, &Control::PairOk { server_name: hostname(), allowed: pending.allow }).await?;
        Ok(())
    }
}

async fn handle_endpoint_stream(
    tx: quinn::SendStream,
    rx: quinn::RecvStream,
    attached: Attached,
    caps: Capabilities,
) -> Result<()> {
    let mut rx = FrameReader::new(rx);
    let open: EpOpen = rx.next().await?.context("endpoint stream closed before EpOpen")?;
    let dev = attached
        .lock()
        .unwrap()
        .get(&open.dev)
        .cloned()
        .with_context(|| format!("EpOpen for unattached device {}", open.dev))?;
    if open.ep == 0 {
        endpoint::run_control(dev, tx, rx).await
    } else {
        endpoint::run_data(dev, open.ep, caps.interrupt_in_push, tx, rx).await
    }
}

/// The client closed the connection on purpose (application close, code 0).
fn is_normal_close(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<quinn::ConnectionError>(),
            Some(quinn::ConnectionError::ApplicationClosed(a)) if a.error_code == 0u32.into()
        ) || matches!(
            c.downcast_ref::<quinn::ReadError>(),
            Some(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(a))) if a.error_code == 0u32.into()
        )
    })
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "usbwire-server".into())
}
