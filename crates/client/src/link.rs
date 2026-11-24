//! Keeping a remote device attached across connection loss.
//!
//! `serve` holds one USB/IP session open towards the OS for as long as it
//! runs. Underneath, the QUIC connection to the server may drop (network
//! outage, laptop sleep, server restart); the supervisor here reconnects,
//! attaches the same device again, and hands the adapter the new [`Link`].
//! The OS never sees the device unplugged, so applications keep their handles.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::watch;
use tracing::{info, warn};
use usbwire_net::quinn;
use usbwire_net::quinn::rustls::pki_types::CertificateDer;
use usbwire_proto::{AttachOk, Capabilities, DevId, DeviceInfo};

use crate::remote::{Remote, ServerRefused};

/// The connection and server-side device id the adapter currently talks to.
/// `generation` changes on every reconnect.
#[derive(Clone)]
pub struct Link {
    pub remote: Arc<Remote>,
    pub dev: DevId,
    pub generation: u64,
}

/// Who to connect to and which device to attach.
pub struct Target {
    pub server: String,
    pub cert: CertificateDer<'static>,
    pub identity: usbwire_net::Identity,
    pub caps: Capabilities,
    pub want: Option<(u16, u16)>,
}

impl Target {
    fn identity(&self) -> usbwire_net::Identity {
        (self.identity.0.clone(), self.identity.1.clone_key())
    }

    pub async fn connect(&self) -> Result<Remote> {
        Remote::connect(&self.server, self.cert.clone(), self.identity(), self.caps).await
    }
}

/// Retrying will not help: stop.
#[derive(Debug)]
struct Fatal(anyhow::Error);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for Fatal {}

fn is_fatal(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<Fatal>() || c.downcast_ref::<ServerRefused>().is_some_and(ServerRefused::fatal))
}

/// Pick the device to attach: by --dev on the first attach; on a reconnect,
/// the device we had (same VID:PID and serial number).
fn pick<'a>(list: &'a [DeviceInfo], want: Option<(u16, u16)>, had: Option<&AttachOk>) -> Result<&'a DeviceInfo> {
    if let Some(had) = had {
        let h = &had.info;
        return list
            .iter()
            .find(|d| d.vid == h.vid && d.pid == h.pid && d.serial == h.serial)
            .context("the device is not (yet) exported by the server");
    }
    match want {
        Some((vid, pid)) => list.iter().find(|d| d.vid == vid && d.pid == pid),
        None if list.len() == 1 => list.first(),
        None => return Err(Fatal(anyhow!("several devices exported; choose one with --dev")).into()),
    }
    .context("device not exported by the server")
}

/// The device answers differently from the one the OS enumerated: resuming
/// would feed the OS descriptors and endpoints it does not know.
fn same_device(a: &AttachOk, b: &AttachOk) -> bool {
    a.descriptors == b.descriptors && a.endpoints == b.endpoints && a.caps == b.caps
}

/// One connection attempt may not take longer than this. QUIC resends its
/// handshake ever less often while the network is down, so an attempt begun
/// during an outage could otherwise hang until the idle timeout after the
/// network is back; a fresh attempt gets through at once.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);

/// Connect and attach once.
pub async fn connect_attach(t: &Target, had: Option<&AttachOk>) -> Result<(Arc<Remote>, AttachOk)> {
    let remote = tokio::time::timeout(ATTEMPT_TIMEOUT, t.connect())
        .await
        .map_err(|_| anyhow!("connecting to {}: no answer within {ATTEMPT_TIMEOUT:?}", t.server))??;
    let remote = Arc::new(remote);
    let result = async {
        let list = remote.list().await?;
        let dev = pick(&list, t.want, had)?.dev;
        let a = remote.attach(dev).await?;
        if let Some(had) = had
            && !same_device(had, &a)
        {
            return Err(Fatal(anyhow!("the device on the server is no longer the one attached here")).into());
        }
        Ok(a)
    }
    .await;
    match result {
        Ok(a) => {
            info!(
                "attached {:04x}:{:04x} {:?}: {} endpoints, snapshot of {} configs / {} strings / {} HID reports",
                a.info.vid,
                a.info.pid,
                a.info.product,
                a.endpoints.len(),
                a.descriptors.configs.len(),
                a.descriptors.strings.len(),
                a.descriptors.hid_reports.len()
            );
            Ok((remote, a))
        }
        Err(e) => {
            remote.close().await;
            Err(e)
        }
    }
}

const BACKOFF_FIRST: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Connect and attach, retrying with backoff until it works, a fatal error,
/// or shutdown (Ok(None)).
pub async fn connect_attach_retrying(
    t: &Target,
    had: Option<&AttachOk>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<(Arc<Remote>, AttachOk)>> {
    let mut delay = BACKOFF_FIRST;
    loop {
        let attempt = tokio::select! {
            r = connect_attach(t, had) => r,
            _ = shutdown.wait_for(|s| *s) => return Ok(None),
        };
        match attempt {
            Ok(ok) => return Ok(Some(ok)),
            Err(e) if is_fatal(&e) => return Err(e),
            Err(e) => warn!("{e:#}; retrying in {delay:?}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.wait_for(|s| *s) => return Ok(None),
        }
        delay = (delay * 2).min(BACKOFF_MAX);
    }
}

/// Watch the connection behind `link_tx`; when it drops, reconnect (if
/// `reconnect`) and publish the new link. Returns on shutdown or a fatal
/// error. `attached` is the device the OS has enumerated.
pub async fn supervise(
    t: &Target,
    attached: &AttachOk,
    link_tx: watch::Sender<Option<Link>>,
    reconnect: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut generation = link_tx.borrow().as_ref().map_or(0, |l| l.generation);
    loop {
        let Some(remote) = link_tx.borrow().as_ref().map(|l| l.remote.clone()) else {
            bail!("no connection to supervise");
        };
        let reason = tokio::select! {
            r = remote.closed() => r,
            _ = shutdown.wait_for(|s| *s) => {
                remote.close().await;
                return Ok(());
            }
        };
        link_tx.send_replace(None);
        if let quinn::ConnectionError::ApplicationClosed(c) = &reason {
            if c.error_code == usbwire_net::CLOSE_SUPERSEDED.into() {
                bail!("another session of this client took over the device; not reconnecting");
            }
            if c.error_code == usbwire_net::CLOSE_REVOKED.into() {
                bail!("the server revoked this client; pair again to use it");
            }
        }
        if !reconnect {
            bail!("connection to the server lost: {reason}");
        }
        warn!("connection to the server lost ({reason}); reconnecting");
        let t0 = Instant::now();
        let Some((remote, a)) = connect_attach_retrying(t, Some(attached), &mut shutdown).await? else {
            return Ok(());
        };
        generation += 1;
        info!("reconnected after {:.1?}", t0.elapsed());
        link_tx.send_replace(Some(Link { remote, dev: a.info.dev, generation }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usbwire_proto::{ErrorCode, Speed};

    fn dev(dev: DevId, pid: u16, serial: Option<&str>) -> DeviceInfo {
        DeviceInfo {
            dev,
            vid: 0x1050,
            pid,
            bcd_device: 0x0543,
            class: 0,
            speed: Speed::Full,
            manufacturer: None,
            product: None,
            serial: serial.map(String::from),
            busy: false,
        }
    }

    #[test]
    fn reconnect_picks_the_same_device_even_if_its_id_changed() {
        let had = AttachOk {
            info: dev(0, 0x0407, Some("123")),
            descriptors: Default::default(),
            endpoints: vec![],
            caps: Capabilities { interrupt_in_push: true, early_out_ack: true, descriptor_cache: true },
        };
        // After a server restart ids are reassigned; another key with the same
        // VID:PID but another serial must not be taken for ours.
        let list = [dev(0, 0x0407, Some("999")), dev(1, 0x0407, Some("123"))];
        assert_eq!(pick(&list, None, Some(&had)).unwrap().dev, 1);
        assert!(pick(&list[..1], None, Some(&had)).is_err());
    }

    #[test]
    fn fatal_errors() {
        let refused = |code| anyhow::Error::from(ServerRefused { code, message: String::new() });
        assert!(is_fatal(&refused(ErrorCode::NotPaired)));
        assert!(is_fatal(&refused(ErrorCode::Unauthorized)));
        assert!(!is_fatal(&refused(ErrorCode::Busy)));
        assert!(!is_fatal(&refused(ErrorCode::NoSuchDevice)));
        assert!(!is_fatal(&anyhow!("timed out")));
        assert!(is_fatal(&anyhow::Error::from(Fatal(anyhow!("changed"))).context("attaching")));
    }
}
