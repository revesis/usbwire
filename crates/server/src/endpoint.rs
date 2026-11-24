//! Per-endpoint stream handlers.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use nusb::Endpoint;
use nusb::transfer::{Buffer, Bulk, Completion, ControlIn, ControlOut, In, Interrupt, Out};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use usbwire_net::{FrameReader, quinn, send};
use usbwire_proto::{Complete, EpMsg, Status, Submit, UrbId, XferType};

use crate::device::{CONTROL_TIMEOUT, OpenDevice, control_type, recipient, status};

// ---------------------------------------------------------------------------
// Default control pipe
// ---------------------------------------------------------------------------

/// Control transfers are serialized, as on a real default pipe.
pub async fn run_control(dev: Arc<OpenDevice>, mut tx: quinn::SendStream, mut rx: FrameReader) -> Result<()> {
    while let Some(msg) = rx.next::<EpMsg>().await? {
        match msg {
            EpMsg::Submit(s) => {
                let c = control(&dev, &s).await;
                send(&mut tx, &EpMsg::Complete(c)).await?;
            }
            // The transfer already finished by the time we read this.
            EpMsg::Cancel { .. } => {}
            other => warn!("unexpected message on control stream: {other:?}"),
        }
    }
    Ok(())
}

async fn control(dev: &OpenDevice, s: &Submit) -> Complete {
    let done = |status, data: Vec<u8>, actual_length| Complete { urb: s.urb, status, actual_length, data };
    let Some(setup) = s.setup else {
        return done(Status::Other(-22), vec![], 0);
    };
    let bm = setup[0];
    let request = setup[1];
    let value = u16::from_le_bytes([setup[2], setup[3]]);
    let index = u16::from_le_bytes([setup[4], setup[5]]);
    let length = u16::from_le_bytes([setup[6], setup[7]]);
    let standard = (bm >> 5) & 3 == 0;
    let rcpt = bm & 0x1f;

    // Requests WinUSB (and usbfs, once interfaces are claimed) won't pass
    // through; handle them the way the Linux usbip stub does.
    if standard {
        match (rcpt, request) {
            (0, 0x05) => return done(Status::Ok, vec![], 0), // SET_ADDRESS: host-controller business
            (0, 0x09) => {
                // SET_CONFIGURATION
                if value as u8 == dev.config_value {
                    return done(Status::Ok, vec![], 0);
                }
                warn!(value, "SET_CONFIGURATION to a different configuration is not supported");
                return done(Status::Stall, vec![], 0);
            }
            (1, 0x0b) => {
                // SET_INTERFACE
                let intf = dev.interface_for(1, index);
                if intf.get_alt_setting() == value as u8 {
                    return done(Status::Ok, vec![], 0);
                }
                return match intf.set_alt_setting(value as u8).await {
                    Ok(()) => done(Status::Ok, vec![], 0),
                    Err(e) => {
                        warn!("SET_INTERFACE {index} alt {value}: {e}");
                        done(Status::Stall, vec![], 0)
                    }
                };
            }
            (2, 0x01) if value == 0 => {
                // CLEAR_FEATURE(ENDPOINT_HALT). TODO(phase 1): route to the endpoint task's clear_halt().
                debug!(ep = index, "CLEAR_FEATURE(ENDPOINT_HALT) acknowledged without action");
                return done(Status::Ok, vec![], 0);
            }
            _ => {}
        }
    }

    let (Some(control_type), Some(recipient)) = (control_type(bm), recipient(bm)) else {
        return done(Status::Stall, vec![], 0);
    };
    let intf = dev.interface_for(rcpt, index);
    if bm & 0x80 != 0 {
        let r = intf
            .control_in(ControlIn { control_type, recipient, request, value, index, length }, CONTROL_TIMEOUT)
            .await;
        match r {
            Ok(data) => {
                let n = data.len() as u32;
                done(Status::Ok, data, n)
            }
            Err(e) => done(status(Err(e)), vec![], 0),
        }
    } else {
        let r = intf
            .control_out(
                ControlOut { control_type, recipient, request, value, index, data: &s.data },
                CONTROL_TIMEOUT,
            )
            .await;
        let n = if r.is_ok() { s.data.len() as u32 } else { 0 };
        done(status(r), vec![], n)
    }
}

// ---------------------------------------------------------------------------
// Interrupt / bulk endpoints
// ---------------------------------------------------------------------------

enum Ep {
    BulkIn(Endpoint<Bulk, In>),
    BulkOut(Endpoint<Bulk, Out>),
    IntIn(Endpoint<Interrupt, In>),
    IntOut(Endpoint<Interrupt, Out>),
}

macro_rules! each {
    ($self:expr, $e:ident => $body:expr) => {
        match $self {
            Ep::BulkIn($e) => $body,
            Ep::BulkOut($e) => $body,
            Ep::IntIn($e) => $body,
            Ep::IntOut($e) => $body,
        }
    };
}

impl Ep {
    fn is_in(&self) -> bool {
        matches!(self, Ep::BulkIn(_) | Ep::IntIn(_))
    }
    fn max_packet(&self) -> usize {
        each!(self, e => e.max_packet_size())
    }
    fn submit(&mut self, b: Buffer) {
        each!(self, e => e.submit(b))
    }
    fn cancel_all(&mut self) {
        each!(self, e => e.cancel_all())
    }
    fn poll_next_complete(&mut self, cx: &mut Context<'_>) -> Poll<Completion> {
        each!(self, e => e.poll_next_complete(cx))
    }
    fn pending(&self) -> usize {
        each!(self, e => e.pending())
    }
}

enum Event {
    Msg(Option<EpMsg>),
    Done(Completion),
}

/// Interrupt IN reads kept pending on the device while a push endpoint is open.
/// More than one, so a report arriving right after another is not held up.
const PUSH_DEPTH: usize = 4;

pub async fn run_data(
    dev: Arc<OpenDevice>,
    addr: u8,
    push: bool,
    mut tx: quinn::SendStream,
    mut rx: FrameReader,
) -> Result<()> {
    let info = *dev.endpoints.get(&addr).with_context(|| format!("no endpoint {addr:#04x}"))?;
    let intf = dev.interfaces.get(&info.interface).context("endpoint's interface not claimed")?;
    let is_in = addr & 0x80 != 0;
    let mut ep = match (info.xfer, is_in) {
        (XferType::Bulk, true) => Ep::BulkIn(intf.endpoint(addr)?),
        (XferType::Bulk, false) => Ep::BulkOut(intf.endpoint(addr)?),
        (XferType::Interrupt, true) => Ep::IntIn(intf.endpoint(addr)?),
        (XferType::Interrupt, false) => Ep::IntOut(intf.endpoint(addr)?),
        (x, _) => bail!("{x:?} endpoints are not supported"),
    };
    debug!(ep = addr, "endpoint stream open");

    // Reader task: turns the QUIC stream into a channel we can poll alongside nusb.
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match rx.next::<EpMsg>().await {
                Ok(Some(m)) => {
                    if msg_tx.send(m).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!("endpoint reader: {e:#}");
                    break;
                }
            }
        }
    });

    if push && matches!(ep, Ep::IntIn(_)) {
        return run_push(ep, addr, tx, msg_rx).await;
    }

    // In submission order; nusb completes transfers in order per endpoint.
    let mut pending: VecDeque<(UrbId, u32)> = VecDeque::new();
    loop {
        let ev = poll_fn(|cx| {
            if !pending.is_empty()
                && let Poll::Ready(c) = ep.poll_next_complete(cx)
            {
                return Poll::Ready(Event::Done(c));
            }
            msg_rx.poll_recv(cx).map(Event::Msg)
        })
        .await;

        match ev {
            Event::Msg(None) => {
                ep.cancel_all();
                return Ok(());
            }
            Event::Msg(Some(EpMsg::Submit(s))) => {
                let buf = if ep.is_in() {
                    // nusb wants IN lengths in whole packets.
                    let mps = ep.max_packet();
                    Buffer::new((s.length as usize).max(1).div_ceil(mps) * mps)
                } else {
                    Buffer::from(s.data)
                };
                debug!(ep = addr, urb = s.urb, len = s.length, early = s.acked_early, "submit");
                ep.submit(buf);
                pending.push_back((s.urb, s.length));
            }
            Event::Msg(Some(EpMsg::Cancel { urb })) => {
                // nusb can only cancel everything pending on the endpoint. With
                // HID there is normally one transfer in flight, so this is exact.
                if pending.iter().any(|(u, _)| *u == urb) {
                    ep.cancel_all();
                }
            }
            Event::Msg(Some(other)) => warn!("unexpected message on endpoint stream: {other:?}"),
            Event::Done(c) => {
                let (urb, requested) = pending.pop_front().expect("completion without pending transfer");
                debug!(ep = addr, urb, status = ?c.status, actual = c.actual_len, "complete");
                let mut st = status(c.status);
                let (data, actual_length) = if ep.is_in() {
                    let mut data = c.buffer.into_vec();
                    data.truncate(c.actual_len);
                    if data.len() > requested as usize {
                        data.truncate(requested as usize);
                        if st.is_ok() {
                            st = Status::Overflow;
                        }
                    }
                    let n = data.len() as u32;
                    (data, n)
                } else {
                    (Vec::new(), c.actual_len as u32)
                };
                send(&mut tx, &EpMsg::Complete(Complete { urb, status: st, actual_length, data })).await?;
            }
        }
    }
}

/// Push mode for an interrupt IN endpoint: read reports continuously while the
/// client has the endpoint open and stream them without waiting to be asked.
/// A Submit (re)starts polling; a Cancel stops it.
async fn run_push(
    mut ep: Ep,
    addr: u8,
    mut tx: quinn::SendStream,
    mut msg_rx: mpsc::UnboundedReceiver<EpMsg>,
) -> Result<()> {
    let mps = ep.max_packet();
    let mut epoch: Option<UrbId> = None;
    loop {
        let ev = poll_fn(|cx| {
            if ep.pending() > 0
                && let Poll::Ready(c) = ep.poll_next_complete(cx)
            {
                return Poll::Ready(Event::Done(c));
            }
            msg_rx.poll_recv(cx).map(Event::Msg)
        })
        .await;

        match ev {
            Event::Msg(None) => {
                ep.cancel_all();
                return Ok(());
            }
            Event::Msg(Some(EpMsg::Submit(s))) => {
                if epoch.is_none() {
                    debug!(ep = addr, epoch = s.urb, "push: start polling");
                    epoch = Some(s.urb);
                    // Leftover cancelled reads still count as pending; top up only.
                    for _ in ep.pending()..PUSH_DEPTH {
                        ep.submit(Buffer::new(mps));
                    }
                }
            }
            Event::Msg(Some(EpMsg::Cancel { .. })) => {
                if epoch.take().is_some() {
                    debug!(ep = addr, "push: stop polling");
                    ep.cancel_all();
                }
            }
            Event::Msg(Some(other)) => warn!("unexpected message on push endpoint: {other:?}"),
            Event::Done(c) => {
                let Some(e) = epoch else { continue }; // stopped: drop leftovers
                match c.status {
                    Ok(()) => {
                        let mut data = c.buffer.into_vec();
                        data.truncate(c.actual_len);
                        debug!(ep = addr, len = data.len(), "push");
                        send(&mut tx, &EpMsg::Push { epoch: e, data }).await?;
                        ep.submit(Buffer::new(mps));
                    }
                    Err(nusb::transfer::TransferError::Cancelled) => {}
                    Err(err) => {
                        warn!(ep = addr, "push: read failed: {err}; stopping");
                        epoch = None;
                        ep.cancel_all();
                        send(&mut tx, &EpMsg::DeferredError { urb: e, status: status(Err(err)) }).await?;
                    }
                }
            }
        }
    }
}
