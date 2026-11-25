//! Per-endpoint stream handlers.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use nusb::Endpoint;
use nusb::transfer::{Buffer, Bulk, Completion, ControlIn, ControlOut, In, Interrupt, Out};
use tokio::sync::{mpsc, oneshot};
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
                // CLEAR_FEATURE(ENDPOINT_HALT): the host recovering from a stall.
                return done(clear_halt(dev, index as u8).await, vec![], 0);
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
    /// Clear the halt; a failed request is reported as a stall, the way a
    /// device answers a control request it rejects.
    async fn clear_halt(&mut self) -> Status {
        match each!(self, e => e.clear_halt().await) {
            Ok(()) => Status::Ok,
            Err(e) => {
                warn!("clear halt failed: {e}");
                Status::Stall
            }
        }
    }
}

enum Event {
    Msg(Option<EpMsg>),
    Done(Completion),
    /// CLEAR_FEATURE(ENDPOINT_HALT) from the control pipe; answer on the sender.
    ClearHalt(oneshot::Sender<Status>),
}

/// Asks a running endpoint task to clear its endpoint's halt.
pub type HaltSender = mpsc::UnboundedSender<oneshot::Sender<Status>>;

/// Clear a halted endpoint. The task running it does the work (nusb wants no
/// transfers pending, and only the task knows them); if no task runs it,
/// open the endpoint just for this.
async fn clear_halt(dev: &OpenDevice, addr: u8) -> Status {
    let task = dev.halt_requests.lock().unwrap().get(&addr).cloned();
    if let Some(task) = task {
        let (tx, rx) = oneshot::channel();
        if task.send(tx).is_ok()
            && let Ok(st) = rx.await
        {
            debug!(ep = addr, ?st, "cleared halt via the endpoint task");
            return st;
        }
    }
    let st = match open_ep(dev, addr) {
        Ok(mut ep) => ep.clear_halt().await,
        Err(e) => {
            warn!(ep = addr, "CLEAR_FEATURE(ENDPOINT_HALT): {e:#}");
            Status::Stall
        }
    };
    debug!(ep = addr, ?st, "cleared halt");
    st
}

fn open_ep(dev: &OpenDevice, addr: u8) -> Result<Ep> {
    let info = *dev.endpoints.get(&addr).with_context(|| format!("no endpoint {addr:#04x}"))?;
    let intf = dev.interfaces.get(&info.interface).context("endpoint's interface not claimed")?;
    Ok(match (info.xfer, addr & 0x80 != 0) {
        (XferType::Bulk, true) => Ep::BulkIn(intf.endpoint(addr)?),
        (XferType::Bulk, false) => Ep::BulkOut(intf.endpoint(addr)?),
        (XferType::Interrupt, true) => Ep::IntIn(intf.endpoint(addr)?),
        (XferType::Interrupt, false) => Ep::IntOut(intf.endpoint(addr)?),
        (x, _) => bail!("{x:?} endpoints are not supported"),
    })
}

/// Unregisters an endpoint task's halt channel when the task ends.
struct HaltRegistration(Arc<OpenDevice>, u8);

impl Drop for HaltRegistration {
    fn drop(&mut self) {
        self.0.halt_requests.lock().unwrap().remove(&self.1);
    }
}

/// Wait for one completion on the endpoint (there must be one pending).
async fn next_complete(ep: &mut Ep) -> Completion {
    poll_fn(|cx| ep.poll_next_complete(cx)).await
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
    let mut ep = open_ep(&dev, addr)?;
    let (halt_tx, mut halt_rx) = mpsc::unbounded_channel();
    dev.halt_requests.lock().unwrap().insert(addr, halt_tx);
    let _registration = HaltRegistration(dev.clone(), addr);
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

    // `push` is decided per endpoint by the caller (interrupt IN always; bulk IN
    // only for CDC-ACM stream endpoints). run_push reads mps-sized buffers, which
    // suits bulk IN as well.
    if push && ep.is_in() {
        return run_push(ep, addr, tx, msg_rx, halt_rx).await;
    }

    // In submission order; nusb completes transfers in order per endpoint.
    let mut pending: VecDeque<Pending> = VecDeque::new();
    loop {
        let ev = poll_fn(|cx| {
            if !pending.is_empty()
                && let Poll::Ready(c) = ep.poll_next_complete(cx)
            {
                return Poll::Ready(Event::Done(c));
            }
            if let Poll::Ready(Some(reply)) = halt_rx.poll_recv(cx) {
                return Poll::Ready(Event::ClearHalt(reply));
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
                pending.push_back(Pending { urb: s.urb, length: s.length, acked_early: s.acked_early });
            }
            Event::Msg(Some(EpMsg::Cancel { urb })) => {
                // nusb can only cancel everything pending on the endpoint. With
                // HID there is normally one transfer in flight, so this is exact.
                if pending.iter().any(|p| p.urb == urb) {
                    ep.cancel_all();
                }
            }
            Event::Msg(Some(other)) => warn!("unexpected message on endpoint stream: {other:?}"),
            Event::Done(c) => {
                let p = pending.pop_front().expect("completion without pending transfer");
                if let Some(msg) = completion_msg(&ep, addr, p, c) {
                    send(&mut tx, &msg).await?;
                }
            }
            Event::ClearHalt(reply) => {
                // nusb wants nothing pending; whatever is, fails like on a stalled pipe.
                if !pending.is_empty() {
                    ep.cancel_all();
                    while let Some(p) = pending.pop_front() {
                        let c = next_complete(&mut ep).await;
                        if let Some(msg) = completion_msg(&ep, addr, p, c) {
                            send(&mut tx, &msg).await?;
                        }
                    }
                }
                let _ = reply.send(ep.clear_halt().await);
            }
        }
    }
}

/// A transfer submitted on a (non-push) data endpoint.
struct Pending {
    urb: UrbId,
    length: u32,
    /// The client already completed it (early OUT ack): report only failure.
    acked_early: bool,
}

/// What to tell the client about a finished transfer, if anything.
fn completion_msg(ep: &Ep, addr: u8, p: Pending, c: Completion) -> Option<EpMsg> {
    debug!(ep = addr, urb = p.urb, status = ?c.status, actual = c.actual_len, "complete");
    let mut st = status(c.status);
    if p.acked_early {
        // The client told the host it succeeded long ago; a failure is
        // reported so the host sees it on its next transfer.
        return (!st.is_ok()).then(|| {
            warn!(ep = addr, urb = p.urb, ?st, "early-acked OUT failed on the device");
            EpMsg::DeferredError { urb: p.urb, status: st }
        });
    }
    let (data, actual_length) = if ep.is_in() {
        let mut data = c.buffer.into_vec();
        data.truncate(c.actual_len);
        if data.len() > p.length as usize {
            data.truncate(p.length as usize);
            if st.is_ok() {
                st = Status::Overflow;
            }
        }
        let n = data.len() as u32;
        (data, n)
    } else {
        (Vec::new(), c.actual_len as u32)
    };
    Some(EpMsg::Complete(Complete { urb: p.urb, status: st, actual_length, data }))
}

/// Keep PUSH_DEPTH reads pending on a push endpoint.
fn top_up(ep: &mut Ep, mps: usize) {
    for _ in ep.pending()..PUSH_DEPTH {
        ep.submit(Buffer::new(mps));
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
    mut halt_rx: mpsc::UnboundedReceiver<oneshot::Sender<Status>>,
) -> Result<()> {
    let mps = ep.max_packet();
    let mut epoch: Option<UrbId> = None;
    // Reports read after the client stopped polling (reads already in flight
    // when the Cancel came). They are gone from the device, so they must reach
    // the client: send them first when polling restarts.
    let mut held: VecDeque<Vec<u8>> = VecDeque::new();
    loop {
        let ev = poll_fn(|cx| {
            if ep.pending() > 0
                && let Poll::Ready(c) = ep.poll_next_complete(cx)
            {
                return Poll::Ready(Event::Done(c));
            }
            if let Poll::Ready(Some(reply)) = halt_rx.poll_recv(cx) {
                return Poll::Ready(Event::ClearHalt(reply));
            }
            msg_rx.poll_recv(cx).map(Event::Msg)
        })
        .await;

        match ev {
            Event::Msg(None) => {
                ep.cancel_all();
                return Ok(());
            }
            Event::ClearHalt(reply) => {
                // nusb wants nothing pending: stop the reads, keep what they got.
                ep.cancel_all();
                while ep.pending() > 0 {
                    let c = next_complete(&mut ep).await;
                    if c.status.is_ok() {
                        let mut data = c.buffer.into_vec();
                        data.truncate(c.actual_len);
                        held.push_back(data);
                    }
                }
                let _ = reply.send(ep.clear_halt().await);
                if let Some(e) = epoch {
                    for data in held.drain(..) {
                        send(&mut tx, &EpMsg::Push { epoch: e, data }).await?;
                    }
                    top_up(&mut ep, mps);
                }
            }
            Event::Msg(Some(EpMsg::Submit(s))) => {
                if epoch.is_none() {
                    debug!(ep = addr, epoch = s.urb, "push: start polling");
                    epoch = Some(s.urb);
                    for data in held.drain(..) {
                        send(&mut tx, &EpMsg::Push { epoch: s.urb, data }).await?;
                    }
                    // Cancelled reads that have not completed yet still count as
                    // pending; they are replaced as they complete (see below).
                    top_up(&mut ep, mps);
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
                let Some(e) = epoch else {
                    if c.status.is_ok() {
                        let mut data = c.buffer.into_vec();
                        data.truncate(c.actual_len);
                        debug!(ep = addr, len = data.len(), "push: holding a report read after stop");
                        held.push_back(data);
                    }
                    continue;
                };
                match c.status {
                    Ok(()) => {
                        let mut data = c.buffer.into_vec();
                        data.truncate(c.actual_len);
                        debug!(ep = addr, len = data.len(), "push");
                        send(&mut tx, &EpMsg::Push { epoch: e, data }).await?;
                        top_up(&mut ep, mps);
                    }
                    // A read cancelled by an earlier stop that only completes now,
                    // after polling restarted: the restart could not replace it
                    // then (it still counted as pending), so replace it now, or
                    // the device would be left with no reads at all.
                    Err(nusb::transfer::TransferError::Cancelled) => top_up(&mut ep, mps),
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
