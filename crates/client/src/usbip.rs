//! Standard USB/IP protocol, served on loopback so the OS's own USB/IP client
//! (Linux vhci_hcd, Windows usbip-win2) can attach the remote device.
//! Loopback round trips cost microseconds, so USB/IP's own inefficiency is
//! irrelevant here; only the QUIC hop crosses the WAN.
//!
//! All integers on the wire are big-endian.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{debug, info, warn};
use usbwire_proto::{AttachOk, Capabilities, Speed, Status, Submit, UrbId, XferType};

use crate::link::Link;
use crate::remote::{EpEvent, EpStreams};

pub const USBIP_VERSION: u16 = 0x0111;
const OP_REQ_DEVLIST: u16 = 0x8005;
const OP_REP_DEVLIST: u16 = 0x0005;
const OP_REQ_IMPORT: u16 = 0x8003;
const OP_REP_IMPORT: u16 = 0x0003;

pub const CMD_SUBMIT: u32 = 1;
pub const CMD_UNLINK: u32 = 2;
pub const RET_SUBMIT: u32 = 3;
pub const RET_UNLINK: u32 = 4;

pub const HEADER_LEN: usize = 48;
pub const BUSID: &str = "1-1";

const ECONNRESET: i32 = -104;

pub fn errno(s: Status) -> i32 {
    match s {
        Status::Ok => 0,
        Status::Stall => -32,       // EPIPE
        Status::Cancelled => ECONNRESET,
        Status::Timeout => -110,    // ETIMEDOUT
        Status::Overflow => -75,    // EOVERFLOW
        Status::NoDevice => -19,    // ENODEV
        Status::Other(e) if e < 0 => e,
        Status::Other(_) => -71,    // EPROTO
    }
}

/// `struct usbip_usb_device` (312 bytes), followed in DEVLIST by 4 bytes per interface.
fn device_record(a: &AttachOk, with_interfaces: bool) -> Vec<u8> {
    let d = &a.descriptors.device;
    let cfg = a.descriptors.configs.get(a.descriptors.active_config as usize);
    let mut out = Vec::with_capacity(312 + 64);
    let mut path = format!("/usbwire/{:04x}:{:04x}", a.info.vid, a.info.pid).into_bytes();
    path.resize(256, 0);
    out.extend_from_slice(&path);
    let mut busid = BUSID.as_bytes().to_vec();
    busid.resize(32, 0);
    out.extend_from_slice(&busid);
    out.extend_from_slice(&1u32.to_be_bytes()); // busnum
    out.extend_from_slice(&1u32.to_be_bytes()); // devnum
    let speed: u32 = match a.info.speed {
        Speed::Low => 1,
        Speed::Full => 2,
        Speed::High => 3,
        Speed::Super => 5,
        Speed::SuperPlus => 6,
        Speed::Unknown => 0,
    };
    out.extend_from_slice(&speed.to_be_bytes());
    out.extend_from_slice(&a.info.vid.to_be_bytes());
    out.extend_from_slice(&a.info.pid.to_be_bytes());
    out.extend_from_slice(&a.info.bcd_device.to_be_bytes());
    out.extend_from_slice(&[d[4], d[5], d[6]]); // class, subclass, protocol
    out.push(cfg.map_or(1, |c| c[5])); // bConfigurationValue
    out.push(d[17]); // bNumConfigurations
    out.push(cfg.map_or(0, |c| c[4])); // bNumInterfaces
    if with_interfaces && let Some(cfg) = cfg {
        let mut off = 0;
        while off + 2 <= cfg.len() && cfg[off] >= 2 {
            // alt setting 0 of each interface
            if cfg[off + 1] == 0x04 && off + 9 <= cfg.len() && cfg[off + 3] == 0 {
                out.extend_from_slice(&[cfg[off + 5], cfg[off + 6], cfg[off + 7], 0]);
            }
            off += cfg[off] as usize;
        }
    }
    out
}

fn op_header(code: u16, status: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(8);
    h.extend_from_slice(&USBIP_VERSION.to_be_bytes());
    h.extend_from_slice(&code.to_be_bytes());
    h.extend_from_slice(&status.to_be_bytes());
    h
}

pub fn ret_submit(seqnum: u32, status: i32, data: &[u8], is_in: bool, actual: u32) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&RET_SUBMIT.to_be_bytes());
    h[4..8].copy_from_slice(&seqnum.to_be_bytes());
    // devid, direction, ep: 0, as the kernel stub sends them
    h[20..24].copy_from_slice(&status.to_be_bytes());
    h[24..28].copy_from_slice(&actual.to_be_bytes());
    if is_in {
        h.extend_from_slice(data);
    }
    h
}

pub fn ret_unlink(seqnum: u32, status: i32) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&RET_UNLINK.to_be_bytes());
    h[4..8].copy_from_slice(&seqnum.to_be_bytes());
    h[20..24].copy_from_slice(&status.to_be_bytes());
    h
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// Shared state of one attached device.
pub struct Adapter {
    pub attach: AttachOk,
    /// Features in effect (asked for by us, granted by the server).
    caps: Capabilities,
    /// The current connection to the server; None while reconnecting.
    link: watch::Receiver<Option<Link>>,
    /// Events from all endpoint streams. Locked for the duration of one import.
    done_rx: Mutex<mpsc::UnboundedReceiver<EpEvent>>,
    done_tx: mpsc::UnboundedSender<EpEvent>,
}

/// A URB that waits for the server.
struct Inflight {
    ep: u8,
    is_in: bool,
    unlink_seq: Option<u32>,
    /// Sent on the current connection. Unsent URBs wait in `Session::held`.
    sent: bool,
}

/// Client side of a push endpoint: vhci's IN URBs on one side, reports the
/// server streams on the other; whichever arrives second completes the pair.
#[derive(Default)]
struct PushEp {
    /// Urb id of the Submit that started the current polling session.
    epoch: Option<UrbId>,
    /// vhci URBs waiting for a report: (seqnum, transfer length).
    pending: VecDeque<(u32, u32)>,
    /// Reports that arrived before vhci asked.
    buffer: VecDeque<Vec<u8>>,
    /// A device error to report on the next URB.
    deferred: Option<Status>,
}

/// Bound on buffered reports per endpoint; the oldest is dropped beyond it.
const PUSH_BUFFER: usize = 64;

/// A transfer whose fate is unknown because the connection dropped while the
/// server had it: we cannot tell whether the device saw it, so fail it.
const EPROTO: i32 = -71;

#[derive(Default)]
struct Session {
    inflight: HashMap<u32, Inflight>,
    push: HashMap<u8, PushEp>,
    /// Submissions made while there was no connection, sent on reconnect.
    held: VecDeque<(u8, Submit)>,
    /// An early-acked OUT failed on the device: the next URB on that endpoint
    /// gets the error, which is how the host learns of a stall.
    out_error: HashMap<u8, Status>,
}

impl Session {
    /// The connection is gone. Fail what the server had (USB/IP replies for
    /// the OS) and forget server-side polling; pending push URBs simply keep
    /// waiting, as they would on a device with nothing to say.
    fn link_down(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.inflight.retain(|&seq, f| {
            if !f.sent {
                return true;
            }
            match f.unlink_seq {
                Some(useq) => out.extend(ret_unlink(useq, ECONNRESET)),
                None => out.extend(ret_submit(seq, EPROTO, &[], f.is_in, 0)),
            }
            false
        });
        for pe in self.push.values_mut() {
            pe.epoch = None;
        }
        out
    }

    /// A new connection is up: push endpoints whose URBs are waiting must
    /// start polling again; held submissions go out.
    fn link_up(&mut self) -> Resume {
        let mut restart = Vec::new();
        for (&ep, pe) in &mut self.push {
            if pe.epoch.is_none()
                && let Some(&(seq, len)) = pe.pending.front()
            {
                pe.epoch = Some(seq as UrbId);
                restart.push((ep, seq, len));
            }
        }
        Resume { restart, held: self.held.drain(..).collect() }
    }
}

/// The endpoint a CLEAR_FEATURE(ENDPOINT_HALT) request is for.
fn clear_halt_target(setup: &[u8; 8]) -> Option<u8> {
    (setup[0] == 0x02 && setup[1] == 0x01 && setup[2] == 0 && setup[3] == 0).then_some(setup[4])
}

impl Session {
    /// Errors held for `ep` are void once the host has cleared its halt.
    fn forget_errors(&mut self, ep: u8) {
        self.out_error.remove(&ep);
        if let Some(pe) = self.push.get_mut(&ep) {
            pe.deferred = None;
        }
    }
}

/// What to send on a new connection.
struct Resume {
    /// Push endpoints to start polling: (ep, epoch, transfer length).
    restart: Vec<(u8, u32, u32)>,
    /// Submissions held while there was no connection, in order.
    held: Vec<(u8, Submit)>,
}

/// One USB/IP command from the OS.
enum Cmd {
    Submit { seq: u32, ep: u8, is_in: bool, len: u32, setup: Option<[u8; 8]>, data: Vec<u8> },
    Unlink { seq: u32, target: u32 },
}

/// Endpoint streams on the current connection, tagged with its generation.
type Current = Option<(u64, EpStreams)>;

/// RET_SUBMIT for an IN URB of `len` bytes completed with `data`.
fn ret_in(seq: u32, len: u32, mut data: Vec<u8>) -> Vec<u8> {
    let mut status = 0;
    if data.len() > len as usize {
        data.truncate(len as usize);
        status = -75; // EOVERFLOW
    }
    ret_submit(seq, status, &data, true, data.len() as u32)
}

impl Adapter {
    pub fn new(attach: AttachOk, link: watch::Receiver<Option<Link>>) -> Arc<Self> {
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        let caps = attach.caps;
        info!(?caps, "features");
        Arc::new(Adapter { attach, caps, link, done_rx: Mutex::new(done_rx), done_tx })
    }

    fn xfer(&self, ep: u8) -> Option<XferType> {
        self.attach.endpoints.iter().find(|e| e.address == ep).map(|e| e.xfer)
    }

    /// CDC-ACM stream endpoint: bulk here may be pushed / early-acked.
    fn is_stream(&self, ep: u8) -> bool {
        self.attach.endpoints.iter().find(|e| e.address == ep).is_some_and(|e| e.stream)
    }

    /// Complete OUT URBs locally instead of waiting a round trip. Without it,
    /// multi-packet CTAPHID messages time out on the device over WAN; for a
    /// CDC-ACM serial stream it hides the write latency the same way.
    fn early_ack(&self, ep: u8) -> bool {
        if ep & 0x80 != 0 || ep == 0 {
            return false;
        }
        match self.xfer(ep) {
            Some(XferType::Interrupt) => self.caps.early_out_ack,
            Some(XferType::Bulk) => self.caps.bulk_out_ack && self.is_stream(ep),
            _ => false,
        }
    }

    fn is_push(&self, ep: u8) -> bool {
        if ep & 0x80 == 0 {
            return false;
        }
        match self.xfer(ep) {
            Some(XferType::Interrupt) => self.caps.interrupt_in_push,
            Some(XferType::Bulk) => self.caps.bulk_in_push && self.is_stream(ep),
            _ => false,
        }
    }

    /// Answer a standard GET_DESCRIPTOR from the attach-time snapshot.
    fn cached_descriptor(&self, setup: &[u8; 8]) -> Option<Vec<u8>> {
        if !self.caps.descriptor_cache || setup[1] != 0x06 {
            return None;
        }
        let (index, ty) = (setup[2], setup[3]);
        let w_index = u16::from_le_bytes([setup[4], setup[5]]);
        let w_length = u16::from_le_bytes([setup[6], setup[7]]) as usize;
        let d = &self.attach.descriptors;
        let full: &[u8] = match (setup[0], ty) {
            (0x80, 0x01) => &d.device,
            (0x80, 0x02) => d.configs.get(index as usize)?,
            (0x80, 0x03) => {
                &d.strings.iter().find(|s| s.index == index && (index == 0 || s.lang_id == w_index))?.raw
            }
            (0x80, 0x0f) => d.bos.as_deref()?,
            (0x81, 0x22) => &d.hid_reports.iter().find(|(i, _)| *i as u16 == w_index)?.1,
            _ => return None,
        };
        Some(full[..full.len().min(w_length)].to_vec())
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        info!("USB/IP adapter on {} (busid {BUSID})", listener.local_addr()?);
        loop {
            let (sock, peer) = listener.accept().await?;
            sock.set_nodelay(true)?;
            debug!(%peer, "USB/IP connection");
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(sock).await {
                    warn!(%peer, "USB/IP session: {e:#}");
                }
            });
        }
    }

    async fn handle(self: Arc<Self>, mut sock: TcpStream) -> Result<()> {
        let mut h = [0u8; 8];
        sock.read_exact(&mut h).await?;
        let code = u16::from_be_bytes([h[2], h[3]]);
        match code {
            OP_REQ_DEVLIST => {
                let mut out = op_header(OP_REP_DEVLIST, 0);
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(&device_record(&self.attach, true));
                sock.write_all(&out).await?;
                Ok(())
            }
            OP_REQ_IMPORT => {
                let mut busid = [0u8; 32];
                sock.read_exact(&mut busid).await?;
                let req = String::from_utf8_lossy(&busid).trim_end_matches('\0').to_string();
                if req != BUSID {
                    sock.write_all(&op_header(OP_REP_IMPORT, 1)).await?;
                    bail!("import of unknown busid {req:?}");
                }
                if self.done_rx.try_lock().is_err() {
                    sock.write_all(&op_header(OP_REP_IMPORT, 1)).await?;
                    bail!("device is already imported");
                }
                let mut out = op_header(OP_REP_IMPORT, 0);
                out.extend_from_slice(&device_record(&self.attach, false));
                sock.write_all(&out).await?;
                info!("imported by local USB/IP client");
                let r = self.clone().urb_loop(sock).await;
                info!("USB/IP client detached");
                r
            }
            other => bail!("unsupported USB/IP op {other:#06x}"),
        }
    }

    /// Turn one server event into USB/IP replies (possibly none).
    fn on_event(sess: &mut Session, ev: EpEvent, out: &mut Vec<u8>) {
        match ev {
            EpEvent::Complete(c) => {
                let seq = c.urb as u32;
                let Some(f) = sess.inflight.remove(&seq) else {
                    // An early-acked OUT, or stale. Failures surface via DeferredError.
                    return;
                };
                let st = errno(c.status);
                match f.unlink_seq {
                    None => out.extend(ret_submit(seq, st, &c.data, f.is_in, c.actual_length)),
                    Some(useq) if c.status == Status::Cancelled => out.extend(ret_unlink(useq, ECONNRESET)),
                    Some(useq) => {
                        // Finished before the cancel took effect.
                        out.extend(ret_submit(seq, st, &c.data, f.is_in, c.actual_length));
                        out.extend(ret_unlink(useq, 0));
                    }
                }
            }
            EpEvent::Push { ep, data } => {
                // Every push is a report the device really sent: keep it even if
                // polling has stopped since (it was in flight), and hand it to the
                // next IN URB, as a device would with a report nobody polled yet.
                let pe = sess.push.entry(ep).or_default();
                match pe.pending.pop_front() {
                    Some((seq, len)) => out.extend(ret_in(seq, len, data)),
                    None => {
                        if pe.buffer.len() == PUSH_BUFFER {
                            pe.buffer.pop_front();
                            warn!(ep, "push buffer full, dropping the oldest report");
                        }
                        pe.buffer.push_back(data);
                    }
                }
            }
            EpEvent::Deferred { ep, urb, status } => match sess.push.get_mut(&ep) {
                Some(pe) if pe.epoch == Some(urb) => {
                    pe.epoch = None; // the server stopped polling
                    match pe.pending.pop_front() {
                        Some((seq, _)) => out.extend(ret_submit(seq, errno(status), &[], true, 0)),
                        None => pe.deferred = Some(status),
                    }
                }
                Some(_) => {}
                None => {
                    warn!(ep, urb, ?status, "early-acked OUT failed on the device; failing the next transfer");
                    sess.out_error.insert(ep, status);
                }
            },
        }
    }

    async fn urb_loop(self: Arc<Self>, sock: TcpStream) -> Result<()> {
        let sess: Arc<StdMutex<Session>> = Default::default();
        let (rd, wr) = sock.into_split();
        // Replies produced here rather than by the server: early OUT acks,
        // cached descriptors, buffered reports, local unlinks, failures.
        let (local_tx, mut local_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Writer: events from the server and locally produced replies.
        let w_sess = sess.clone();
        let me = self.clone();
        let writer = tokio::spawn(async move {
            let mut done_rx = me.done_rx.lock().await;
            let mut wr = BufWriter::new(wr);
            let mut out = Vec::new();
            loop {
                // Flush whenever nothing else is ready, before sleeping. This sits at
                // the top so that no path can leave replies stranded in the buffer;
                // several ready events still batch into one write.
                if !wr.buffer().is_empty() && done_rx.is_empty() && local_rx.is_empty() {
                    wr.flush().await?;
                }
                tokio::select! {
                    ev = done_rx.recv() => {
                        let Some(ev) = ev else { break };
                        Self::on_event(&mut w_sess.lock().unwrap(), ev, &mut out);
                    }
                    u = local_rx.recv() => {
                        let Some(u) = u else { break };
                        out = u;
                    }
                }
                wr.write_all(&out).await?;
                out.clear();
            }
            anyhow::Ok(())
        });

        // Reader: the socket is read by its own task, so that the loop below
        // can also react to the connection changing while the OS is quiet.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(256);
        let reader = tokio::spawn(read_cmds(rd, cmd_tx));

        let mut link = self.link.clone();
        let mut cur: Current = None;
        let mut link_open = true;
        let first = link.borrow_and_update().clone();
        self.switch_link(&mut cur, first, &sess, &local_tx).await;
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => match cmd {
                    Some(cmd) => self.on_cmd(cmd, &mut cur, &sess, &local_tx).await,
                    None => break,
                },
                changed = link.changed(), if link_open => match changed {
                    Ok(()) => {
                        let l = link.borrow_and_update().clone();
                        self.switch_link(&mut cur, l, &sess, &local_tx).await;
                    }
                    Err(_) => link_open = false,
                },
            }
        }
        drop(cur); // finishes endpoint streams; the server cancels what is pending
        drop(local_tx);
        writer.abort();
        reader.await?
    }

    /// Move to another connection (or none). Whatever the old connection
    /// had in flight is failed; waiting work restarts on the new one.
    async fn switch_link(&self, cur: &mut Current, new: Option<Link>, sess: &StdMutex<Session>, local: &Local) {
        if cur.as_ref().map(|c| c.0) == new.as_ref().map(|l| l.generation) {
            return;
        }
        if cur.take().is_some() {
            let replies = sess.lock().unwrap().link_down();
            if !replies.is_empty() {
                let _ = local.send(replies);
            }
        }
        let Some(l) = new else { return };
        *cur = Some((l.generation, l.remote.endpoints(l.dev, self.done_tx.clone())));
        let Resume { restart, held } = sess.lock().unwrap().link_up();
        if !restart.is_empty() || !held.is_empty() {
            info!(restart = restart.len(), held = held.len(), "resuming on the new connection");
        }
        for (ep, seq, len) in restart {
            let s = Submit { urb: seq as UrbId, setup: None, length: len, data: vec![], acked_early: false };
            if !send_now(cur, ep, s).await
                && let Some(pe) = sess.lock().unwrap().push.get_mut(&ep)
            {
                pe.epoch = None;
            }
        }
        for (ep, s) in held {
            self.submit_or_hold(cur, sess, ep, s).await;
        }
    }

    /// Send a submission now if there is a connection, else keep it for the
    /// next one.
    async fn submit_or_hold(&self, cur: &mut Current, sess: &StdMutex<Session>, ep: u8, s: Submit) {
        let seq = s.urb as u32;
        if send_now(cur, ep, s.clone()).await {
            if let Some(f) = sess.lock().unwrap().inflight.get_mut(&seq) {
                f.sent = true;
            }
        } else {
            let mut ss = sess.lock().unwrap();
            if let Some(f) = ss.inflight.get_mut(&seq) {
                f.sent = false;
            }
            ss.held.push_back((ep, s));
        }
    }

    async fn on_cmd(&self, cmd: Cmd, cur: &mut Current, sess: &StdMutex<Session>, local: &Local) {
        match cmd {
            Cmd::Submit { seq, ep, is_in, len, setup, data } => {
                if let Some(d) = setup.as_ref().and_then(|s| self.cached_descriptor(s)) {
                    let _ = local.send(ret_submit(seq, 0, &d, true, d.len() as u32));
                    return;
                }
                if let Some(halted) = setup.as_ref().and_then(clear_halt_target) {
                    // The host clears a halt: errors we were holding for that
                    // endpoint are answered by this. The request still goes to
                    // the device, which clears the real halt.
                    sess.lock().unwrap().forget_errors(halted);
                }

                if self.is_push(ep) {
                    let start = {
                        let mut s = sess.lock().unwrap();
                        let pe = s.push.entry(ep).or_default();
                        if let Some(st) = pe.deferred.take() {
                            let _ = local.send(ret_submit(seq, errno(st), &[], true, 0));
                        } else if let Some(d) = pe.buffer.pop_front() {
                            let _ = local.send(ret_in(seq, len, d));
                        } else {
                            pe.pending.push_back((seq, len));
                        }
                        // Without a connection, polling starts on reconnect (link_up).
                        let start = pe.epoch.is_none() && cur.is_some();
                        if start {
                            pe.epoch = Some(seq as UrbId);
                        }
                        start
                    };
                    if start {
                        let s = Submit { urb: seq as UrbId, setup: None, length: len, data, acked_early: false };
                        if !send_now(cur, ep, s).await
                            && let Some(pe) = sess.lock().unwrap().push.get_mut(&ep)
                        {
                            pe.epoch = None;
                        }
                    }
                    return;
                }

                let acked_early = self.early_ack(ep);
                if acked_early && let Some(st) = sess.lock().unwrap().out_error.remove(&ep) {
                    // A previous OUT failed after we acked it: fail this one instead.
                    let _ = local.send(ret_submit(seq, errno(st), &[], false, 0));
                    return;
                }
                if acked_early {
                    let _ = local.send(ret_submit(seq, 0, &[], false, len));
                } else {
                    sess.lock().unwrap().inflight.insert(seq, Inflight { ep, is_in, unlink_seq: None, sent: false });
                }
                let s = Submit { urb: seq as UrbId, setup, length: len, data, acked_early };
                self.submit_or_hold(cur, sess, ep, s).await;
            }
            Cmd::Unlink { seq, target } => {
                enum Found {
                    /// A push URB waiting locally; Some(epoch) if polling should stop.
                    Push(u8, Option<UrbId>),
                    /// A URB the server has.
                    Remote(u8),
                    /// A URB waiting for a connection: dropped here.
                    Held,
                    None,
                }
                let found = {
                    let mut guard = sess.lock().unwrap();
                    let s = &mut *guard;
                    let push_hit = s.push.iter_mut().find_map(|(&ep, pe)| {
                        let i = pe.pending.iter().position(|&(q, _)| q == target)?;
                        pe.pending.remove(i);
                        // usbhid unlinks its IN URB when the device is closed:
                        // stop reading so the device isn't drained while nobody listens.
                        // Reports already read stay buffered for the next reader.
                        let stop = if pe.pending.is_empty() { pe.epoch.take() } else { None };
                        Some(Found::Push(ep, stop))
                    });
                    match push_hit {
                        Some(f) => f,
                        None => match s.inflight.get_mut(&target) {
                            Some(f) if f.sent => {
                                f.unlink_seq = Some(seq);
                                Found::Remote(f.ep)
                            }
                            Some(_) => {
                                s.inflight.remove(&target);
                                s.held.retain(|(_, h)| h.urb as u32 != target);
                                Found::Held
                            }
                            None => Found::None,
                        },
                    }
                };
                match found {
                    Found::Push(ep, stop) => {
                        let _ = local.send(ret_unlink(seq, ECONNRESET));
                        if let Some(epoch) = stop
                            && let Some((_, eps)) = cur
                        {
                            let _ = eps.cancel(ep, epoch).await;
                        }
                    }
                    // If the cancel cannot be sent, the connection is going down
                    // and link_down answers the unlink.
                    Found::Remote(ep) => {
                        if let Some((_, eps)) = cur {
                            let _ = eps.cancel(ep, target as UrbId).await;
                        }
                    }
                    Found::Held => {
                        let _ = local.send(ret_unlink(seq, ECONNRESET));
                    }
                    // Already completed and returned.
                    Found::None => {
                        let _ = local.send(ret_unlink(seq, 0));
                    }
                }
            }
        }
    }
}

type Local = mpsc::UnboundedSender<Vec<u8>>;

/// Send on the current connection; false if there is none or it failed.
async fn send_now(cur: &mut Current, ep: u8, s: Submit) -> bool {
    match cur {
        Some((_, eps)) => match eps.submit(ep, s).await {
            Ok(()) => true,
            Err(e) => {
                debug!(ep, "submit failed, holding it for the next connection: {e:#}");
                false
            }
        },
        None => false,
    }
}

/// Parse USB/IP commands from the OS until it disconnects (Ok) or errs.
async fn read_cmds(mut rd: tokio::net::tcp::OwnedReadHalf, tx: mpsc::Sender<Cmd>) -> Result<()> {
    let mut hdr = [0u8; HEADER_LEN];
    loop {
        if let Err(e) = rd.read_exact(&mut hdr).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e.into());
        }
        let cmd = be32(&hdr, 0);
        let seq = be32(&hdr, 4);
        let is_in = be32(&hdr, 12) == 1;
        let epnum = be32(&hdr, 16) as u8;
        let c = match cmd {
            CMD_SUBMIT => {
                let len = be32(&hdr, 24);
                let npackets = be32(&hdr, 32) as i32;
                let mut data = Vec::new();
                if !is_in && len > 0 {
                    data = vec![0; len as usize];
                    rd.read_exact(&mut data).await?;
                }
                if npackets > 0 {
                    bail!("isochronous transfers are not supported");
                }
                let ep = if epnum == 0 { 0 } else { epnum | if is_in { 0x80 } else { 0 } };
                let setup: Option<[u8; 8]> = (ep == 0).then(|| hdr[40..48].try_into().unwrap());
                Cmd::Submit { seq, ep, is_in, len, setup, data }
            }
            CMD_UNLINK => Cmd::Unlink { seq, target: be32(&hdr, 20) },
            other => bail!("unexpected USB/IP command {other}"),
        };
        if tx.send(c).await.is_err() {
            return Ok(());
        }
    }
}

pub fn import_request() -> Vec<u8> {
    let mut out = op_header(OP_REQ_IMPORT, 0);
    let mut busid = BUSID.as_bytes().to_vec();
    busid.resize(32, 0);
    out.extend_from_slice(&busid);
    out
}

pub fn cmd_submit(seq: u32, ep: u8, is_in: bool, len: u32, setup: [u8; 8]) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&CMD_SUBMIT.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&0x0001_0001u32.to_be_bytes()); // devid busnum<<16|devnum
    h[12..16].copy_from_slice(&(is_in as u32).to_be_bytes());
    h[16..20].copy_from_slice(&((ep & 0x0f) as u32).to_be_bytes());
    h[24..28].copy_from_slice(&len.to_be_bytes());
    h[40..48].copy_from_slice(&setup);
    h
}

pub fn cmd_unlink(seq: u32, target: u32) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&CMD_UNLINK.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&0x0001_0001u32.to_be_bytes());
    h[20..24].copy_from_slice(&target.to_be_bytes());
    h
}

pub fn parse_ret(hdr: &[u8; HEADER_LEN]) -> (u32, u32, i32, u32) {
    (be32(hdr, 0), be32(hdr, 4), be32(hdr, 20) as i32, be32(hdr, 24))
}

pub async fn expect_import_reply(sock: &mut TcpStream) -> Result<()> {
    let mut h = [0u8; 8];
    sock.read_exact(&mut h).await?;
    if u16::from_be_bytes([h[2], h[3]]) != OP_REP_IMPORT || be32(&h, 4) != 0 {
        bail!("import refused: {h:02x?}");
    }
    let mut dev = [0u8; 312];
    sock.read_exact(&mut dev).await.context("reading import reply")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use usbwire_proto::Complete;

    fn parse(out: &[u8]) -> Vec<(u32, u32, i32, Vec<u8>)> {
        // (command, seqnum, status, IN payload) for each reply in `out`
        let mut v = Vec::new();
        let mut off = 0;
        while off < out.len() {
            let h: &[u8; HEADER_LEN] = out[off..off + HEADER_LEN].try_into().unwrap();
            let (cmd, seq, status, actual) = parse_ret(h);
            off += HEADER_LEN;
            let n = if cmd == RET_SUBMIT { actual as usize } else { 0 };
            v.push((cmd, seq, status, out[off..off + n].to_vec()));
            off += n;
        }
        v
    }

    fn push_session(epoch: UrbId) -> Session {
        let mut s = Session::default();
        s.push.insert(0x84, PushEp { epoch: Some(epoch), ..Default::default() });
        s
    }

    #[test]
    fn push_completes_waiting_urb() {
        let mut s = push_session(10);
        s.push.get_mut(&0x84).unwrap().pending.push_back((11, 64));
        let mut out = Vec::new();
        Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![7; 64] }, &mut out);
        assert_eq!(parse(&out), vec![(RET_SUBMIT, 11, 0, vec![7; 64])]);
        assert!(s.push[&0x84].pending.is_empty());
    }

    #[test]
    fn push_before_urb_is_buffered_even_after_stop() {
        // Reports in flight when polling stopped are real device data: keep
        // them, in order, for the next IN URB.
        let mut s = push_session(10);
        let mut out = Vec::new();
        Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![1] }, &mut out);
        s.push.get_mut(&0x84).unwrap().epoch = None; // the host unlinked its last URB
        Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![2] }, &mut out);
        Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![3] }, &mut out);
        assert!(out.is_empty());
        assert_eq!(s.push[&0x84].buffer, VecDeque::from([vec![1], vec![2], vec![3]]));
    }

    #[test]
    fn push_buffer_is_bounded() {
        let mut s = push_session(1);
        let mut out = Vec::new();
        for i in 0..(PUSH_BUFFER + 5) {
            Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![i as u8] }, &mut out);
        }
        let b = &s.push[&0x84].buffer;
        assert_eq!(b.len(), PUSH_BUFFER);
        assert_eq!(b.front(), Some(&vec![5u8]));
    }

    #[test]
    fn deferred_error_fails_next_urb_and_stops_epoch() {
        let mut s = push_session(4);
        let mut out = Vec::new();
        Adapter::on_event(&mut s, EpEvent::Deferred { ep: 0x84, urb: 4, status: Status::Stall }, &mut out);
        assert!(out.is_empty());
        let pe = &s.push[&0x84];
        assert_eq!((pe.epoch, pe.deferred), (None, Some(Status::Stall)));
    }

    #[test]
    fn short_urb_gets_overflow() {
        let mut s = push_session(1);
        s.push.get_mut(&0x84).unwrap().pending.push_back((2, 8));
        let mut out = Vec::new();
        Adapter::on_event(&mut s, EpEvent::Push { ep: 0x84, data: vec![9; 64] }, &mut out);
        assert_eq!(parse(&out), vec![(RET_SUBMIT, 2, -75, vec![9; 8])]);
    }

    #[test]
    fn unlinked_urb_cancelled_by_server() {
        let mut s = Session::default();
        s.inflight.insert(5, Inflight { ep: 0x02, is_in: false, unlink_seq: Some(6), sent: true });
        let mut out = Vec::new();
        let c = Complete { urb: 5, status: Status::Cancelled, actual_length: 0, data: vec![] };
        Adapter::on_event(&mut s, EpEvent::Complete(c), &mut out);
        assert_eq!(parse(&out), vec![(RET_UNLINK, 6, ECONNRESET, vec![])]);
    }

    #[test]
    fn link_down_fails_what_the_server_had_and_keeps_the_rest() {
        let mut s = push_session(10);
        s.push.get_mut(&0x84).unwrap().pending.push_back((11, 64));
        s.inflight.insert(20, Inflight { ep: 0x81, is_in: true, unlink_seq: None, sent: true });
        s.inflight.insert(21, Inflight { ep: 0x02, is_in: false, unlink_seq: Some(22), sent: true });
        s.inflight.insert(23, Inflight { ep: 0x02, is_in: false, unlink_seq: None, sent: false });
        let mut out = parse(&s.link_down());
        out.sort_by_key(|r| r.1);
        // Sent and unanswered: fate unknown, failed. Unlink requested: answered.
        assert_eq!(out, vec![(RET_SUBMIT, 20, EPROTO, vec![]), (RET_UNLINK, 22, ECONNRESET, vec![])]);
        // Held (never sent) stays for the next connection.
        assert_eq!(s.inflight.keys().collect::<Vec<_>>(), vec![&23]);
        // The push URB keeps waiting; the server no longer polls for it.
        let pe = &s.push[&0x84];
        assert_eq!((pe.epoch, pe.pending.len()), (None, 1));
    }

    #[test]
    fn link_up_restarts_polling_and_releases_held_submissions() {
        let mut s = push_session(10);
        s.link_down();
        s.push.get_mut(&0x84).unwrap().pending.extend([(11, 64), (12, 64)]);
        s.push.insert(0x83, PushEp::default()); // nobody waiting: stays idle
        let sub = |urb| Submit { urb, setup: None, length: 0, data: vec![1], acked_early: true };
        s.held.extend([(0x04, sub(30)), (0x04, sub(31))]);
        let r = s.link_up();
        assert_eq!(r.restart, vec![(0x84, 11, 64)]);
        assert_eq!(r.held.iter().map(|(_, h)| h.urb).collect::<Vec<_>>(), vec![30, 31]);
        assert_eq!(s.push[&0x84].epoch, Some(11));
        assert_eq!(s.push[&0x83].epoch, None);
        assert!(s.held.is_empty());
    }


    #[test]
    fn failed_early_acked_out_fails_the_next_urb_until_halt_is_cleared() {
        let mut s = Session::default();
        let mut out = Vec::new();
        // No push endpoint 0x04: this is an interrupt OUT that was acked early.
        Adapter::on_event(&mut s, EpEvent::Deferred { ep: 0x04, urb: 7, status: Status::Stall }, &mut out);
        assert!(out.is_empty());
        assert_eq!(s.out_error.get(&0x04), Some(&Status::Stall));
        // CLEAR_FEATURE(ENDPOINT_HALT) for 0x04.
        let setup = [0x02, 0x01, 0, 0, 0x04, 0, 0, 0];
        assert_eq!(clear_halt_target(&setup), Some(0x04));
        assert_eq!(clear_halt_target(&[0x80, 0x06, 0, 1, 0, 0, 18, 0]), None);
        s.forget_errors(0x04);
        assert!(s.out_error.is_empty());
    }

}
