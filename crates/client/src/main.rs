//! usbwire-client
//!
//!   usbwire-client pair  --server HOST:PORT --code XXXXX-XXXXX    once per server
//!   usbwire-client list  --server HOST:PORT
//!   usbwire-client serve --server HOST:PORT --dev VID:PID [--listen 127.0.0.1:3240] [--attach]
//!       (with --attach and no --listen the adapter takes any free local port)
//!       If the connection to the server drops, serve reconnects and resumes
//!       without the OS seeing the device unplugged (--no-reconnect: exit).
//!       then: usbip attach -r 127.0.0.1 -b 1-1 (Linux, or usbip-win2 usbip.exe on Windows);
//!       --attach runs that for you
//!   usbwire-client bench --server HOST:PORT --dev VID:PID [-n 200]
//!       plays the part of vhci against the local adapter and times FIDO round trips
//!
//!   usbwire-client service install <serve options>     (Windows, as Administrator)
//!       run serve --attach as a service from boot; `service uninstall` removes it
//!
//! The client's identity and the certificates of paired servers live in
//! --state (default: ~/.config/usbwire, %APPDATA%\usbwire on Windows).

mod link;
mod remote;
#[cfg(windows)]
mod service;
mod usbip;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use usbwire_proto::{AttachOk, Capabilities, XferType};

use crate::remote::Remote;
use crate::usbip::Adapter;

struct Args {
    cmd: String,
    server: String,
    state: PathBuf,
    /// Override the stored server certificate (testing).
    cert: Option<PathBuf>,
    code: String,
    dev: Option<(u16, u16)>,
    /// Adapter address; default 127.0.0.1:3240, or any free port with --attach.
    listen: Option<String>,
    rounds: usize,
    caps: Capabilities,
    /// serve: run `usbip attach` against our own adapter once it listens.
    auto_attach: bool,
    /// serve: reconnect when the connection to the server drops.
    reconnect: bool,
}

const USAGE: &str = "usage: usbwire-client <pair|list|serve|bench|service install|service uninstall> --server HOST:PORT [--code CODE] [--dev VID:PID] \
[--listen ADDR] [--attach] [--no-reconnect] [-n N] [--state DIR] [--cert FILE] [--no-early-ack] [--no-push] [--no-desc-cache]";

fn default_state() -> PathBuf {
    if let Ok(d) = std::env::var("USBWIRE_CLIENT_STATE") {
        return d.into();
    }
    #[cfg(windows)]
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| ".".into());
    #[cfg(not(windows))]
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
    });
    base.join("usbwire")
}

/// Where the pinned certificate of `server` is stored.
fn server_cert_path(state: &std::path::Path, server: &str) -> PathBuf {
    let safe: String = server.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    state.join("servers").join(format!("{safe}.der"))
}

fn parse_args(raw: Vec<String>) -> Result<Args> {
    let mut it = raw.into_iter();
    let mut a = Args {
        cmd: it.next().context(USAGE)?,
        server: String::new(),
        state: default_state(),
        cert: None,
        code: String::new(),
        dev: None,
        listen: None,
        rounds: 200,
        caps: Capabilities { interrupt_in_push: true, early_out_ack: true, descriptor_cache: true },
        auto_attach: false,
        reconnect: true,
    };
    while let Some(arg) = it.next() {
        let mut val = || it.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--server" => a.server = val()?,
            "--cert" => a.cert = Some(val()?.into()),
            "--state" => a.state = val()?.into(),
            "--code" => a.code = val()?,
            "--listen" => a.listen = Some(val()?),
            "-n" => a.rounds = val()?.parse()?,
            "--attach" => a.auto_attach = true,
            "--no-reconnect" => a.reconnect = false,
            "--no-early-ack" => a.caps.early_out_ack = false,
            "--no-push" => a.caps.interrupt_in_push = false,
            "--no-desc-cache" => a.caps.descriptor_cache = false,
            "--dev" => {
                let v = val()?;
                let (vid, pid) = v.split_once(':').context("--dev wants VID:PID in hex")?;
                a.dev = Some((u16::from_str_radix(vid, 16)?, u16::from_str_radix(pid, 16)?));
            }
            _ => bail!("{USAGE}"),
        }
    }
    if a.server.is_empty() {
        bail!("{USAGE}");
    }
    Ok(a)
}

fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("service") {
        #[cfg(windows)]
        return service::main(&raw[1..]);
        #[cfg(not(windows))]
        bail!("`service` is for Windows; on Linux, run serve from systemd (see contrib/usbwire-client.service)");
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = parse_args(raw)?;
    tokio::runtime::Runtime::new()?.block_on(async {
        // Ctrl-C and friends, as a flag every wait in serve can watch.
        let (stop_tx, stop_rx) = watch::channel(false);
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = stop_tx.send(true);
        });
        run(args, stop_rx).await
    })
}

/// Run one command. `stop` turns true when the client should shut down
/// (Ctrl-C, or the service manager).
async fn run(args: Args, stop: watch::Receiver<bool>) -> Result<()> {
    let identity = usbwire_net::load_or_create_identity(&args.state)?;

    if args.cmd == "pair" {
        if args.code.is_empty() {
            bail!("pair needs --code (shown by `usbwire-server pair` on the server)");
        }
        let my_fp = usbwire_net::auth::fingerprint(&identity.0);
        let p = remote::pair(&args.server, identity, &args.code).await?;
        let path = server_cert_path(&args.state, &args.server);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, &p.server_cert)?;
        println!(
            "paired with {} ({}); allowed devices: {}",
            p.server_name,
            usbwire_net::auth::short_fp(&usbwire_net::auth::fingerprint(&p.server_cert)),
            p.allowed.join(", ")
        );
        println!("this client: {}", usbwire_net::auth::short_fp(&my_fp));
        return Ok(());
    }

    let cert_path = args.cert.clone().unwrap_or_else(|| server_cert_path(&args.state, &args.server));
    let server_cert = std::fs::read(&cert_path)
        .map(usbwire_net::quinn::rustls::pki_types::CertificateDer::from)
        .with_context(|| format!("not paired with {} (no {}): run `usbwire-client pair` first", args.server, cert_path.display()))?;
    let target = link::Target { server: args.server.clone(), cert: server_cert, identity, caps: args.caps, want: args.dev };
    match args.cmd.as_str() {
        "serve" => serve(&args, target, stop).await,
        "list" => {
            let remote = target.connect().await?;
            let result = list(&remote).await;
            remote.close().await;
            result
        }
        "bench" => {
            let (remote, attach) = link::connect_attach(&target, None).await?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (_link_tx, link_rx) = watch::channel(Some(link::Link { remote: remote.clone(), dev: attach.info.dev, generation: 1 }));
            tokio::spawn(Adapter::new(attach.clone(), link_rx).serve(listener));
            let result = bench(&remote, &attach, addr, args.rounds).await;
            remote.close().await;
            result
        }
        _ => bail!("{USAGE}"),
    }
}

async fn list(remote: &Remote) -> Result<()> {
    for d in remote.list().await? {
        println!(
            "dev {}  {:04x}:{:04x}  {:?}  {} {}{}",
            d.dev,
            d.vid,
            d.pid,
            d.speed,
            d.manufacturer.as_deref().unwrap_or(""),
            d.product.as_deref().unwrap_or(""),
            if d.busy { "  (in use)" } else { "" }
        );
    }
    Ok(())
}

/// Serve the device to the OS's USB/IP client until shut down, reconnecting
/// to the server underneath as needed.
async fn serve(args: &Args, target: link::Target, mut stop_rx: watch::Receiver<bool>) -> Result<()> {
    // We tell usbip the port ourselves with --attach, so any free one
    // will do (3240 is often taken, e.g. by usbipd-win on Windows).
    let default = if args.auto_attach { "127.0.0.1:0" } else { "127.0.0.1:3240" };
    let addr = args.listen.as_deref().unwrap_or(default);
    // Bind first: failing here must not cost the server a driver swap.
    let listener = TcpListener::bind(addr).await.with_context(|| format!("listening on {addr}"))?;
    let port = listener.local_addr()?.port();

    let first = if args.reconnect {
        link::connect_attach_retrying(&target, None, &mut stop_rx).await?
    } else {
        Some(link::connect_attach(&target, None).await?)
    };
    let Some((remote, attach)) = first else { return Ok(()) };

    let (link_tx, link_rx) = watch::channel(Some(link::Link { remote, dev: attach.info.dev, generation: 1 }));
    let served = tokio::spawn(Adapter::new(attach.clone(), link_rx).serve(listener));
    if args.auto_attach {
        tokio::spawn(async move {
            if let Err(e) = usbip_attach(port).await {
                tracing::error!("usbip attach: {e:#}");
            }
        });
    }
    let result = link::supervise(&target, &attach, link_tx, args.reconnect, stop_rx).await;
    served.abort();
    result
}

/// The OS's USB/IP tool: usbip-win2's usbip.exe on Windows, usbip on Linux.
fn usbip_tool() -> PathBuf {
    #[cfg(windows)]
    {
        let installed = PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()))
            .join("USBip")
            .join("usbip.exe");
        if installed.exists() {
            return installed;
        }
    }
    "usbip".into()
}

/// Attach our adapter's device to the OS (vhci_hcd / usbip-win2). The
/// attachment ends by itself when the adapter connection closes.
async fn usbip_attach(port: u16) -> Result<()> {
    let tool = usbip_tool();
    let mut cmd = tokio::process::Command::new(&tool);
    if port != 3240 {
        cmd.args(["--tcp-port", &port.to_string()]);
    }
    cmd.args(["attach", "-r", "127.0.0.1", "-b", usbip::BUSID]);
    // usbip-win2 keeps re-attaching after the connection drops unless told
    // not to; the attachment should end with this client.
    #[cfg(windows)]
    cmd.arg("--once");
    let out = cmd.output().await.with_context(|| format!("running {}", tool.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string() + String::from_utf8_lossy(&out.stderr).trim();
    if !out.status.success() {
        bail!("{} failed ({}): {text}", tool.display(), out.status);
    }
    tracing::info!("attached to the local USB/IP driver{}", if text.is_empty() { String::new() } else { format!(": {text}") });
    Ok(())
}

/// Ctrl-C, SIGTERM on Unix, closing the console window on Windows: either way we fall through to a clean QUIC
/// close so the server releases the device immediately.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_close, ctrl_shutdown};
        let (mut close, mut shutdown) = (ctrl_close().expect("console close handler"), ctrl_shutdown().expect("shutdown handler"));
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = close.recv() => {}
            _ = shutdown.recv() => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Bench: act like vhci_hcd against the adapter
// ---------------------------------------------------------------------------

struct Vhci {
    sock: TcpStream,
    seq: u32,
}

impl Vhci {
    async fn submit(&mut self, ep: u8, is_in: bool, len: u32, setup: [u8; 8], out: &[u8]) -> Result<u32> {
        self.seq += 1;
        let mut msg = usbip::cmd_submit(self.seq, ep, is_in, len, setup);
        msg.extend_from_slice(out);
        self.sock.write_all(&msg).await?;
        Ok(self.seq)
    }

    async fn unlink(&mut self, target: u32) -> Result<u32> {
        self.seq += 1;
        self.sock.write_all(&usbip::cmd_unlink(self.seq, target)).await?;
        Ok(self.seq)
    }

    /// (command, seqnum, status, data)
    async fn reply(&mut self, in_len: impl Fn(u32) -> bool) -> Result<(u32, u32, i32, Vec<u8>)> {
        let mut hdr = [0u8; usbip::HEADER_LEN];
        tokio::time::timeout(Duration::from_secs(5), self.sock.read_exact(&mut hdr))
            .await
            .context("timed out waiting for a USB/IP reply")??;
        let (cmd, seq, status, actual) = usbip::parse_ret(&hdr);
        let mut data = Vec::new();
        if cmd == usbip::RET_SUBMIT && in_len(seq) {
            data = vec![0; actual as usize];
            self.sock.read_exact(&mut data).await?;
        }
        Ok((cmd, seq, status, data))
    }
}

fn stats(name: &str, mut t: Vec<Duration>) {
    t.sort();
    let us = |d: Duration| d.as_micros();
    println!(
        "{name:<34} n={:<4} min {:>6}us  p50 {:>6}us  p90 {:>6}us  max {:>6}us",
        t.len(),
        us(t[0]),
        us(t[t.len() / 2]),
        us(t[t.len() * 9 / 10]),
        us(*t.last().unwrap())
    );
}

async fn bench(remote: &Remote, a: &AttachOk, adapter: std::net::SocketAddr, rounds: usize) -> Result<()> {
    // Network floor: one QUIC round trip on the control stream.
    let mut pings = Vec::new();
    for _ in 0..rounds.min(50) {
        pings.push(remote.ping().await?);
    }
    stats("QUIC ping (network floor)", pings);

    let mut sock = TcpStream::connect(adapter).await?;
    sock.set_nodelay(true)?;
    sock.write_all(&usbip::import_request()).await?;
    usbip::expect_import_reply(&mut sock).await?;
    let mut v = Vhci { sock, seq: 0 };

    // GET_DESCRIPTOR(device) over the control pipe.
    let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0];
    let mut ctl = Vec::new();
    for _ in 0..rounds.min(50) {
        let t = Instant::now();
        let s = v.submit(0, true, 18, setup, &[]).await?;
        let (cmd, seq, status, data) = v.reply(|_| true).await?;
        if cmd != usbip::RET_SUBMIT || seq != s || status != 0 || data != a.descriptors.device {
            bail!("bad GET_DESCRIPTOR reply: cmd {cmd} seq {seq} status {status} data {data:02x?}");
        }
        ctl.push(t.elapsed());
    }
    stats("control GET_DESCRIPTOR(device)", ctl);

    // FIDO: the HID interface with interrupt IN + OUT.
    let (ep_in, ep_out) = {
        let mut found = None;
        for o in a.endpoints.iter().filter(|e| e.xfer == XferType::Interrupt && e.address & 0x80 == 0) {
            if let Some(i) = a.endpoints.iter().find(|e| {
                e.xfer == XferType::Interrupt && e.address & 0x80 != 0 && e.interface == o.interface
            }) {
                found = Some((i.address, o.address));
            }
        }
        found.context("no interrupt IN+OUT pair (not a FIDO device?)")?
    };
    println!("FIDO endpoints: IN {ep_in:#04x} OUT {ep_out:#04x}");

    let mut init = Vec::new();
    let mut cid = [0xff; 4];
    let mut stale = 0usize;
    for round in 0..rounds {
        let nonce = (round as u64 ^ 0x1122_3344_5566_0000).to_be_bytes();
        let mut pkt = [0u8; 64];
        pkt[..4].copy_from_slice(&[0xff; 4]);
        pkt[4] = 0x86;
        pkt[5..7].copy_from_slice(&8u16.to_be_bytes());
        pkt[7..15].copy_from_slice(&nonce);

        let t = Instant::now();
        let mut in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
        let out_seq = v.submit(ep_out, false, 64, [0; 8], &pkt).await?;
        let mut got_in = None;
        let mut got_out = false;
        while got_in.is_none() || !got_out {
            let cur_in = in_seq;
            let (cmd, seq, status, data) = v.reply(|s| s == cur_in).await?;
            if cmd != usbip::RET_SUBMIT || status != 0 {
                bail!("transfer failed: cmd {cmd} seq {seq} status {status}");
            }
            if seq == in_seq {
                if data.len() >= 15 && data[4] == 0x86 && data[7..15] == nonce {
                    got_in = Some(data);
                } else {
                    // Not our reply (e.g. the rest of a message an earlier session
                    // abandoned): skip it, as libfido2 does.
                    stale += 1;
                    in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
                }
            } else if seq == out_seq {
                got_out = true;
            }
        }
        let data = got_in.unwrap();
        cid.copy_from_slice(&data[15..19]);
        init.push(t.elapsed());
    }
    stats("FIDO CTAPHID_INIT (OUT+IN)", init);
    if stale > 0 {
        println!("(skipped {stale} stale reports left in the key by an earlier session)");
    }

    // Unlink: park an IN transfer (the key has nothing to say) and cancel it,
    // as usbhid does on close.
    let target = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t = Instant::now();
    let useq = v.unlink(target).await?;
    let (cmd, seq, status, _) = v.reply(|s| s == target).await?;
    println!(
        "unlink parked IN: reply cmd {cmd} seq {seq} status {status} in {:?} -> {}",
        t.elapsed(),
        if cmd == usbip::RET_UNLINK && seq == useq && status == -104 { "OK" } else { "UNEXPECTED" }
    );

    stall_recovery(&mut v, ep_in, ep_out).await?;

    // 1 KB CTAPHID_PING, driven exactly like Linux usbhid + hidraw: one IN URB
    // always pending and resubmitted on completion, each OUT report waited for.
    let payload: Vec<u8> = (0..1024u32).map(|i| (i * 7) as u8).collect();
    let mut in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
    let mut pings = Vec::new();
    for _ in 0..(rounds / 10).max(5) {
        let t = Instant::now();
        let echoed = ctap_ping(&mut v, ep_in, ep_out, cid, &payload, &mut in_seq).await?;
        if echoed != payload {
            bail!("CTAPHID_PING echo mismatch");
        }
        pings.push(t.elapsed());
    }
    stats("FIDO 1 KB CTAPHID_PING (usbhid-style)", pings);
    Ok(())
}

/// Halt the FIDO OUT endpoint on the device (SET_FEATURE(ENDPOINT_HALT)),
/// then check what a host would see: the early-acked OUT that hits the halt
/// fails later, so the next OUT gets EPIPE; CLEAR_FEATURE(ENDPOINT_HALT)
/// reaches the device and a full CTAPHID_INIT works again.
async fn stall_recovery(v: &mut Vhci, ep_in: u8, ep_out: u8) -> Result<()> {
    const EPIPE: i32 = -32;
    let control = async |v: &mut Vhci, request: u8| -> Result<i32> {
        let s = v.submit(0, false, 0, [0x02, request, 0, 0, ep_out, 0, 0, 0], &[]).await?;
        let (_, seq, status, _) = v.reply(|_| false).await?;
        if seq != s {
            bail!("control reply for seq {seq}, expected {s}");
        }
        Ok(status)
    };
    let mut pkt = [0u8; 64];
    pkt[..4].copy_from_slice(&[0xff; 4]);
    pkt[4] = 0x86;
    pkt[5..7].copy_from_slice(&8u16.to_be_bytes());
    pkt[7..15].copy_from_slice(b"stalltst");

    let set = control(v, 0x03).await?;
    if set != 0 {
        println!("stall recovery: device refused SET_FEATURE(ENDPOINT_HALT) (status {set}); skipped");
        return Ok(());
    }
    let s1 = v.submit(ep_out, false, 64, [0; 8], &pkt).await?;
    let (_, _, st1, _) = v.reply(|_| false).await?;
    // Give the device's failure time to come back as a deferred error.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s2 = v.submit(ep_out, false, 64, [0; 8], &pkt).await?;
    let (_, seq2, st2, _) = v.reply(|_| false).await?;
    let cleared = control(v, 0x01).await?;

    // A full round trip afterwards.
    let in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
    v.submit(ep_out, false, 64, [0; 8], &pkt).await?;
    let mut works = false;
    for _ in 0..4 {
        let (cmd, seq, status, data) = v.reply(|s| s == in_seq).await?;
        if cmd == usbip::RET_SUBMIT && seq == in_seq && status == 0 && data.get(7..15) == Some(&b"stalltst"[..]) {
            works = true;
            break;
        }
    }
    let ok = st1 == 0 && seq2 == s2 && st2 == EPIPE && cleared == 0 && works;
    println!(
        "stall recovery: OUT on halted ep acked {st1} (seq {s1}), next OUT {st2} (want {EPIPE}), \
         CLEAR_FEATURE {cleared}, INIT afterwards {} -> {}",
        if works { "ok" } else { "FAILED" },
        if ok { "OK" } else { "UNEXPECTED" }
    );
    if !ok {
        bail!("stall recovery did not behave as on a local device");
    }
    Ok(())
}

/// Send one CTAPHID message and collect the reply, usbhid style. Returns the reply payload.
async fn ctap_ping(
    v: &mut Vhci,
    ep_in: u8,
    ep_out: u8,
    cid: [u8; 4],
    payload: &[u8],
    in_seq: &mut u32,
) -> Result<Vec<u8>> {
    // Fragment: init packet carries 57 bytes, continuation packets 59.
    let mut packets = Vec::new();
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&cid);
    p[4] = 0x81; // CTAPHID_PING
    p[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(57);
    p[7..7 + first].copy_from_slice(&payload[..first]);
    packets.push(p);
    for (seq, chunk) in payload[first..].chunks(59).enumerate() {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid);
        p[4] = seq as u8;
        p[5..5 + chunk.len()].copy_from_slice(chunk);
        packets.push(p);
    }

    // Reports on our channel; anything else (e.g. keep-alives) is dropped.
    let mut reports: Vec<Vec<u8>> = Vec::new();
    let keep = |data: Vec<u8>, reports: &mut Vec<Vec<u8>>| {
        if data.len() == 64 && data[..4] == cid {
            reports.push(data);
        }
    };
    for pkt in &packets {
        let out_seq = v.submit(ep_out, false, 64, [0; 8], pkt).await?;
        loop {
            let cur_in = *in_seq;
            let (cmd, seq, status, data) = v.reply(|s| s == cur_in).await?;
            if cmd != usbip::RET_SUBMIT || status != 0 {
                bail!("transfer failed: cmd {cmd} seq {seq} status {status}");
            }
            if seq == cur_in {
                keep(data, &mut reports);
                *in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
            } else if seq == out_seq {
                break;
            }
        }
    }
    let total = payload.len();
    let have = |r: &Vec<Vec<u8>>| -> usize {
        if r.is_empty() { 0 } else { (57 + (r.len() - 1) * 59).min(total) }
    };
    let ctap_error = |r: &Vec<Vec<u8>>| -> Result<()> {
        match r.first() {
            Some(f) if f[4] == 0xbf => bail!("device answered CTAPHID_ERROR {:#04x} after {} OUT packets", f[7], packets.len()),
            _ => Ok(()),
        }
    };
    ctap_error(&reports)?;
    while have(&reports) < total {
        ctap_error(&reports)?;
        let cur_in = *in_seq;
        let (cmd, seq, status, data) = v.reply(|s| s == cur_in).await?;
        if cmd != usbip::RET_SUBMIT || status != 0 || seq != cur_in {
            bail!("unexpected reply: cmd {cmd} seq {seq} status {status}");
        }
        keep(data, &mut reports);
        *in_seq = v.submit(ep_in, true, 64, [0; 8], &[]).await?;
    }
    let first = reports.first().context("no reply")?;
    if first[4] != 0x81 {
        bail!("CTAPHID error reply {first:02x?}");
    }
    let mut out = first[7..64].to_vec();
    for r in &reports[1..] {
        out.extend_from_slice(&r[5..64]);
    }
    out.truncate(total);
    Ok(out)
}
