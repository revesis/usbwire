//! Phase 0b proof of concept.
//!
//!   winswap list                     list USB devices with their driver
//!   winswap export  <instance-id>    (Windows) bind the whole device to inbox WinUSB
//!   winswap restore <instance-id>    (Windows) remove the device node and rescan so
//!                                    Windows reinstalls its default drivers
//!   winswap probe   <vid>:<pid> [n]  open with nusb, read descriptors, and time n
//!                                    CTAPHID_INIT round trips on the FIDO interface
//!
//! Safety: export/restore only accept a composite *parent* node (no `&MI_`) and,
//! unless `--any-vid` is given, only Yubico devices (VID 1050).

#[cfg(windows)]
use winswap::swap;

use std::time::{Duration, Instant};

use nusb::MaybeFuture;
use nusb::descriptors::TransferType;
use nusb::transfer::{Buffer, ControlIn, ControlType, Direction, In, Interrupt, Out, Recipient};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    tracing_subscriber::fmt().without_time().with_target(false).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let any_vid = args.iter().any(|a| a == "--any-vid");
    let args: Vec<&str> = args.iter().map(String::as_str).filter(|a| !a.starts_with("--")).collect();

    let res = match args.as_slice() {
        ["list"] => list(),
        ["probe", id] => probe(id, 20),
        ["probe", id, n] => n.parse().map_err(Into::into).and_then(|n| probe(id, n)),
        ["export", inst] => export(inst, any_vid),
        ["restore", inst] => restore(inst, any_vid),
        _ => {
            eprintln!(
                "usage: winswap list | probe <vid>:<pid> [n] | export <instance-id> | restore <instance-id> [--any-vid]"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn list() -> Result<()> {
    for d in nusb::list_devices().wait()? {
        #[cfg(windows)]
        let extra = {
            let inst = d.instance_id().to_string_lossy();
            let remote = if swap::is_usbip_virtual(&inst) { " [usbip]" } else { "" };
            format!("driver={:<10} {inst}{remote}", d.driver().unwrap_or("-"))
        };
        #[cfg(not(windows))]
        let extra = String::new();
        println!(
            "{:04x}:{:04x}  {:<32} {}",
            d.vendor_id(),
            d.product_id(),
            d.product_string().unwrap_or("?"),
            extra
        );
    }
    Ok(())
}

#[cfg(windows)]
fn export(inst: &str, any_vid: bool) -> Result<()> {
    swap::check_instance_id(inst, any_vid)?;
    swap::export(inst)
}
#[cfg(windows)]
fn restore(inst: &str, any_vid: bool) -> Result<()> {
    swap::check_instance_id(inst, any_vid)?;
    swap::restore(inst)
}
#[cfg(not(windows))]
fn export(_: &str, _: bool) -> Result<()> {
    Err("export is Windows-only".into())
}
#[cfg(not(windows))]
fn restore(_: &str, _: bool) -> Result<()> {
    Err("restore is Windows-only".into())
}

fn parse_vid_pid(s: &str) -> Result<(u16, u16)> {
    let (v, p) = s.split_once(':').ok_or("expected <vid>:<pid> in hex")?;
    Ok((u16::from_str_radix(v, 16)?, u16::from_str_radix(p, 16)?))
}

fn probe(id: &str, rounds: usize) -> Result<()> {
    let (vid, pid) = parse_vid_pid(id)?;
    let info = nusb::list_devices()
        .wait()?
        .find(|d| d.vendor_id() == vid && d.product_id() == pid)
        .ok_or("device not found")?;
    println!("found {:04x}:{:04x} {:?}", vid, pid, info.product_string());
    let dev = info.open().wait()?;

    // Find the FIDO interface: HID class with an interrupt OUT endpoint
    // (the OTP keyboard interface has only an IN endpoint).
    let cfg = dev.active_configuration()?;
    let mut fido = None;
    for intf in cfg.interfaces() {
        for alt in intf.alt_settings() {
            print!("  intf {} alt {} class {:02x}:", alt.interface_number(), alt.alternate_setting(), alt.class());
            let (mut ep_in, mut ep_out) = (None, None);
            for ep in alt.endpoints() {
                print!(" ep {:02x} {:?} mps {}", ep.address(), ep.transfer_type(), ep.max_packet_size());
                if ep.transfer_type() == TransferType::Interrupt {
                    match ep.direction() {
                        Direction::In => ep_in = Some(ep.address()),
                        Direction::Out => ep_out = Some(ep.address()),
                    }
                }
            }
            println!();
            if alt.class() == 3
                && fido.is_none()
                && let (Some(i), Some(o)) = (ep_in, ep_out)
            {
                fido = Some((alt.interface_number(), i, o));
            }
        }
    }
    let (ifnum, ep_in, ep_out) = fido.ok_or("no HID interface with interrupt IN+OUT")?;
    println!("FIDO interface {ifnum}: IN {ep_in:02x} OUT {ep_out:02x}");
    let intf = dev.claim_interface(ifnum).wait()?;

    // Control transfers through the interface handle (the only way on WinUSB).
    let t = Instant::now();
    let desc = intf
        .control_in(
            ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Device,
                request: 6,
                value: 0x0100,
                index: 0,
                length: 18,
            },
            Duration::from_secs(1),
        )
        .wait()?;
    println!("GET_DESCRIPTOR(device) {:?}: {:02x?}", t.elapsed(), desc);

    let report = intf
        .control_in(
            ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Interface,
                request: 6,
                value: 0x2200,
                index: ifnum as u16,
                length: 256,
            },
            Duration::from_secs(1),
        )
        .wait()?;
    let is_fido = report.starts_with(&[0x06, 0xd0, 0xf1]);
    println!("HID report descriptor: {} bytes, FIDO usage page: {is_fido}", report.len());

    // CTAPHID_INIT round trips: needs no user touch.
    let mut out = intf.endpoint::<Interrupt, Out>(ep_out)?;
    let mut inp = intf.endpoint::<Interrupt, In>(ep_in)?;
    let mps = inp.max_packet_size();
    let mut times = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let nonce = (round as u64 ^ 0x5a5a_1234_9876_0000).to_be_bytes();
        let mut pkt = vec![0u8; 64];
        pkt[..4].copy_from_slice(&[0xff; 4]); // broadcast CID
        pkt[4] = 0x86; // CTAPHID_INIT
        pkt[5..7].copy_from_slice(&8u16.to_be_bytes());
        pkt[7..15].copy_from_slice(&nonce);

        let t = Instant::now();
        inp.submit(Buffer::new(mps));
        out.submit(Buffer::from(pkt));
        out.wait_next_complete(Duration::from_secs(2)).ok_or("OUT timeout")?.into_result()?;
        // Skip unrelated broadcast responses until our nonce comes back.
        loop {
            let c = inp.wait_next_complete(Duration::from_secs(2)).ok_or("IN timeout")?;
            let buf = c.into_result()?;
            if buf.len() >= 15 && buf[4] == 0x86 && buf[7..15] == nonce {
                times.push(t.elapsed());
                if round == 0 {
                    println!(
                        "CTAPHID_INIT ok: channel {:02x?}, protocol {}, fw {}.{}.{}, caps {:#04x}",
                        &buf[15..19],
                        buf[19],
                        buf[20],
                        buf[21],
                        buf[22],
                        buf[23]
                    );
                }
                break;
            }
            inp.submit(Buffer::new(mps));
        }
    }
    times.sort();
    let us = |d: Duration| d.as_micros();
    println!(
        "{} CTAPHID_INIT round trips: min {}us  p50 {}us  p90 {}us  max {}us",
        times.len(),
        us(times[0]),
        us(times[times.len() / 2]),
        us(times[times.len() * 9 / 10]),
        us(*times.last().unwrap())
    );
    Ok(())
}
