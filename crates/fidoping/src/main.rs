//! fidoping: talk CTAPHID to a FIDO key through the operating system's HID
//! stack, the way browsers and libfido2 do, and time it. Works the same on a
//! local key and on one attached through usbwire, so the two can be compared.
//!
//!   fidoping list                 FIDO HID devices (usage page 0xF1D0)
//!   fidoping [FILTER] [-n N]      CTAPHID_INIT n times, then 1 KB CTAPHID_PING n/10 times
//!
//! FILTER picks the device whose path contains it (case-insensitive); without
//! it there must be exactly one FIDO device. No touch is needed: INIT and PING
//! never ask for user presence. On Windows, FIDO devices need Administrator.

use std::process::exit;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const REPORT: usize = 64;
const CMD_PING: u8 = 0x81;
const CMD_INIT: u8 = 0x86;
const CMD_ERROR: u8 = 0xbf;
const BROADCAST: [u8; 4] = [0xff; 4];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut n = 100usize;
    let mut filter = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-n" => n = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "-h" | "--help" => usage(),
            "list" if filter.is_none() => {
                match hid::fido_devices() {
                    Ok(d) if d.is_empty() => println!("no FIDO HID devices"),
                    Ok(d) => d.iter().for_each(|p| println!("{p}")),
                    Err(e) => fail(e),
                }
                return;
            }
            f => filter = Some(f.to_ascii_lowercase()),
        }
    }
    // Reads block; never hang a test run on a silent device.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        eprintln!("error: no answer from the device within 60 s");
        exit(3);
    });
    if let Err(e) = run(filter.as_deref(), n.max(1)) {
        fail(e);
    }
}

fn usage() -> ! {
    eprintln!("usage: fidoping list | fidoping [FILTER] [-n N]");
    exit(2)
}

fn fail(e: Box<dyn std::error::Error>) -> ! {
    eprintln!("error: {e}");
    exit(1)
}

fn run(filter: Option<&str>, n: usize) -> Result<()> {
    let all = hid::fido_devices()?;
    let picked: Vec<&String> = all.iter().filter(|p| filter.is_none_or(|f| p.to_ascii_lowercase().contains(f))).collect();
    let path = match picked.as_slice() {
        [one] => *one,
        [] => return Err("no matching FIDO HID device (try `fidoping list`)".into()),
        _ => return Err(format!("{} FIDO devices match; pass a FILTER (see `fidoping list`)", picked.len()).into()),
    };
    println!("device: {path}");
    let t = Instant::now();
    let mut dev = hid::Device::open(path)?;
    println!("open: {:?}", t.elapsed());

    let mut init = Vec::with_capacity(n);
    let mut cid = BROADCAST;
    let mut skipped = 0;
    for i in 0..n {
        let nonce = (i as u64 ^ 0x5a5a_0000_0000_0000).to_be_bytes();
        let t = Instant::now();
        let (reply, stale) = transact(&mut dev, BROADCAST, CMD_INIT, &nonce, Some(&nonce))?;
        init.push(t.elapsed());
        skipped += stale;
        if reply.len() < 17 {
            return Err(format!("short INIT reply {reply:02x?}").into());
        }
        cid.copy_from_slice(&reply[8..12]);
        if i == 0 {
            println!(
                "CTAPHID v{}, device version {}.{}.{}, capabilities {:#04x}",
                reply[12], reply[13], reply[14], reply[15], reply[16]
            );
        }
    }
    stats("CTAPHID_INIT", init);

    let payload: Vec<u8> = (0..1024u32).map(|i| (i * 13 + 5) as u8).collect();
    let mut ping = Vec::new();
    for _ in 0..(n / 10).max(3) {
        let t = Instant::now();
        let (echo, stale) = transact(&mut dev, cid, CMD_PING, &payload, None)?;
        ping.push(t.elapsed());
        skipped += stale;
        if echo != payload {
            return Err("CTAPHID_PING echo differs from what was sent".into());
        }
    }
    stats("1 KB CTAPHID_PING", ping);
    if skipped > 0 {
        println!("(skipped {skipped} reports meant for other channels)");
    }
    println!("OK");
    Ok(())
}

/// Send one CTAPHID message and read the reply on the same channel. For INIT
/// on the broadcast channel, `nonce` identifies our reply. Returns the reply
/// payload and the number of foreign reports skipped.
fn transact(dev: &mut hid::Device, cid: [u8; 4], cmd: u8, data: &[u8], nonce: Option<&[u8]>) -> Result<(Vec<u8>, usize)> {
    // Init packet carries 57 bytes, continuation packets 59 each.
    let mut pkt = [0u8; REPORT];
    pkt[..4].copy_from_slice(&cid);
    pkt[4] = cmd;
    pkt[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(57);
    pkt[7..7 + first].copy_from_slice(&data[..first]);
    dev.write(&pkt)?;
    for (seq, chunk) in data[first..].chunks(59).enumerate() {
        let mut pkt = [0u8; REPORT];
        pkt[..4].copy_from_slice(&cid);
        pkt[4] = seq as u8;
        pkt[5..5 + chunk.len()].copy_from_slice(chunk);
        dev.write(&pkt)?;
    }

    let mut skipped = 0;
    let head = loop {
        let r = dev.read()?;
        let ours = r[..4] == cid && (r[4] == cmd || r[4] == CMD_ERROR) && nonce.is_none_or(|n| r[7..7 + n.len()] == *n);
        if ours {
            break r;
        }
        skipped += 1;
    };
    if head[4] == CMD_ERROR {
        return Err(format!("device answered CTAPHID_ERROR {:#04x}", head[7]).into());
    }
    let total = u16::from_be_bytes([head[5], head[6]]) as usize;
    let mut out = head[7..].to_vec();
    let mut seq = 0u8;
    while out.len() < total {
        let r = dev.read()?;
        if r[..4] != cid {
            skipped += 1;
            continue;
        }
        if r[4] != seq {
            return Err(format!("continuation packet {} where {seq} was expected", r[4]).into());
        }
        out.extend_from_slice(&r[5..]);
        seq += 1;
    }
    out.truncate(total);
    Ok((out, skipped))
}

fn stats(name: &str, mut t: Vec<Duration>) {
    t.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!(
        "{name:<20} n={:<4} min {:>7.2} ms  p50 {:>7.2} ms  p90 {:>7.2} ms  max {:>7.2} ms",
        t.len(),
        ms(t[0]),
        ms(t[t.len() / 2]),
        ms(t[t.len() * 9 / 10]),
        ms(*t.last().unwrap())
    );
}

#[cfg(target_os = "linux")]
mod hid {
    use super::{REPORT, Result};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};

    /// hidraw nodes whose report descriptor starts with Usage Page (FIDO).
    pub fn fido_devices() -> Result<Vec<String>> {
        let mut out = Vec::new();
        for e in fs::read_dir("/sys/class/hidraw")? {
            let e = e?;
            let rd = fs::read(e.path().join("device/report_descriptor")).unwrap_or_default();
            if rd.starts_with(&[0x06, 0xd0, 0xf1]) {
                out.push(format!("/dev/{}", e.file_name().to_string_lossy()));
            }
        }
        out.sort();
        Ok(out)
    }

    pub struct Device(File);

    impl Device {
        pub fn open(path: &str) -> Result<Self> {
            Ok(Device(OpenOptions::new().read(true).write(true).open(path)?))
        }

        pub fn write(&mut self, report: &[u8; REPORT]) -> Result<()> {
            // hidraw: first byte is the report id (0: the device uses none).
            let mut buf = [0u8; REPORT + 1];
            buf[1..].copy_from_slice(report);
            self.0.write_all(&buf)?;
            Ok(())
        }

        pub fn read(&mut self) -> Result<[u8; REPORT]> {
            let mut buf = [0u8; REPORT];
            let n = self.0.read(&mut buf)?;
            if n != REPORT {
                return Err(format!("short HID read of {n} bytes").into());
            }
            Ok(buf)
        }
    }
}

#[cfg(windows)]
mod hid {
    use super::{REPORT, Result};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
    use windows_sys::Win32::Devices::HumanInterfaceDevice::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::core::GUID;

    const FIDO_USAGE_PAGE: u16 = 0xf1d0;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn os_err(what: &str) -> Box<dyn std::error::Error> {
        format!("{what}: {}", std::io::Error::last_os_error()).into()
    }

    fn open_raw(path: &str, access: u32) -> HANDLE {
        unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        }
    }

    /// (usage page, input report length, output report length), readable
    /// without access rights, so it works on FIDO devices even unelevated.
    fn caps(path: &str) -> Option<(u16, u16, u16)> {
        let h = open_raw(path, 0);
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut out = None;
        unsafe {
            let mut pp: PHIDP_PREPARSED_DATA = 0;
            if HidD_GetPreparsedData(h, &mut pp) {
                let mut c: HIDP_CAPS = std::mem::zeroed();
                if HidP_GetCaps(pp, &mut c) == HIDP_STATUS_SUCCESS {
                    out = Some((c.UsagePage, c.InputReportByteLength, c.OutputReportByteLength));
                }
                HidD_FreePreparsedData(pp);
            }
            CloseHandle(h);
        }
        out
    }

    pub fn fido_devices() -> Result<Vec<String>> {
        let mut out = Vec::new();
        unsafe {
            let mut guid: GUID = std::mem::zeroed();
            HidD_GetHidGuid(&mut guid);
            let set = SetupDiGetClassDevsW(&guid, null(), null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if set == INVALID_HANDLE_VALUE as HDEVINFO {
                return Err(os_err("SetupDiGetClassDevsW"));
            }
            for i in 0.. {
                let mut ifd: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
                ifd.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
                if SetupDiEnumDeviceInterfaces(set, null(), &guid, i, &mut ifd) == 0 {
                    break;
                }
                // Detail data: a u32 size then the path; use a u32-aligned buffer.
                let mut buf = vec![0u32; 512];
                let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
                (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
                if SetupDiGetDeviceInterfaceDetailW(set, &ifd, detail, (buf.len() * 4) as u32, null_mut(), null_mut()) == 0 {
                    continue;
                }
                let p = std::ptr::addr_of!((*detail).DevicePath) as *const u16;
                let len = (0..).take_while(|&k| *p.add(k) != 0).count();
                let path = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                if caps(&path).is_some_and(|c| c.0 == FIDO_USAGE_PAGE) {
                    out.push(path);
                }
            }
            SetupDiDestroyDeviceInfoList(set);
        }
        out.sort();
        Ok(out)
    }

    pub struct Device {
        h: HANDLE,
        in_len: usize,
        out_len: usize,
    }

    impl Device {
        pub fn open(path: &str) -> Result<Self> {
            let (_, in_len, out_len) = caps(path).ok_or("cannot read HID capabilities")?;
            let h = open_raw(path, GENERIC_READ | GENERIC_WRITE);
            if h == INVALID_HANDLE_VALUE {
                return Err(os_err("opening the device (FIDO devices need Administrator)"));
            }
            Ok(Device { h, in_len: in_len as usize, out_len: out_len as usize })
        }

        pub fn write(&mut self, report: &[u8; REPORT]) -> Result<()> {
            // Report id byte, then the report, padded to the output report length.
            let mut buf = vec![0u8; self.out_len.max(REPORT + 1)];
            buf[1..=REPORT].copy_from_slice(report);
            let mut n = 0;
            if unsafe { WriteFile(self.h, buf.as_ptr(), buf.len() as u32, &mut n, null_mut()) } == 0 {
                return Err(os_err("WriteFile"));
            }
            Ok(())
        }

        pub fn read(&mut self) -> Result<[u8; REPORT]> {
            let mut buf = vec![0u8; self.in_len.max(REPORT + 1)];
            let mut n = 0;
            if unsafe { ReadFile(self.h, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) } == 0 {
                return Err(os_err("ReadFile"));
            }
            if (n as usize) < REPORT + 1 {
                return Err(format!("short HID read of {n} bytes").into());
            }
            let mut r = [0u8; REPORT];
            r.copy_from_slice(&buf[1..=REPORT]);
            Ok(r)
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.h) };
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod hid {
    use super::{REPORT, Result};
    pub fn fido_devices() -> Result<Vec<String>> {
        Err("fidoping supports Linux and Windows only".into())
    }
    pub struct Device;
    impl Device {
        pub fn open(_: &str) -> Result<Self> {
            unreachable!()
        }
        pub fn write(&mut self, _: &[u8; REPORT]) -> Result<()> {
            unreachable!()
        }
        pub fn read(&mut self) -> Result<[u8; REPORT]> {
            unreachable!()
        }
    }
}
