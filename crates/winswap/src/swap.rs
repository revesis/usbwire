//! Swap a USB device's driver to the inbox WinUSB and back, without any
//! third-party INF or signing: we install Windows' own `winusb.inf` ("WinUsb
//! Device"), exactly what Device Manager does with "Let me pick from a list".
//!
//! Restore removes the device node and rescans, so PnP ranks drivers afresh;
//! `winusb.inf` does not match the device's hardware IDs, so the original
//! driver (usbccgp for a composite device) wins again.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{addr_of, null, null_mut};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegQueryValueExW, RegSetValueExW,
};

use tracing::{info, warn};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Class GUID of "Universal Serial Bus devices", the class winusb.inf installs into.
const GUID_DEVCLASS_USBDEVICE: &str = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}";
/// Hardware ID of the generic "WinUsb Device" entry in winusb.inf.
const WINUSB_HWID: &str = "USB\\MS_COMP_WINUSB";

pub fn check_instance_id(inst: &str, any_vid: bool) -> Result<()> {
    let up = inst.to_ascii_uppercase();
    if !up.starts_with("USB\\VID_") {
        return Err("instance id must start with USB\\VID_".into());
    }
    if up.contains("&MI_") {
        return Err("pass the composite parent node, not an interface (&MI_xx) node".into());
    }
    if !any_vid && !up.starts_with("USB\\VID_1050&") {
        return Err("refusing non-Yubico device without --any-vid".into());
    }
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn last_error(what: &str) -> Box<dyn std::error::Error + Send + Sync> {
    let code = unsafe { GetLastError() };
    format!("{what} failed: Win32 error {code} ({:#x})", code).into()
}

/// One device opened in its own SetupAPI device-info set.
struct Dev {
    set: HDEVINFO,
    data: SP_DEVINFO_DATA,
}

impl Dev {
    fn open(inst: &str) -> Result<Self> {
        unsafe {
            let set = SetupDiCreateDeviceInfoList(null(), null_mut());
            if set == -1 {
                return Err(last_error("SetupDiCreateDeviceInfoList"));
            }
            let mut data: SP_DEVINFO_DATA = std::mem::zeroed();
            data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            let mut dev = Dev { set, data };
            if SetupDiOpenDeviceInfoW(dev.set, wide(inst).as_ptr(), null_mut(), 0, &mut dev.data) == 0 {
                return Err(last_error("SetupDiOpenDeviceInfoW (is the device plugged in?)"));
            }
            Ok(dev)
        }
    }

    fn prop(&self, prop: u32) -> Option<String> {
        let mut buf = [0u16; 512];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.set,
                &self.data,
                prop,
                null_mut(),
                buf.as_mut_ptr().cast(),
                (buf.len() * 2) as u32,
                null_mut(),
            )
        };
        (ok != 0).then(|| from_wide(&buf))
    }

    /// The device's serial `PortName` (e.g. "COM3"), if it is a COM-port device.
    /// usbser stores it under the device's hardware key (DIREG_DEV); a WinUSB
    /// device has none. Read it while the device is still a serial port so the
    /// same COM number can be reapplied after a restore (which recreates the
    /// node and would otherwise let usbser claim the next free number).
    fn port_name(&self) -> Option<String> {
        unsafe {
            let key: HKEY =
                SetupDiOpenDevRegKey(self.set, &self.data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
            if key.is_null() || key == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut buf = [0u16; 64];
            let mut len = (buf.len() * 2) as u32;
            let r = RegQueryValueExW(
                key,
                wide("PortName").as_ptr(),
                null_mut(),
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            );
            RegCloseKey(key);
            (r == 0).then(|| from_wide(&buf)).filter(|s| !s.is_empty())
        }
    }

    /// Write the device's `PortName` back, so usbser reuses this COM number.
    fn set_port_name(&self, port: &str) -> Result<()> {
        unsafe {
            let key: HKEY = SetupDiOpenDevRegKey(
                self.set,
                &self.data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DEV,
                KEY_SET_VALUE,
            );
            if key.is_null() || key == INVALID_HANDLE_VALUE {
                return Err(last_error("SetupDiOpenDevRegKey(DIREG_DEV, write)"));
            }
            let val = wide(port); // NUL-terminated UTF-16
            let r = RegSetValueExW(
                key,
                wide("PortName").as_ptr(),
                0,
                REG_SZ,
                val.as_ptr().cast(),
                (val.len() * 2) as u32,
            );
            RegCloseKey(key);
            if r != 0 {
                return Err(format!("RegSetValueExW(PortName={port}) failed: {r}").into());
            }
            Ok(())
        }
    }

    fn set_class_guid(&mut self, guid: &str) -> Result<()> {
        let w = wide(guid);
        let ok = unsafe {
            SetupDiSetDeviceRegistryPropertyW(
                self.set,
                &mut self.data,
                SPDRP_CLASSGUID,
                w.as_ptr().cast(),
                (w.len() * 2) as u32,
            )
        };
        if ok == 0 {
            return Err(last_error("SetupDiSetDeviceRegistryPropertyW(CLASSGUID)"));
        }
        Ok(())
    }

    /// Build the class driver list from winusb.inf only and install its
    /// generic "WinUsb Device" entry. Returns Ok(false) if the list held no
    /// usable entry (e.g. filtered out because the device class differs).
    fn install_winusb(&mut self) -> Result<bool> {
        unsafe {
            let mut p: SP_DEVINSTALL_PARAMS_W = std::mem::zeroed();
            p.cbSize = size_of::<SP_DEVINSTALL_PARAMS_W>() as u32;
            if SetupDiGetDeviceInstallParamsW(self.set, &self.data, &mut p) == 0 {
                return Err(last_error("SetupDiGetDeviceInstallParamsW"));
            }
            let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let inf = wide(&format!("{windir}\\INF\\winusb.inf"));
            p.DriverPath = [0; 260];
            p.DriverPath[..inf.len()].copy_from_slice(&inf);
            p.Flags |= DI_ENUMSINGLEINF;
            p.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
            if SetupDiSetDeviceInstallParamsW(self.set, &self.data, &p) == 0 {
                return Err(last_error("SetupDiSetDeviceInstallParamsW"));
            }
            if SetupDiBuildDriverInfoList(self.set, &mut self.data, SPDIT_CLASSDRIVER) == 0 {
                return Err(last_error("SetupDiBuildDriverInfoList"));
            }

            let mut chosen: Option<SP_DRVINFO_DATA_V2_W> = None;
            let mut count = 0;
            for i in 0.. {
                let mut drv: SP_DRVINFO_DATA_V2_W = std::mem::zeroed();
                drv.cbSize = size_of::<SP_DRVINFO_DATA_V2_W>() as u32;
                if SetupDiEnumDriverInfoW(self.set, &self.data, SPDIT_CLASSDRIVER, i, &mut drv) == 0 {
                    if GetLastError() == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    return Err(last_error("SetupDiEnumDriverInfoW"));
                }
                count += 1;
                let hwid = driver_hwid(self.set, &self.data, &drv).unwrap_or_default();
                info!(
                    "  candidate: {:?} by {:?} hwid={hwid}",
                    from_wide(&drv.Description),
                    from_wide(&drv.MfgName)
                );
                if hwid.eq_ignore_ascii_case(WINUSB_HWID) {
                    chosen = Some(drv);
                }
            }
            let Some(mut drv) = chosen else {
                SetupDiDestroyDriverInfoList(self.set, &self.data, SPDIT_CLASSDRIVER);
                info!("  no '{WINUSB_HWID}' entry among {count} candidate(s)");
                return Ok(false);
            };

            if SetupDiSetSelectedDriverW(self.set, &mut self.data, &mut drv) == 0 {
                return Err(last_error("SetupDiSetSelectedDriverW"));
            }
            let mut reboot = 0;
            let ok = DiInstallDevice(
                null_mut(),
                self.set,
                &self.data,
                &drv,
                DIIDFLAG_NOFINISHINSTALLUI,
                &mut reboot,
            );
            let err = (ok == 0).then(|| last_error("DiInstallDevice"));
            SetupDiDestroyDriverInfoList(self.set, &self.data, SPDIT_CLASSDRIVER);
            if let Some(e) = err {
                return Err(e);
            }
            if reboot != 0 {
                warn!("Windows reports a reboot is needed");
            }
            Ok(true)
        }
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.set) };
    }
}

/// First hardware ID of a driver node.
unsafe fn driver_hwid(set: HDEVINFO, data: &SP_DEVINFO_DATA, drv: &SP_DRVINFO_DATA_V2_W) -> Option<String> {
    // Variable-length struct: allocate generously, u64-aligned.
    let mut buf = vec![0u64; 2048];
    let detail = buf.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
    unsafe {
        (*detail).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32;
        let mut need = 0;
        if SetupDiGetDriverInfoDetailW(set, data, drv, detail, (buf.len() * 8) as u32, &mut need) == 0 {
            return None;
        }
        let start = addr_of!((*detail).HardwareID) as *const u16;
        let max = (buf.len() * 8 - (start as usize - buf.as_ptr() as usize)) / 2;
        let s = std::slice::from_raw_parts(start, max);
        Some(from_wide(s))
    }
}

pub fn journal_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    PathBuf::from(base).join("usbwire").join("winswap-journal.tsv")
}

pub fn export(inst: &str) -> Result<()> {
    let mut dev = Dev::open(inst)?;
    let service = dev.prop(SPDRP_SERVICE).unwrap_or_default();
    let class = dev.prop(SPDRP_CLASSGUID).unwrap_or_default();
    let desc = dev.prop(SPDRP_DEVICEDESC).unwrap_or_default();
    // Serial COM port, if any: saved so restore can reapply it instead of letting
    // usbser pick the next free number and make the COM climb on every swap.
    let port = dev.port_name().unwrap_or_default();
    info!("{inst}: {desc:?} service={service} class={class} port={port:?}");
    if service.eq_ignore_ascii_case("winusb") {
        info!("already bound to WinUSB");
        return Ok(());
    }

    // Journal first, so a crash mid-swap can still be restored.
    let jp = journal_path();
    fs::create_dir_all(jp.parent().unwrap())?;
    writeln!(OpenOptions::new().create(true).append(true).open(&jp)?, "{inst}\t{service}\t{class}\t{port}")?;
    info!("journal: {}", jp.display());

    info!("attempt 1: winusb.inf class list as-is");
    let mut done = dev.install_winusb()?;
    if !done {
        info!("attempt 2: set device class to USBDevice, then retry");
        dev.set_class_guid(GUID_DEVCLASS_USBDEVICE)?;
        done = dev.install_winusb()?;
    }
    if !done {
        return Err("winusb.inf offered no WinUsb Device entry; run `restore` to undo the class change".into());
    }
    drop(dev);
    let after = Dev::open(inst)?.prop(SPDRP_SERVICE).unwrap_or_default();
    info!("exported: service is now {after:?}");
    Ok(())
}

pub fn restore(inst: &str) -> Result<()> {
    let before = Dev::open(inst).ok().and_then(|d| d.prop(SPDRP_SERVICE));
    info!("{inst}: service before restore = {before:?}");
    // The COM port saved at export: /remove-device deletes the node (PortName and
    // all), so reapply it afterwards instead of letting usbser pick a new number.
    let saved_port = journal_port(inst);
    run("pnputil", &["/remove-device", inst])?;
    run("pnputil", &["/scan-devices"])?;

    // Give PnP a moment to reinstall the default drivers.
    let mut after = None;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        after = Dev::open(inst).ok().and_then(|d| d.prop(SPDRP_SERVICE));
        if after.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("winusb")) {
            break;
        }
    }
    info!("restored: service is now {after:?}");

    // Reapply the original COM number so it stays stable across swaps.
    if let Some(port) = saved_port.filter(|p| !p.is_empty())
        && after.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("winusb"))
    {
        match Dev::open(inst).and_then(|d| d.set_port_name(&port)) {
            Ok(()) => {
                info!("reapplied COM port {port}; restarting the device to take effect");
                if let Err(e) = run("pnputil", &["/restart-device", inst]) {
                    warn!("restart-device after setting {port}: {e}");
                }
            }
            Err(e) => warn!("could not reapply COM port {port}: {e}"),
        }
    }

    let jp = journal_path();
    if let Ok(text) = fs::read_to_string(&jp) {
        let rest: String = text
            .lines()
            .filter(|l| !l.split('\t').next().unwrap_or("").eq_ignore_ascii_case(inst))
            .map(|l| format!("{l}\n"))
            .collect();
        fs::write(&jp, rest)?;
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    info!("> {cmd} {}", args.join(" "));
    let out = Command::new(cmd).args(args).output()?;
    info!("{}", String::from_utf8_lossy(&out.stdout).trim());
    if !out.status.success() {
        return Err(format!("{cmd} exited with {}", out.status).into());
    }
    Ok(())
}

/// Instance ids still recorded as exported: left over from a crash if the
/// server is not running. Restore them on startup.
pub fn journal_entries() -> Vec<String> {
    fs::read_to_string(journal_path())
        .map(|t| t.lines().filter_map(|l| l.split('\t').next()).filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

/// The serial COM port recorded for `inst` in the swap journal (column 4), if any.
fn journal_port(inst: &str) -> Option<String> {
    let text = fs::read_to_string(journal_path()).ok()?;
    text.lines()
        .find(|l| l.split('\t').next().unwrap_or("").eq_ignore_ascii_case(inst))
        .and_then(|l| l.split('\t').nth(3))
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// The driver service currently bound to a device node, if it is present.
pub fn current_service(inst: &str) -> Option<String> {
    Dev::open(inst).ok().and_then(|d| d.prop(SPDRP_SERVICE))
}

/// Instance ids of a device's ancestors, nearest first, up to the root.
pub fn ancestors(inst: &str) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let mut node = 0u32;
        if CM_Locate_DevNodeW(&mut node, wide(inst).as_ptr(), CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS {
            return out;
        }
        let mut parent = 0u32;
        while CM_Get_Parent(&mut parent, node, 0) == CR_SUCCESS {
            let mut buf = [0u16; 512];
            if CM_Get_Device_IDW(parent, buf.as_mut_ptr(), buf.len() as u32, 0) != CR_SUCCESS {
                break;
            }
            out.push(from_wide(&buf));
            node = parent;
        }
    }
    out
}

/// True if the device hangs off a USB/IP virtual host controller
/// (usbip-win2), i.e. it is a remote device attached to this machine. The
/// server must never export or swap those: it would loop a device back
/// through itself.
pub fn is_usbip_virtual(inst: &str) -> bool {
    ancestors(inst).iter().any(|a| {
        a.to_ascii_lowercase().contains("usbip")
            || current_service(a).is_some_and(|s| s.to_ascii_lowercase().contains("usbip"))
    })
}
