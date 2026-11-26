//! Device discovery, ownership, opening, and the descriptor snapshot.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use nusb::MaybeFuture;
use nusb::descriptors::TransferType;
use nusb::transfer::{ControlIn, ControlType, Recipient, TransferError};
use tracing::{debug, info, warn};
use usbwire_net::quinn;
use usbwire_proto::{
    AttachOk, Capabilities, DescriptorSnapshot, DevId, DeviceInfo, EndpointInfo, ErrorCode, Speed,
    StringDescriptor, XferType,
};

use crate::state::{self, State};

pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// USB CDC data-interface class; its bulk endpoints carry a byte stream.
const CDC_DATA_CLASS: u8 = 0x0a;

/// An attach refused for a reason the client should see.
#[derive(Debug, thiserror::Error)]
#[error("{1}")]
pub struct Refused(pub ErrorCode, pub String);

fn refuse(code: ErrorCode, msg: impl Into<String>) -> anyhow::Error {
    Refused(code, msg.into()).into()
}

/// Stable identity of a physical device: survives the driver swap, which
/// re-enumerates the device under a new handle. Enumeration is not used on
/// Android (the device arrives as an fd via `--from-fd`).
#[cfg(not(target_os = "android"))]
fn device_key(d: &nusb::DeviceInfo) -> String {
    #[cfg(windows)]
    {
        d.instance_id().to_string_lossy().into_owned()
    }
    #[cfg(not(windows))]
    {
        format!("{}-{:?}", d.bus_id(), d.port_chain())
    }
}

struct Holder {
    fingerprint: String,
    conn: quinn::Connection,
}

/// A single device handed to us as an already-open usbdevfs fd (Android
/// UsbManager / Linux portal), served without enumeration. Its DevId is fixed
/// at 0 and its registry key at "fd0".
struct Pinned {
    device: nusb::Device,
    info: DeviceInfo,
    key: String,
}

/// Devices, who holds them, and which ones we bound to WinUSB.
pub struct Registry {
    state: Arc<State>,
    /// DevId = index into this list.
    keys: Mutex<Vec<String>>,
    holders: Mutex<HashMap<String, Holder>>,
    /// Devices we swapped to WinUSB: key -> (instance id, release generation).
    swapped: Mutex<HashMap<String, (String, u64)>>,
    /// Set in `--from-fd` mode: the one device we export, already open.
    pinned: Option<Pinned>,
}

impl Registry {
    pub fn new(state: Arc<State>) -> Arc<Self> {
        Arc::new(Registry {
            state,
            keys: Default::default(),
            holders: Default::default(),
            swapped: Default::default(),
            pinned: None,
        })
    }

    /// `--from-fd` mode: adopt an already-open usbdevfs fd and export just that
    /// device. nusb reads descriptors straight from the fd (no sysfs, no root),
    /// which is exactly what Android's `UsbDeviceConnection.getFileDescriptor()`
    /// hands us after the user grants USB permission.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub async fn from_fd(state: Arc<State>, raw: i32) -> Result<Arc<Self>> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let device =
            nusb::Device::from_fd(owned).await.context("opening USB device from the provided fd")?;
        let dd = device.device_descriptor();
        let info = DeviceInfo {
            dev: 0,
            vid: dd.vendor_id(),
            pid: dd.product_id(),
            bcd_device: dd.device_version(),
            class: dd.class(),
            speed: match device.speed() {
                Some(nusb::Speed::Low) => Speed::Low,
                Some(nusb::Speed::Full) => Speed::Full,
                Some(nusb::Speed::High) => Speed::High,
                Some(nusb::Speed::Super) => Speed::Super,
                Some(nusb::Speed::SuperPlus) => Speed::SuperPlus,
                _ => Speed::Unknown,
            },
            manufacturer: None,
            product: None,
            serial: None,
            busy: false,
        };
        info!(
            "from-fd: exporting {:04x}:{:04x} (class {:02x}) from fd {raw}",
            info.vid, info.pid, info.class
        );
        Ok(Arc::new(Registry {
            state,
            keys: Mutex::new(vec!["fd0".to_string()]),
            holders: Default::default(),
            swapped: Default::default(),
            pinned: Some(Pinned { device, info, key: "fd0".to_string() }),
        }))
    }

    fn id_for(&self, key: &str) -> DevId {
        let mut keys = self.keys.lock().unwrap();
        match keys.iter().position(|k| k == key) {
            Some(i) => i as DevId,
            None => {
                keys.push(key.to_string());
                (keys.len() - 1) as DevId
            }
        }
    }

    /// Devices the server offers (config `export`) that this client may use.
    #[cfg(not(target_os = "android"))]
    fn offered(&self, d: &nusb::DeviceInfo, allow: &[String]) -> Result<bool> {
        let cfg = self.state.config()?;
        Ok(d.class() != 0x09
            && !is_remote(d)
            && state::any_matches(&cfg.export, d.vendor_id(), d.product_id())
            && state::any_matches(allow, d.vendor_id(), d.product_id()))
    }

    /// Whether the pinned device's vid/pid is both exported by the server and
    /// allowed for this client. Same policy as `offered`, minus enumeration.
    fn pinned_offered(&self, info: &DeviceInfo, allow: &[String]) -> Result<bool> {
        let cfg = self.state.config()?;
        Ok(state::any_matches(&cfg.export, info.vid, info.pid)
            && state::any_matches(allow, info.vid, info.pid))
    }

    pub fn list(&self, allow: &[String]) -> Result<Vec<DeviceInfo>> {
        if let Some(p) = &self.pinned {
            if !self.pinned_offered(&p.info, allow)? {
                return Ok(Vec::new());
            }
            let mut info = p.info.clone();
            info.busy = self.holders.lock().unwrap().contains_key(&p.key);
            return Ok(vec![info]);
        }
        #[cfg(target_os = "android")]
        {
            let _ = allow;
            return Ok(Vec::new());
        }
        #[cfg(not(target_os = "android"))]
        {
            let holders = self.holders.lock().unwrap();
            let mut out = Vec::new();
            for d in nusb::list_devices().wait()? {
                if self.offered(&d, allow)? {
                    let key = device_key(&d);
                    let mut info = device_info(self.id_for(&key), &d);
                    info.busy = holders.contains_key(&key);
                    out.push(info);
                }
            }
            Ok(out)
        }
    }

    #[cfg(not(target_os = "android"))]
    fn find(&self, key: &str) -> Result<Option<nusb::DeviceInfo>> {
        Ok(nusb::list_devices().wait()?.find(|d| device_key(d) == key))
    }

    /// Take ownership of the device for this connection. A stale connection of
    /// the same client (e.g. it restarted without closing) is closed and its
    /// claim taken over; another client's claim is refused.
    async fn acquire(self: &Arc<Self>, key: &str, fingerprint: &str, conn: &quinn::Connection) -> Result<Lease> {
        for _ in 0..50 {
            {
                let mut holders = self.holders.lock().unwrap();
                match holders.get(key) {
                    None => {
                        holders.insert(key.into(), Holder { fingerprint: fingerprint.into(), conn: conn.clone() });
                        return Ok(Lease { registry: self.clone(), key: key.into(), conn_id: conn.stable_id() });
                    }
                    Some(h) if h.conn.stable_id() == conn.stable_id() => {
                        return Err(refuse(ErrorCode::Busy, "already attached on this connection"));
                    }
                    Some(h) if h.fingerprint == fingerprint => {
                        info!("closing this client's previous session to take over the device");
                        h.conn.close(usbwire_net::CLOSE_SUPERSEDED.into(), b"superseded by a new session");
                    }
                    Some(_) => return Err(refuse(ErrorCode::Busy, "device is in use by another client")),
                }
            }
            // Wait for the old session to release the device.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(refuse(ErrorCode::Busy, "previous session did not release the device"))
    }

    pub async fn attach(
        self: &Arc<Self>,
        dev: DevId,
        client: &state::Client,
        conn: &quinn::Connection,
    ) -> Result<OpenDevice> {
        if let Some(p) = &self.pinned {
            if dev != 0 {
                return Err(refuse(ErrorCode::NoSuchDevice, "unknown device id (list devices first)"));
            }
            if !self.pinned_offered(&p.info, &client.allow)? {
                return Err(refuse(ErrorCode::Unauthorized, "this client is not allowed to use the device"));
            }
            let lease = self.acquire(&p.key, &client.fingerprint, conn).await?;
            // Device is Arc-backed; the clone shares the same open fd and lets a
            // reconnecting client re-claim interfaces the previous lease dropped.
            let open = OpenDevice::from_open_device(dev, p.device.clone(), p.info.clone(), lease).await?;
            return Ok(open);
        }
        #[cfg(target_os = "android")]
        {
            let _ = (dev, client, conn);
            Err(refuse(ErrorCode::NoSuchDevice, "no device (server was started without --from-fd)"))
        }
        #[cfg(not(target_os = "android"))]
        {
            let key = self.keys.lock().unwrap().get(dev as usize).cloned();
            let key = key.ok_or_else(|| refuse(ErrorCode::NoSuchDevice, "unknown device id (list devices first)"))?;
            let info = self.find(&key)?.ok_or_else(|| refuse(ErrorCode::NoSuchDevice, "device is no longer present"))?;
            if !self.offered(&info, &client.allow)? {
                return Err(refuse(ErrorCode::Unauthorized, "this client is not allowed to use the device"));
            }
            let lease = self.acquire(&key, &client.fingerprint, conn).await?;

            #[cfg(windows)]
            let info = self.ensure_winusb(&key, info).await?;
            let open = OpenDevice::open(dev, &info, lease).await?;
            Ok(open)
        }
    }

    /// Windows: bind the device to WinUSB if it isn't yet, and wait for it to
    /// come back under the new driver.
    #[cfg(windows)]
    async fn ensure_winusb(&self, key: &str, info: nusb::DeviceInfo) -> Result<nusb::DeviceInfo> {
        if info.driver().is_some_and(|d| d.eq_ignore_ascii_case("winusb")) {
            return Ok(info);
        }
        let inst = info.instance_id().to_string_lossy().into_owned();
        info!(%inst, driver = ?info.driver(), "binding device to WinUSB");
        {
            let inst = inst.clone();
            tokio::task::spawn_blocking(move || winswap::swap::export(&inst))
                .await?
                .map_err(|e| anyhow!("driver swap failed: {e}"))?;
        }
        self.swapped.lock().unwrap().entry(key.into()).or_insert((inst, 0));
        for _ in 0..100 {
            if let Some(d) = self.find(key)?
                && d.driver().is_some_and(|d| d.eq_ignore_ascii_case("winusb"))
            {
                // Give the new driver stack a moment to settle before opening.
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(d);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow!("device did not reappear with WinUSB after the driver swap"))
    }

    fn release(self: &Arc<Self>, key: &str, conn_id: usize) {
        {
            let mut holders = self.holders.lock().unwrap();
            if holders.get(key).is_some_and(|h| h.conn.stable_id() == conn_id) {
                holders.remove(key);
            }
        }
        let cfg = match self.state.config() {
            Ok(c) => c,
            Err(e) => return warn!("reading config: {e:#}"),
        };
        if !cfg.restore_on_release {
            return;
        }
        let generation = {
            let mut swapped = self.swapped.lock().unwrap();
            let Some(entry) = swapped.get_mut(key) else { return };
            entry.1 += 1;
            entry.1
        };
        // Restore after a grace period unless someone attached again meanwhile.
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let (me, key) = (self.clone(), key.to_string());
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(cfg.restore_delay_secs)).await;
            if me.holders.lock().unwrap().contains_key(&key) {
                return;
            }
            let inst = {
                let mut swapped = me.swapped.lock().unwrap();
                match swapped.get(&key) {
                    Some((inst, g)) if *g == generation => {
                        let inst = inst.clone();
                        swapped.remove(&key);
                        inst
                    }
                    _ => return,
                }
            };
            restore_blocking(inst).await;
        });
    }

    /// Give every device we swapped back to its drivers (shutdown).
    pub async fn restore_all(&self) {
        let all: Vec<String> = self.swapped.lock().unwrap().drain().map(|(_, (inst, _))| inst).collect();
        for inst in all {
            restore_blocking(inst).await;
        }
    }
}

#[cfg(windows)]
pub async fn restore_blocking(inst: String) {
    info!(%inst, "restoring the device's own drivers");
    match tokio::task::spawn_blocking(move || winswap::swap::restore(&inst).map_err(|e| e.to_string())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("driver restore failed: {e}"),
        Err(e) => warn!("driver restore task: {e}"),
    }
}

#[cfg(not(windows))]
pub async fn restore_blocking(_inst: String) {}

/// Windows: restore devices a crashed server left bound to WinUSB.
pub async fn recover_from_journal() {
    #[cfg(windows)]
    for inst in winswap::swap::journal_entries() {
        warn!(%inst, "found in the swap journal from an earlier run; restoring");
        restore_blocking(inst).await;
    }
}

/// Releases the device when the attachment ends (last field of OpenDevice,
/// so it drops after the device handles).
pub struct Lease {
    registry: Arc<Registry>,
    key: String,
    conn_id: usize,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.registry.release(&self.key, self.conn_id);
    }
}

/// A device that is itself attached over USB/IP (usbip-win2 on this machine).
/// Exporting it would loop it back through the server.
#[cfg(not(target_os = "android"))]
fn is_remote(d: &nusb::DeviceInfo) -> bool {
    #[cfg(windows)]
    {
        winswap::swap::is_usbip_virtual(&d.instance_id().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        // Linux: vhci_hcd root hubs.
        let bus = std::path::Path::new("/sys/bus/usb/devices").join(format!("usb{}", d.busnum()));
        std::fs::read_link(bus.join("..").canonicalize().unwrap_or_default().join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().starts_with("vhci_hcd")))
            .unwrap_or(false)
    }
}

#[cfg(not(target_os = "android"))]
fn device_info(dev: DevId, d: &nusb::DeviceInfo) -> DeviceInfo {
    DeviceInfo {
        dev,
        vid: d.vendor_id(),
        pid: d.product_id(),
        bcd_device: d.device_version(),
        class: d.class(),
        speed: match d.speed() {
            Some(nusb::Speed::Low) => Speed::Low,
            Some(nusb::Speed::Full) => Speed::Full,
            Some(nusb::Speed::High) => Speed::High,
            Some(nusb::Speed::Super) => Speed::Super,
            Some(nusb::Speed::SuperPlus) => Speed::SuperPlus,
            _ => Speed::Unknown,
        },
        manufacturer: d.manufacturer_string().map(Into::into),
        product: d.product_string().map(Into::into),
        serial: d.serial_number().map(Into::into),
        busy: false,
    }
}

pub struct OpenDevice {
    pub info: DeviceInfo,
    /// Keeps the device open for as long as we hold its interfaces.
    _device: nusb::Device,
    pub interfaces: BTreeMap<u8, nusb::Interface>,
    pub endpoints: HashMap<u8, EndpointInfo>,
    pub config_value: u8,
    pub snapshot: DescriptorSnapshot,
    /// Endpoint tasks that are running, by address: where a CLEAR_FEATURE
    /// (ENDPOINT_HALT) goes, since the task owns the endpoint.
    pub halt_requests: std::sync::Mutex<HashMap<u8, crate::endpoint::HaltSender>>,
    /// Last: released after the device handles are closed.
    _lease: Lease,
}

impl OpenDevice {
    #[cfg(not(target_os = "android"))]
    async fn open(dev: DevId, d: &nusb::DeviceInfo, lease: Lease) -> Result<Self> {
        let device = d.open().await?;
        Self::from_open_device(dev, device, device_info(dev, d), lease).await
    }

    /// Build from an already-open device. The enumeration path opens via a
    /// `DeviceInfo`; the `--from-fd` path passes a device opened from an
    /// external usbdevfs fd. `info` is its descriptor-derived wire identity.
    async fn from_open_device(
        dev: DevId,
        device: nusb::Device,
        info: DeviceInfo,
        lease: Lease,
    ) -> Result<Self> {
        let cfg = device.active_configuration()?;
        let config_value = cfg.configuration_value();

        let mut interfaces = BTreeMap::new();
        let mut endpoints = HashMap::new();
        for intf in cfg.interfaces() {
            let n = intf.interface_number();
            #[cfg(target_os = "linux")]
            let claimed = device.detach_and_claim_interface(n).await;
            #[cfg(not(target_os = "linux"))]
            let claimed = device.claim_interface(n).await;
            interfaces.insert(n, claimed.with_context(|| format!("claiming interface {n}"))?);

            // Endpoints of every alt setting; streams are opened per address.
            for alt in intf.alt_settings() {
                // CDC-ACM data interface (class 0x0A): its bulk endpoints are a
                // byte stream, so bulk IN may be pushed and bulk OUT early-acked.
                let stream = alt.class() == CDC_DATA_CLASS;
                for ep in alt.endpoints() {
                    endpoints.entry(ep.address()).or_insert(EndpointInfo {
                        address: ep.address(),
                        interface: n,
                        xfer: match ep.transfer_type() {
                            TransferType::Control => XferType::Control,
                            TransferType::Isochronous => XferType::Isochronous,
                            TransferType::Bulk => XferType::Bulk,
                            TransferType::Interrupt => XferType::Interrupt,
                        },
                        max_packet: ep.max_packet_size() as u16,
                        interval: ep.interval(),
                        stream,
                    });
                }
            }
        }
        let any = interfaces.values().next().cloned().context("device has no interfaces")?;
        let snapshot = snapshot(&any, &interfaces, config_value).await?;
        info!(
            dev,
            "opened {:04x}:{:04x}: {} interfaces, {} endpoints, snapshot {} strings, {} HID reports",
            info.vid,
            info.pid,
            interfaces.len(),
            endpoints.len(),
            snapshot.strings.len(),
            snapshot.hid_reports.len()
        );
        Ok(OpenDevice {
            info,
            _device: device,
            interfaces,
            endpoints,
            config_value,
            snapshot,
            halt_requests: Default::default(),
            _lease: lease,
        })
    }

    pub fn attach_ok(&self, mut caps: Capabilities) -> AttachOk {
        let mut endpoints: Vec<_> = self.endpoints.values().copied().collect();
        endpoints.sort_by_key(|e| e.address);
        // Bulk push / early-ack are offered only for CDC-ACM stream endpoints.
        if !endpoints.iter().any(|e| e.stream) {
            caps.bulk_in_push = false;
            caps.bulk_out_ack = false;
        }
        AttachOk {
            info: self.info.clone(),
            descriptors: self.snapshot.clone(),
            endpoints,
            caps,
        }
    }

    /// Interface handle to send a control request through.
    pub fn interface_for(&self, recipient: u8, index: u16) -> &nusb::Interface {
        let by_number = |n: u8| self.interfaces.get(&n);
        match recipient {
            1 => by_number(index as u8),
            2 => self.endpoints.get(&(index as u8)).and_then(|e| by_number(e.interface)),
            _ => None,
        }
        .unwrap_or_else(|| self.interfaces.values().next().unwrap())
    }
}

pub fn control_type(bm_request_type: u8) -> Option<ControlType> {
    match (bm_request_type >> 5) & 3 {
        0 => Some(ControlType::Standard),
        1 => Some(ControlType::Class),
        2 => Some(ControlType::Vendor),
        _ => None,
    }
}

pub fn recipient(bm_request_type: u8) -> Option<Recipient> {
    match bm_request_type & 0x1f {
        0 => Some(Recipient::Device),
        1 => Some(Recipient::Interface),
        2 => Some(Recipient::Endpoint),
        3 => Some(Recipient::Other),
        _ => None,
    }
}

async fn get_descriptor(
    intf: &nusb::Interface,
    recipient: Recipient,
    ty: u8,
    index: u8,
    w_index: u16,
    len: u16,
) -> Result<Vec<u8>, TransferError> {
    intf.control_in(
        ControlIn {
            control_type: ControlType::Standard,
            recipient,
            request: 0x06,
            value: (ty as u16) << 8 | index as u16,
            index: w_index,
            length: len,
        },
        CONTROL_TIMEOUT,
    )
    .await
}

/// Read every descriptor the host will ask for during enumeration.
async fn snapshot(
    intf: &nusb::Interface,
    interfaces: &BTreeMap<u8, nusb::Interface>,
    config_value: u8,
) -> Result<DescriptorSnapshot> {
    let dev = Recipient::Device;
    let device = get_descriptor(intf, dev, 0x01, 0, 0, 18).await?;
    if device.len() < 18 {
        return Err(anyhow!("short device descriptor"));
    }
    let bcd_usb = u16::from_le_bytes([device[2], device[3]]);
    let num_configs = device[17];

    let mut configs = Vec::new();
    let mut active_config = 0;
    for i in 0..num_configs {
        let head = get_descriptor(intf, dev, 0x02, i, 0, 9).await?;
        let total = u16::from_le_bytes([head[2], head[3]]);
        let full = get_descriptor(intf, dev, 0x02, i, 0, total).await?;
        if full.get(5) == Some(&config_value) {
            active_config = i;
        }
        configs.push(full);
    }

    // String indices referenced from device, config and interface descriptors.
    let mut idx: Vec<u8> = vec![device[14], device[15], device[16]];
    let mut hid_ifaces = Vec::new();
    for cfg in &configs {
        idx.push(cfg[6]);
        let mut off = 0;
        while off + 2 <= cfg.len() && cfg[off] >= 2 {
            if cfg[off + 1] == 0x04 && off + 9 <= cfg.len() {
                idx.push(cfg[off + 8]);
                if cfg[off + 5] == 0x03 {
                    hid_ifaces.push(cfg[off + 2]);
                }
            }
            off += cfg[off] as usize;
        }
    }
    idx.retain(|&i| i != 0);
    idx.sort_unstable();
    idx.dedup();

    let mut strings = Vec::new();
    if let Ok(langs) = get_descriptor(intf, dev, 0x03, 0, 0, 255).await {
        let lang_ids: Vec<u16> =
            langs.get(2..).unwrap_or(&[]).as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        strings.push(StringDescriptor { index: 0, lang_id: 0, raw: langs });
        for &lang_id in &lang_ids {
            for &index in &idx {
                match get_descriptor(intf, dev, 0x03, index, lang_id, 255).await {
                    Ok(raw) => strings.push(StringDescriptor { index, lang_id, raw }),
                    Err(e) => debug!(index, lang_id, "string descriptor: {e}"),
                }
            }
        }
    }

    let mut hid_reports = Vec::new();
    hid_ifaces.sort_unstable();
    hid_ifaces.dedup();
    for n in hid_ifaces {
        let Some(i) = interfaces.get(&n) else { continue };
        match get_descriptor(i, Recipient::Interface, 0x22, 0, n as u16, 4096).await {
            Ok(r) => hid_reports.push((n, r)),
            Err(e) => debug!(interface = n, "HID report descriptor: {e}"),
        }
    }

    let bos = if bcd_usb >= 0x0201 {
        match get_descriptor(intf, dev, 0x0f, 0, 0, 5).await {
            Ok(h) if h.len() >= 5 => {
                let total = u16::from_le_bytes([h[2], h[3]]);
                get_descriptor(intf, dev, 0x0f, 0, 0, total).await.ok()
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(DescriptorSnapshot { device, configs, active_config, strings, bos, hid_reports })
}

/// Map nusb's result onto the wire status.
pub fn status(r: Result<(), TransferError>) -> usbwire_proto::Status {
    use usbwire_proto::Status;
    match r {
        Ok(()) => Status::Ok,
        Err(TransferError::Cancelled) => Status::Cancelled,
        Err(TransferError::Stall) => Status::Stall,
        Err(TransferError::Disconnected) => Status::NoDevice,
        Err(TransferError::Fault) => Status::Other(-71),           // EPROTO
        Err(TransferError::InvalidArgument) => Status::Other(-22), // EINVAL
        Err(TransferError::Unknown(e)) => Status::Other(e as i32),
    }
}
