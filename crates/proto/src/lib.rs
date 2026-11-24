//! usbwire wire protocol.
//!
//! Transport layout (QUIC):
//! - **Control stream** (first bidi stream opened by the client): [`Control`] messages.
//! - **One bidi stream per (device, endpoint)**, opened by the client after `AttachOk`.
//!   The first frame on it is [`EpOpen`]; after that it carries [`EpMsg`] frames.
//!   One stream per endpoint keeps ordering within an endpoint without
//!   head-of-line blocking between endpoints.
//!
//! Every message is one frame: `u32 LE length` + postcard-encoded payload (see [`frame`]).

pub mod frame;

use serde::{Deserialize, Serialize};

/// Protocol version; bump on any incompatible change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Server-local device handle, valid for the lifetime of one plug-in.
pub type DevId = u32;
/// Client-chosen transfer id, unique per endpoint stream.
pub type UrbId = u64;

// ---------------------------------------------------------------------------
// Control stream
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    Hello(Hello),
    HelloOk { version: u16, server_name: String },
    ListDevices,
    DeviceList(Vec<DeviceInfo>),
    Attach { dev: DevId },
    AttachOk(Box<AttachOk>),
    Detach { dev: DevId },
    /// Port reset; the server re-reads descriptors and answers with `AttachOk`.
    Reset { dev: DevId },
    Event { dev: DevId, event: DeviceEvent },
    Error { code: ErrorCode, message: String },
    Ping { nonce: u64 },
    Pong { nonce: u64 },

    // Pairing: an unpaired client may send only `Pair`. See usbwire_net::auth.
    /// client → server: SPAKE2 message keyed by the one-time code.
    Pair { client_name: String, spake: Vec<u8> },
    /// server → client: its SPAKE2 message and key confirmation.
    PairStep { spake: Vec<u8>, confirm: Vec<u8> },
    /// client → server: the client's key confirmation.
    PairConfirm { confirm: Vec<u8> },
    /// server → client: paired; `allowed` lists the devices this client may use.
    PairOk { server_name: String, allowed: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub client_name: String,
    pub caps: Capabilities,
}

/// Optional latency features; the effective set is the intersection of both peers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Server keeps interrupt IN transfers pending and pushes reports unasked.
    pub interrupt_in_push: bool,
    /// Client may complete OUT transfers before the device confirms them.
    pub early_out_ack: bool,
    /// Client answers standard GET_DESCRIPTOR requests from the snapshot.
    pub descriptor_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub dev: DevId,
    pub vid: u16,
    pub pid: u16,
    pub bcd_device: u16,
    pub class: u8,
    pub speed: Speed,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// Already attached by some client.
    pub busy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Speed {
    Low,
    Full,
    High,
    Super,
    SuperPlus,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachOk {
    pub info: DeviceInfo,
    pub descriptors: DescriptorSnapshot,
    pub endpoints: Vec<EndpointInfo>,
    /// Features enabled for this device (policy may disable some per device class).
    pub caps: Capabilities,
}

/// Everything the client needs to enumerate the device without a round trip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorSnapshot {
    /// Raw 18-byte device descriptor.
    pub device: Vec<u8>,
    /// Full configuration descriptors (wTotalLength bytes each), by index.
    pub configs: Vec<Vec<u8>>,
    /// Index of the active configuration in `configs`.
    pub active_config: u8,
    pub strings: Vec<StringDescriptor>,
    pub bos: Option<Vec<u8>>,
    /// HID report descriptors, by interface number.
    pub hid_reports: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringDescriptor {
    pub index: u8,
    pub lang_id: u16,
    /// Raw descriptor bytes (bLength, bDescriptorType, UTF-16LE).
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// bEndpointAddress (bit 7 = IN).
    pub address: u8,
    pub interface: u8,
    pub xfer: XferType,
    pub max_packet: u16,
    pub interval: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceEvent {
    Unplugged,
    Replugged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    VersionMismatch,
    /// Client certificate is not paired with this server.
    NotPaired,
    /// Paired, but not allowed to do this (e.g. device not in its allow list).
    Unauthorized,
    NoSuchDevice,
    Busy,
    Internal,
}

// ---------------------------------------------------------------------------
// Endpoint streams
// ---------------------------------------------------------------------------

/// First frame on an endpoint stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpOpen {
    pub dev: DevId,
    /// bEndpointAddress; 0x00 is the default control pipe.
    pub ep: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpMsg {
    /// client → server. On a push endpoint the first Submit starts polling;
    /// further ones are not sent.
    Submit(Submit),
    /// server → client
    Complete(Complete),
    /// server → client, interrupt IN data the client did not ask for yet
    /// (only with `interrupt_in_push`). `epoch` is the urb id of the Submit
    /// that started polling, so the client can drop reports from an earlier open.
    Push { epoch: UrbId, data: Vec<u8> },
    /// client → server. On a push endpoint: stop polling (the host closed it).
    Cancel { urb: UrbId },
    /// server → client: an OUT that the client already acked early failed.
    /// The client reports `status` on the next transfer on this endpoint.
    DeferredError { urb: UrbId, status: Status },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submit {
    pub urb: UrbId,
    /// Present only on the control pipe.
    pub setup: Option<[u8; 8]>,
    /// IN: bytes requested. OUT: ignored (len of `data`).
    pub length: u32,
    /// OUT payload; empty for IN.
    pub data: Vec<u8>,
    /// The client has already completed this OUT locally (early ack).
    pub acked_early: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Complete {
    pub urb: UrbId,
    pub status: Status,
    pub actual_length: u32,
    /// IN payload; empty for OUT.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Ok,
    Stall,
    Cancelled,
    Timeout,
    Overflow,
    NoDevice,
    /// Platform-specific error code.
    Other(i32),
}

impl Status {
    pub fn is_ok(self) -> bool {
        matches!(self, Status::Ok)
    }
}
