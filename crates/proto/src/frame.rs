//! Length-prefixed framing: `u32 LE payload length` followed by a postcard payload.

use bytes::{Buf, BufMut, BytesMut};
use serde::{Serialize, de::DeserializeOwned};

/// Upper bound for one frame. HID/CCID transfers are tiny; this only guards
/// against a corrupt or hostile peer making us allocate gigabytes.
pub const MAX_FRAME: usize = 1 << 20;

const HEADER: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds limit of {MAX_FRAME}")]
    TooLarge(usize),
    #[error("codec: {0}")]
    Codec(#[from] postcard::Error),
}

/// Append one encoded frame to `out`.
pub fn encode<T: Serialize>(msg: &T, out: &mut BytesMut) -> Result<(), FrameError> {
    let payload = postcard::to_stdvec(msg)?;
    if payload.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(payload.len()));
    }
    out.reserve(HEADER + payload.len());
    out.put_u32_le(payload.len() as u32);
    out.put_slice(&payload);
    Ok(())
}

/// Decode one frame from the front of `buf`, consuming it.
///
/// Returns `Ok(None)` when `buf` does not yet hold a whole frame; call again
/// after reading more bytes.
pub fn decode<T: DeserializeOwned>(buf: &mut BytesMut) -> Result<Option<T>, FrameError> {
    if buf.len() < HEADER {
        return Ok(None);
    }
    let len = u32::from_le_bytes(buf[..HEADER].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    if buf.len() < HEADER + len {
        buf.reserve(HEADER + len - buf.len());
        return Ok(None);
    }
    buf.advance(HEADER);
    let payload = buf.split_to(len);
    Ok(Some(postcard::from_bytes(&payload)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn submit(urb: UrbId, n: usize) -> EpMsg {
        EpMsg::Submit(Submit {
            urb,
            setup: None,
            length: n as u32,
            data: vec![0xAB; n],
            acked_early: true,
        })
    }

    #[test]
    fn roundtrip_many_frames() {
        let mut buf = BytesMut::new();
        let msgs: Vec<EpMsg> = (0..50).map(|i| submit(i, i as usize * 3)).collect();
        for m in &msgs {
            encode(m, &mut buf).unwrap();
        }
        for m in &msgs {
            assert_eq!(decode::<EpMsg>(&mut buf).unwrap().as_ref(), Some(m));
        }
        assert!(decode::<EpMsg>(&mut buf).unwrap().is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frames_byte_by_byte() {
        let msg = Control::AttachOk(Box::new(AttachOk {
            info: DeviceInfo {
                dev: 7,
                vid: 0x1050,
                pid: 0x0407,
                bcd_device: 0x0543,
                class: 0,
                speed: Speed::Full,
                manufacturer: Some("Yubico".into()),
                product: Some("YubiKey OTP+FIDO+CCID".into()),
                serial: None,
                busy: false,
            },
            descriptors: DescriptorSnapshot {
                device: vec![18, 1, 0, 2, 0, 0, 0, 64, 0x50, 0x10, 0x07, 0x04, 0x43, 0x05, 1, 2, 0, 1],
                configs: vec![vec![9, 2, 9, 0, 1, 1, 0, 0x80, 15]],
                ..Default::default()
            },
            endpoints: vec![EndpointInfo {
                address: 0x84,
                interface: 1,
                xfer: XferType::Interrupt,
                max_packet: 64,
                interval: 2,
                stream: false,
            }],
            caps: Capabilities {
                interrupt_in_push: true,
                early_out_ack: true,
                descriptor_cache: true,
                bulk_in_push: true,
                bulk_out_ack: true,
            },
        }));
        let mut wire = BytesMut::new();
        encode(&msg, &mut wire).unwrap();

        let mut rx = BytesMut::new();
        let mut got = None;
        for (i, b) in wire.iter().enumerate() {
            assert!(got.is_none(), "decoded early at byte {i}");
            rx.put_u8(*b);
            got = decode::<Control>(&mut rx).unwrap();
        }
        assert_eq!(got, Some(msg));
    }

    #[test]
    fn rejects_oversized_header() {
        let mut buf = BytesMut::new();
        buf.put_u32_le((MAX_FRAME + 1) as u32);
        assert!(matches!(decode::<EpMsg>(&mut buf), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn hid_report_frame_is_small() {
        // A 64-byte HID report should cost only a few bytes of overhead on the wire.
        let mut buf = BytesMut::new();
        encode(&EpMsg::Push { epoch: 1000, data: vec![0; 64] }, &mut buf).unwrap();
        assert!(buf.len() <= 64 + 10, "frame is {} bytes", buf.len());
    }
}
