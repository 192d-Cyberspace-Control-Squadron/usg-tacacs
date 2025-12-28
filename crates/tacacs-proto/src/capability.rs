// SPDX-License-Identifier: AGPL-3.0-only
//! Vendor-specific capability/keepalive packet helper (non-standard).

use crate::header::Header;
use crate::{TYPE_CAPABILITY, VERSION};
use anyhow::{Result, ensure};
use bytes::{BufMut, BytesMut};

pub const CAPABILITY_FLAG_REQUEST: u8 = 0x01;
pub const CAPABILITY_FLAG_RESPONSE: u8 = 0x02;

#[derive(Debug, Clone, Copy)]
pub struct CapabilityFlags(pub u32);

impl CapabilityFlags {
    pub fn single_connect(self) -> bool {
        self.0 & 0x1 != 0
    }
    pub fn keepalive(self) -> bool {
        self.0 & 0x2 != 0
    }
    pub fn with_single_connect(mut self) -> Self {
        self.0 |= 0x1;
        self
    }
    pub fn with_keepalive(mut self) -> Self {
        self.0 |= 0x2;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub header: Header,
    pub version: u8,
    pub flags: u8,
    pub vendor: u16,
    pub capabilities: CapabilityFlags,
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

pub fn parse_capability_body(header: Header, body: &[u8]) -> Result<Capability> {
    ensure!(body.len() >= 8, "capability body too short");
    let version = body[0];
    let flags = body[1];
    let vendor = u16::from_be_bytes([body[2], body[3]]);
    let caps = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let mut cursor = 8;
    let mut tlvs = Vec::new();
    while cursor + 2 <= body.len() {
        let t = body[cursor];
        let l = body[cursor + 1] as usize;
        cursor += 2;
        ensure!(cursor + l <= body.len(), "capability TLV truncated");
        tlvs.push((t, body[cursor..cursor + l].to_vec()));
        cursor += l;
    }
    Ok(Capability {
        header,
        version,
        flags,
        vendor,
        capabilities: CapabilityFlags(caps),
        tlvs,
    })
}

pub fn encode_capability(cap: &Capability) -> Result<Vec<u8>> {
    ensure!(
        cap.header.packet_type == TYPE_CAPABILITY,
        "capability header type invalid"
    );
    let mut buf = BytesMut::new();
    buf.put_u8(cap.version);
    buf.put_u8(cap.flags);
    buf.put_u16(cap.vendor);
    buf.put_u32(cap.capabilities.0);
    for (t, v) in &cap.tlvs {
        ensure!(v.len() <= u8::MAX as usize, "capability TLV too long");
        buf.put_u8(*t);
        buf.put_u8(v.len() as u8);
        buf.extend_from_slice(v);
    }
    Ok(buf.to_vec())
}

pub fn capability_request(
    session_id: u32,
    vendor: u16,
    capabilities: CapabilityFlags,
) -> Capability {
    Capability {
        header: Header {
            version: VERSION,
            packet_type: TYPE_CAPABILITY,
            seq_no: 1,
            flags: 0,
            session_id,
            length: 0,
        },
        version: 1,
        flags: CAPABILITY_FLAG_REQUEST,
        vendor,
        capabilities,
        tlvs: Vec::new(),
    }
}
