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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Header;

    fn make_capability_header(session_id: u32, length: u32) -> Header {
        Header {
            version: VERSION,
            packet_type: TYPE_CAPABILITY,
            seq_no: 1,
            flags: 0,
            session_id,
            length,
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let cap = capability_request(0xdead_beef, 0x0009, CapabilityFlags(0x03));
        let body = encode_capability(&cap).expect("encode");
        let header = make_capability_header(cap.header.session_id, body.len() as u32);
        let parsed = parse_capability_body(header, &body).expect("parse");
        assert_eq!(parsed.version, cap.version);
        assert_eq!(parsed.flags, cap.flags);
        assert_eq!(parsed.vendor, cap.vendor);
        assert_eq!(parsed.capabilities.0, cap.capabilities.0);
    }

    // ==================== CapabilityFlags Tests ====================

    #[test]
    fn capability_flags_default() {
        let flags = CapabilityFlags(0);
        assert!(!flags.single_connect());
        assert!(!flags.keepalive());
    }

    #[test]
    fn capability_flags_single_connect() {
        let flags = CapabilityFlags(0x1);
        assert!(flags.single_connect());
        assert!(!flags.keepalive());
    }

    #[test]
    fn capability_flags_keepalive() {
        let flags = CapabilityFlags(0x2);
        assert!(!flags.single_connect());
        assert!(flags.keepalive());
    }

    #[test]
    fn capability_flags_both() {
        let flags = CapabilityFlags(0x3);
        assert!(flags.single_connect());
        assert!(flags.keepalive());
    }

    #[test]
    fn capability_flags_with_single_connect() {
        let flags = CapabilityFlags(0).with_single_connect();
        assert!(flags.single_connect());
        assert!(!flags.keepalive());
        assert_eq!(flags.0, 0x1);
    }

    #[test]
    fn capability_flags_with_keepalive() {
        let flags = CapabilityFlags(0).with_keepalive();
        assert!(!flags.single_connect());
        assert!(flags.keepalive());
        assert_eq!(flags.0, 0x2);
    }

    #[test]
    fn capability_flags_chain_builders() {
        let flags = CapabilityFlags(0).with_single_connect().with_keepalive();
        assert!(flags.single_connect());
        assert!(flags.keepalive());
        assert_eq!(flags.0, 0x3);
    }

    #[test]
    fn capability_flags_copy() {
        let flags = CapabilityFlags(0x03);
        let copied = flags;
        assert_eq!(copied.0, flags.0);
    }

    // ==================== capability_request Tests ====================

    #[test]
    fn capability_request_creates_valid_header() {
        let cap = capability_request(0x12345678, 0x0009, CapabilityFlags(0x03));

        assert_eq!(cap.header.session_id, 0x12345678);
        assert_eq!(cap.header.packet_type, TYPE_CAPABILITY);
        assert_eq!(cap.header.seq_no, 1);
        assert_eq!(cap.header.version, VERSION);
        assert_eq!(cap.header.flags, 0);
    }

    #[test]
    fn capability_request_sets_fields() {
        let cap = capability_request(123, 0x1234, CapabilityFlags(0x05));

        assert_eq!(cap.version, 1);
        assert_eq!(cap.flags, CAPABILITY_FLAG_REQUEST);
        assert_eq!(cap.vendor, 0x1234);
        assert_eq!(cap.capabilities.0, 0x05);
        assert!(cap.tlvs.is_empty());
    }

    // ==================== parse_capability_body Tests ====================

    #[test]
    fn parse_capability_body_minimal() {
        let header = make_capability_header(123, 8);
        let body = vec![
            0x01, // version
            0x02, // flags
            0x00, 0x09, // vendor
            0x00, 0x00, 0x00, 0x03, // capabilities
        ];

        let cap = parse_capability_body(header, &body).unwrap();
        assert_eq!(cap.version, 1);
        assert_eq!(cap.flags, 2);
        assert_eq!(cap.vendor, 9);
        assert_eq!(cap.capabilities.0, 3);
        assert!(cap.tlvs.is_empty());
    }

    #[test]
    fn parse_capability_body_with_tlvs() {
        let header = make_capability_header(123, 14);
        let mut body = vec![
            0x01, // version
            0x01, // flags
            0x00, 0x09, // vendor
            0x00, 0x00, 0x00, 0x01, // capabilities
        ];
        // Add TLV: type=1, length=4, value="test"
        body.push(0x01);
        body.push(0x04);
        body.extend_from_slice(b"test");

        let cap = parse_capability_body(header, &body).unwrap();
        assert_eq!(cap.tlvs.len(), 1);
        assert_eq!(cap.tlvs[0].0, 1);
        assert_eq!(cap.tlvs[0].1, b"test".to_vec());
    }

    #[test]
    fn parse_capability_body_multiple_tlvs() {
        let header = make_capability_header(123, 18);
        let mut body = vec![
            0x01, // version
            0x01, // flags
            0x00, 0x09, // vendor
            0x00, 0x00, 0x00, 0x01, // capabilities
        ];
        // TLV 1: type=1, length=2, value="ab"
        body.push(0x01);
        body.push(0x02);
        body.extend_from_slice(b"ab");
        // TLV 2: type=2, length=2, value="cd"
        body.push(0x02);
        body.push(0x02);
        body.extend_from_slice(b"cd");

        let cap = parse_capability_body(header, &body).unwrap();
        assert_eq!(cap.tlvs.len(), 2);
        assert_eq!(cap.tlvs[0], (1, b"ab".to_vec()));
        assert_eq!(cap.tlvs[1], (2, b"cd".to_vec()));
    }

    #[test]
    fn parse_capability_body_too_short_fails() {
        let header = make_capability_header(123, 4);
        let body = vec![0x01, 0x02, 0x00, 0x09]; // Only 4 bytes, need 8

        let result = parse_capability_body(header, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("short"));
    }

    #[test]
    fn parse_capability_body_truncated_tlv_fails() {
        let header = make_capability_header(123, 12);
        let mut body = vec![
            0x01, // version
            0x01, // flags
            0x00, 0x09, // vendor
            0x00, 0x00, 0x00, 0x01, // capabilities
        ];
        // TLV header claims 10 bytes but only 2 available
        body.push(0x01);
        body.push(0x0A); // length = 10
        body.extend_from_slice(b"ab"); // only 2 bytes

        let result = parse_capability_body(header, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    // ==================== encode_capability Tests ====================

    #[test]
    fn encode_capability_minimal() {
        let cap = capability_request(123, 0x0009, CapabilityFlags(0x01));
        let body = encode_capability(&cap).unwrap();

        assert_eq!(body.len(), 8);
        assert_eq!(body[0], 1); // version
        assert_eq!(body[1], CAPABILITY_FLAG_REQUEST); // flags
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), 0x0009); // vendor
        assert_eq!(
            u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            0x01
        ); // capabilities
    }

    #[test]
    fn encode_capability_with_tlvs() {
        let mut cap = capability_request(123, 0x0009, CapabilityFlags(0x01));
        cap.tlvs.push((0x01, b"hello".to_vec()));

        let body = encode_capability(&cap).unwrap();

        assert_eq!(body.len(), 8 + 2 + 5); // header + TLV header + TLV value
        assert_eq!(body[8], 0x01); // TLV type
        assert_eq!(body[9], 0x05); // TLV length
        assert_eq!(&body[10..15], b"hello");
    }

    #[test]
    fn encode_capability_wrong_type_fails() {
        let mut cap = capability_request(123, 0x0009, CapabilityFlags(0x01));
        cap.header.packet_type = 0x01; // Wrong type

        let result = encode_capability(&cap);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type"));
    }

    #[test]
    fn encode_capability_tlv_too_long_fails() {
        let mut cap = capability_request(123, 0x0009, CapabilityFlags(0x01));
        cap.tlvs.push((0x01, vec![0u8; 256])); // Too long (max 255)

        let result = encode_capability(&cap);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("long"));
    }

    // ==================== Capability Debug/Clone Tests ====================

    #[test]
    fn capability_debug() {
        let cap = capability_request(123, 0x0009, CapabilityFlags(0x03));
        let debug_str = format!("{:?}", cap);
        assert!(debug_str.contains("Capability"));
    }

    #[test]
    fn capability_clone() {
        let cap = capability_request(123, 0x0009, CapabilityFlags(0x03));
        let cloned = cap.clone();
        assert_eq!(cloned.header.session_id, cap.header.session_id);
        assert_eq!(cloned.vendor, cap.vendor);
        assert_eq!(cloned.capabilities.0, cap.capabilities.0);
    }

    #[test]
    fn capability_flags_debug() {
        let flags = CapabilityFlags(0x03);
        let debug_str = format!("{:?}", flags);
        assert!(debug_str.contains("CapabilityFlags"));
    }
}
