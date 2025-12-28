// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ packet header parsing and serialization for async streams.

use anyhow::{Context, Result, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub packet_type: u8,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: u32,
    pub length: u32,
}

impl Header {
    pub fn response(&self, length: u32) -> Header {
        Header {
            version: self.version,
            packet_type: self.packet_type,
            seq_no: self.seq_no.wrapping_add(1),
            flags: self.flags, // mirrors request flags; caller can override if needed
            session_id: self.session_id,
            length,
        }
    }
}

pub async fn read_header<R>(reader: &mut R) -> Result<Header>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 12];
    reader
        .read_exact(&mut buf)
        .await
        .with_context(|| "reading TACACS+ header")?;

    let version = buf[0];
    let packet_type = buf[1];
    let seq_no = buf[2];
    let flags = buf[3];
    let session_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let length = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    Ok(Header {
        version,
        packet_type,
        seq_no,
        flags,
        session_id,
        length,
    })
}

pub async fn write_header<W>(writer: &mut W, header: &Header) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 12];
    buf[0] = header.version;
    buf[1] = header.packet_type;
    buf[2] = header.seq_no;
    buf[3] = header.flags;
    buf[4..8].copy_from_slice(&header.session_id.to_be_bytes());
    buf[8..12].copy_from_slice(&header.length.to_be_bytes());
    writer
        .write_all(&buf)
        .await
        .with_context(|| "writing TACACS+ header")
}

pub fn validate_request_header(
    header: &Header,
    expected_packet_type: Option<u8>,
    allowed_flags: u8,
    require_odd_seq: bool,
    expected_major: u8,
) -> Result<()> {
    if let Some(packet_type) = expected_packet_type {
        ensure!(
            header.packet_type == packet_type,
            "unexpected TACACS+ type {}, expected {}",
            header.packet_type,
            packet_type
        );
    }
    ensure!(
        header.version >> 4 == expected_major,
        "unsupported TACACS+ major version {:x}",
        header.version >> 4
    );
    ensure!(
        header.flags & !allowed_flags == 0,
        "unsupported TACACS+ flags set {:02x}",
        header.flags & !allowed_flags
    );
    if require_odd_seq {
        ensure!(
            header.seq_no % 2 == 1,
            "client TACACS+ packets must use odd seq numbers"
        );
    }
    Ok(())
}

pub fn validate_response_header(
    header: &Header,
    expected_packet_type: Option<u8>,
    allowed_flags: u8,
    require_even_seq: bool,
    expected_major: u8,
) -> Result<()> {
    if let Some(packet_type) = expected_packet_type {
        ensure!(
            header.packet_type == packet_type,
            "unexpected TACACS+ type {}, expected {}",
            header.packet_type,
            packet_type
        );
    }
    ensure!(
        header.version >> 4 == expected_major,
        "unsupported TACACS+ major version {:x}",
        header.version >> 4
    );
    ensure!(
        header.flags & !allowed_flags == 0,
        "unsupported TACACS+ flags set {:02x}",
        header.flags & !allowed_flags
    );
    if require_even_seq {
        ensure!(
            header.seq_no % 2 == 0,
            "server TACACS+ packets must use even seq numbers"
        );
    }
    Ok(())
}

pub fn is_known_service(service: &str) -> bool {
    matches!(
        service.to_ascii_lowercase().as_str(),
        "shell" | "login" | "enable" | "ppp" | "arap" | "tty-daemon" | "connection" | "none"
    )
}
