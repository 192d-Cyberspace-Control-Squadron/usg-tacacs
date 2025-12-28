// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ authentication packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::read_bytes;
use crate::{
    AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW,
    AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS, AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS,
    AUTHEN_STATUS_RESTART, AUTHEN_TYPE_ARAP, AUTHEN_TYPE_ASCII, AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP,
};
use anyhow::{Result, ensure};
use bytes::{BufMut, BytesMut};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct AuthenStart {
    pub header: Header,
    pub action: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub service: u8,
    pub user_raw: Vec<u8>,
    pub user: String,
    pub port_raw: Vec<u8>,
    pub port: String,
    pub rem_addr_raw: Vec<u8>,
    pub rem_addr: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthenContinue {
    pub header: Header,
    pub user_msg: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct AuthenReply {
    pub status: u8,
    pub flags: u8,
    pub server_msg: String,
    pub server_msg_raw: Vec<u8>,
    pub data: Vec<u8>,
}

impl AuthenReply {
    /// Returns the server_msg as raw bytes, preferring the raw buffer when present.
    pub fn server_msg_bytes(&self) -> Cow<'_, [u8]> {
        if !self.server_msg_raw.is_empty() {
            Cow::Borrowed(self.server_msg_raw.as_slice())
        } else {
            Cow::Owned(self.server_msg.as_bytes().to_vec())
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthenPacket {
    Start(AuthenStart),
    Continue(AuthenContinue),
}

impl AuthenStart {
    pub fn builder(
        session_id: u32,
        action: u8,
        priv_lvl: u8,
        authen_type: u8,
        service: u8,
    ) -> AuthenStart {
        AuthenStart {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHEN,
                flags: 0,
            },
            action,
            priv_lvl,
            authen_type,
            service,
            user_raw: Vec::new(),
            user: String::new(),
            port_raw: Vec::new(),
            port: String::new(),
            rem_addr_raw: Vec::new(),
            rem_addr: String::new(),
            data: Vec::new(),
        }
    }

    pub fn with_user(mut self, user_raw: Vec<u8>, user: String) -> Self {
        self.user_raw = user_raw;
        self.user = user;
        self
    }

    pub fn with_port(mut self, port_raw: Vec<u8>, port: String) -> Self {
        self.port_raw = port_raw;
        self.port = port;
        self
    }

    pub fn with_rem_addr(mut self, rem_addr_raw: Vec<u8>, rem_addr: String) -> Self {
        self.rem_addr_raw = rem_addr_raw;
        self.rem_addr = rem_addr;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_authen_start(&self)?;
        Ok(self)
    }
}

impl AuthenContinue {
    pub fn builder(session_id: u32) -> AuthenContinue {
        AuthenContinue {
            header: Header {
                version: crate::VERSION,
                seq_no: 2,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHEN,
                flags: 0,
            },
            user_msg: Vec::new(),
            data: Vec::new(),
            flags: 0,
        }
    }

    pub fn with_seq(mut self, seq_no: u8) -> Self {
        self.header.seq_no = seq_no;
        self
    }

    pub fn with_user_msg(mut self, msg: Vec<u8>) -> Self {
        self.user_msg = msg;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_authen_continue(&self)?;
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub enum AuthenData {
    Pap { password: String },
    Chap { chap_id: u8, response: Vec<u8> },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct AuthSessionState {
    pub last_seq: u8,
    pub expect_client: bool,
    pub authen_type: Option<u8>,
    pub challenge: Option<Vec<u8>>,
    pub username: Option<String>,
    pub username_raw: Option<Vec<u8>>,
    pub port_raw: Option<Vec<u8>>,
    pub port: Option<String>,
    pub rem_addr_raw: Option<Vec<u8>>,
    pub rem_addr: Option<String>,
    pub chap_id: Option<u8>,
    pub ascii_need_user: bool,
    pub ascii_need_pass: bool,
    pub ascii_attempts: u8,
    pub ascii_user_attempts: u8,
    pub ascii_pass_attempts: u8,
    pub service: Option<u8>,
    pub action: Option<u8>,
}

impl AuthSessionState {
    pub fn new_from_start(
        header: &Header,
        authen_type: u8,
        username: String,
        username_raw: Vec<u8>,
        port: String,
        port_raw: Vec<u8>,
        rem_addr: String,
        rem_addr_raw: Vec<u8>,
        service: u8,
        action: u8,
    ) -> Result<Self> {
        ensure!(header.seq_no % 2 == 1, "auth start must use odd seq");
        Ok(Self {
            last_seq: header.seq_no,
            expect_client: false,
            authen_type: Some(authen_type),
            challenge: None,
            username: Some(username),
            username_raw: Some(username_raw),
            port_raw: Some(port_raw.clone()),
            port: if port_raw.is_empty() || port.is_empty() {
                None
            } else {
                Some(port)
            },
            rem_addr_raw: Some(rem_addr_raw.clone()),
            rem_addr: if rem_addr_raw.is_empty() || rem_addr.is_empty() {
                None
            } else {
                Some(rem_addr)
            },
            chap_id: None,
            ascii_need_user: false,
            ascii_need_pass: false,
            ascii_attempts: 0,
            ascii_user_attempts: 0,
            ascii_pass_attempts: 0,
            service: Some(service),
            action: Some(action),
        })
    }

    pub fn validate_client(&mut self, header: &Header) -> Result<()> {
        ensure!(self.expect_client, "unexpected client packet order");
        ensure!(header.seq_no % 2 == 1, "client packets must be odd seq");
        ensure!(
            header.seq_no == self.last_seq.wrapping_add(1),
            "client seq out of order"
        );
        self.last_seq = header.seq_no;
        self.expect_client = false;
        Ok(())
    }

    pub fn prepare_server_reply(&mut self, header: &Header) -> Result<()> {
        ensure!(!self.expect_client, "unexpected server turn");
        ensure!(
            header.seq_no == self.last_seq.wrapping_add(1),
            "server reply seq mismatch"
        );
        ensure!(header.seq_no % 2 == 0, "server replies must be even seq");
        self.last_seq = header.seq_no;
        self.expect_client = true;
        Ok(())
    }
}

impl AuthenStart {
    pub fn parsed_data(&self) -> AuthenData {
        match self.authen_type {
            AUTHEN_TYPE_PAP => match String::from_utf8(self.data.clone()) {
                Ok(password) => AuthenData::Pap { password },
                Err(_) => AuthenData::Raw(self.data.clone()),
            },
            AUTHEN_TYPE_CHAP if self.data.len() >= 2 => AuthenData::Chap {
                chap_id: self.data[0],
                response: self.data[1..].to_vec(),
            },
            _ => AuthenData::Raw(self.data.clone()),
        }
    }
}

pub fn parse_authen_body(header: Header, body: &[u8]) -> Result<AuthenPacket> {
    ensure!(body.len() >= 4, "authentication body too short");
    ensure!(
        header.seq_no % 2 == 1,
        "authentication client packets must use odd seq"
    );
    ensure!(
        body[0] == 0x01 || body[0] == 0x02,
        "invalid authen action (only login/enable allowed)"
    );
    ensure!(body[1] <= 0x0f, "invalid priv_lvl");
    ensure!(
        body[2] == AUTHEN_TYPE_ASCII
            || body[2] == AUTHEN_TYPE_PAP
            || body[2] == AUTHEN_TYPE_CHAP
            || body[2] == AUTHEN_TYPE_ARAP,
        "invalid authen_type"
    );
    // service is opaque in RFC; only ensure it fits in a byte already done by parsing
    if body.len() >= 8 {
        let user_len = body[4] as usize;
        let port_len = body[5] as usize;
        let rem_addr_len = body[6] as usize;
        let data_len = body[7] as usize;
        let expected = 8 + user_len + port_len + rem_addr_len + data_len;
        if expected <= body.len() {
            let mut cursor = 8;
            let (user_bytes, next) = read_bytes(body, cursor, user_len, "user")?;
            let user_raw = user_bytes.clone();
            let user = String::from_utf8(user_bytes).unwrap_or_default();
            cursor = next;
            let (port_bytes, next) = read_bytes(body, cursor, port_len, "port")?;
            let port_raw = port_bytes.clone();
            let port = String::from_utf8(port_bytes).unwrap_or_default();
            cursor = next;
            let (rem_addr_bytes, next) = read_bytes(body, cursor, rem_addr_len, "rem_addr")?;
            let rem_addr_raw = rem_addr_bytes.clone();
            let rem_addr = String::from_utf8(rem_addr_bytes).unwrap_or_default();
            cursor = next;
            let (data, _) = read_bytes(body, cursor, data_len, "data")?;

            return Ok(AuthenPacket::Start(AuthenStart {
                header,
                action: body[0],
                priv_lvl: body[1],
                authen_type: body[2],
                service: body[3],
                user_raw,
                user,
                port_raw,
                port,
                rem_addr_raw,
                rem_addr,
                data,
            }));
        }
    }

    ensure!(body.len() >= 5, "authentication continue body too short");
    let user_msg_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let data_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let flags = body[4];
    let next = 5 + user_msg_len + data_len;
    ensure!(next <= body.len(), "authentication continue exceeds body");
    let (user_msg, next) = read_bytes(body, 5, user_msg_len, "user_msg")?;
    let (data, _) = read_bytes(body, next, data_len, "data")?;

    Ok(AuthenPacket::Continue(AuthenContinue {
        header,
        user_msg,
        data,
        flags,
    }))
}

pub fn encode_authen_reply(reply: &AuthenReply) -> Result<Vec<u8>> {
    let mut buf = BytesMut::new();
    buf.put_u8(reply.status);
    buf.put_u8(reply.flags);
    let msg_bytes = if reply.server_msg_raw.is_empty() {
        reply.server_msg.as_bytes()
    } else {
        reply.server_msg_raw.as_slice()
    };
    buf.put_u16(msg_bytes.len() as u16);
    buf.put_u16(reply.data.len() as u16);
    buf.extend_from_slice(msg_bytes);
    buf.extend_from_slice(&reply.data);
    Ok(buf.to_vec())
}

pub fn parse_authen_reply(_header: Header, body: &[u8]) -> Result<AuthenReply> {
    ensure!(body.len() >= 6, "authentication reply body too short");
    let status = body[0];
    let flags = body[1];
    ensure!(
        matches!(
            status,
            AUTHEN_STATUS_PASS
                | AUTHEN_STATUS_FAIL
                | AUTHEN_STATUS_GETDATA
                | AUTHEN_STATUS_GETUSER
                | AUTHEN_STATUS_GETPASS
                | AUTHEN_STATUS_RESTART
                | AUTHEN_STATUS_ERROR
                | AUTHEN_STATUS_FOLLOW
        ),
        "invalid authen status"
    );
    ensure!(
        flags & !(AUTHEN_FLAG_NOECHO) == 0,
        "invalid authen reply flags"
    );
    let msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let expected = 6 + msg_len + data_len;
    ensure!(
        expected <= body.len(),
        "authentication reply exceeds body length"
    );
    let server_msg_bytes = body[6..6 + msg_len].to_vec();
    let server_msg = String::from_utf8(server_msg_bytes.clone())
        .unwrap_or_else(|_| format!("(non-utf8 {} bytes)", server_msg_bytes.len()));
    let data = body[6 + msg_len..expected].to_vec();

    Ok(AuthenReply {
        status,
        flags,
        server_msg,
        server_msg_raw: server_msg_bytes,
        data,
    })
}
