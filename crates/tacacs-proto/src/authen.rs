// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ authentication packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::read_bytes;
use crate::{AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP};
use anyhow::{Context, Result, ensure};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct AuthenStart {
    pub header: Header,
    pub action: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub service: u8,
    pub user: String,
    pub port: String,
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
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum AuthenPacket {
    Start(AuthenStart),
    Continue(AuthenContinue),
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
    pub chap_id: Option<u8>,
    pub ascii_need_user: bool,
    pub ascii_need_pass: bool,
    pub ascii_attempts: u8,
}

impl AuthSessionState {
    pub fn new_from_start(header: &Header, authen_type: u8, username: String) -> Result<Self> {
        ensure!(header.seq_no % 2 == 1, "auth start must use odd seq");
        Ok(Self {
            last_seq: header.seq_no,
            expect_client: false,
            authen_type: Some(authen_type),
            challenge: None,
            username: Some(username),
            chap_id: None,
            ascii_need_user: false,
            ascii_need_pass: false,
            ascii_attempts: 0,
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
    if body.len() >= 8 {
        let user_len = body[4] as usize;
        let port_len = body[5] as usize;
        let rem_addr_len = body[6] as usize;
        let data_len = body[7] as usize;
        let expected = 8 + user_len + port_len + rem_addr_len + data_len;
        if expected <= body.len() {
            let mut cursor = 8;
            let (user, next) = read_bytes(body, cursor, user_len, "user")?;
            cursor = next;
            let (port, next) = read_bytes(body, cursor, port_len, "port")?;
            cursor = next;
            let (rem_addr, next) = read_bytes(body, cursor, rem_addr_len, "rem_addr")?;
            cursor = next;
            let (data, _) = read_bytes(body, cursor, data_len, "data")?;

            return Ok(AuthenPacket::Start(AuthenStart {
                header,
                action: body[0],
                priv_lvl: body[1],
                authen_type: body[2],
                service: body[3],
                user: String::from_utf8(user).context("decoding user")?,
                port: String::from_utf8(port).context("decoding port")?,
                rem_addr: String::from_utf8(rem_addr).context("decoding rem_addr")?,
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
    buf.put_u16(reply.server_msg.len() as u16);
    buf.put_u16(reply.data.len() as u16);
    buf.extend_from_slice(reply.server_msg.as_bytes());
    buf.extend_from_slice(&reply.data);
    Ok(buf.to_vec())
}

pub fn parse_authen_reply(_header: Header, body: &[u8]) -> Result<AuthenReply> {
    ensure!(body.len() >= 6, "authentication reply body too short");
    let status = body[0];
    let flags = body[1];
    let msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let expected = 6 + msg_len + data_len;
    ensure!(
        expected <= body.len(),
        "authentication reply exceeds body length"
    );
    let server_msg = String::from_utf8(body[6..6 + msg_len].to_vec())
        .context("decoding authen reply server_msg")?;
    let data = body[6 + msg_len..expected].to_vec();

    Ok(AuthenReply {
        status,
        flags,
        server_msg,
        data,
    })
}
