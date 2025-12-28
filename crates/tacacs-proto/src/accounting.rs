// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ accounting packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::{parse_attributes, read_string};
use crate::{ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG};
use anyhow::{Result, anyhow, ensure};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct AccountingRequest {
    pub header: Header,
    pub flags: u8,
    pub authen_method: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub authen_service: u8,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AccountingResponse {
    pub status: u8,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

pub fn parse_accounting_body(header: Header, body: &[u8]) -> Result<AccountingRequest> {
    ensure!(body.len() >= 9, "accounting body too short");
    let flags = body[0];
    let authen_method = body[1];
    let priv_lvl = body[2];
    let authen_type = body[3];
    let authen_service = body[4];
    let user_len = body[5] as usize;
    let port_len = body[6] as usize;
    let rem_addr_len = body[7] as usize;
    let arg_cnt = body[8] as usize;

    let valid_mask: u8 = ACCT_FLAG_START | ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG;
    let flag_bits: u8 = flags & valid_mask;
    ensure!(
        flag_bits.count_ones() == 1 && flags & !valid_mask == 0,
        "accounting flags invalid"
    );

    let mut cursor: usize = 9;
    let (user, next) = read_string(body, cursor, user_len, "user")?;
    cursor = next;
    let (port, next) = read_string(body, cursor, port_len, "port")?;
    cursor = next;
    let (rem_addr, next) = read_string(body, cursor, rem_addr_len, "rem_addr")?;
    cursor = next;

    let arg_lens: &[u8] = body
        .get(cursor..cursor + arg_cnt)
        .ok_or_else(|| anyhow!("accounting args length truncated"))?;
    cursor += arg_cnt;

    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + total_args_len <= body.len(),
        "accounting args exceed body length"
    );

    let mut args: Vec<String> = Vec::with_capacity(arg_cnt);
    for (idx, len) in arg_lens.iter().enumerate() {
        ensure!(*len > 0, "accounting arg length invalid");
        let (arg, next_cursor) = read_string(body, cursor, *len as usize, &format!("arg[{idx}]"))?;
        cursor = next_cursor;
        args.push(arg);
    }

    Ok(AccountingRequest {
        header,
        flags,
        authen_method,
        priv_lvl,
        authen_type,
        authen_service,
        user,
        port,
        rem_addr,
        args,
    })
}

impl AccountingRequest {
    pub fn attributes(&self) -> Vec<crate::util::Attribute> {
        parse_attributes(&self.args)
    }
}

pub fn encode_accounting_response(response: &AccountingResponse) -> Result<Vec<u8>> {
    let mut buf: BytesMut = BytesMut::new();
    buf.put_u8(response.status);
    buf.put_u16(response.server_msg.len() as u16);
    buf.put_u16(response.data.len() as u16);
    buf.put_u8(response.args.len() as u8);
    for arg in &response.args {
        buf.put_u8(arg.len() as u8);
    }
    buf.extend_from_slice(response.server_msg.as_bytes());
    buf.extend_from_slice(response.data.as_bytes());
    for arg in &response.args {
        buf.extend_from_slice(arg.as_bytes());
    }
    Ok(buf.to_vec())
}
