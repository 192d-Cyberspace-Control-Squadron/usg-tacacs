// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ accounting packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::{parse_attributes, read_string, validate_attributes};
use crate::{
    ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG, ACCT_STATUS_ERROR, ACCT_STATUS_FOLLOW,
    ACCT_STATUS_SUCCESS,
};
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
    ensure!(
        (1..=8).contains(&authen_method),
        "accounting authen_method invalid"
    );
    ensure!(authen_type <= 0x04, "accounting authen_type invalid");
    ensure!(authen_service <= 0x07, "accounting authen_service invalid");
    ensure!(priv_lvl <= 0x0f, "accounting priv_lvl invalid");
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

    validate_attributes(
        &args,
        &[
            "cmd",
            "cmd-arg",
            "service",
            "protocol",
            "acl",
            "addr",
            "priv-lvl",
            "task_id",
            "elapsed_time",
            "status",
            "start_time",
            "elapsed_seconds",
            "bytes_in",
            "bytes_out",
        ],
    )?;

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

    pub fn with_service(mut self, service: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("service="));
        self.args.insert(0, format!("service={}", service.as_ref()));
        self
    }

    pub fn with_protocol(mut self, protocol: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("protocol="));
        let service_pos = self
            .args
            .iter()
            .position(|a| a.to_lowercase().starts_with("service="));
        let insert_pos = service_pos.map(|p| p + 1).unwrap_or(self.args.len());
        self.args
            .insert(insert_pos, format!("protocol={}", protocol.as_ref()));
        self
    }

    pub fn with_cmd(mut self, cmd: impl AsRef<str>) -> Self {
        self.args.retain(|a| !a.to_lowercase().starts_with("cmd="));
        self.args.push(format!("cmd={}", cmd.as_ref()));
        self
    }

    pub fn add_cmd_arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(format!("cmd-arg={}", arg.as_ref()));
        self
    }

    pub fn with_task_id(mut self, task: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("task_id="));
        self.args.push(format!("task_id={}", task.as_ref()));
        self
    }

    pub fn with_status(mut self, status: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("status="));
        self.args.push(format!("status={}", status.as_ref()));
        self
    }

    pub fn with_bytes(mut self, bytes_in: impl AsRef<str>, bytes_out: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("bytes_in="));
        self.args
            .retain(|a| !a.to_lowercase().starts_with("bytes_out="));
        self.args.push(format!("bytes_in={}", bytes_in.as_ref()));
        self.args.push(format!("bytes_out={}", bytes_out.as_ref()));
        self
    }

    pub fn builder(session_id: u32, flags: u8) -> AccountingRequest {
        AccountingRequest {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_ACCT,
                flags: 0,
            },
            flags,
            authen_method: 1,
            priv_lvl: 1,
            authen_type: 1,
            authen_service: 1,
            user: String::new(),
            port: String::new(),
            rem_addr: String::new(),
            args: Vec::new(),
        }
    }

    pub fn with_authen(mut self, method: u8, authen_type: u8, service: u8, priv_lvl: u8) -> Self {
        self.authen_method = method;
        self.authen_type = authen_type;
        self.authen_service = service;
        self.priv_lvl = priv_lvl;
        self
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = user;
        self
    }

    pub fn with_port(mut self, port: String) -> Self {
        self.port = port;
        self
    }

    pub fn with_rem_addr(mut self, rem_addr: String) -> Self {
        self.rem_addr = rem_addr;
        self
    }

    pub fn add_arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_accounting_request(&self)?;
        Ok(self)
    }
}

pub fn encode_accounting_response(response: &AccountingResponse) -> Result<Vec<u8>> {
    ensure!(
        response.status == ACCT_STATUS_SUCCESS
            || response.status == ACCT_STATUS_ERROR
            || response.status == ACCT_STATUS_FOLLOW,
        "accounting response status invalid"
    );
    ensure!(
        response.args.len() <= u8::MAX as usize,
        "too many accounting response args"
    );
    ensure!(
        response.server_msg.len() <= u16::MAX as usize,
        "accounting server_msg too long"
    );
    ensure!(
        response.data.len() <= u16::MAX as usize,
        "accounting data too long"
    );
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
