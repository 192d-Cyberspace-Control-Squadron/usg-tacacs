// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ authorization packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::{parse_attributes, read_string};
use anyhow::{anyhow, ensure, Result};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub header: Header,
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
pub struct AuthorizationResponse {
    pub status: u8,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

impl AuthorizationRequest {
    pub fn command_string(&self) -> Option<String> {
        let mut base = None;
        let mut arguments = Vec::new();

        for arg in &self.args {
            if let Some(cmd) = arg.strip_prefix("cmd=") {
                base = Some(cmd.to_string());
            } else if let Some(cmd_arg) = arg.strip_prefix("cmd-arg=") {
                arguments.push(cmd_arg.to_string());
            }
        }

        if base.is_none() && !self.args.is_empty() {
            base = Some(self.args.join(" "));
        }

        base.map(|mut cmd| {
            if !arguments.is_empty() {
                if !cmd.is_empty() {
                    cmd.push(' ');
                }
                cmd.push_str(&arguments.join(" "));
            }
            cmd
        })
    }

    pub fn is_shell_start(&self) -> bool {
        self.args
            .iter()
            .any(|arg| arg.eq_ignore_ascii_case("service=shell"))
            && self
                .args
                .iter()
                .all(|arg| arg.starts_with("service=") || arg.starts_with("protocol="))
    }

    pub fn attributes(&self) -> Vec<crate::util::Attribute> {
        parse_attributes(&self.args)
    }

    pub fn has_cmd_attrs(&self) -> bool {
        self.args.iter().any(|a| a.starts_with("cmd=") || a.starts_with("cmd-arg="))
    }

    pub fn has_service_attr(&self) -> bool {
        self.args.iter().any(|a| a.starts_with("service="))
    }
}

pub fn parse_author_body(header: Header, body: &[u8]) -> Result<AuthorizationRequest> {
    ensure!(body.len() >= 8, "authorization body too short");
    let authen_method = body[0];
    let priv_lvl = body[1];
    let authen_type = body[2];
    let authen_service = body[3];
    let user_len = body[4] as usize;
    let port_len = body[5] as usize;
    let rem_addr_len = body[6] as usize;
    let arg_cnt = body[7] as usize;

    let mut cursor = 8;
    let (user, next) = read_string(body, cursor, user_len, "user")?;
    cursor = next;
    let (port, next) = read_string(body, cursor, port_len, "port")?;
    cursor = next;
    let (rem_addr, next) = read_string(body, cursor, rem_addr_len, "rem_addr")?;
    cursor = next;

    let arg_lens = body
        .get(cursor..cursor + arg_cnt)
        .ok_or_else(|| anyhow!("authorization args length truncated"))?;
    cursor += arg_cnt;

    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + total_args_len <= body.len(),
        "authorization args exceed body length"
    );

    let mut args = Vec::with_capacity(arg_cnt);
    for (idx, len) in arg_lens.iter().enumerate() {
        ensure!(*len > 0, "authorization arg length invalid");
        let (arg, next_cursor) = read_string(body, cursor, *len as usize, &format!("arg[{idx}]"))?;
        cursor = next_cursor;
        args.push(arg);
    }

    Ok(AuthorizationRequest {
        header,
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

pub fn encode_author_response(response: &AuthorizationResponse) -> Result<Vec<u8>> {
    let mut buf = BytesMut::new();
    buf.put_u8(response.status);
    buf.put_u8(response.args.len() as u8);
    buf.put_u16(response.server_msg.len() as u16);
    buf.put_u16(response.data.len() as u16);
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
