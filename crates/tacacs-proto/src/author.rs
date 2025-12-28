// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ authorization packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::validate_attributes;
use crate::util::{parse_attributes, read_string};
use crate::{
    AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL,
};
use anyhow::{Result, anyhow, ensure};
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
    /// Set or replace the service attribute (enforced to appear first).
    pub fn with_service(mut self, service: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("service="));
        self.args.insert(0, format!("service={}", service.as_ref()));
        self
    }

    /// Set or replace the protocol attribute (kept after service when present).
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

    /// Set or replace the cmd attribute.
    pub fn with_cmd(mut self, cmd: impl AsRef<str>) -> Self {
        self.args.retain(|a| !a.to_lowercase().starts_with("cmd="));
        self.args.push(format!("cmd={}", cmd.as_ref()));
        self
    }

    /// Add a cmd-arg attribute (multiple allowed).
    pub fn add_cmd_arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(format!("cmd-arg={}", arg.as_ref()));
        self
    }

    /// Convenience for shell start requests: sets service and protocol.
    pub fn as_shell(mut self, protocol: impl AsRef<str>) -> Self {
        self = self.with_service("shell");
        self = self.with_protocol(protocol);
        self
    }

    pub fn builder(session_id: u32) -> AuthorizationRequest {
        AuthorizationRequest {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHOR,
                flags: 0,
            },
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
        crate::validate_author_request(&self)?;
        Ok(self)
    }

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
        self.args
            .iter()
            .any(|a| a.starts_with("cmd=") || a.starts_with("cmd-arg="))
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
    ensure!(
        (1..=8).contains(&authen_method),
        "authorization authen_method invalid"
    );
    ensure!(authen_type <= 0x04, "authorization authen_type invalid");
    ensure!(
        authen_service <= 0x07,
        "authorization authen_service invalid"
    );
    ensure!(priv_lvl <= 0x0f, "authorization priv_lvl invalid");
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

    // Basic TACACS+ attr validation: require name=value, known prefixes, non-empty.
    validate_attributes(
        &args,
        &[
            "cmd", "cmd-arg", "service", "protocol", "acl", "addr", "priv-lvl",
        ],
    )?;

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
    ensure!(
        response.status == AUTHOR_STATUS_PASS_REPL
            || response.status == AUTHOR_STATUS_PASS_ADD
            || response.status == AUTHOR_STATUS_FAIL
            || response.status == AUTHOR_STATUS_ERROR,
        "authorization response status invalid"
    );
    ensure!(
        response.args.len() <= u8::MAX as usize,
        "too many authorization response args"
    );
    ensure!(
        response.server_msg.len() <= u16::MAX as usize,
        "authorization server_msg too long"
    );
    ensure!(
        response.data.len() <= u16::MAX as usize,
        "authorization data too long"
    );
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
