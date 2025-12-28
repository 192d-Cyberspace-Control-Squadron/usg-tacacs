// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ protocol helpers: headers, authn/authz bodies, and shared-secret body crypto.
//! Focused on async IO parsing/encoding for server-side use.
//! The `legacy-md5` feature (on by default) enables the TACACS+ MD5 body obfuscation; disable it for FIPS-only builds.

use anyhow::{Context, Result, anyhow, bail, ensure};
use log::warn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod accounting;
mod authen;
mod author;
mod capability;
pub mod client;
mod crypto;
pub mod header;
mod util;

pub use accounting::{AccountingRequest, AccountingResponse};
pub use authen::{
    AuthSessionState, AuthenContinue, AuthenData, AuthenPacket, AuthenReply, AuthenStart,
};
pub use author::{AuthorizationRequest, AuthorizationResponse};
pub use capability::{
    CAPABILITY_FLAG_REQUEST, CAPABILITY_FLAG_RESPONSE, Capability, CapabilityFlags,
    capability_request, encode_capability,
};
pub use header::Header;

pub const VERSION: u8 = 0xc << 4; // Major version 0xC, minor 0

pub const TYPE_AUTHEN: u8 = 0x01;
pub const TYPE_AUTHOR: u8 = 0x02;
pub const TYPE_ACCT: u8 = 0x03;
pub const TYPE_CAPABILITY: u8 = 0x04;

pub const FLAG_UNENCRYPTED: u8 = 0x01;
pub const FLAG_SINGLE_CONNECT: u8 = 0x04;
const ALLOWED_FLAGS: u8 = FLAG_UNENCRYPTED | FLAG_SINGLE_CONNECT;
pub const MIN_SECRET_LEN: usize = 8;

pub const AUTHEN_STATUS_PASS: u8 = 0x01;
pub const AUTHEN_STATUS_FAIL: u8 = 0x02;
pub const AUTHEN_STATUS_GETDATA: u8 = 0x03;
pub const AUTHEN_STATUS_GETUSER: u8 = 0x04;
pub const AUTHEN_STATUS_GETPASS: u8 = 0x05;
pub const AUTHEN_STATUS_RESTART: u8 = 0x06;
pub const AUTHEN_STATUS_ERROR: u8 = 0x07;
pub const AUTHEN_STATUS_FOLLOW: u8 = 0x21;

pub const AUTHEN_FLAG_NOECHO: u8 = 0x01;

pub const AUTHEN_TYPE_ASCII: u8 = 0x01;
pub const AUTHEN_TYPE_PAP: u8 = 0x02;
pub const AUTHEN_TYPE_CHAP: u8 = 0x03;
pub const AUTHEN_TYPE_ARAP: u8 = 0x04;

pub const AUTHOR_STATUS_PASS_ADD: u8 = 0x01;
pub const AUTHOR_STATUS_PASS_REPL: u8 = 0x02;
pub const AUTHOR_STATUS_FAIL: u8 = 0x10;
pub const AUTHOR_STATUS_ERROR: u8 = 0x11;

pub const ACCT_STATUS_SUCCESS: u8 = 0x01;
pub const ACCT_STATUS_ERROR: u8 = 0x02;
pub const ACCT_STATUS_FOLLOW: u8 = 0x21;
pub const ACCT_FLAG_START: u8 = 0x02;
pub const ACCT_FLAG_STOP: u8 = 0x04;
pub const ACCT_FLAG_WATCHDOG: u8 = 0x08;

#[derive(Debug, Clone)]
pub enum Packet {
    Authorization(AuthorizationRequest),
    Authentication(AuthenPacket),
    Accounting(accounting::AccountingRequest),
    Capability(Capability),
}

pub async fn read_packet<R>(reader: &mut R, secret: Option<&[u8]>) -> Result<Option<Packet>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let header = match header::read_header(reader).await {
        Ok(h) => h,
        Err(err) if is_clean_eof(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet received (deprecated and refused)");
    }
    if let Some(sec) = secret {
        if sec.len() < MIN_SECRET_LEN {
            bail!("shared secret too short; minimum {MIN_SECRET_LEN} bytes required");
        }
    } else {
        bail!("TACACS+ packet requires obfuscation but no secret provided");
    }
    header::validate_request_header(&header, None, ALLOWED_FLAGS, true, VERSION >> 4)?;

    let mut body = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut body)
        .await
        .with_context(|| "reading TACACS+ body")?;
    crypto::apply_body_crypto(&header, &mut body, secret)?;

    match header.packet_type {
        TYPE_AUTHOR => author::parse_author_body(header, &body)
            .map(Packet::Authorization)
            .map(Some),
        TYPE_AUTHEN => authen::parse_authen_body(header, &body)
            .map(Packet::Authentication)
            .map(Some),
        TYPE_ACCT => accounting::parse_accounting_body(header, &body)
            .map(Packet::Accounting)
            .map(Some),
        TYPE_CAPABILITY => capability::parse_capability_body(header, &body)
            .map(Packet::Capability)
            .map(Some),
        other => bail!("unsupported TACACS+ type {}", other),
    }
}

pub async fn read_author_request<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AuthorizationRequest>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match read_packet(reader, secret).await? {
        Some(Packet::Authorization(req)) => Ok(Some(req)),
        Some(Packet::Authentication(_)) => {
            bail!("got authentication packet when authorization expected")
        }
        Some(Packet::Accounting(_)) => bail!("got accounting packet when authorization expected"),
        Some(Packet::Capability(_)) => bail!("got capability packet when authorization expected"),
        None => Ok(None),
    }
}

pub async fn write_author_response<W>(
    writer: &mut W,
    request_header: &Header,
    response: &AuthorizationResponse,
    secret: Option<&[u8]>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if request_header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet not permitted");
    }
    if let Some(sec) = secret {
        if sec.len() < MIN_SECRET_LEN {
            bail!("shared secret too short; minimum {MIN_SECRET_LEN} bytes required");
        }
    } else {
        bail!("cannot send encrypted TACACS+ response without a shared secret");
    }
    let mut body = author::encode_author_response(response)?;
    crypto::apply_body_crypto(request_header, &mut body, secret)?;
    let header = request_header.response(body.len() as u32);
    header::validate_response_header(
        &header,
        Some(TYPE_AUTHOR),
        ALLOWED_FLAGS,
        true,
        VERSION >> 4,
    )?;
    header::write_header(writer, &header).await?;
    writer
        .write_all(&body)
        .await
        .with_context(|| "writing authorization response body")?;
    writer.flush().await.context("flushing response")
}

pub async fn write_authen_reply<W>(
    writer: &mut W,
    request_header: &Header,
    reply: &AuthenReply,
    secret: Option<&[u8]>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if request_header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet not permitted");
    }
    if let Some(sec) = secret {
        if sec.len() < MIN_SECRET_LEN {
            bail!("shared secret too short; minimum {MIN_SECRET_LEN} bytes required");
        }
    } else {
        bail!("cannot send encrypted TACACS+ response without a shared secret");
    }
    let mut body: Vec<u8> = authen::encode_authen_reply(reply)?;
    crypto::apply_body_crypto(request_header, &mut body, secret)?;
    let header: Header = request_header.response(body.len() as u32);
    header::validate_response_header(
        &header,
        Some(TYPE_AUTHEN),
        ALLOWED_FLAGS,
        true,
        VERSION >> 4,
    )?;
    header::write_header(writer, &header).await?;
    writer
        .write_all(&body)
        .await
        .with_context(|| "writing authentication reply body")?;
    writer.flush().await.context("flushing authen reply")
}

pub async fn write_accounting_response<W>(
    writer: &mut W,
    request_header: &Header,
    response: &accounting::AccountingResponse,
    secret: Option<&[u8]>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if request_header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet not permitted");
    }
    if let Some(sec) = secret {
        if sec.len() < MIN_SECRET_LEN {
            bail!("shared secret too short; minimum {MIN_SECRET_LEN} bytes required");
        }
    } else {
        bail!("cannot send encrypted TACACS+ response without a shared secret");
    }
    let mut body: Vec<u8> = accounting::encode_accounting_response(response)?;
    crypto::apply_body_crypto(request_header, &mut body, secret)?;
    let header: Header = request_header.response(body.len() as u32);
    header::validate_response_header(&header, Some(TYPE_ACCT), ALLOWED_FLAGS, true, VERSION >> 4)?;
    header::write_header(writer, &header).await?;
    writer
        .write_all(&body)
        .await
        .with_context(|| "writing accounting response body")?;
    writer.flush().await.context("flushing accounting response")
}

pub async fn write_capability<W>(
    writer: &mut W,
    request_header: &Header,
    cap: &Capability,
    secret: Option<&[u8]>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if request_header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet not permitted");
    }
    let sec = secret.context("cannot send encrypted TACACS+ capability without a shared secret")?;
    ensure!(
        sec.len() >= MIN_SECRET_LEN,
        "shared secret too short; minimum {MIN_SECRET_LEN} bytes required"
    );
    let mut body = encode_capability(cap)?;
    crypto::apply_body_crypto(request_header, &mut body, secret)?;
    let header: Header = request_header.response(body.len() as u32);
    header::validate_response_header(
        &header,
        Some(TYPE_CAPABILITY),
        ALLOWED_FLAGS,
        true,
        VERSION >> 4,
    )?;
    header::write_header(writer, &header).await?;
    writer
        .write_all(&body)
        .await
        .with_context(|| "writing capability response body")?;
    writer.flush().await.context("flushing capability response")
}

pub async fn read_authen_reply<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AuthenReply>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let header = match header::read_header(reader).await {
        Ok(h) => h,
        Err(err) if is_clean_eof(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet received (deprecated and refused)");
    }
    if secret.is_none() {
        bail!("encrypted TACACS+ packet received without a shared secret");
    }
    header::validate_response_header(
        &header,
        Some(TYPE_AUTHEN),
        ALLOWED_FLAGS,
        true,
        VERSION >> 4,
    )?;

    let mut body = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut body)
        .await
        .with_context(|| "reading TACACS+ authen reply body")?;
    crypto::apply_body_crypto(&header, &mut body, secret)?;
    let reply = authen::parse_authen_reply(header, &body)?;
    Ok(Some(reply))
}

pub async fn read_author_response<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AuthorizationResponse>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let header = match header::read_header(reader).await {
        Ok(h) => h,
        Err(err) if is_clean_eof(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet received (deprecated and refused)");
    }
    if secret.is_none() {
        bail!("encrypted TACACS+ packet received without a shared secret");
    }
    validate_author_response_header(&header)?;
    let mut body = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut body)
        .await
        .with_context(|| "reading TACACS+ authorization response body")?;
    crypto::apply_body_crypto(&header, &mut body, secret)?;

    ensure!(body.len() >= 5, "authorization response too short");
    let status = body[0];
    ensure!(
        status == AUTHOR_STATUS_PASS_REPL
            || status == AUTHOR_STATUS_PASS_ADD
            || status == AUTHOR_STATUS_FAIL
            || status == AUTHOR_STATUS_ERROR,
        "authorization response status invalid"
    );
    if status == ACCT_STATUS_FOLLOW {
        warn!("authorization response uses deprecated FOLLOW status");
        bail!("authorization response uses deprecated FOLLOW status");
    }
    ensure!(
        status == AUTHOR_STATUS_PASS_REPL
            || status == AUTHOR_STATUS_PASS_ADD
            || status == AUTHOR_STATUS_FAIL
            || status == AUTHOR_STATUS_ERROR,
        "authorization response status invalid"
    );
    let arg_cnt = body[1] as usize;
    let server_msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let mut cursor = 6;
    let arg_lens = body
        .get(cursor..cursor + arg_cnt)
        .ok_or_else(|| anyhow!("authorization response args length truncated"))?;
    cursor += arg_cnt;
    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + server_msg_len + data_len + total_args_len <= body.len(),
        "authorization response exceeds body length"
    );
    let server_msg = String::from_utf8(body[cursor..cursor + server_msg_len].to_vec())
        .context("decoding authorization server_msg")?;
    cursor += server_msg_len;
    let data = String::from_utf8(body[cursor..cursor + data_len].to_vec())
        .context("decoding authorization data")?;
    cursor += data_len;
    let mut args = Vec::with_capacity(arg_cnt);
    for (idx, len) in arg_lens.iter().enumerate() {
        let (arg, next_cursor) =
            util::read_string(&body, cursor, *len as usize, &format!("arg[{idx}]"))?;
        cursor = next_cursor;
        args.push(arg);
    }

    Ok(Some(AuthorizationResponse {
        status,
        server_msg,
        data,
        args,
    }))
}

pub fn validate_author_response_header(header: &Header) -> Result<()> {
    header::validate_response_header(header, Some(TYPE_AUTHOR), ALLOWED_FLAGS, true, VERSION >> 4)
}

pub fn validate_accounting_response_header(header: &Header) -> Result<()> {
    header::validate_response_header(header, Some(TYPE_ACCT), ALLOWED_FLAGS, true, VERSION >> 4)
}

/// Validate an outgoing authorization request against basic RFC 8907 semantics.
pub fn validate_author_request(req: &AuthorizationRequest) -> Result<()> {
    ensure!(
        (1..=8).contains(&req.authen_method),
        "authorization authen_method invalid"
    );
    ensure!(req.priv_lvl <= 0x0f, "authorization priv_lvl invalid");
    ensure!(
        req.authen_type <= AUTHEN_TYPE_ARAP,
        "authorization authen_type invalid"
    );
    ensure!(
        req.authen_service <= 0x07,
        "authorization authen_service invalid"
    );

    let attrs = req.attributes();
    let service_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("service"))
        .collect();
    ensure!(
        service_attrs.len() == 1,
        "authorization must include exactly one service attribute"
    );
    let service_val = service_attrs[0].value.as_deref().unwrap_or("");
    ensure!(
        !service_val.is_empty(),
        "authorization service attribute must have a value"
    );
    ensure!(
        crate::header::is_known_service(service_val),
        "authorization service attribute value unknown"
    );

    let protocol_attr = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("protocol"));
    let cmd_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd"))
        .collect();
    let cmd_arg_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd-arg"))
        .collect();

    if service_val.eq_ignore_ascii_case("shell") {
        ensure!(
            protocol_attr.is_some(),
            "shell authorization requires protocol attribute"
        );
        if let Some(proto) = protocol_attr.and_then(|p| p.value.as_deref()) {
            ensure!(
                !proto.is_empty(),
                "authorization protocol attribute must have a value"
            );
        }
        ensure!(
            cmd_attrs.is_empty() && cmd_arg_attrs.is_empty(),
            "shell authorization must not include cmd/cmd-arg attributes"
        );
    } else {
        let protocol_count = attrs
            .iter()
            .filter(|a| a.name.eq_ignore_ascii_case("protocol"))
            .count();
        ensure!(
            protocol_count <= 1,
            "authorization must include at most one protocol attribute"
        );
        if let Some(proto) = protocol_attr.and_then(|p| p.value.as_deref()) {
            ensure!(
                !proto.is_empty(),
                "authorization protocol attribute must have a value"
            );
            let allowed = [
                "ip", "ipv6", "lat", "mop", "vpdn", "xremote", "pad", "shell", "ppp", "arap",
                "none",
            ];
            ensure!(
                allowed.iter().any(|p| proto.eq_ignore_ascii_case(p)),
                "authorization protocol attribute value unknown"
            );
        }
        ensure!(
            cmd_attrs.len() == 1,
            "authorization must include exactly one cmd attribute for non-shell services"
        );
        ensure!(
            !cmd_attrs[0].value.as_deref().unwrap_or("").is_empty(),
            "cmd attribute must have a value"
        );
        ensure!(
            !cmd_arg_attrs
                .iter()
                .any(|a| a.value.as_deref().unwrap_or("").is_empty()),
            "cmd-arg attributes must have values"
        );
        // Service must precede cmd/cmd-arg in the arg list.
        let service_pos = req
            .args
            .iter()
            .position(|a| a.to_lowercase().starts_with("service="))
            .unwrap_or(0);
        let protocol_positions = req
            .args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.to_lowercase().starts_with("protocol="))
            .map(|(i, _)| i);
        ensure!(
            !protocol_positions.clone().any(|i| i < service_pos),
            "service attribute must precede protocol attributes"
        );
        let cmd_positions = req
            .args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.to_lowercase().starts_with("cmd"))
            .map(|(i, _)| i);
        ensure!(
            !cmd_positions.clone().any(|i| i < service_pos),
            "service attribute must precede command attributes"
        );
    }

    if let Some(attr) = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("priv-lvl"))
    {
        if let Some(val) = attr.value.as_deref() {
            let parsed: u32 = val
                .parse()
                .map_err(|_| anyhow!("priv-lvl must be numeric"))?;
            ensure!(parsed <= 0x0f, "priv-lvl must be 0-15");
            ensure!(
                parsed as u8 == req.priv_lvl,
                "priv-lvl attribute must match header priv_lvl"
            );
        }
    }

    Ok(())
}

/// Validate an outgoing accounting request against RFC 8907 semantics.
pub fn validate_accounting_request(req: &AccountingRequest) -> Result<()> {
    ensure!(
        (1..=8).contains(&req.authen_method),
        "accounting authen_method invalid"
    );
    ensure!(req.authen_type <= 0x04, "accounting authen_type invalid");
    ensure!(
        req.authen_service <= 0x07,
        "accounting authen_service invalid"
    );
    ensure!(req.priv_lvl <= 0x0f, "accounting priv_lvl invalid");

    let valid_mask: u8 = ACCT_FLAG_START | ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG;
    ensure!(
        req.flags & !valid_mask == 0 && (req.flags & valid_mask).count_ones() == 1,
        "accounting flags invalid"
    );

    let is_start = req.flags & ACCT_FLAG_START != 0;
    let is_stop = req.flags & ACCT_FLAG_STOP != 0;
    let is_watchdog = req.flags & ACCT_FLAG_WATCHDOG != 0;
    ensure!(
        !(is_start || is_stop || is_watchdog) || !req.args.is_empty(),
        "accounting records require attributes"
    );

    let attrs = req.attributes();
    let has_service_or_cmd = attrs.iter().any(|a| {
        let name = a.name.as_str();
        name.eq_ignore_ascii_case("service")
            || name.eq_ignore_ascii_case("cmd")
            || name.eq_ignore_ascii_case("cmd-arg")
    });
    ensure!(
        has_service_or_cmd,
        "accounting requires service or command attributes"
    );

    let has_task = attrs.iter().any(|a| a.name.eq_ignore_ascii_case("task_id"));
    let has_elapsed = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("elapsed_time"));
    let has_status = attrs.iter().any(|a| a.name.eq_ignore_ascii_case("status"));
    let has_bytes_in = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("bytes_in"));
    let has_bytes_out = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("bytes_out"));

    if is_start {
        ensure!(has_task, "start accounting requires task_id attribute");
    }
    if is_stop {
        ensure!(
            has_task && has_elapsed && has_status,
            "stop accounting requires task_id, elapsed_time, and status attributes"
        );
        ensure!(
            has_bytes_in && has_bytes_out,
            "stop accounting requires bytes_in and bytes_out attributes"
        );
    }
    if is_watchdog {
        ensure!(has_task, "watchdog accounting requires task_id attribute");
    }

    let mut status_val: Option<u32> = None;
    let parse_u32 = |key: &str| -> Result<Option<u32>> {
        if let Some(attr) = attrs.iter().find(|a| a.name.eq_ignore_ascii_case(key)) {
            let val = attr.value.as_deref().unwrap_or("");
            let parsed: u32 = val
                .parse()
                .map_err(|_| anyhow!("accounting attribute {key} must be numeric"))?;
            return Ok(Some(parsed));
        }
        Ok(None)
    };
    if has_task {
        parse_u32("task_id")?;
    }
    if has_elapsed {
        parse_u32("elapsed_time")?;
    }
    if has_status {
        status_val = parse_u32("status")?;
    }
    for key in ["bytes_in", "bytes_out", "elapsed_seconds"].iter() {
        parse_u32(key)?;
    }
    if let Some(code) = status_val {
        ensure!(code <= 0x0f, "accounting status code must be 0-15");
        ensure!(
            code == 0 || is_stop,
            "non-success accounting status is only valid on stop records"
        );
    }
    Ok(())
}

/// Validate an outgoing authentication start packet for basic RFC compliance.
pub fn validate_authen_start(req: &authen::AuthenStart) -> Result<()> {
    ensure!(
        req.header.seq_no % 2 == 1,
        "authentication start must use odd sequence number"
    );
    ensure!(
        req.authen_type == AUTHEN_TYPE_ASCII
            || req.authen_type == AUTHEN_TYPE_PAP
            || req.authen_type == AUTHEN_TYPE_CHAP,
        "authentication type invalid or unsupported"
    );
    ensure!(req.priv_lvl <= 0x0f, "authentication priv_lvl invalid");
    // For ASCII, username may be empty initially; for PAP/CHAP, credentials must be present.
    match req.authen_type {
        AUTHEN_TYPE_PAP | AUTHEN_TYPE_CHAP => {
            ensure!(
                !req.data.is_empty(),
                "authentication payload required for PAP/CHAP"
            );
        }
        AUTHEN_TYPE_ASCII => {}
        _ => {}
    }
    Ok(())
}

/// Validate an outgoing authentication continue packet for basic RFC compliance.
pub fn validate_authen_continue(req: &authen::AuthenContinue) -> Result<()> {
    ensure!(
        req.header.seq_no % 2 == 0,
        "authentication continue must use even sequence number"
    );
    // Only AUTHEN_FLAG_NOECHO is defined for continue requests per RFC.
    ensure!(
        req.flags == 0 || req.flags == crate::AUTHEN_FLAG_NOECHO,
        "authentication continue flags invalid"
    );
    Ok(())
}

pub async fn read_accounting_response<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<accounting::AccountingResponse>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let header = match header::read_header(reader).await {
        Ok(h) => h,
        Err(err) if is_clean_eof(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if header.flags & FLAG_UNENCRYPTED != 0 {
        bail!("unencrypted TACACS+ packet received (deprecated and refused)");
    }
    if secret.is_none() {
        bail!("encrypted TACACS+ packet received without a shared secret");
    }
    validate_accounting_response_header(&header)?;
    let mut body = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut body)
        .await
        .with_context(|| "reading TACACS+ accounting response body")?;
    crypto::apply_body_crypto(&header, &mut body, secret)?;

    ensure!(body.len() >= 5, "accounting response too short");
    let status = body[0];
    ensure!(
        status == ACCT_STATUS_SUCCESS
            || status == ACCT_STATUS_ERROR
            || status == ACCT_STATUS_FOLLOW,
        "accounting response status invalid"
    );
    if status == ACCT_STATUS_FOLLOW {
        warn!("accounting response uses deprecated FOLLOW status");
        bail!("accounting response uses deprecated FOLLOW status");
    }
    let server_msg_len = u16::from_be_bytes([body[1], body[2]]) as usize;
    let data_len = u16::from_be_bytes([body[3], body[4]]) as usize;
    let arg_cnt = body.get(5).copied().unwrap_or(0) as usize;
    let mut cursor = 6;
    let arg_lens = body
        .get(cursor..cursor + arg_cnt)
        .ok_or_else(|| anyhow!("accounting response args length truncated"))?;
    cursor += arg_cnt;
    for (idx, len) in arg_lens.iter().enumerate() {
        ensure!(*len > 0, "accounting response arg[{idx}] length invalid");
    }
    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + server_msg_len + data_len + total_args_len <= body.len(),
        "accounting response exceeds body length"
    );
    let server_msg = String::from_utf8(body[cursor..cursor + server_msg_len].to_vec())
        .context("decoding accounting server_msg")?;
    cursor += server_msg_len;
    let data = String::from_utf8(body[cursor..cursor + data_len].to_vec())
        .context("decoding accounting data")?;
    cursor += data_len;
    let mut args = Vec::with_capacity(arg_cnt);
    for (idx, len) in arg_lens.iter().enumerate() {
        let (arg, next_cursor) =
            util::read_string(&body, cursor, *len as usize, &format!("arg[{idx}]"))?;
        cursor = next_cursor;
        args.push(arg);
    }

    Ok(Some(accounting::AccountingResponse {
        status,
        server_msg,
        data,
        args,
    }))
}

fn is_clean_eof(err: &anyhow::Error) -> bool {
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        return io_err.kind() == std::io::ErrorKind::UnexpectedEof;
    }
    false
}
