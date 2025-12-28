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
pub mod client;
mod crypto;
pub mod header;
mod util;

pub use accounting::{AccountingRequest, AccountingResponse};
pub use authen::{AuthSessionState, AuthenData, AuthenPacket, AuthenReply};
pub use author::{AuthorizationRequest, AuthorizationResponse};
pub use header::Header;

pub const VERSION: u8 = 0xc << 4; // Major version 0xC, minor 0

pub const TYPE_AUTHEN: u8 = 0x01;
pub const TYPE_AUTHOR: u8 = 0x02;
pub const TYPE_ACCT: u8 = 0x03;

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
        status == ACCT_STATUS_SUCCESS || status == ACCT_STATUS_ERROR || status == ACCT_STATUS_FOLLOW,
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
