// SPDX-License-Identifier: AGPL-3.0-only
//! Minimal client-side helpers to read validated TACACS+ responses.

use crate::{
    read_accounting_response, read_authen_reply, read_author_response, AccountingResponse,
    AuthenReply, AuthorizationResponse,
};
use anyhow::Result;

pub async fn recv_authorization<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AuthorizationResponse>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_author_response(reader, secret).await
}

pub async fn recv_accounting<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AccountingResponse>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_accounting_response(reader, secret).await
}

pub async fn recv_authentication<R>(
    reader: &mut R,
    secret: Option<&[u8]>,
) -> Result<Option<AuthenReply>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_authen_reply(reader, secret).await
}
