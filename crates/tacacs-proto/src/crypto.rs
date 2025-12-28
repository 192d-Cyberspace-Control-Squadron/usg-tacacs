// SPDX-License-Identifier: AGPL-3.0-only
//! TACACS+ shared-secret body obfuscation (MD5 pad).

use crate::FLAG_UNENCRYPTED;
use crate::header::Header;
#[cfg(not(feature = "legacy-md5"))]
use anyhow::bail;
use anyhow::{Result, anyhow, bail};
#[cfg(feature = "legacy-md5")]
use openssl::hash::MessageDigest;
#[cfg(feature = "legacy-md5")]
use openssl::hash::hash;
use std::convert::TryInto;

pub fn apply_body_crypto(header: &Header, body: &mut [u8], secret: Option<&[u8]>) -> Result<()> {
    if header.flags & FLAG_UNENCRYPTED != 0 {
        return Ok(());
    }

    let secret = secret.ok_or_else(|| anyhow!("encrypted TACACS+ body but no secret provided"))?;
    if secret.len() < crate::MIN_SECRET_LEN {
        bail!(
            "shared secret too short; minimum {} bytes required",
            crate::MIN_SECRET_LEN
        );
    }

    #[cfg(not(feature = "legacy-md5"))]
    {
        bail!("legacy TACACS+ obfuscation is disabled (legacy-md5 feature off)");
    }

    #[cfg(feature = "legacy-md5")]
    {
        let mut pad: Vec<u8> = Vec::with_capacity(body.len());
        let mut prev: Option<[u8; 16]> = None;

        while pad.len() < body.len() {
            let mut seed: Vec<u8> = Vec::with_capacity(4 + secret.len() + 2 + 16);
            seed.extend_from_slice(&header.session_id.to_be_bytes());
            seed.extend_from_slice(secret);
            seed.push(header.version);
            seed.push(header.seq_no);
            if let Some(prev_pad) = prev {
                seed.extend_from_slice(&prev_pad);
            }
            let digest: openssl::hash::DigestBytes = hash(MessageDigest::md5(), &seed)?;
            let digest: [u8; 16] = digest
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("unexpected MD5 length"))?;
            pad.extend_from_slice(&digest);
            prev = Some(digest);
        }

        for (b, p) in body.iter_mut().zip(pad.iter()) {
            *b ^= *p;
        }
        Ok(())
    }
}
