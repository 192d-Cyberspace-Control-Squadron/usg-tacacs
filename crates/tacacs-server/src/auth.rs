// SPDX-License-Identifier: AGPL-3.0-only
use openssl::hash::{MessageDigest, hash};
use std::collections::HashMap;

pub fn verify_pap(user: &str, password: &str, creds: &HashMap<String, String>) -> bool {
    creds
        .get(user)
        .map(|stored| stored == password)
        .unwrap_or(false)
}

pub fn compute_chap_response(
    user: &str,
    creds: &HashMap<String, String>,
    continue_data: &[u8],
    challenge: &[u8],
) -> Option<bool> {
    if continue_data.len() != 1 + 16 || challenge.len() != 16 {
        return None;
    }
    let chap_id = continue_data[0];
    let response = &continue_data[1..];
    let password = creds.get(user)?;
    let mut buf = Vec::with_capacity(1 + password.len() + challenge.len());
    buf.push(chap_id);
    buf.extend_from_slice(password.as_bytes());
    buf.extend_from_slice(challenge);
    let digest = hash(MessageDigest::md5(), &buf).ok()?;
    Some(digest.as_ref() == response)
}
