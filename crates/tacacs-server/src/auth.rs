// SPDX-License-Identifier: AGPL-3.0-only
use openssl::hash::{MessageDigest, hash};
use std::collections::HashMap;
use usg_tacacs_proto::{
    AuthSessionState, AuthenReply, AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_PASS,
};

pub fn verify_pap(user: &str, password: &str, creds: &HashMap<String, String>) -> bool {
    creds
        .get(user)
        .map(|stored| stored == password)
        .unwrap_or(false)
}

pub fn verify_pap_bytes(user: &str, password: &[u8], creds: &HashMap<String, String>) -> bool {
    creds
        .get(user)
        .map(|stored| stored.as_bytes() == password)
        .unwrap_or(false)
}

pub fn verify_pap_bytes_username(
    username: &[u8],
    password: &[u8],
    creds: &HashMap<String, String>,
) -> bool {
    creds
        .iter()
        .any(|(u, p)| u.as_bytes() == username && p.as_bytes() == password)
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

pub fn handle_chap_continue(
    user: &str,
    cont_data: &[u8],
    state: &mut AuthSessionState,
    credentials: &HashMap<String, String>,
) -> AuthenReply {
    if cont_data.len() != 1 + 16 {
        return AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: "invalid CHAP continue length".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if state.chap_id.is_some() && cont_data[0] != state.chap_id.unwrap() {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "CHAP identifier mismatch".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if let Some(expected) = compute_chap_response(
        user,
        credentials,
        cont_data,
        state.challenge.as_deref().unwrap_or(&[]),
    ) {
        state.challenge = None;
        state.chap_id = None;
        if expected {
            AuthenReply {
                status: AUTHEN_STATUS_PASS,
                flags: 0,
                server_msg: String::new(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        } else {
            AuthenReply {
                status: AUTHEN_STATUS_FAIL,
                flags: 0,
                server_msg: "invalid CHAP response".into(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        }
    } else {
        AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: "missing credentials".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        }
    }
}
