// SPDX-License-Identifier: AGPL-3.0-only
use crate::auth::{verify_pap_bytes, verify_pap_bytes_username};
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::{
    AuthSessionState, AuthenReply, AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS, AUTHEN_STATUS_RESTART,
};

const AUTHEN_CONT_ABORT: u8 = 0x01;

pub struct AsciiConfig {
    pub attempt_limit: u8,
    pub user_attempt_limit: u8,
    pub pass_attempt_limit: u8,
    pub backoff_ms: u64,
    pub backoff_max_ms: u64,
    pub lockout_limit: u8,
}

pub fn calc_ascii_backoff_capped(base_ms: u64, attempt: u8, cap_ms: u64) -> Option<Duration> {
    if base_ms == 0 {
        return None;
    }
    // exponential backoff: base * 2^(attempt-1)
    let exp = base_ms.saturating_mul(1u64 << attempt.saturating_sub(1));
    let capped = if cap_ms == 0 { exp } else { exp.min(cap_ms) };
    let mut jitter = 0;
    let mut buf = [0u8; 2];
    if rand_bytes(&mut buf).is_ok() {
        let max_jitter = base_ms.min(5_000);
        jitter = (u16::from_be_bytes(buf) as u64) % (max_jitter + 1);
    }
    Some(Duration::from_millis(capped.saturating_add(jitter)))
}

pub fn username_for_policy<'a>(
    decoded: Option<&'a str>,
    raw: Option<&'a Vec<u8>>,
) -> Option<String> {
    if let Some(u) = decoded {
        return Some(u.to_string());
    }
    raw.map(|bytes| hex::encode(bytes))
}

pub fn field_for_policy<'a>(decoded: Option<&'a str>, raw: Option<&'a Vec<u8>>) -> Option<String> {
    if let Some(v) = decoded {
        return Some(v.to_string());
    }
    raw.map(|bytes| hex::encode(bytes))
}

fn build_ascii_prompts(
    policy: &PolicyEngine,
    state: &AuthSessionState,
    user_msg: &[u8],
    username_for_policy: Option<&str>,
    port_for_policy: Option<&str>,
    rem_for_policy: Option<&str>,
) -> (Vec<u8>, Vec<u8>) {
    let policy_user_prompt = policy
        .prompt_username(username_for_policy, port_for_policy, rem_for_policy)
        .map(|s| s.as_bytes().to_vec());
    let policy_pass_prompt = policy
        .prompt_password(username_for_policy)
        .map(|s| s.as_bytes().to_vec());
    let uname_prompt = if !user_msg.is_empty() {
        user_msg.to_vec()
    } else if let Some(custom) = policy_user_prompt {
        custom
    } else {
        match (state.service, state.action) {
            (Some(svc), Some(act)) => {
                format!("Username (service {svc}, action {act}):").into_bytes()
            }
            (Some(svc), None) => format!("Username (service {svc}):").into_bytes(),
            _ => b"Username:".to_vec(),
        }
    };
    let pwd_prompt = if !user_msg.is_empty() {
        user_msg.to_vec()
    } else if let Some(custom) = policy_pass_prompt {
        custom
    } else {
        match (state.service, state.action) {
            (Some(svc), Some(act)) => {
                format!("Password (service {svc}, action {act}):").into_bytes()
            }
            (Some(svc), None) => format!("Password (service {svc}):").into_bytes(),
            _ => b"Password:".to_vec(),
        }
    };
    (uname_prompt, pwd_prompt)
}

pub async fn handle_ascii_continue(
    cont_user_msg: &[u8],
    cont_data: &[u8],
    cont_flags: u8,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &HashMap<String, String>,
    config: &AsciiConfig,
) -> AuthenReply {
    let policy_user = username_for_policy(state.username.as_deref(), state.username_raw.as_ref());
    let policy_port = field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
    let policy_rem = field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
    let (uname_prompt, pwd_prompt) = {
        let policy = policy.read().await;
        build_ascii_prompts(
            &policy,
            state,
            cont_user_msg,
            policy_user.as_deref(),
            policy_port.as_deref(),
            policy_rem.as_deref(),
        )
    };

    if cont_flags & AUTHEN_CONT_ABORT != 0 {
        state.ascii_need_user = true;
        state.ascii_need_pass = false;
        state.username = None;
        state.username_raw = None;
        state.ascii_attempts = 0;
        state.ascii_user_attempts = 0;
        state.ascii_pass_attempts = 0;
        let policy_abort = {
            let policy = policy.read().await;
            policy.message_abort().map(|m| m.to_string())
        };
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: policy_abort.unwrap_or_else(|| "authentication aborted".into()),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }

    if config.attempt_limit > 0 && state.ascii_attempts >= config.attempt_limit {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many authentication attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if state.ascii_need_user
        && config.user_attempt_limit > 0
        && state.ascii_user_attempts >= config.user_attempt_limit
    {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many username attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if state.ascii_need_pass
        && config.pass_attempt_limit > 0
        && state.ascii_pass_attempts >= config.pass_attempt_limit
    {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many password attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }

    if config.attempt_limit > 0 {
        state.ascii_attempts = state.ascii_attempts.saturating_add(1);
    }
    if config.lockout_limit > 0 && state.ascii_attempts >= config.lockout_limit {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "authentication locked out".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }

    if state.ascii_need_user {
        state.ascii_user_attempts = state.ascii_user_attempts.saturating_add(1);
        let username_raw = cont_data.to_vec();
        if !username_raw.is_empty() {
            state.username_raw = Some(username_raw.clone());
            state.username = String::from_utf8(username_raw).ok();
            state.ascii_need_user = false;
            state.ascii_need_pass = true;
            AuthenReply {
                status: AUTHEN_STATUS_GETPASS,
                flags: AUTHEN_FLAG_NOECHO,
                server_msg: String::new(),
                server_msg_raw: Vec::new(),
                data: pwd_prompt,
            }
        } else {
            if let Some(delay) =
                calc_ascii_backoff_capped(config.backoff_ms, state.ascii_attempts, config.backoff_max_ms)
            {
                sleep(delay).await;
            }
            AuthenReply {
                status: AUTHEN_STATUS_GETUSER,
                flags: 0,
                server_msg: String::new(),
                server_msg_raw: Vec::new(),
                data: uname_prompt,
            }
        }
    } else if state.ascii_need_pass {
        state.ascii_pass_attempts = state.ascii_pass_attempts.saturating_add(1);
        if cont_data.is_empty() {
            if let Some(delay) =
                calc_ascii_backoff_capped(config.backoff_ms, state.ascii_attempts, config.backoff_max_ms)
            {
                sleep(delay).await;
            }
            AuthenReply {
                status: AUTHEN_STATUS_GETPASS,
                flags: AUTHEN_FLAG_NOECHO,
                server_msg: String::new(),
                server_msg_raw: Vec::new(),
                data: pwd_prompt,
            }
        } else {
            state.ascii_need_pass = false;
            let ok = if let Some(raw_user) = state.username_raw.as_ref() {
                verify_pap_bytes_username(raw_user, cont_data, credentials)
            } else {
                let user = state.username.clone().unwrap_or_default();
                verify_pap_bytes(&user, cont_data, credentials)
            };
            if !ok {
                if let Some(delay) =
                    calc_ascii_backoff_capped(config.backoff_ms, state.ascii_attempts, config.backoff_max_ms)
                {
                    sleep(delay).await;
                }
            }
            let svc_str = state
                .service
                .map(|svc| format!(" (service {svc})"))
                .unwrap_or_default();
            let act_str = state
                .action
                .map(|act| format!(" action {act}"))
                .unwrap_or_default();
            let policy = policy.read().await;
            AuthenReply {
                status: if ok {
                    AUTHEN_STATUS_PASS
                } else {
                    AUTHEN_STATUS_FAIL
                },
                flags: 0,
                server_msg: if ok {
                    policy
                        .message_success()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| format!("authentication succeeded{svc_str}{act_str}"))
                } else {
                    policy
                        .message_failure()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| format!("invalid credentials{svc_str}{act_str}"))
                },
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        }
    } else {
        state.ascii_need_user = true;
        state.ascii_need_pass = false;
        state.username = None;
        state.username_raw = None;
        state.ascii_attempts = 0;
        state.ascii_user_attempts = 0;
        state.ascii_pass_attempts = 0;
        AuthenReply {
            status: AUTHEN_STATUS_RESTART,
            flags: 0,
            server_msg: "restart authentication".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        }
    }
}
