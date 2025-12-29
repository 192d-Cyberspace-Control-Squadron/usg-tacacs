// SPDX-License-Identifier: AGPL-3.0-only
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use openssl::hash::{MessageDigest, hash};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use usg_tacacs_proto::{
    AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_PASS, AuthSessionState, AuthenReply,
};

#[derive(Clone, Debug)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub search_base: String,
    pub username_attr: String,
    pub timeout: Duration,
    pub ca_file: Option<PathBuf>,
    pub required_group: Vec<String>,
    pub group_attr: String,
}

impl LdapConfig {
    pub async fn authenticate(&self, username: &str, password: &str) -> bool {
        let cfg = self.clone();
        let user = username.to_string();
        let pass = password.to_string();
        task::spawn_blocking(move || ldap_authenticate_blocking(cfg, &user, &pass))
            .await
            .unwrap_or(false)
    }
}

fn ldap_authenticate_blocking(cfg: LdapConfig, username: &str, password: &str) -> bool {
    if !cfg.url.to_lowercase().starts_with("ldaps://") {
        return false;
    }
    let settings = LdapConnSettings::new().set_conn_timeout(cfg.timeout);
    if cfg.ca_file.is_some() {
        // ldap3 with tls-native uses system roots; custom CA not supported in this build.
    }
    let Ok(mut ldap) = LdapConn::with_settings(settings, &cfg.url) else {
        return false;
    };
    if ldap
        .simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .and_then(|r| r.success())
        .is_err()
    {
        return false;
    }
    let filter = format!("({}={})", cfg.username_attr, username);
    let search = ldap.search(
        &cfg.search_base,
        Scope::Subtree,
        &filter,
        vec!["dn", &cfg.group_attr],
    );
    let Ok((results, _res)) = search.and_then(|r| r.success()) else {
        return false;
    };
    let Some(entry) = results.into_iter().next() else {
        return false;
    };
    let user_dn = SearchEntry::construct(entry).dn;
    if !cfg.required_group.is_empty() {
        let search = ldap
            .search(&cfg.search_base, Scope::Subtree, &filter, vec![&cfg.group_attr])
            .and_then(|r| r.success());
        if let Ok((entries, _)) = search {
            if let Some(entry) = entries.into_iter().next() {
                let se = SearchEntry::construct(entry);
                let groups = se.attrs.get(&cfg.group_attr).cloned().unwrap_or_default();
                if !groups.iter().any(|g| {
                    cfg.required_group
                        .iter()
                        .any(|req| g.eq_ignore_ascii_case(req))
                }) {
                    return false;
                }
            }
        }
    }
    ldap.simple_bind(&user_dn, password)
        .and_then(|r| r.success())
        .is_ok()
}

pub async fn ldap_fetch_groups(cfg: &Arc<LdapConfig>, username: &str) -> Vec<String> {
    let cfg = cfg.clone();
    let user = username.to_string();
    task::spawn_blocking(move || ldap_fetch_groups_blocking(cfg, &user))
        .await
        .unwrap_or_default()
}

fn ldap_fetch_groups_blocking(cfg: Arc<LdapConfig>, username: &str) -> Vec<String> {
    if !cfg.url.to_lowercase().starts_with("ldaps://") {
        return Vec::new();
    }
    let settings = LdapConnSettings::new().set_conn_timeout(cfg.timeout);
    let Ok(mut ldap) = LdapConn::with_settings(settings, &cfg.url) else {
        return Vec::new();
    };
    if ldap.simple_bind(&cfg.bind_dn, &cfg.bind_password).and_then(|r| r.success()).is_err() {
        return Vec::new();
    }
    let filter = format!("({}={})", cfg.username_attr, username);
    let search = ldap
        .search(&cfg.search_base, Scope::Subtree, &filter, vec![&cfg.group_attr])
        .and_then(|r| r.success());
    let Ok((entries, _)) = search else {
        return Vec::new();
    };
    if let Some(entry) = entries.into_iter().next() {
        let se = SearchEntry::construct(entry);
        let groups = se
            .attrs
            .get(&cfg.group_attr)
            .cloned()
            .unwrap_or_default();
        return groups.into_iter().map(|g| g.to_lowercase()).collect();
    }
    Vec::new()
}

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

pub async fn verify_password_sources(
    username: Option<&str>,
    password: &[u8],
    creds: &HashMap<String, String>,
    ldap: Option<&Arc<LdapConfig>>,
) -> bool {
    // Prefer raw-byte match against static credentials.
    if let Some(user) = username {
        if verify_pap_bytes(user, password, creds) {
            return true;
        }
    }
    // Try LDAP if enabled and username/password are UTF-8.
    if let (Some(user), Some(ldap_cfg)) = (username, ldap) {
        if let Ok(pass_str) = std::str::from_utf8(password) {
            return ldap_cfg.authenticate(user, pass_str).await;
        }
    }
    false
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
