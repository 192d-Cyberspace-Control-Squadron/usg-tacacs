// SPDX-License-Identifier: AGPL-3.0-only
use crate::config::StaticCreds;
use argon2::{PasswordHash, PasswordVerifier};
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
    #[tracing::instrument(skip(self, password), fields(ldap.url = %self.url))]
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
            .search(
                &cfg.search_base,
                Scope::Subtree,
                &filter,
                vec![&cfg.group_attr],
            )
            .and_then(|r| r.success());
        if let Ok((entries, _)) = search
            && let Some(entry) = entries.into_iter().next()
        {
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
    ldap.simple_bind(&user_dn, password)
        .and_then(|r| r.success())
        .is_ok()
}

#[tracing::instrument(skip(cfg), fields(ldap.url = %cfg.url))]
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
    if ldap
        .simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .and_then(|r| r.success())
        .is_err()
    {
        return Vec::new();
    }
    let filter = format!("({}={})", cfg.username_attr, username);
    let search = ldap
        .search(
            &cfg.search_base,
            Scope::Subtree,
            &filter,
            vec![&cfg.group_attr],
        )
        .and_then(|r| r.success());
    let Ok((entries, _)) = search else {
        return Vec::new();
    };
    if let Some(entry) = entries.into_iter().next() {
        let se = SearchEntry::construct(entry);
        let groups = se.attrs.get(&cfg.group_attr).cloned().unwrap_or_default();
        return groups.into_iter().map(|g| g.to_lowercase()).collect();
    }
    Vec::new()
}

#[tracing::instrument(skip(password, creds))]
pub fn verify_pap(user: &str, password: &str, creds: &StaticCreds) -> bool {
    if creds
        .plain
        .get(user)
        .map(|stored| stored == password)
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(hash) = creds.argon.get(user) {
        return verify_argon_hash(hash, password.as_bytes());
    }
    false
}

fn verify_argon_hash(hash: &str, password: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(password, &parsed)
        .is_ok()
}

pub fn verify_pap_bytes(user: &str, password: &[u8], creds: &StaticCreds) -> bool {
    if creds
        .plain
        .get(user)
        .map(|stored| stored.as_bytes() == password)
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(hash) = creds.argon.get(user) {
        return verify_argon_hash(hash, password);
    }
    false
}

pub fn verify_pap_bytes_username(username: &[u8], password: &[u8], creds: &StaticCreds) -> bool {
    creds
        .plain
        .iter()
        .any(|(u, p)| u.as_bytes() == username && p.as_bytes() == password)
        || creds
            .argon
            .iter()
            .any(|(u, h)| u.as_bytes() == username && verify_argon_hash(h, password))
}

#[tracing::instrument(skip(password, creds, ldap), fields(has_ldap = ldap.is_some()))]
pub async fn verify_password_sources(
    username: Option<&str>,
    password: &[u8],
    creds: &StaticCreds,
    ldap: Option<&Arc<LdapConfig>>,
) -> bool {
    // Prefer raw-byte match against static credentials.
    if let Some(user) = username
        && verify_pap_bytes(user, password, creds)
    {
        tracing::debug!("authenticated via static credentials");
        return true;
    }
    // Try LDAP if enabled and username/password are UTF-8.
    if let (Some(user), Some(ldap_cfg)) = (username, ldap)
        && let Ok(pass_str) = std::str::from_utf8(password)
    {
        let result = ldap_cfg.authenticate(user, pass_str).await;
        if result {
            tracing::debug!("authenticated via LDAP");
        }
        return result;
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
    credentials: &StaticCreds,
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
        &credentials.plain,
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

#[cfg(test)]
mod tests {
    use super::*;
    use usg_tacacs_proto::Header;

    fn make_creds() -> StaticCreds {
        let mut creds = StaticCreds::default();
        creds.plain.insert("admin".into(), "secret123".into());
        creds.plain.insert("user".into(), "password".into());
        creds
    }

    fn make_argon_creds() -> StaticCreds {
        let mut creds = StaticCreds::default();
        // Valid argon2id hash for password "test123"
        creds.argon.insert(
            "hashed_user".into(),
            "$argon2id$v=19$m=19456,t=2,p=1$bXlzYWx0MTIzNDU2Nzg$lT9bGlM5c7M8vbdNjLy3sA".into(),
        );
        creds
    }

    fn make_test_header() -> Header {
        Header {
            version: 0xC0,
            packet_type: 0x01,
            seq_no: 1,
            flags: 0,
            session_id: 12345,
            length: 0,
        }
    }

    fn make_test_session_state() -> AuthSessionState {
        let header = make_test_header();
        AuthSessionState::new_from_start(
            &header,
            0x01, // PAP
            "testuser".into(),
            b"testuser".to_vec(),
            "console".into(),
            b"console".to_vec(),
            "192.168.1.1".into(),
            b"192.168.1.1".to_vec(),
            0x01, // service
            0x01, // action
        )
        .unwrap()
    }

    // ==================== verify_pap Tests ====================

    #[test]
    fn verify_pap_valid_plain() {
        let creds = make_creds();
        assert!(verify_pap("admin", "secret123", &creds));
    }

    #[test]
    fn verify_pap_invalid_password() {
        let creds = make_creds();
        assert!(!verify_pap("admin", "wrongpassword", &creds));
    }

    #[test]
    fn verify_pap_unknown_user() {
        let creds = make_creds();
        assert!(!verify_pap("unknown", "secret123", &creds));
    }

    #[test]
    fn verify_pap_empty_password() {
        let mut creds = StaticCreds::default();
        creds.plain.insert("emptypass".into(), "".into());
        assert!(verify_pap("emptypass", "", &creds));
    }

    #[test]
    fn verify_pap_case_sensitive() {
        let creds = make_creds();
        assert!(!verify_pap("ADMIN", "secret123", &creds));
        assert!(!verify_pap("admin", "SECRET123", &creds));
    }

    #[test]
    fn verify_pap_argon_invalid_hash() {
        // Invalid argon2 hash format should return false
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "not-a-valid-hash".into());
        assert!(!verify_pap("user", "anypassword", &creds));
    }

    // ==================== verify_pap_bytes Tests ====================

    #[test]
    fn verify_pap_bytes_valid() {
        let creds = make_creds();
        assert!(verify_pap_bytes("admin", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_invalid() {
        let creds = make_creds();
        assert!(!verify_pap_bytes("admin", b"wrong", &creds));
    }

    #[test]
    fn verify_pap_bytes_with_null() {
        let mut creds = StaticCreds::default();
        // Password with embedded null byte
        creds.plain.insert("user".into(), "pass\0word".into());
        assert!(verify_pap_bytes("user", b"pass\0word", &creds));
    }

    #[test]
    fn verify_pap_bytes_binary() {
        let mut creds = StaticCreds::default();
        // Use String::from_utf8_lossy for binary data
        let binary_pass = String::from_utf8_lossy(&[0x7f, 0x00, 0x7e]).to_string();
        creds.plain.insert("user".into(), binary_pass.clone());
        assert!(verify_pap_bytes("user", binary_pass.as_bytes(), &creds));
    }

    // ==================== verify_pap_bytes_username Tests ====================

    #[test]
    fn verify_pap_bytes_username_valid() {
        let creds = make_creds();
        assert!(verify_pap_bytes_username(b"admin", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_invalid() {
        let creds = make_creds();
        assert!(!verify_pap_bytes_username(b"admin", b"wrong", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_unknown() {
        let creds = make_creds();
        assert!(!verify_pap_bytes_username(b"unknown", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_binary() {
        let mut creds = StaticCreds::default();
        // Use valid ASCII characters for username
        let binary_user = String::from_utf8_lossy(&[0x7f, 0x7e]).to_string();
        creds.plain.insert(binary_user.clone(), "pass".into());
        assert!(verify_pap_bytes_username(
            binary_user.as_bytes(),
            b"pass",
            &creds
        ));
    }

    // ==================== compute_chap_response Tests ====================

    #[test]
    fn compute_chap_response_valid() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        // Construct valid CHAP data: 1 byte ID + 16 bytes response
        let chap_id = 0x42u8;
        let challenge = [0x11u8; 16];

        // Compute expected MD5(id || password || challenge)
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let expected_digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut continue_data = vec![chap_id];
        continue_data.extend_from_slice(expected_digest.as_ref());

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn compute_chap_response_invalid() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 16];
        // Wrong response
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]); // All zeros = wrong

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn compute_chap_response_unknown_user() {
        let creds = HashMap::new();
        let challenge = [0x11u8; 16];
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]);

        let result = compute_chap_response("unknown", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    #[test]
    fn compute_chap_response_wrong_length() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 16];
        let continue_data = vec![0x42, 0x00, 0x00]; // Too short

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    #[test]
    fn compute_chap_response_wrong_challenge_length() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 8]; // Wrong length
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]);

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    // ==================== handle_chap_continue Tests ====================

    #[test]
    fn handle_chap_continue_invalid_length() {
        let mut state = make_test_session_state();
        let creds = make_creds();

        let result = handle_chap_continue("admin", &[0x42, 0x00, 0x00], &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_ERROR);
        assert!(result.server_msg.contains("length"));
    }

    #[test]
    fn handle_chap_continue_id_mismatch() {
        let mut state = make_test_session_state();
        state.chap_id = Some(0x42);
        state.challenge = Some(vec![0x11; 16]);
        let creds = make_creds();

        let mut cont_data = vec![0x99]; // Wrong ID
        cont_data.extend_from_slice(&[0u8; 16]);

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
        assert!(result.server_msg.contains("mismatch"));
    }

    #[test]
    fn handle_chap_continue_missing_credentials() {
        let mut state = make_test_session_state();
        state.challenge = Some(vec![0x11; 16]);
        let creds = StaticCreds::default();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]);

        let result = handle_chap_continue("unknown", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_ERROR);
        assert!(result.server_msg.contains("credentials"));
    }

    #[test]
    fn handle_chap_continue_invalid_response() {
        let mut state = make_test_session_state();
        state.challenge = Some(vec![0x11; 16]);
        let creds = make_creds();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]); // Wrong hash

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
        assert!(result.server_msg.contains("invalid CHAP response"));
    }

    #[test]
    fn handle_chap_continue_valid() {
        let mut state = make_test_session_state();
        let challenge = vec![0x11u8; 16];
        state.challenge = Some(challenge.clone());
        let chap_id = 0x42u8;
        state.chap_id = Some(chap_id);

        let mut creds = StaticCreds::default();
        creds.plain.insert("admin".into(), "secret".into());

        // Compute correct response
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut cont_data = vec![chap_id];
        cont_data.extend_from_slice(digest.as_ref());

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_PASS);
        assert!(state.challenge.is_none());
        assert!(state.chap_id.is_none());
    }

    // ==================== LdapConfig Tests ====================

    #[test]
    fn ldap_config_clone() {
        let config = LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin,dc=example,dc=com".into(),
            bind_password: "secret".into(),
            search_base: "dc=example,dc=com".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: Some(PathBuf::from("/etc/ssl/certs/ca.pem")),
            required_group: vec!["cn=admins,dc=example,dc=com".into()],
            group_attr: "memberOf".into(),
        };

        let cloned = config.clone();
        assert_eq!(cloned.url, config.url);
        assert_eq!(cloned.bind_dn, config.bind_dn);
        assert_eq!(cloned.bind_password, config.bind_password);
        assert_eq!(cloned.search_base, config.search_base);
        assert_eq!(cloned.username_attr, config.username_attr);
        assert_eq!(cloned.timeout, config.timeout);
        assert_eq!(cloned.ca_file, config.ca_file);
        assert_eq!(cloned.required_group, config.required_group);
        assert_eq!(cloned.group_attr, config.group_attr);
    }

    #[test]
    fn ldap_config_debug() {
        let config = LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("LdapConfig"));
        assert!(debug_str.contains("ldaps://example.com"));
    }

    // ==================== ldap_authenticate_blocking Tests ====================

    #[test]
    fn ldap_authenticate_blocking_non_ldaps_fails() {
        let config = LdapConfig {
            url: "ldap://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let result = ldap_authenticate_blocking(config, "user", "pass");
        assert!(!result); // Should fail because not LDAPS
    }

    #[test]
    fn ldap_authenticate_blocking_http_url_fails() {
        let config = LdapConfig {
            url: "http://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let result = ldap_authenticate_blocking(config, "user", "pass");
        assert!(!result);
    }

    // ==================== ldap_fetch_groups_blocking Tests ====================

    #[test]
    fn ldap_fetch_groups_blocking_non_ldaps_returns_empty() {
        let config = Arc::new(LdapConfig {
            url: "ldap://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        });

        let result = ldap_fetch_groups_blocking(config, "user");
        assert!(result.is_empty());
    }
}
