// SPDX-License-Identifier: AGPL-3.0-only
use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "usg-tacacs", version, about = "Rust TACACS+ server")]
pub struct Args {
    /// Validate a policy file and exit.
    #[arg(long)]
    pub check_policy: Option<PathBuf>,

    /// JSON schema to validate policy files against.
    #[arg(long)]
    pub schema: Option<PathBuf>,

    /// Path to the active policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Listen address for TACACS+ over TLS (mTLS required).
    #[arg(long)]
    pub listen_tls: Option<SocketAddr>,

    /// Listen address for legacy plaintext TACACS+.
    #[arg(long)]
    pub listen_legacy: Option<SocketAddr>,

    /// Server certificate (PEM).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Server private key (PEM).
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Client CA bundle (PEM).
    #[arg(long)]
    pub client_ca: Option<PathBuf>,

    /// Additional trusted root CAs for client mTLS verification (PEM, repeatable).
    #[arg(long, value_name = "CA_PEM", num_args = 0..)]
    pub tls_trust_root: Vec<PathBuf>,

    /// Shared secret for TACACS+ body obfuscation (required for legacy, recommended otherwise).
    #[arg(long)]
    pub secret: Option<String>,

    /// Reject UNENCRYPTED TACACS+ packets when a secret is configured, even over TLS.
    #[arg(long)]
    pub forbid_unencrypted: bool,

    /// Separate PSK for TLS; must not match the TACACS+ obfuscation secret.
    #[arg(long)]
    pub tls_psk: Option<String>,

    /// Static user:password pairs for PAP/CHAP verification (repeatable).
    #[arg(long, value_parser = parse_user_password, value_name = "USER:PASS")]
    pub user_password: Vec<(String, String)>,

    /// Maximum ASCII authentication attempts before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 5)]
    pub ascii_attempt_limit: u8,

    /// Maximum username prompts for ASCII auth before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 3)]
    pub ascii_user_attempt_limit: u8,

    /// Maximum password prompts for ASCII auth before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 5)]
    pub ascii_pass_attempt_limit: u8,

    /// Base backoff (ms) before repeating ASCII username/password prompts (0 = no delay).
    #[arg(long, default_value_t = 0)]
    pub ascii_backoff_ms: u64,

    /// Maximum backoff (ms) for ASCII prompt retries (0 = no cap).
    #[arg(long, default_value_t = 5000)]
    pub ascii_backoff_max_ms: u64,

    /// Lock out ASCII auth after this many attempts (0 = no lockout).
    #[arg(long, default_value_t = 0)]
    pub ascii_lockout_limit: u8,

    /// Idle timeout (seconds) for single-connection sessions before closing (0 = disabled).
    #[arg(long, default_value_t = 300)]
    pub single_connect_idle_secs: u64,

    /// Expected keepalive activity interval (seconds) for single-connection sessions; 0 disables the timeout.
    #[arg(long, default_value_t = 120)]
    pub single_connect_keepalive_secs: u64,

    /// Maximum concurrent connections allowed per peer IP (0 = unlimited).
    #[arg(long, default_value_t = 50)]
    pub max_connections_per_ip: u32,

    /// Allowed client certificate Common Names (exact match). If set, client CN must match one of these.
    #[arg(long, value_name = "CN", num_args = 0..)]
    pub tls_allowed_client_cn: Vec<String>,

    /// Allowed client certificate SAN entries (DNS/IP/URI exact match). If set, client SAN must match one of these.
    #[arg(long, value_name = "SAN", num_args = 0..)]
    pub tls_allowed_client_san: Vec<String>,

    /// LDAPS URL for LDAP authentication (must start with ldaps://). If unset, LDAP auth is disabled.
    #[arg(long)]
    pub ldaps_url: Option<String>,

    /// LDAP service account bind DN.
    #[arg(long)]
    pub ldap_bind_dn: Option<String>,

    /// LDAP service account password.
    #[arg(long)]
    pub ldap_bind_password: Option<String>,

    /// LDAP search base for locating user entries.
    #[arg(long)]
    pub ldap_search_base: Option<String>,

    /// LDAP attribute to match the TACACS+ username (default: uid).
    #[arg(long, default_value = "uid")]
    pub ldap_username_attr: String,

    /// LDAP connect/operation timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub ldap_timeout_ms: u64,

    /// Optional CA file for LDAPS validation.
    #[arg(long)]
    pub ldap_ca_file: Option<PathBuf>,

    /// Optional LDAP group DNs required for authentication (match-any).
    #[arg(long, value_name = "GROUP_DN", num_args = 0..)]
    pub ldap_required_group: Vec<String>,

    /// LDAP attribute to read group membership from (default: memberOf).
    #[arg(long, default_value = "memberOf")]
    pub ldap_group_attr: String,

    /// Legacy TACACS+ per-NAD secrets (IP:SECRET). When set, only listed NADs may use legacy TACACS+.
    #[arg(long, value_parser = parse_nad_secret, value_name = "IP:SECRET", num_args = 0..)]
    pub legacy_nad_secret: Vec<(IpAddr, String)>,
}

pub fn credentials_map(args: &Args) -> HashMap<String, String> {
    args.user_password.clone().into_iter().collect()
}

fn parse_user_password(s: &str) -> std::result::Result<(String, String), String> {
    let mut parts = s.splitn(2, ':');
    let user = parts
        .next()
        .ok_or_else(|| "missing user".to_string())?
        .to_string();
    let pass = parts
        .next()
        .ok_or_else(|| "missing password".to_string())?
        .to_string();
    if user.is_empty() {
        return Err("user cannot be empty".into());
    }
    Ok((user, pass))
}

fn parse_nad_secret(s: &str) -> std::result::Result<(IpAddr, String), String> {
    let mut parts = s.splitn(2, ':');
    let ip = parts
        .next()
        .ok_or_else(|| "missing NAD IP".to_string())?
        .parse::<IpAddr>()
        .map_err(|e| format!("invalid IP: {e}"))?;
    let secret = parts
        .next()
        .ok_or_else(|| "missing secret".to_string())?
        .to_string();
    if secret.is_empty() {
        return Err("secret cannot be empty".into());
    }
    Ok((ip, secret))
}
