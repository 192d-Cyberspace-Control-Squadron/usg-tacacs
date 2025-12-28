// SPDX-License-Identifier: AGPL-3.0-only
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
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
