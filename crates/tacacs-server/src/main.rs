use crate::config::{Args, credentials_map};
use crate::server::{
    ConnLimiter, serve_legacy, serve_tls, tls_acceptor, validate_policy, watch_sighup,
};
use crate::auth::LdapConfig;
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, warn};
use tracing_subscriber::fmt::time::UtcTime;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::MIN_SECRET_LEN;

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_timer(UtcTime::rfc_3339())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let args = Args::parse();

    if let Some(policy_path) = args.check_policy.as_ref() {
        let schema = args
            .schema
            .as_ref()
            .context("--schema is required with --check-policy")?;
        validate_policy(policy_path, Some(schema))?;
        println!("policy validated");
        return Ok(());
    }

    let policy_path = args
        .policy
        .as_ref()
        .context("a --policy path is required to start the server")?;
    let engine = PolicyEngine::from_path(policy_path, args.schema.as_ref())?;
    let shared_policy = Arc::new(RwLock::new(engine));
    let shared_secret: Option<Arc<Vec<u8>>> = args
        .secret
        .as_ref()
        .map(|s| Arc::new(s.clone().into_bytes()));
    if let (Some(secret), Some(psk)) = (args.secret.as_ref(), args.tls_psk.as_ref()) {
        if secret == psk {
            bail!("TACACS+ shared secret must not match TLS PSK");
        }
    }
    let credentials: Arc<HashMap<String, String>> = Arc::new(credentials_map(&args));
    let ascii_backoff_max_ms = args.ascii_backoff_max_ms;
    let ascii_lockout_limit = args.ascii_lockout_limit;
    let single_connect_idle_secs = args.single_connect_idle_secs;
    let single_connect_keepalive_secs = args.single_connect_keepalive_secs;
    let conn_limiter = ConnLimiter::new(args.max_connections_per_ip);
    let ldap_config: Option<Arc<LdapConfig>> = if let Some(url) = args.ldaps_url.clone() {
        let bind_dn = args
            .ldap_bind_dn
            .clone()
            .context("--ldap-bind-dn is required with --ldaps-url")?;
        let bind_password = args
            .ldap_bind_password
            .clone()
            .context("--ldap-bind-password is required with --ldaps-url")?;
        let search_base = args
            .ldap_search_base
            .clone()
            .context("--ldap-search-base is required with --ldaps-url")?;
        Some(Arc::new(LdapConfig {
            url,
            bind_dn,
            bind_password,
            search_base,
            username_attr: args.ldap_username_attr.clone(),
            timeout: Duration::from_millis(args.ldap_timeout_ms),
            ca_file: args.ldap_ca_file.clone(),
        }))
    } else {
        None
    };

    let mut handles = Vec::new();

    if let Some(addr) = args.listen_tls {
        let allow_unencrypted = !(args.forbid_unencrypted
            && shared_secret
                .as_ref()
                .map(|s| s.len() >= MIN_SECRET_LEN)
                .unwrap_or(false));
        if allow_unencrypted
            && shared_secret.as_ref().map(|s| s.len()).unwrap_or(0) < MIN_SECRET_LEN
        {
            warn!("TLS mode: shared secret missing/short; UNENCRYPTED packets will be accepted");
        }
        let cert = args
            .tls_cert
            .as_ref()
            .context("--tls-cert is required when --listen-tls is set")?;
        let key = args
            .tls_key
            .as_ref()
            .context("--tls-key is required when --listen-tls is set")?;
        let ca = args
            .client_ca
            .as_ref()
            .context("--client-ca is required when --listen-tls is set")?;
        let acceptor = tls_acceptor(cert, key, ca, &args.tls_trust_root)?;
        let policy = shared_policy.clone();
        let secret = shared_secret.clone();
        let credentials = credentials.clone();
        let ascii_attempt_limit = args.ascii_attempt_limit;
        let ascii_user_attempt_limit = args.ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = args.ascii_pass_attempt_limit;
        let ascii_backoff_ms = args.ascii_backoff_ms;
        let ascii_backoff_max_ms = ascii_backoff_max_ms;
        let ascii_lockout_limit = ascii_lockout_limit;
        let single_connect_idle_secs = single_connect_idle_secs;
        let single_connect_keepalive_secs = single_connect_keepalive_secs;
        let conn_limiter = conn_limiter.clone();
        let allowed_cn = args.tls_allowed_client_cn.clone();
        let allowed_san = args.tls_allowed_client_san.clone();
        let ldap_config = ldap_config.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_tls(
                addr,
                acceptor,
                policy,
                secret,
                credentials,
                ascii_attempt_limit,
                ascii_user_attempt_limit,
                ascii_pass_attempt_limit,
                ascii_backoff_ms,
                ascii_backoff_max_ms,
                ascii_lockout_limit,
                single_connect_idle_secs,
                single_connect_keepalive_secs,
                conn_limiter,
                allowed_cn,
                allowed_san,
                ldap_config,
            )
            .await
            {
                error!(error = %err, "TLS listener stopped");
            }
        }));
    }

    if let Some(addr) = args.listen_legacy {
        if shared_secret.as_deref().map(|s| s.len()).unwrap_or(0) < MIN_SECRET_LEN {
            bail!(
                "legacy TACACS+ requires a shared secret of at least {} bytes",
                MIN_SECRET_LEN
            );
        }
        let policy = shared_policy.clone();
        let secret = shared_secret.clone();
        let credentials = credentials.clone();
        let ascii_attempt_limit = args.ascii_attempt_limit;
        let ascii_user_attempt_limit = args.ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = args.ascii_pass_attempt_limit;
        let ascii_backoff_ms = args.ascii_backoff_ms;
        let ascii_backoff_max_ms = ascii_backoff_max_ms;
        let ascii_lockout_limit = ascii_lockout_limit;
        let single_connect_idle_secs = single_connect_idle_secs;
        let single_connect_keepalive_secs = single_connect_keepalive_secs;
        let conn_limiter = conn_limiter.clone();
        let ldap_config = ldap_config.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_legacy(
                addr,
                policy,
                secret,
                credentials,
                ascii_attempt_limit,
                ascii_user_attempt_limit,
                ascii_pass_attempt_limit,
                ascii_backoff_ms,
                ascii_backoff_max_ms,
                ascii_lockout_limit,
                single_connect_idle_secs,
                single_connect_keepalive_secs,
                conn_limiter,
                ldap_config,
            )
            .await
            {
                error!(error = %err, "legacy listener stopped");
            }
        }));
    }

    if handles.is_empty() {
        bail!("no listeners configured; set --listen-tls and/or --listen-legacy");
    }

    let policy = shared_policy.clone();
    let schema_path = args.schema.clone();
    let policy_path = policy_path.clone();
    handles.push(tokio::spawn(async move {
        watch_sighup(policy_path, schema_path, policy).await;
    }));

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

mod ascii;
mod auth;
mod config;
mod policy;
mod server;
mod session;
mod tls;
