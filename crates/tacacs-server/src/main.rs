use crate::config::{Args, credentials_map};
use crate::server::{serve_legacy, serve_tls, tls_acceptor, validate_policy, watch_sighup, ConnLimiter};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
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
        let acceptor = tls_acceptor(cert, key, ca)?;
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
