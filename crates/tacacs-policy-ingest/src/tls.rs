// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, sync::Arc};

/// Build a RustlsConfig that *requires* client certs (mTLS).
/// Env:
///  - TLS_CERT: server cert PEM (may include chain)
///  - TLS_KEY: server key PEM (PKCS#8)
///  - CLIENT_CA: CA PEM used to verify *client* certs (publishers)
///  - CLIENT_ALLOWED_CN: optional comma-separated CN allowlist
///  - CLIENT_ALLOWED_SAN: optional comma-separated DNS SAN allowlist
pub async fn make_rustls_config_from_env() -> Result<RustlsConfig> {
    let cert_path = std::env::var("TLS_CERT").context("TLS_CERT required")?;
    let key_path = std::env::var("TLS_KEY").context("TLS_KEY required")?;
    let client_ca_path = std::env::var("CLIENT_CA").context("CLIENT_CA required")?;
    let allowed_cn = std::env::var("CLIENT_ALLOWED_CN").unwrap_or_default();
    let allowed_san = std::env::var("CLIENT_ALLOWED_SAN").unwrap_or_default();

    let server_certs = load_certs(&cert_path)?;
    let server_key = load_key(&key_path)?;
    let client_roots = load_ca_roots(&client_ca_path)?;

    let base = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .context("failed building client verifier")?;

    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        if allowed_cn.is_empty() && allowed_san.is_empty() {
            base
        } else {
            Arc::new(crate::tls_allowlist::AllowlistVerifier::new(
                base,
                allowed_cn,
                allowed_san,
            ))
        };

    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .context("failed building rustls ServerConfig")?;

    Ok(RustlsConfig::from_config(Arc::new(cfg)))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| format!("open cert: {path}"))?;
    let mut r = BufReader::new(f);
    let certs = certs(&mut r).collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = File::open(path).with_context(|| format!("open key: {path}"))?;
    let mut r = BufReader::new(f);
    let keys = pkcs8_private_keys(&mut r).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = keys.into_iter().next().context("no PKCS#8 key found")?;
    Ok(key.into())
}

fn load_ca_roots(path: &str) -> Result<RootCertStore> {
    let f = File::open(path).with_context(|| format!("open client ca: {path}"))?;
    let mut r = BufReader::new(f);

    let mut roots = RootCertStore::empty();
    let ca = certs(&mut r).collect::<std::result::Result<Vec<_>, _>>()?;
    for c in ca {
        roots.add(c)?;
    }
    Ok(roots)
}
