// SPDX-License-Identifier: AGPL-3.0-only
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use tokio_rustls::rustls::{
    self, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};

pub fn build_tls_config(
    cert: &PathBuf,
    key: &PathBuf,
    client_ca: &PathBuf,
) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'_>> = load_certs(cert)?;
    let key: PrivateKeyDer<'_> = load_key(key)?;
    let mut roots: RootCertStore = RootCertStore::empty();
    for ca in load_certs(client_ca)? {
        roots.add(ca).context("adding client CA")?;
    }

    let client_auth = WebPkiClientVerifier::builder(roots.into())
        .build()
        .context("building client verifier")?;
    let mut config: rustls::ServerConfig =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
            .context("building TLS config")?;

    config.alpn_protocols = vec![];
    Ok(config)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader: BufReader<File> = BufReader::new(
        File::open(path).with_context(|| format!("opening certificate {}", path.display()))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))?;
    Ok(certs)
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let mut reader: BufReader<File> = BufReader::new(
        File::open(path).with_context(|| format!("opening private key {}", path.display()))?,
    );
    if let Some(key) = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("reading private key {}", path.display()))?
    {
        Ok(key)
    } else {
        bail!("no private key found in {}", path.display());
    }
}
