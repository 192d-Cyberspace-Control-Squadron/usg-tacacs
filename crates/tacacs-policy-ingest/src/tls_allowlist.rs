// SPDX-License-Identifier: AGPL-3.0-only
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use std::sync::Arc;
use x509_parser::{extensions::GeneralName, prelude::FromDer};

#[derive(Debug)]
pub struct AllowlistVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allowed_cn: Vec<String>,
    allowed_san: Vec<String>,
}

impl AllowlistVerifier {
    pub fn new(inner: Arc<dyn ClientCertVerifier>, cn_csv: String, san_csv: String) -> Self {
        let allowed_cn = cn_csv
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let allowed_san = san_csv
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        Self {
            inner,
            allowed_cn,
            allowed_san,
        }
    }
}

impl ClientCertVerifier for AllowlistVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        // Chain/time validation
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        if self.allowed_cn.is_empty() && self.allowed_san.is_empty() {
            return Ok(ClientCertVerified::assertion());
        }

        let (_rem, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("invalid client cert".into()))?;

        if !self.allowed_cn.is_empty()
            && let Some(cn) = cert.subject().iter_common_name().next()
            && let Ok(cn_str) = cn.as_str()
            && self
                .allowed_cn
                .iter()
                .any(|a| a.eq_ignore_ascii_case(cn_str.trim()))
        {
            return Ok(ClientCertVerified::assertion());
        }

        if !self.allowed_san.is_empty()
            && let Ok(Some(sans)) = cert.subject_alternative_name()
        {
            for san in sans.value.general_names.iter() {
                if let GeneralName::DNSName(dns) = san {
                    let dns_val = dns.to_string();
                    if self
                        .allowed_san
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(dns_val.trim()))
                    {
                        return Ok(ClientCertVerified::assertion());
                    }
                }
            }
        }

        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
