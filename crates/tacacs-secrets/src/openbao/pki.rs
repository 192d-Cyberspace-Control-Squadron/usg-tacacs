//! PKI secrets engine client for certificate management.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;
use tracing::info;

/// Client for the PKI secrets engine.
///
/// Supports issuing and managing TLS certificates via OpenBao's PKI secrets engine.
pub struct PkiClient {
    /// PKI secrets engine mount point (e.g., "pki").
    mount: String,

    /// PKI role name for certificate issuance.
    role: String,
}

/// A certificate bundle returned from PKI issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBundle {
    /// The issued certificate in PEM format.
    pub certificate: String,

    /// The private key in PEM format.
    pub private_key: String,

    /// The issuing CA certificate in PEM format.
    pub issuing_ca: String,

    /// The full CA chain in PEM format (optional).
    #[serde(default)]
    pub ca_chain: Vec<String>,

    /// Certificate serial number.
    pub serial_number: String,

    /// Certificate expiration time.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub expiration: Option<OffsetDateTime>,
}

impl CertificateBundle {
    /// Get the full certificate chain (cert + CA chain).
    pub fn full_chain(&self) -> String {
        let mut chain = self.certificate.clone();
        for ca in &self.ca_chain {
            chain.push('\n');
            chain.push_str(ca);
        }
        chain
    }

    /// Write the certificate and key to files.
    pub fn write_to_files(&self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<()> {
        // Write certificate with proper permissions
        std::fs::write(cert_path, &self.certificate)
            .with_context(|| format!("failed to write certificate to {:?}", cert_path))?;

        // Write private key with restricted permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(key_path)
                .with_context(|| format!("failed to create key file {:?}", key_path))?;
            std::io::Write::write_all(&mut file, self.private_key.as_bytes())
                .with_context(|| format!("failed to write key to {:?}", key_path))?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(key_path, &self.private_key)
                .with_context(|| format!("failed to write key to {:?}", key_path))?;
        }

        info!(cert_path = ?cert_path, key_path = ?key_path, "wrote certificate and key files");
        Ok(())
    }

    /// Check if the certificate should be renewed based on TTL threshold.
    ///
    /// Returns true if the certificate has passed the specified percentage of its lifetime.
    pub fn should_renew(&self, threshold_percent: u8) -> bool {
        let Some(expiration) = self.expiration else {
            // If we don't know the expiration, assume renewal is needed
            return true;
        };

        let now = OffsetDateTime::now_utc();
        if expiration <= now {
            // Already expired
            return true;
        }

        // We don't have the not_before time from the API response,
        // so we estimate based on typical cert lifetime patterns
        // For simplicity, check if we're past the threshold of remaining time
        let remaining = expiration - now;
        let total_lifetime = time::Duration::days(30); // Assume 30-day certs as default

        let elapsed_ratio = 1.0 - (remaining.whole_seconds() as f64 / total_lifetime.whole_seconds() as f64);
        elapsed_ratio >= (threshold_percent as f64 / 100.0)
    }
}

/// PKI issue request parameters.
#[derive(Debug, Serialize)]
pub struct IssueRequest {
    /// Common name for the certificate.
    pub common_name: String,

    /// TTL for the certificate (e.g., "720h").
    pub ttl: String,

    /// Alternative names (SANs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,

    /// IP SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_sans: Vec<String>,
}

impl PkiClient {
    /// Create a new PKI client.
    pub fn new(mount: String, role: String) -> Self {
        Self { mount, role }
    }

    /// Get the API path for issuing certificates.
    pub fn issue_path(&self) -> String {
        format!("{}/issue/{}", self.mount, self.role)
    }

    /// Get the API path for reading the CA certificate.
    pub fn ca_path(&self) -> String {
        format!("{}/cert/ca", self.mount)
    }

    /// Create an issue request with the given common name and TTL.
    pub fn issue_request(&self, common_name: &str, ttl_hours: u32) -> IssueRequest {
        IssueRequest {
            common_name: common_name.to_string(),
            ttl: format!("{}h", ttl_hours),
            alt_names: Vec::new(),
            ip_sans: Vec::new(),
        }
    }

    /// Get the mount point.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// Get the role name.
    pub fn role(&self) -> &str {
        &self.role
    }
}

/// PKI issue response from OpenBao.
#[derive(Debug, Deserialize)]
pub struct IssueResponse {
    pub certificate: String,
    pub private_key: String,
    pub issuing_ca: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    pub serial_number: String,
    pub expiration: Option<i64>, // Unix timestamp
}

impl From<IssueResponse> for CertificateBundle {
    fn from(resp: IssueResponse) -> Self {
        let expiration = resp.expiration.map(|ts| {
            OffsetDateTime::from_unix_timestamp(ts).unwrap_or_else(|_| OffsetDateTime::now_utc())
        });

        Self {
            certificate: resp.certificate,
            private_key: resp.private_key,
            issuing_ca: resp.issuing_ca,
            ca_chain: resp.ca_chain,
            serial_number: resp.serial_number,
            expiration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_path() {
        let client = PkiClient::new("pki".to_string(), "tacacs-server".to_string());
        assert_eq!(client.issue_path(), "pki/issue/tacacs-server");
    }

    #[test]
    fn test_ca_path() {
        let client = PkiClient::new("pki".to_string(), "tacacs-server".to_string());
        assert_eq!(client.ca_path(), "pki/cert/ca");
    }

    #[test]
    fn test_issue_request() {
        let client = PkiClient::new("pki".to_string(), "tacacs-server".to_string());
        let req = client.issue_request("nyc01.tacacs.internal", 720);

        assert_eq!(req.common_name, "nyc01.tacacs.internal");
        assert_eq!(req.ttl, "720h");
        assert!(req.alt_names.is_empty());
    }

    #[test]
    fn test_certificate_bundle_full_chain() {
        let bundle = CertificateBundle {
            certificate: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_string(),
            private_key: "key".to_string(),
            issuing_ca: "ca".to_string(),
            ca_chain: vec!["intermediate".to_string(), "root".to_string()],
            serial_number: "123".to_string(),
            expiration: None,
        };

        let chain = bundle.full_chain();
        assert!(chain.contains("cert"));
        assert!(chain.contains("intermediate"));
        assert!(chain.contains("root"));
    }

    #[test]
    fn test_should_renew_expired() {
        let bundle = CertificateBundle {
            certificate: "cert".to_string(),
            private_key: "key".to_string(),
            issuing_ca: "ca".to_string(),
            ca_chain: vec![],
            serial_number: "123".to_string(),
            expiration: Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
        };

        assert!(bundle.should_renew(70));
    }

    #[test]
    fn test_should_renew_no_expiration() {
        let bundle = CertificateBundle {
            certificate: "cert".to_string(),
            private_key: "key".to_string(),
            issuing_ca: "ca".to_string(),
            ca_chain: vec![],
            serial_number: "123".to_string(),
            expiration: None,
        };

        assert!(bundle.should_renew(70));
    }
}
