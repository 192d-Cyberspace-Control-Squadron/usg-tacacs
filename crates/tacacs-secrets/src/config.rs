//! Configuration structures for secrets management.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level secrets configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// OpenBao configuration (optional).
    #[serde(default)]
    pub openbao: Option<OpenBaoConfig>,

    /// PKI configuration for automatic certificate management (optional).
    #[serde(default)]
    pub pki: Option<PkiConfig>,
}

/// OpenBao/Vault client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBaoConfig {
    /// OpenBao server address (e.g., "https://openbao.internal:8200").
    pub address: String,

    /// Authentication method. Currently only "approle" is supported.
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// Path to file containing the AppRole role_id.
    pub role_id_file: PathBuf,

    /// Path to file containing the AppRole secret_id.
    pub secret_id_file: PathBuf,

    /// Optional CA certificate file for TLS verification.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,

    /// Secret refresh interval in seconds.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// Location identifier for per-location secrets.
    #[serde(default)]
    pub location: Option<String>,

    /// Base path for TACACS secrets in OpenBao.
    #[serde(default = "default_secret_path")]
    pub secret_path: String,

    /// Connection timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum retry attempts for transient failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

impl Default for OpenBaoConfig {
    fn default() -> Self {
        Self {
            address: "https://openbao.internal:8200".to_string(),
            auth_method: default_auth_method(),
            role_id_file: PathBuf::from("/etc/tacacs/openbao-role-id"),
            secret_id_file: PathBuf::from("/etc/tacacs/openbao-secret-id"),
            ca_file: None,
            refresh_interval_secs: default_refresh_interval(),
            location: None,
            secret_path: default_secret_path(),
            timeout_ms: default_timeout_ms(),
            max_retries: default_max_retries(),
        }
    }
}

/// PKI secrets engine configuration for automatic certificate management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Whether PKI auto-renewal is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// PKI secrets engine mount point (default: "pki").
    #[serde(default = "default_pki_mount")]
    pub mount: String,

    /// PKI role name for certificate issuance.
    #[serde(default = "default_pki_role")]
    pub role: String,

    /// Common name for the certificate.
    pub common_name: Option<String>,

    /// Certificate TTL in hours (default: 720 = 30 days).
    #[serde(default = "default_pki_ttl_hours")]
    pub ttl_hours: u32,

    /// Path to write the certificate PEM file.
    pub cert_path: PathBuf,

    /// Path to write the private key PEM file.
    pub key_path: PathBuf,

    /// Renewal threshold as percentage of TTL (default: 70%).
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold_percent: u8,

    /// Check interval for certificate renewal in seconds.
    #[serde(default = "default_renewal_check_interval")]
    pub renewal_check_interval_secs: u64,
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount: default_pki_mount(),
            role: default_pki_role(),
            common_name: None,
            ttl_hours: default_pki_ttl_hours(),
            cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            key_path: PathBuf::from("/etc/tacacs/server.key"),
            renewal_threshold_percent: default_renewal_threshold(),
            renewal_check_interval_secs: default_renewal_check_interval(),
        }
    }
}

// Default value functions for serde
fn default_auth_method() -> String {
    "approle".to_string()
}

fn default_refresh_interval() -> u64 {
    300 // 5 minutes
}

fn default_secret_path() -> String {
    "secret/data/tacacs".to_string()
}

fn default_timeout_ms() -> u64 {
    5000 // 5 seconds
}

fn default_max_retries() -> u32 {
    5
}

fn default_pki_mount() -> String {
    "pki".to_string()
}

fn default_pki_role() -> String {
    "tacacs-server".to_string()
}

fn default_pki_ttl_hours() -> u32 {
    720 // 30 days
}

fn default_renewal_threshold() -> u8 {
    70
}

fn default_renewal_check_interval() -> u64 {
    3600 // 1 hour
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_openbao_config() {
        let config = OpenBaoConfig::default();
        assert_eq!(config.auth_method, "approle");
        assert_eq!(config.refresh_interval_secs, 300);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_default_pki_config() {
        let config = PkiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.mount, "pki");
        assert_eq!(config.role, "tacacs-server");
        assert_eq!(config.ttl_hours, 720);
        assert_eq!(config.renewal_threshold_percent, 70);
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = SecretsConfig {
            openbao: Some(OpenBaoConfig {
                address: "https://vault.example.com:8200".to_string(),
                location: Some("NYC01".to_string()),
                ..Default::default()
            }),
            pki: Some(PkiConfig {
                enabled: true,
                common_name: Some("nyc01.tacacs.internal".to_string()),
                ..Default::default()
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SecretsConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.openbao.as_ref().unwrap().address,
            "https://vault.example.com:8200"
        );
        assert_eq!(
            parsed.openbao.as_ref().unwrap().location,
            Some("NYC01".to_string())
        );
        assert!(parsed.pki.as_ref().unwrap().enabled);
    }
}
