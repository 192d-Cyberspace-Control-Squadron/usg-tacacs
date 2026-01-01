//! KV v2 secrets engine client.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tracing::debug;

/// Client for the KV v2 secrets engine.
///
/// Supports reading secrets from OpenBao's KV v2 secrets engine,
/// which stores secrets with versioning and metadata.
pub struct KvClient {
    /// Base path for secrets (e.g., "secret/data/tacacs").
    base_path: String,
}

/// KV v2 secret data wrapper.
#[derive(Debug, Deserialize)]
pub struct KvData<T> {
    pub data: T,
    pub metadata: KvMetadata,
}

/// KV v2 secret metadata.
#[derive(Debug, Deserialize)]
pub struct KvMetadata {
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    pub version: u64,
}

/// Simple string value wrapper for secrets that are just strings.
#[derive(Debug, Deserialize)]
pub struct StringValue {
    pub value: String,
}

impl KvClient {
    /// Create a new KV client with the given base path.
    pub fn new(base_path: String) -> Self {
        Self { base_path }
    }

    /// Get the full API path for a secret.
    ///
    /// Handles the KV v2 path format where "secret/data/..." is used for reads.
    pub fn secret_path(&self, key: &str) -> String {
        // If base_path already contains /data/, use it directly
        // Otherwise, assume it's the mount point and add /data/
        if self.base_path.contains("/data/") {
            format!("{}/{}", self.base_path, key)
        } else {
            // Convert "secret/tacacs" to "secret/data/tacacs"
            let parts: Vec<&str> = self.base_path.splitn(2, '/').collect();
            if parts.len() == 2 {
                format!("{}/data/{}/{}", parts[0], parts[1], key)
            } else {
                format!("{}/data/{}", self.base_path, key)
            }
        }
    }

    /// Read a secret value as raw bytes.
    ///
    /// The secret is expected to be stored with a "value" field containing the data.
    pub async fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        // This would call the OpenBaoClient, but we need a reference to it
        // In practice, this is called through OpenBaoProvider which has the client
        // For now, this provides the path formatting logic
        debug!(path = %path, "reading secret from KV");

        // The actual HTTP call is made by OpenBaoClient
        // This method is called via the provider which has access to the client
        Ok(None) // Placeholder - actual implementation in OpenBaoProvider
    }

    /// Read a secret and deserialize it as JSON.
    pub async fn read_json<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        debug!(path = %path, "reading JSON secret from KV");

        // Placeholder - actual implementation in OpenBaoProvider
        Ok(None)
    }

    /// Get the base path.
    pub fn base_path(&self) -> &str {
        &self.base_path
    }
}

/// Actual KV read operations that work with an OpenBaoClient.
/// These are extension methods used by OpenBaoProvider.
impl KvClient {
    /// Parse a KV v2 response and extract the value.
    pub fn parse_string_value(data: &serde_json::Value) -> Result<Option<Vec<u8>>> {
        // KV v2 wraps data in a "data" object
        if let Some(inner_data) = data.get("data") {
            if let Some(value) = inner_data.get("value") {
                if let Some(s) = value.as_str() {
                    return Ok(Some(s.as_bytes().to_vec()));
                }
            }
        }
        Ok(None)
    }

    /// Parse a KV v2 response and deserialize the data field.
    pub fn parse_json_value<T: DeserializeOwned>(data: &serde_json::Value) -> Result<Option<T>> {
        if let Some(inner_data) = data.get("data") {
            let parsed: T = serde_json::from_value(inner_data.clone())
                .context("failed to parse secret data as JSON")?;
            return Ok(Some(parsed));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_path_with_data() {
        let kv = KvClient::new("secret/data/tacacs".to_string());
        assert_eq!(kv.secret_path("shared-secret"), "secret/data/tacacs/shared-secret");
    }

    #[test]
    fn test_secret_path_without_data() {
        let kv = KvClient::new("secret/tacacs".to_string());
        assert_eq!(kv.secret_path("shared-secret"), "secret/data/tacacs/shared-secret");
    }

    #[test]
    fn test_parse_string_value() {
        let json = serde_json::json!({
            "data": {
                "value": "my-secret-value"
            },
            "metadata": {
                "created_time": "2024-01-15T00:00:00Z",
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        });

        let result = KvClient::parse_string_value(&json).unwrap();
        assert_eq!(result, Some(b"my-secret-value".to_vec()));
    }

    #[test]
    fn test_parse_json_value() {
        use std::collections::HashMap;

        let json = serde_json::json!({
            "data": {
                "10.1.1.1": "secret1",
                "10.1.1.2": "secret2"
            },
            "metadata": {
                "created_time": "2024-01-15T00:00:00Z",
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        });

        let result: Option<HashMap<String, String>> = KvClient::parse_json_value(&json).unwrap();
        let map = result.unwrap();
        assert_eq!(map.get("10.1.1.1"), Some(&"secret1".to_string()));
        assert_eq!(map.get("10.1.1.2"), Some(&"secret2".to_string()));
    }
}
