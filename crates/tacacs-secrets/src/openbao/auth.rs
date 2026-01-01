//! AppRole authentication for OpenBao.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::debug;

/// AppRole authentication handler.
///
/// Reads role_id and secret_id from files on disk, as recommended by
/// OpenBao/Vault best practices for service authentication.
pub struct AppRoleAuth {
    role_id_file: PathBuf,
    secret_id_file: PathBuf,
}

impl AppRoleAuth {
    /// Create a new AppRole auth handler.
    pub fn new(role_id_file: PathBuf, secret_id_file: PathBuf) -> Self {
        Self {
            role_id_file,
            secret_id_file,
        }
    }

    /// Load credentials from the configured files.
    ///
    /// Returns (role_id, secret_id).
    pub fn load_credentials(&self) -> Result<(String, String)> {
        let role_id = self.load_role_id()?;
        let secret_id = self.load_secret_id()?;
        Ok((role_id, secret_id))
    }

    /// Load the role_id from file.
    fn load_role_id(&self) -> Result<String> {
        let content = std::fs::read_to_string(&self.role_id_file).with_context(|| {
            format!(
                "failed to read AppRole role_id from {:?}",
                self.role_id_file
            )
        })?;
        let role_id = content.trim().to_string();
        debug!(path = ?self.role_id_file, "loaded AppRole role_id");
        Ok(role_id)
    }

    /// Load the secret_id from file.
    fn load_secret_id(&self) -> Result<String> {
        let content = std::fs::read_to_string(&self.secret_id_file).with_context(|| {
            format!(
                "failed to read AppRole secret_id from {:?}",
                self.secret_id_file
            )
        })?;
        let secret_id = content.trim().to_string();
        debug!(path = ?self.secret_id_file, "loaded AppRole secret_id");
        Ok(secret_id)
    }

    /// Get the role_id file path.
    pub fn role_id_file(&self) -> &PathBuf {
        &self.role_id_file
    }

    /// Get the secret_id file path.
    pub fn secret_id_file(&self) -> &PathBuf {
        &self.secret_id_file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_credentials() {
        let mut role_file = NamedTempFile::new().unwrap();
        let mut secret_file = NamedTempFile::new().unwrap();

        writeln!(role_file, "test-role-id").unwrap();
        writeln!(secret_file, "test-secret-id").unwrap();

        let auth = AppRoleAuth::new(
            role_file.path().to_path_buf(),
            secret_file.path().to_path_buf(),
        );

        let (role_id, secret_id) = auth.load_credentials().unwrap();
        assert_eq!(role_id, "test-role-id");
        assert_eq!(secret_id, "test-secret-id");
    }

    #[test]
    fn test_load_credentials_trims_whitespace() {
        let mut role_file = NamedTempFile::new().unwrap();
        let mut secret_file = NamedTempFile::new().unwrap();

        // Include extra whitespace
        writeln!(role_file, "  role-with-spaces  ").unwrap();
        writeln!(secret_file, "\n\tsecret-with-tabs\n").unwrap();

        let auth = AppRoleAuth::new(
            role_file.path().to_path_buf(),
            secret_file.path().to_path_buf(),
        );

        let (role_id, secret_id) = auth.load_credentials().unwrap();
        assert_eq!(role_id, "role-with-spaces");
        assert_eq!(secret_id, "secret-with-tabs");
    }

    #[test]
    fn test_load_credentials_missing_file() {
        let auth = AppRoleAuth::new(
            PathBuf::from("/nonexistent/role-id"),
            PathBuf::from("/nonexistent/secret-id"),
        );

        let result = auth.load_credentials();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("role_id"));
    }
}
