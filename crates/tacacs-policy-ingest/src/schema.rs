// SPDX-License-Identifier: AGPL-3.0-only
use anyhow::{Context, Result};
use jsonschema::{Draft, Validator};
use serde_json::Value;

pub struct SchemaSet {
    config: Validator,
    policy: Validator,
}

impl SchemaSet {
    pub async fn load_from_files(config_path: &str, policy_path: &str) -> Result<Self> {
        let config_bytes = tokio::fs::read(config_path).await?;
        let policy_bytes = tokio::fs::read(policy_path).await?;

        let config_json: Value = serde_json::from_slice(&config_bytes)
            .with_context(|| format!("parse config schema {config_path}"))?;
        let policy_json: Value = serde_json::from_slice(&policy_bytes)
            .with_context(|| format!("parse policy schema {policy_path}"))?;

        // Config and policy schemas use draft-07
        let config = jsonschema::options()
            .with_draft(Draft::Draft7)
            .build(&config_json)
            .context("compile config schema")?;

        let policy = jsonschema::options()
            .with_draft(Draft::Draft7)
            .build(&policy_json)
            .context("compile policy schema")?;

        Ok(Self { config, policy })
    }

    pub fn validate_config(&self, instance: &Value) -> Result<()> {
        if let Err(err) = self.config.validate(instance) {
            anyhow::bail!("config schema validation failed: {}", err);
        }
        Ok(())
    }

    pub fn validate_policy(&self, instance: &Value) -> Result<()> {
        if let Err(err) = self.policy.validate(instance) {
            anyhow::bail!("policy schema validation failed: {}", err);
        }
        Ok(())
    }
}
