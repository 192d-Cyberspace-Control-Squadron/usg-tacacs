// SPDX-License-Identifier: AGPL-3.0-only
use anyhow::{Context, Result};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

pub struct SchemaSet {
    config: JSONSchema,
    policy: JSONSchema,
}

impl SchemaSet {
    pub async fn load_from_files(config_path: &str, policy_path: &str) -> Result<Self> {
        let config_bytes = tokio::fs::read(config_path).await?;
        let policy_bytes = tokio::fs::read(policy_path).await?;

        let config_json: Value = serde_json::from_slice(&config_bytes)
            .with_context(|| format!("parse config schema {config_path}"))?;
        let policy_json: Value = serde_json::from_slice(&policy_bytes)
            .with_context(|| format!("parse policy schema {policy_path}"))?;

        // jsonschema 0.18 requires schema lifetimes to be 'static; leak in-process copies.
        let config_static: &'static Value = Box::leak(Box::new(config_json));
        let policy_static: &'static Value = Box::leak(Box::new(policy_json));

        // Config and policy schemas use draft-07
        let config = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(config_static)
            .context("compile config schema")?;

        let policy = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(policy_static)
            .context("compile policy schema")?;

        Ok(Self { config, policy })
    }

    pub fn validate_config(&self, instance: &Value) -> Result<()> {
        if let Err(errors) = self.config.validate(instance) {
            let msgs: Vec<String> = errors.map(|e| e.to_string()).collect();
            anyhow::bail!("config schema validation failed: {}", msgs.join("; "));
        }
        Ok(())
    }

    pub fn validate_policy(&self, instance: &Value) -> Result<()> {
        if let Err(errors) = self.policy.validate(instance) {
            let msgs: Vec<String> = errors.map(|e| e.to_string()).collect();
            anyhow::bail!("policy schema validation failed: {}", msgs.join("; "));
        }
        Ok(())
    }
}
