// SPDX-License-Identifier: AGPL-3.0-only
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;

#[derive(Debug)]
pub struct ParsedBundle {
    pub policies: HashMap<String, Value>, // location_code -> policy JSON
    pub configs: HashMap<String, Value>,  // location_code -> config JSON
}

/// Parse a tar.gz bundle and extract:
/// - policy/locations/<CODE>.json
/// - config/locations/<CODE>.json
pub fn parse_tar_gz(bytes: &[u8]) -> Result<ParsedBundle> {
    let gz = GzDecoder::new(bytes);
    let mut ar = Archive::new(gz);

    let mut policies = HashMap::new();
    let mut configs = HashMap::new();

    for entry in ar.entries().context("read tar entries")? {
        let mut entry = entry?;
        let path = entry
            .path()
            .context("read entry path")?
            .to_string_lossy()
            .to_string();

        if let Some(code) = path
            .strip_prefix("policy/locations/")
            .and_then(|p| p.strip_suffix(".json"))
        {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            let v: Value = serde_json::from_str(&s).with_context(|| format!("parse {path}"))?;
            policies.insert(code.to_string(), v);
            continue;
        }

        if let Some(code) = path
            .strip_prefix("config/locations/")
            .and_then(|p| p.strip_suffix(".json"))
        {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            let v: Value = serde_json::from_str(&s).with_context(|| format!("parse {path}"))?;
            configs.insert(code.to_string(), v);
            continue;
        }
    }

    if policies.is_empty() && configs.is_empty() {
        anyhow::bail!("bundle contained no policy/locations or config/locations entries");
    }

    Ok(ParsedBundle { policies, configs })
}
