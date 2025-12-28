// SPDX-License-Identifier: AGPL-3.0-only
//! Shared parsing utilities for TACACS+ packet bodies.

use anyhow::{anyhow, Context, Result};

pub fn read_bytes(body: &[u8], offset: usize, len: usize, label: &str) -> Result<(Vec<u8>, usize)> {
    let next = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("overflow parsing {label}"))?;
    let slice = body
        .get(offset..next)
        .ok_or_else(|| anyhow!("{label} truncated"))?;
    Ok((slice.to_vec(), next))
}

pub fn read_string(body: &[u8], offset: usize, len: usize, label: &str) -> Result<(String, usize)> {
    let (raw, next) = read_bytes(body, offset, len, label)?;
    let value = String::from_utf8(raw).with_context(|| format!("decoding {label} as UTF-8"))?;
    Ok((value, next))
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

pub fn parse_attributes(args: &[String]) -> Vec<Attribute> {
    args.iter()
        .map(|s| {
            if let Some(idx) = s.find('=') {
                let (name, val) = s.split_at(idx);
                Attribute {
                    name: name.to_string(),
                    value: Some(val[1..].to_string()),
                }
            } else {
                Attribute {
                    name: s.clone(),
                    value: None,
                }
            }
        })
        .collect()
}

pub fn validate_attributes(args: &[String], allowed_prefixes: &[&str]) -> Result<()> {
    for (idx, arg) in args.iter().enumerate() {
        if arg.is_empty() {
            return Err(anyhow!("attr[{idx}] is empty"));
        }
        let mut parts = arg.splitn(2, '=');
        let name = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if name.is_empty() || value.is_empty() {
            return Err(anyhow!("attr[{idx}] must be name=value"));
        }
        if !allowed_prefixes.iter().any(|p| name.eq_ignore_ascii_case(p)) {
            return Err(anyhow!("attr[{idx}] uses unsupported name '{}'", name));
        }
        if arg.len() > 255 {
            return Err(anyhow!("attr[{idx}] exceeds 255 bytes"));
        }
    }
    Ok(())
}
