use anyhow::{Context, Result, anyhow};
use jsonschema::{Draft, JSONSchema};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: i32,
    pub effect: Effect,
    pub pattern: String,
    #[serde(default)]
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDocument {
    pub default_allow: bool,
    #[serde(default)]
    pub shell_start: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub ascii_prompts: Option<AsciiPrompts>,
    #[serde(default)]
    pub ascii_user_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_password_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_port_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_remaddr_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_messages: Option<AsciiMessages>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsciiPrompts {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsciiMessages {
    pub success: Option<String>,
    pub failure: Option<String>,
    pub abort: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub priority: i32,
    pub effect: Effect,
    pub users: Vec<String>,
    pub regex: Regex,
    pub order: usize,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default_allow: bool,
    shell_start: HashMap<String, Vec<String>>,
    ascii_prompts: Option<AsciiPrompts>,
    ascii_user_prompts: HashMap<String, String>,
    ascii_password_prompts: HashMap<String, String>,
    ascii_port_prompts: HashMap<String, String>,
    ascii_remaddr_prompts: HashMap<String, String>,
    ascii_messages: Option<AsciiMessages>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub matched_rule: Option<String>,
}

impl PolicyEngine {
    pub fn from_path(policy: impl AsRef<Path>, schema: Option<impl AsRef<Path>>) -> Result<Self> {
        let policy_path = policy.as_ref();
        let policy_contents = fs::read_to_string(policy_path)
            .with_context(|| format!("reading policy {}", policy_path.display()))?;
        let value: Value = serde_json::from_str(&policy_contents)
            .with_context(|| format!("parsing JSON policy {}", policy_path.display()))?;

        if let Some(schema_path) = schema {
            validate_against_schema(&value, schema_path.as_ref())?;
        }

        let document: PolicyDocument = serde_json::from_value(value)
            .with_context(|| format!("deserializing policy {}", policy_path.display()))?;
        Self::from_document(document)
    }

    pub fn from_document(document: PolicyDocument) -> Result<Self> {
        let mut rules = Vec::with_capacity(document.rules.len());

        for (order, rule) in document.rules.into_iter().enumerate() {
            let regex = compile_pattern(&rule.pattern)
                .with_context(|| format!("compiling rule {} pattern {}", rule.id, rule.pattern))?;
            let users = rule
                .users
                .into_iter()
                .map(|u| u.to_lowercase())
                .collect::<Vec<_>>();
            rules.push(Rule {
                id: rule.id,
                priority: rule.priority,
                effect: rule.effect,
                users,
                regex,
                order,
            });
        }

        let mut shell_start = HashMap::with_capacity(document.shell_start.len());
        for (user, attrs) in document.shell_start {
            shell_start.insert(user.to_lowercase(), attrs);
        }

        Ok(Self {
            default_allow: document.default_allow,
            shell_start,
            ascii_prompts: document.ascii_prompts,
            ascii_user_prompts: document
                .ascii_user_prompts
                .into_iter()
                .map(|(u, p)| (u.to_lowercase(), p))
                .collect(),
            ascii_password_prompts: document
                .ascii_password_prompts
                .into_iter()
                .map(|(u, p)| (u.to_lowercase(), p))
                .collect(),
            ascii_port_prompts: document.ascii_port_prompts,
            ascii_remaddr_prompts: document.ascii_remaddr_prompts,
            ascii_messages: document.ascii_messages,
            rules,
        })
    }

    pub fn authorize(&self, user: &str, command: &str) -> Decision {
        let normalized_user = user.to_lowercase();
        let normalized_cmd = normalize_command(command);

        let mut selected: Option<&Rule> = None;
        for rule in &self.rules {
            if !rule.users.is_empty() && !rule.users.iter().any(|u| u == &normalized_user) {
                continue;
            }
            if rule.regex.is_match(&normalized_cmd) {
                match selected {
                    None => selected = Some(rule),
                    Some(current) if rule.priority > current.priority => selected = Some(rule),
                    Some(current)
                        if rule.priority == current.priority && rule.order > current.order =>
                    {
                        selected = Some(rule)
                    }
                    _ => {}
                }
            }
        }

        let allowed = selected
            .map(|r| r.effect == Effect::Allow)
            .unwrap_or(self.default_allow);

        Decision {
            allowed,
            matched_rule: selected.map(|r| r.id.clone()),
        }
    }

    pub fn shell_attributes_for(&self, user: &str) -> Option<Vec<String>> {
        self.shell_start.get(&user.to_lowercase()).cloned()
    }

    pub fn prompt_username(&self, user: Option<&str>, port: Option<&str>, rem_addr: Option<&str>) -> Option<&str> {
        if let Some(user) = user {
            if let Some(custom) = self.ascii_user_prompts.get(&user.to_lowercase()) {
                return Some(custom.as_str());
            }
        }
        if let Some(port) = port {
            if let Some(custom) = self.ascii_port_prompts.get(port) {
                return Some(custom.as_str());
            }
        }
        if let Some(rem) = rem_addr {
            if let Some(custom) = self.ascii_remaddr_prompts.get(rem) {
                return Some(custom.as_str());
            }
        }
        self.ascii_prompts
            .as_ref()
            .and_then(|p| p.username.as_deref())
    }

    pub fn prompt_password(&self, user: Option<&str>) -> Option<&str> {
        if let Some(user) = user {
            if let Some(custom) = self.ascii_password_prompts.get(&user.to_lowercase()) {
                return Some(custom.as_str());
            }
        }
        self.ascii_prompts
            .as_ref()
            .and_then(|p| p.password.as_deref())
    }

    /// Hook for observing raw server messages from auth replies (currently a no-op).
    pub fn observe_server_msg(
        &self,
        _user: Option<&str>,
        _port: Option<&str>,
        _rem_addr: Option<&str>,
        _raw: &[u8],
    ) {
    }

    pub fn message_success(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.success.as_deref())
    }

    pub fn message_failure(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.failure.as_deref())
    }

    pub fn message_abort(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.abort.as_deref())
    }
}

pub fn validate_policy_file(
    policy: impl AsRef<Path>,
    schema: impl AsRef<Path>,
) -> Result<PolicyDocument> {
    let path = policy.as_ref();
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing JSON policy {}", path.display()))?;
    validate_against_schema(&value, schema.as_ref())?;
    let document: PolicyDocument = serde_json::from_value(value)
        .with_context(|| format!("deserializing policy {}", path.display()))?;
    Ok(document)
}

pub fn normalize_command(cmd: &str) -> String {
    let lowered = cmd.trim().to_lowercase();
    let mut result = String::with_capacity(lowered.len());
    let mut last_was_space = false;
    for ch in lowered.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
        } else {
            result.push(ch);
            last_was_space = false;
        }
    }
    result
}

fn compile_pattern(raw: &str) -> Result<Regex> {
    let anchored = format!("^(?:{})$", raw);
    Regex::new(&anchored).context("invalid regex")
}

fn validate_against_schema(value: &Value, schema_path: &Path) -> Result<()> {
    let schema_contents = fs::read_to_string(schema_path)
        .with_context(|| format!("reading schema {}", schema_path.display()))?;
    let schema_json: Value = serde_json::from_str(&schema_contents)
        .with_context(|| format!("parsing JSON schema {}", schema_path.display()))?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_json)
        .map_err(|err| anyhow!("compiling schema {}: {err}", schema_path.display()))?;

    compiled.validate(value).map_err(|errors| {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        anyhow!("policy failed schema validation: {}", messages.join("; "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_whitespace_and_case() {
        assert_eq!(normalize_command(" Show  Run "), "show run");
        assert_eq!(normalize_command("show\tint  Gi0/1"), "show int gi0/1");
    }

    #[test]
    fn last_match_wins_with_priority() {
        let doc = PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            rules: vec![
                RuleConfig {
                    id: "allow1".into(),
                    priority: 10,
                    effect: Effect::Allow,
                    pattern: "show.*".into(),
                    users: vec![],
                },
                RuleConfig {
                    id: "deny1".into(),
                    priority: 10,
                    effect: Effect::Deny,
                    pattern: "show.*".into(),
                    users: vec![],
                },
                RuleConfig {
                    id: "allow2".into(),
                    priority: 20,
                    effect: Effect::Allow,
                    pattern: "show.*".into(),
                    users: vec![],
                },
            ],
        };

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "allow2");
    }
}
