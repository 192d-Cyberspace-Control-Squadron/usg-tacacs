use anyhow::{Context, Result, anyhow};
use hex;
use jsonschema::Draft;
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
    #[serde(default)]
    pub groups: Vec<String>,
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
    #[serde(default = "default_allow_raw_server_msg")]
    pub allow_raw_server_msg: bool,
    #[serde(default)]
    pub raw_server_msg_allow_prefixes: Vec<String>,
    #[serde(default)]
    pub raw_server_msg_deny_prefixes: Vec<String>,
    #[serde(default)]
    pub raw_server_msg_user_overrides: HashMap<String, RawServerMsgOverride>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct RawServerMsgOverride {
    pub allow: Option<bool>,
    #[serde(default)]
    pub allow_prefixes: Vec<String>,
    #[serde(default)]
    pub deny_prefixes: Vec<String>,
    #[serde(default)]
    pub allow_services: Vec<u8>,
    #[serde(default)]
    pub allow_actions: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub priority: i32,
    pub effect: Effect,
    pub users: Vec<String>,
    pub groups: Vec<String>,
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
    allow_raw_server_msg: bool,
    raw_server_msg_allow_prefixes: Vec<String>,
    raw_server_msg_deny_prefixes: Vec<String>,
    raw_server_msg_user_overrides: HashMap<String, RawServerMsgOverride>,
    ascii_messages: Option<AsciiMessages>,
    rules: Vec<Rule>,
}

fn default_allow_raw_server_msg() -> bool {
    true
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
            let groups = rule
                .groups
                .into_iter()
                .map(|g| g.to_lowercase())
                .collect::<Vec<_>>();
            rules.push(Rule {
                id: rule.id,
                priority: rule.priority,
                effect: rule.effect,
                users,
                groups,
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
            allow_raw_server_msg: document.allow_raw_server_msg,
            raw_server_msg_allow_prefixes: document
                .raw_server_msg_allow_prefixes
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            raw_server_msg_deny_prefixes: document
                .raw_server_msg_deny_prefixes
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            raw_server_msg_user_overrides: document
                .raw_server_msg_user_overrides
                .into_iter()
                .map(|(u, o)| (u.to_lowercase(), o))
                .collect(),
            ascii_messages: document.ascii_messages,
            rules,
        })
    }

    pub fn authorize(&self, user: &str, command: &str) -> Decision {
        self.authorize_with_groups(user, &[], command)
    }

    pub fn authorize_with_groups(&self, user: &str, groups: &[String], command: &str) -> Decision {
        let normalized_user = user.to_lowercase();
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();
        let normalized_cmd = normalize_command(command);

        let mut selected: Option<&Rule> = None;
        for rule in &self.rules {
            if !rule.users.is_empty() && !rule.users.iter().any(|u| u == &normalized_user) {
                continue;
            }
            if !rule.groups.is_empty()
                && !rule
                    .groups
                    .iter()
                    .any(|g| normalized_groups.iter().any(|ug| ug == g))
            {
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

    /// Returns the number of authorization rules in the policy.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn prompt_username(
        &self,
        user: Option<&str>,
        port: Option<&str>,
        rem_addr: Option<&str>,
    ) -> Option<&str> {
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

    /// Hook for observing/enforcing raw server messages from auth replies.
    pub fn observe_server_msg(
        &self,
        user: Option<&str>,
        port: Option<&str>,
        rem_addr: Option<&str>,
        service: Option<u8>,
        action: Option<u8>,
        raw: &[u8],
    ) -> bool {
        if !self.allow_raw_server_msg && !raw.is_empty() {
            return false;
        }
        if raw.is_empty() {
            return true;
        }
        let hex = hex::encode(raw).to_lowercase();
        if let Some(user) = user {
            if let Some(override_policy) =
                self.raw_server_msg_user_overrides.get(&user.to_lowercase())
            {
                if let Some(allow) = override_policy.allow {
                    if !allow {
                        return false;
                    }
                }
                if !override_policy.allow_services.is_empty() {
                    if let Some(svc) = service {
                        if !override_policy.allow_services.contains(&svc) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if !override_policy.allow_actions.is_empty() {
                    if let Some(act) = action {
                        if !override_policy.allow_actions.contains(&act) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if override_policy
                    .deny_prefixes
                    .iter()
                    .any(|p| hex.starts_with(&p.to_lowercase()))
                {
                    return false;
                }
                if !override_policy.allow_prefixes.is_empty()
                    && !override_policy
                        .allow_prefixes
                        .iter()
                        .any(|p| hex.starts_with(&p.to_lowercase()))
                {
                    return false;
                }
            }
        }
        if self
            .raw_server_msg_deny_prefixes
            .iter()
            .any(|p| hex.starts_with(p))
        {
            return false;
        }
        if !self.raw_server_msg_allow_prefixes.is_empty()
            && !self
                .raw_server_msg_allow_prefixes
                .iter()
                .any(|p| hex.starts_with(p))
        {
            return false;
        }
        let _ = (user, port, rem_addr); // reserved for future rule-based decisions
        true
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
    let compiled = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(&schema_json)
        .map_err(|err| anyhow!("compiling schema {}: {err}", schema_path.display()))?;

    compiled
        .validate(value)
        .map_err(|err| anyhow!("policy failed schema validation: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy_doc(rules: Vec<RuleConfig>) -> PolicyDocument {
        PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: Vec::new(),
            raw_server_msg_deny_prefixes: Vec::new(),
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules,
        }
    }

    fn make_rule(id: &str, priority: i32, effect: Effect, pattern: &str) -> RuleConfig {
        RuleConfig {
            id: id.into(),
            priority,
            effect,
            pattern: pattern.into(),
            users: vec![],
            groups: vec![],
        }
    }

    // ==================== normalize_command Tests ====================

    #[test]
    fn normalizes_whitespace_and_case() {
        assert_eq!(normalize_command(" Show  Run "), "show run");
        assert_eq!(normalize_command("show\tint  Gi0/1"), "show int gi0/1");
    }

    #[test]
    fn normalize_command_preserves_single_spaces() {
        assert_eq!(normalize_command("show run"), "show run");
    }

    #[test]
    fn normalize_command_handles_empty() {
        assert_eq!(normalize_command(""), "");
        assert_eq!(normalize_command("   "), "");
    }

    #[test]
    fn normalize_command_handles_newlines() {
        assert_eq!(normalize_command("show\n\nrun"), "show run");
    }

    // ==================== authorize Tests ====================

    #[test]
    fn authorize_default_deny_when_no_match() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show.*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "configure terminal");
        assert!(!decision.allowed);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn authorize_default_allow_when_configured() {
        let mut doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Deny, "show.*")]);
        doc.default_allow = true;
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "configure terminal");
        assert!(decision.allowed);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn authorize_matches_rule() {
        let doc = make_policy_doc(vec![make_rule("allow-show", 10, Effect::Allow, "show.*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show running-config");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "allow-show");
    }

    #[test]
    fn authorize_case_insensitive_command() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show run")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "SHOW RUN");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_case_insensitive_user() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["ALICE".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
    }

    #[test]
    fn last_match_wins_with_priority() {
        let doc = make_policy_doc(vec![
            make_rule("allow1", 10, Effect::Allow, "show.*"),
            make_rule("deny1", 10, Effect::Deny, "show.*"),
            make_rule("allow2", 20, Effect::Allow, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "allow2");
    }

    #[test]
    fn same_priority_last_rule_wins() {
        let doc = make_policy_doc(vec![
            make_rule("allow1", 10, Effect::Allow, "show.*"),
            make_rule("deny1", 10, Effect::Deny, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed); // deny1 is last with same priority
        assert_eq!(decision.matched_rule.unwrap(), "deny1");
    }

    #[test]
    fn higher_priority_wins_regardless_of_order() {
        let doc = make_policy_doc(vec![
            make_rule("high-priority-deny", 100, Effect::Deny, "show.*"),
            make_rule("low-priority-allow", 10, Effect::Allow, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "high-priority-deny");
    }

    // ==================== User Filtering Tests ====================

    #[test]
    fn authorize_user_filter_matches() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["alice".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_user_filter_no_match() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["bob".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed); // Falls through to default_allow=false
    }

    #[test]
    fn authorize_empty_users_matches_all() {
        let rule = make_rule("r1", 10, Effect::Allow, "show.*");
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("bob", "show run").allowed);
        assert!(engine.authorize("charlie", "show run").allowed);
    }

    // ==================== Group Filtering Tests ====================

    #[test]
    fn authorize_with_groups_matches() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["admins".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["admins".to_string(), "users".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_with_groups_no_match() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["admins".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["users".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(!decision.allowed);
    }

    #[test]
    fn authorize_with_groups_case_insensitive() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["ADMINS".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["admins".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(decision.allowed);
    }

    // ==================== Shell Attributes Tests ====================

    #[test]
    fn shell_attributes_for_existing_user() {
        let mut doc = make_policy_doc(vec![]);
        doc.shell_start.insert(
            "alice".into(),
            vec!["priv-lvl=15".into(), "timeout=300".into()],
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("alice");
        assert!(attrs.is_some());
        let attrs = attrs.unwrap();
        assert!(attrs.contains(&"priv-lvl=15".to_string()));
        assert!(attrs.contains(&"timeout=300".to_string()));
    }

    #[test]
    fn shell_attributes_for_case_insensitive() {
        let mut doc = make_policy_doc(vec![]);
        doc.shell_start
            .insert("ALICE".into(), vec!["priv-lvl=15".into()]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("alice");
        assert!(attrs.is_some());
    }

    #[test]
    fn shell_attributes_for_nonexistent_user() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("unknown");
        assert!(attrs.is_none());
    }

    // ==================== Prompt Tests ====================

    #[test]
    fn prompt_username_user_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_user_prompts
            .insert("alice".into(), "Alice's Username: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(Some("alice"), None, None);
        assert_eq!(prompt, Some("Alice's Username: "));
    }

    #[test]
    fn prompt_username_port_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_port_prompts
            .insert("console".into(), "Console Login: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, Some("console"), None);
        assert_eq!(prompt, Some("Console Login: "));
    }

    #[test]
    fn prompt_username_remaddr_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_remaddr_prompts
            .insert("192.168.1.1".into(), "Remote Login: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, None, Some("192.168.1.1"));
        assert_eq!(prompt, Some("Remote Login: "));
    }

    #[test]
    fn prompt_username_global_fallback() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Global Username: ".into()),
            password: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, None, None);
        assert_eq!(prompt, Some("Global Username: "));
    }

    #[test]
    fn prompt_username_user_takes_priority() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_user_prompts
            .insert("alice".into(), "User Prompt".into());
        doc.ascii_port_prompts
            .insert("console".into(), "Port Prompt".into());
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Global Prompt".into()),
            password: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        // User prompt should win
        let prompt = engine.prompt_username(Some("alice"), Some("console"), None);
        assert_eq!(prompt, Some("User Prompt"));
    }

    #[test]
    fn prompt_password_user_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_password_prompts
            .insert("alice".into(), "Alice's Password: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_password(Some("alice"));
        assert_eq!(prompt, Some("Alice's Password: "));
    }

    #[test]
    fn prompt_password_global_fallback() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: None,
            password: Some("Enter Password: ".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_password(None);
        assert_eq!(prompt, Some("Enter Password: "));
    }

    // ==================== Message Tests ====================

    #[test]
    fn message_success() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: Some("Welcome!".into()),
            failure: None,
            abort: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_success(), Some("Welcome!"));
    }

    #[test]
    fn message_failure() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: None,
            failure: Some("Access Denied".into()),
            abort: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_failure(), Some("Access Denied"));
    }

    #[test]
    fn message_abort() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: None,
            failure: None,
            abort: Some("Session Aborted".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_abort(), Some("Session Aborted"));
    }

    // ==================== Raw Server Message Tests ====================

    #[test]
    fn observe_server_msg_allowed_by_default() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.observe_server_msg(None, None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_empty_allowed() {
        let mut doc = make_policy_doc(vec![]);
        doc.allow_raw_server_msg = false;
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Empty messages are always allowed
        assert!(engine.observe_server_msg(None, None, None, None, None, b""));
    }

    #[test]
    fn observe_server_msg_denied_when_disabled() {
        let mut doc = make_policy_doc(vec![]);
        doc.allow_raw_server_msg = false;
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(None, None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_deny_prefix() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_deny_prefixes = vec!["48656c".into()]; // "Hel" in hex
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(None, None, None, None, None, b"Hello"));
        assert!(engine.observe_server_msg(None, None, None, None, None, b"World"));
    }

    #[test]
    fn observe_server_msg_allow_prefix_required() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_allow_prefixes = vec!["48656c".into()]; // "Hel" in hex
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.observe_server_msg(None, None, None, None, None, b"Hello"));
        assert!(!engine.observe_server_msg(None, None, None, None, None, b"World"));
    }

    // ==================== Regex Pattern Tests ====================

    #[test]
    fn authorize_regex_pattern() {
        let doc = make_policy_doc(vec![make_rule(
            "r1",
            10,
            Effect::Allow,
            "show (run|start|version)",
        )]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("alice", "show start").allowed);
        assert!(engine.authorize("alice", "show version").allowed);
        assert!(!engine.authorize("alice", "show interface").allowed);
    }

    #[test]
    fn authorize_wildcard_pattern() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, ".*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "any command").allowed);
        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("alice", "configure terminal").allowed);
    }

    #[test]
    fn authorize_anchored_pattern() {
        // Patterns should be anchored (full match required)
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show").allowed);
        assert!(!engine.authorize("alice", "show run").allowed); // Not a full match
    }
}
