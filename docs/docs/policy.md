---
icon: lucide/key-round
---

# Policy guide

## What a policy is

The policy file (`policy.example.json`, validated by `policy.schema.json`) is a list of ordered rules that decide whether a user (and optional group membership) may execute a normalized TACACS+ command. Rules are evaluated highest priority first, and ties are resolved by last-match-wins.

## Rule fields

- `id` (string): identifier echoed in audit logs.
- `priority` (int): higher wins; ties use file order (last match wins).
- `pattern` (string): regex for the normalized command. Auto-anchored; matching is case-insensitive and whitespace-normalized.
- `effect` (`"allow"` | `"deny"`): decision outcome.
- `users` (array<string>): match-any usernames; empty means “any user”.
- `groups` (array<string>): match-any group/DN (case-insensitive). Evaluated in addition to `users`.
- `args` (array<string>, optional): attributes to return on allow. Shell defaults are injected if omitted (see below).

## Matching logic

1. Normalize the incoming command (collapse whitespace, lowercase where applicable).
2. For each rule (priority desc, last match wins on tie):
   - If `users` is non-empty, require user match (case-insensitive).
   - If `groups` is non-empty, require group match (match-any, case-insensitive).
   - If regex matches `pattern`, select this rule; keep scanning for a later rule of equal priority (last wins).
3. If selected rule is `allow`, return `args` (or defaults); otherwise deny.

## Defaults for shell sessions

When authorizing a shell start and the matched rule supplies no `args`, the server injects sensible defaults:

```sh
service=shell
protocol=shell
priv-lvl=1
```

For non-shell requests, only the attributes you specify are returned.

## Examples

### Allow netops group full shell, deny others

```json
{
  "rules": [
    {
      "id": "netops-shell",
      "priority": 100,
      "pattern": ".*",
      "effect": "allow",
      "groups": ["cn=netops,ou=groups,dc=example,dc=com"]
    },
    {
      "id": "default-deny",
      "priority": 0,
      "pattern": ".*",
      "effect": "deny"
    }
  ]
}
```

### Allow show commands, deny config

```json
{
  "rules": [
    {
      "id": "show-only",
      "priority": 50,
      "pattern": "^show\\s+.*",
      "effect": "allow",
      "users": ["readuser"]
    },
    {
      "id": "deny-config",
      "priority": 40,
      "pattern": "^configure\\b",
      "effect": "deny"
    }
  ]
}
```

### Custom attributes on allow

```json
{
  "rules": [
    {
      "id": "ops-priv15",
      "priority": 90,
      "pattern": ".*",
      "effect": "allow",
      "users": ["ops1", "ops2"],
      "args": [
        "service=shell",
        "protocol=ssh",
        "priv-lvl=15"
      ]
    }
  ]
}
```

## Validation

Validate policies before deploying:

```sh
cargo run -p tacacs-server -- \
  --check-policy ./policy/policy.example.json \
  --schema ./policy/policy.schema.json
```

Set `--schema` to `null` if you want to skip validation (not recommended).

## LDAP groups

If LDAPS is enabled and group fetching is configured, the server passes user groups into policy evaluation. `groups` entries are match-any and case-insensitive; they can be full DNs or short names, as long as they match the LDAP attribute values you configured (`ldap_group_attr`).

## Audit signals

Audit events include the matched rule `id`, decision, and reason (e.g., policy-allow/policy-deny). For authz allows, server data includes `reason=policy-allow;rule=<id>` and, if present, `groups=<comma-separated>`.
