---
icon: lucide/lock
---

# Authentication

This server supports two credential sources:

- **Static user/password map**: provided via `user_password` entries (`user:password`). Used for PAP and ASCII.
- **LDAPS**: service-account bind + user bind, optional group requirements, and group-aware policy evaluation.

Only **LDAPS** (ldaps://) is allowed. StartTLS is rejected.

## Static credentials

- Configure via CLI `--user-password user:pass` (repeatable) or `user_password` array in config JSON.
- Used for PAP and ASCII. CHAP still requires static secrets (no LDAP for CHAP).
- ASCII flow obeys attempt limits/backoff/lockout (`ascii_attempt_limit`, `ascii_user_attempt_limit`, `ascii_pass_attempt_limit`, `ascii_backoff_ms`, `ascii_backoff_max_ms`, `ascii_lockout_limit`).

## LDAPS configuration

CLI flags (see `config.schema.json` for JSON keys):

- `--ldaps-url ldaps://ldap.example.com` (required to enable LDAP; must start with ldaps://).
- `--ldap-bind-dn`, `--ldap-bind-password`: service account used for search.
- `--ldap-search-base`: base DN for user lookup.
- `--ldap-username-attr` (default `uid`): attribute used to find the user entry.
- `--ldap-group-attr` (default `memberOf`): attribute to read group membership.
- `--ldap-required-group` (repeatable): match-any required group/DN; case-insensitive.
- `--ldap-timeout-ms` (default 5000): connect/operation timeout.
- `--ldap-ca-file`: optional extra trust anchor for LDAPS.

Behavior:

- Service account bind → search for user DN → (optional) verify membership in any `ldap_required_group` → user bind with presented password.
- Group membership is fetched and passed into policy; `groups` rules are match-any and case-insensitive.
- If LDAPS is unreachable or credentials/required group fail, authentication fails.
- StartTLS is not supported; use LDAPS only.

## Policy interaction

- Policy can match `users` and/or `groups`. Both must match when provided.
- Authz allow responses include rule id and, when present, groups: `reason=policy-allow;rule=<id>;groups=g1,g2`.

## Troubleshooting

- **User not found**: check `ldap_search_base` and `ldap_username_attr`.
- **Group requirement failing**: confirm `ldap_group_attr` values and `ldap_required_group` strings match (case-insensitive).
- **TLS errors**: ensure server cert chain is trusted; provide `--ldap-ca-file` if using private PKI.
- **Timeouts**: raise `--ldap-timeout-ms` for slow directories.
