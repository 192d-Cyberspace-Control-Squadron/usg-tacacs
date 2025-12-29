---
icon: lucide/settings
---

# Configuration reference

You can configure via CLI flags or JSON (`config.example.json` / `config.schema.json`). This page mirrors the schema fields.

## Transport & TLS

- `listen_tls` (string, required): host:port for TLS listener.
- `listen_legacy` (string|null): optional legacy TACACS+ listener (TCP/49).
- `tls_cert`, `tls_key` (string, required): server cert/key.
- `client_ca` (string, required): CA bundle to verify client certs.
- `tls_trust_root` (array<string>, default []): extra trust anchors for client auth.
- `tls_allowed_client_cn` / `tls_allowed_client_san` (array<string>, default []): allowlists for client identities (match-any).
- `tls_psk` (string|null): TLS pre-shared key (optional).
- `secret` (string|null, minLength 8): TACACS+ shared secret for obfuscation (legacy listener).
- `forbid_unencrypted` (bool, default true): drop requests with `TAC_PLUS_UNENCRYPTED_FLAG`.
- `legacy_nad_secret` (array<object>): per-NAD legacy secrets; when set, legacy connections must originate from a listed IP and will use that IP’s secret. Each entry: `{"ip": "192.0.2.10", "secret": "at-least-8-bytes"}`.
- `single_connect_idle_secs` (int, default 300): idle timeout for single-connection sessions.
- `single_connect_keepalive_secs` (int, default 120): keepalive timer for single-connection sessions.
- `max_connections_per_ip` (int, default 50): per-IP connection cap.

## Authentication

- `user_password` (array<string>, default []): `user:password` entries for static auth.
- `ascii_attempt_limit` (int, default 5): total ASCII attempts.
- `ascii_user_attempt_limit` (int, default 3): username prompt attempts.
- `ascii_pass_attempt_limit` (int, default 5): password prompt attempts.
- `ascii_backoff_ms` (int, default 0): initial backoff between attempts (ms).
- `ascii_backoff_max_ms` (int, default 5000): cap for exponential backoff (ms).
- `ascii_lockout_limit` (int, default 0): lockout after N failures (0 disables).

## LDAPS (authentication + groups)

- `ldaps_url` (string|null): must start with `ldaps://` to enable LDAP.
- `ldap_bind_dn` / `ldap_bind_password` (string|null): service account for search.
- `ldap_search_base` (string|null): base DN for user lookup.
- `ldap_username_attr` (string, default `uid`): attribute to locate user entries.
- `ldap_group_attr` (string, default `memberOf`): attribute containing group membership.
- `ldap_required_group` (array<string>, default []): match-any required group/DN (case-insensitive).
- `ldap_timeout_ms` (int, default 5000): connection/operation timeout.
- `ldap_ca_file` (string|null): optional extra trust anchor for LDAPS.

## Policy/validation

- `policy` (string, required): path to policy JSON.
- `schema` (string|null): optional custom schema path.
- `check_policy` (string|null): validate policy and exit.

## JSON example (abridged)

```json
{
  "listen_tls": "0.0.0.0:300",
  "tls_cert": "./certs/server.pem",
  "tls_key": "./certs/server-key.pem",
  "client_ca": "./certs/client-ca.pem",
  "tls_trust_root": ["./certs/extra-root.pem"],
  "secret": "strong-shared-secret",
  "forbid_unencrypted": true,
  "user_password": ["admin:changeme"],
  "ldaps_url": "ldaps://ldap.example.com",
  "ldap_bind_dn": "cn=svc,ou=svc,dc=example,dc=com",
  "ldap_bind_password": "svc-secret",
  "ldap_search_base": "dc=example,dc=com",
  "ldap_required_group": [
    "cn=netops,ou=groups,dc=example,dc=com",
    "cn=secops,ou=groups,dc=example,dc=com"
  ],
  "policy": "./policy/policy.example.json"
}
```

Run-time validation:

```sh
cargo run -p tacacs-server -- \
  --check-policy ./policy/policy.example.json \
  --schema ./policy/policy.schema.json
```
