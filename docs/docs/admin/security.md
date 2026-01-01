---
icon: lucide/lock-keyhole
---

# Security Hardening Guide

This guide covers security best practices for deploying `usg-tacacs` in production environments.

## Defense in Depth

`usg-tacacs` implements multiple layers of security:

1. **Transport Security** - TLS 1.3 with mutual authentication
2. **Protocol Security** - MD5 obfuscation (legacy compatibility)
3. **Access Control** - Certificate allowlists and policy enforcement
4. **Audit Trail** - Comprehensive logging of all operations

## TLS Configuration

### Minimum Requirements

- TLS 1.3 only (no fallback to older versions)
- Mutual TLS (mTLS) required for all connections
- Strong cipher suites (Rustls defaults)

### Certificate Best Practices

1. **Use dedicated PKI** for TACACS+ client certificates
2. **Short validity periods** (90 days recommended)
3. **Automate rotation** with ACME or internal CA
4. **Separate server and client certificates**

### Client Identity Verification

Restrict clients by certificate identity:

```json
{
  "tls_allowed_client_cn": [
    "router1.example.com",
    "switch1.example.com"
  ],
  "tls_allowed_client_san": [
    "tacacs-client.example.com"
  ]
}
```

!!! warning "Prefer SAN over CN"
    Subject Alternative Names (SAN) are the modern standard. Use CN allowlists only for legacy devices.

## Shared Secret Management

### For Legacy TACACS+ (TCP/49)

If you must support legacy TACACS+:

1. **Minimum 16 characters** (8 is the protocol minimum, use more)
2. **High entropy** - Use a password generator
3. **Unique per deployment** - Never reuse secrets
4. **Rotate regularly** - At least annually

```json
{
  "secret": "use-a-cryptographically-strong-random-secret-here",
  "forbid_unencrypted": true
}
```

### Per-NAD Secrets

For finer control, assign unique secrets per network device:

```json
{
  "legacy_nad_secret": [
    {"ip": "192.0.2.10", "secret": "router1-unique-secret"},
    {"ip": "192.0.2.11", "secret": "switch1-unique-secret"}
  ]
}
```

## Process Hardening

### Linux Security

```ini
# /etc/systemd/system/usg-tacacs.service.d/security.conf
[Service]
# Privilege restrictions
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/usg-tacacs

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6

# Resource limits
LimitNOFILE=4096
LimitNPROC=256
MemoryMax=512M

# Kernel protections
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictSUIDSGID=yes
```

### Container Security

When running in containers:

```yaml
services:
  tacacs:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,nodev
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
```

## Connection Limits

Protect against connection exhaustion:

```json
{
  "max_connections_per_ip": 50,
  "single_connect_idle_secs": 300,
  "single_connect_keepalive_secs": 120
}
```

## Authentication Security

### ASCII/PAP Brute Force Protection

Configure attempt limits and backoff:

```json
{
  "ascii_attempt_limit": 5,
  "ascii_user_attempt_limit": 3,
  "ascii_pass_attempt_limit": 5,
  "ascii_backoff_ms": 1000,
  "ascii_backoff_max_ms": 30000,
  "ascii_lockout_limit": 10
}
```

### LDAPS Security

1. **Always use LDAPS** (StartTLS is rejected)
2. **Verify server certificate** with `ldap_ca_file`
3. **Use service account** with minimal permissions
4. **Require group membership** for additional control

```json
{
  "ldaps_url": "ldaps://ldap.example.com:636",
  "ldap_ca_file": "/etc/usg-tacacs/ldap-ca.pem",
  "ldap_required_group": [
    "cn=network-admins,ou=groups,dc=example,dc=com"
  ]
}
```

### Argon2 Password Hashing

For static credentials, use Argon2 hashes instead of plaintext:

```json
{
  "user_password_hash": [
    "admin:$argon2id$v=19$m=65536,t=3,p=4$..."
  ],
  "allow_static_credentials": true
}
```

Generate hashes with:

```sh
echo -n "password" | argon2 $(openssl rand -hex 16) -id -e
```

## Audit and Compliance

### Log Security

1. **Forward logs** to a central SIEM
2. **Use TLS** for log transport
3. **Retain logs** per compliance requirements
4. **Monitor for anomalies**:
   - Multiple failed authentications
   - Unusual command patterns
   - Connections from unexpected IPs

### Sensitive Data

The server does NOT log:

- Passwords or secrets
- Full certificate contents
- Sensitive command arguments (configurable)

The server DOES log:

- Usernames
- Source IPs
- Commands (for authorization decisions)
- Session IDs

## Supply Chain Security

### Build Security

```sh
# Use locked dependencies
cargo build --locked --release

# Vendor dependencies for offline builds
cargo vendor --locked vendor/

# Generate SBOM
syft packages dir:. -o spdx-json > sbom.json

# Audit for vulnerabilities
cargo audit
cargo deny check
```

### Artifact Signing

```sh
# Generate checksums
sha256sum target/release/usg-tacacs-server > SHA256SUMS

# Sign with GPG
gpg --clearsign SHA256SUMS
```

## Incident Response

### Indicators of Compromise

Monitor for:

- Repeated authentication failures from single IP
- Authentication from unexpected sources
- Unusual command patterns in authorization logs
- Configuration file modifications
- Unexpected process restarts

### Response Actions

1. **Isolate** - Block suspicious IPs at firewall
2. **Investigate** - Review audit logs
3. **Rotate** - Change secrets and certificates
4. **Notify** - Alert security team
5. **Document** - Record incident details

## Security Checklist

- [ ] TLS 1.3 with mTLS enabled
- [ ] Client certificate allowlist configured
- [ ] Strong shared secret (if legacy enabled)
- [ ] `forbid_unencrypted` set to true
- [ ] Process running as non-root user
- [ ] systemd security directives applied
- [ ] Connection limits configured
- [ ] Authentication backoff enabled
- [ ] Logs forwarded to SIEM
- [ ] Secrets rotated regularly
- [ ] Certificates have short validity
- [ ] Policy validated before deployment
- [ ] SBOM generated for release
- [ ] Dependencies audited
