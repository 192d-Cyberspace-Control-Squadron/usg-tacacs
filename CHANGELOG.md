# Changelog

All notable changes to the TACACS+ RS project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 4: Secrets & Certificate Management

- **New `tacacs-secrets` crate** for secrets management with OpenBao integration
  - `SecretsProvider` trait for pluggable secrets backends
  - `FileProvider` for backward compatibility with file-based secrets
  - `OpenBaoProvider` with AppRole authentication and automatic token renewal
  - `OpenBaoClient` with HTTP client, exponential backoff retry logic
  - `KvClient` for KV v2 secrets engine (shared secrets, LDAP passwords, per-NAD secrets)
  - `PkiClient` for PKI secrets engine (automatic TLS certificate issuance)
  - `CertificateBundle` with 70% TTL threshold for auto-renewal

- **OpenBao CLI arguments** for `tacacs-server`:
  - `--openbao-enabled` - Enable OpenBao/Vault integration
  - `--openbao-address` - OpenBao server address
  - `--openbao-auth-method` - Authentication method (approle)
  - `--openbao-role-id-file` - Path to AppRole role_id file
  - `--openbao-secret-id-file` - Path to AppRole secret_id file
  - `--openbao-ca-file` - Optional CA certificate for TLS verification
  - `--openbao-refresh-interval-secs` - Secret refresh interval
  - `--openbao-secret-path` - Base path for secrets in KV engine
  - `--openbao-location` - Location identifier for per-location secrets

- **OpenBao PKI CLI arguments** for automatic certificate management:
  - `--openbao-pki-enabled` - Enable PKI certificate management
  - `--openbao-pki-mount` - PKI secrets engine mount point
  - `--openbao-pki-role` - PKI role name for certificate issuance
  - `--openbao-pki-common-name` - Certificate common name
  - `--openbao-pki-ttl-hours` - Certificate TTL in hours
  - `--openbao-pki-renewal-threshold` - Renewal threshold percentage

- **Ansible role `tacacs_openbao`** for OpenBao integration:
  - Automatic policy creation for TACACS secrets access
  - AppRole provisioning with role_id/secret_id deployment
  - PKI secrets engine setup with CA and role configuration
  - Support for per-location and per-NAD secrets

- **Ansible role `tacacs_sops`** for encrypted secrets in Git:
  - SOPS binary installation and configuration
  - Support for age encryption and AWS KMS
  - Age key file deployment with secure permissions
  - `.sops.yaml` configuration template

### Dependencies

- Added `reqwest` (0.12) for HTTP client
- Added `backoff` (0.4) for retry logic
- Added `async-trait` (0.1) for async trait support
- Updated `time` with formatting/parsing features for certificate expiration handling

## [0.76.0] - Previous Release

See ROADMAP.md for details on Phases 1-3:
- Phase 1: Observability Foundation (Prometheus metrics, health endpoints, JSON logging, OpenTelemetry)
- Phase 2: Infrastructure as Code (Ansible roles, Terraform modules, systemd hardening, Packer images)
- Phase 3: High Availability (HAProxy load balancing, PostgreSQL HA with Patroni, BGP Anycast, graceful shutdown)
