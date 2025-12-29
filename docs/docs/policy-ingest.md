---
icon: lucide/download
---

# TACACS policy ingest service

`tacacs-policy-ingest` is a small mTLS-protected service that ingests policy/config bundles, validates them against JSON Schemas, and tracks versions in Postgres.

## Features

- mTLS required for all endpoints (TLS_CERT/TLS_KEY/CLIENT_CA envs).
- Optional client identity allowlists via CN/SAN (`CLIENT_ALLOWED_CN`, `CLIENT_ALLOWED_SAN`).
- Validates policy/config JSON against provided schemas before persisting.
- Stores bundle metadata and active selections in Postgres.
- Lightweight Axum API with tracing support.

## Environment variables

- `LISTEN` (required): host:port to bind (e.g., `[::]:8443`).
- `DATABASE_URL` (required): Postgres connection string.
- `CONFIG_SCHEMA_PATH` (default `schemas/config.schema.json`): JSON Schema for configs.
- `POLICY_SCHEMA_PATH` (default `schemas/policy.schema.json`): JSON Schema for policies.
- `REPO_ALLOWLIST` (optional): comma-separated repo IDs allowed to ingest/promote.
- `TLS_CERT` / `TLS_KEY` (required): server cert/key (PEM; key must be PKCS#8).
- `CLIENT_CA` (required): CA bundle to verify client certs.
- `CLIENT_ALLOWED_CN` / `CLIENT_ALLOWED_SAN` (optional): comma-separated allowlists for client cert CN/SAN.

## API

- `POST /api/v1/ingest`
  - Headers: `X-Repo-Id` (req), `X-Commit-SHA` (req), `X-Ref` (opt), `X-Bundle-SHA256` (opt).
  - Body: `tar.gz` containing `policy/locations/<CODE>.json` and/or `config/locations/<CODE>.json`.
  - Validates schemas and upserts versions; records ingest run.
  - Response: `200 OK` on success; 4xx/5xx with message on failure.
- `POST /api/v1/promote/:repo_id/:location_code/:commit_sha`
  - Headers: `X-Activated-By` (opt; defaults to `mtls-client`).
  - Marks a commit as active for a location; rejects if repo not in allowlist.

## Running locally

```sh
export LISTEN=[::1]:8443
export DATABASE_URL=postgres://user:pass@localhost:5432/tacacs
export TLS_CERT=certs/server.pem
export TLS_KEY=certs/server-key.pem
export CLIENT_CA=certs/client-ca.pem
cargo run -p tacacs-policy-ingest
```

## Bundle format

`tar.gz` with JSON files:

- `policy/locations/<CODE>.json`
- `config/locations/<CODE>.json`

Schemas live in `crates/tacacs-policy-ingest/schemas/`.

## Notes

- Client auth is enforced via mTLS; add CN/SAN allowlists for tighter control.
- Uses tracing with env filter; set `RUST_LOG=info` (or similar) for logs.

## Database tables (`crates/tacacs-policy-ingest/sql/schema.sql`)
- `ingest_runs`: records each ingest attempt (id, repo_id, commit_sha, ref, received_at).
- `policy_versions`: versioned policy JSON per repo + commit + location_code (unique on that tuple).
- `config_versions`: versioned config JSON per repo + commit + location_code (unique on that tuple).
- `active_set`: current active commit per repo/location_code, with activation metadata (activated_by, activated_at).
