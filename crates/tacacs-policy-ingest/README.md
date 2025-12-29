# tacacs-policy-ingest (mTLS GitOps ingest service)

This service accepts policy/config bundles over HTTPS with **mTLS required**, validates them against JSON Schemas,
and stores versioned artifacts in Postgres. It is designed for "zero Git creds in ingest": CI pipelines clone/validate
and POST bundles to this service.

## Endpoints

- `POST /api/v1/ingest`
  - Headers:
    - `X-Repo-Id`: `org/repo` (GitHub) or `group/project` (GitLab)
    - `X-Commit-SHA`: commit SHA
    - `X-Ref`: branch/tag (optional)
    - `X-Bundle-SHA256`: optional integrity check of the uploaded bundle
  - Body: `application/gzip` tarball containing:
    - `policy/locations/<LOCATION>.json`
    - `config/locations/<LOCATION>.json`

- `POST /api/v1/promote/{repo_id}/{location_code}/{commit_sha}`
  - Promotes a staged commit to active for a location.
  - Optional header `X-Activated-By` is recorded; in a hardened deployment you would derive this from the client cert identity.

## Environment

```
LISTEN=0.0.0.0:8443
DATABASE_URL=postgres://user:pass@dbhost:5432/tacacs_ingest

TLS_CERT=/etc/ingest/tls/server.crt
TLS_KEY=/etc/ingest/tls/server.key
CLIENT_CA=/etc/ingest/tls/ci-publishers-ca.crt

CONFIG_SCHEMA_PATH=schemas/config.schema.json
POLICY_SCHEMA_PATH=schemas/policy.schema.json

# Optional allowlist of repos that may publish
REPO_ALLOWLIST=org/repo,group/project
```

## Run

```
cargo run --release
```

## Notes

- The service enforces TLS 1.3 only by default (see `src/tls.rs`).
- Schemas included under `schemas/` are taken from your provided files.
