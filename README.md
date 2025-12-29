# usg-tacacs

Rust TACACS+ server with:

- RFC 9887 TACACS+ over TLS 1.3 (mTLS only) on TCP/300
- Optional legacy TACACS+ (TCP/49)
- Per-command authorization
- JSON policy with priorities + last-match-wins
- JSON Schema validation + validate-only mode
- SIGHUP hot reload
- Command normalization + regex auto-anchoring
- Capability/keepalive packet support (vendor-specific, single-connect/keepalive bits, request/ack)
- Hardened RFC 8907 semantics: authz protocol/service checks, explicit FOLLOW rejection, richer audit telemetry
- Process hardening guidance: run as non-root, optionally chroot/jail, set RLIMITs, and drop ambient caps (see below)

## Process hardening (recommended)

Run the daemon under a dedicated non-root user, with strict sandboxing/limits. Example systemd unit excerpt:

```
[Service]
User=tacacs
Group=tacacs
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=4096
LimitNPROC=256
MemoryAccounting=yes
TasksAccounting=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
```

If you require chroot/jail, place certs/policy inside the jail and adjust paths accordingly.

## Supply-chain hygiene

- Build reproducibly with locked deps: `cargo build --locked`; keep `Cargo.lock` under version control.
- Vendor third-party crates for offline/attestable builds: `cargo vendor --locked vendor/` and point `CARGO_HOME`/`CARGO_REGISTRIES_CRATES_IO_PROTOCOL=file`.
- Generate an SBOM for releases (e.g., `syft packages dir:. -o spdx-json > sbom.json` or `cargo audit-sbom`).
- Sign release artifacts/hashes (e.g., `sha256sum target/release/usg-tacacs-* | gpg --clearsign`).
- Optional: run `cargo audit` / `cargo deny check` in CI to catch vulnerable/banlisted crates.

## Logging/auditing guidance

- UTC timestamps enabled by default via tracing subscriber; include peer/user/session/outcome fields in audit logs for correlation.
- Forward logs to a central collector with integrity (e.g., TLS/syslog with signing) and set up rotation/retention at the service manager level (systemd journald or logrotate).
- Consider shipping signed hash manifests of log files for tamper detection if storing locally.

## Validate policy

cargo run -p tacacs-server -- \
  --check-policy ./policy/policy.example.json \
  --schema ./policy/policy.schema.json

## Run TLS server

cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json
