# TACACS+ RS Enterprise Roadmap

Production deployment roadmap for 184+ locations with centralized GitOps
management.

**Target Environment**: On-premises bare metal/VMs with systemd, Ansible,
Terraform

**GitOps Tooling**: ArgoCD

**Observability**: Prometheus + Grafana + Loki, Elastic (ELK) Stack

---

## Current State (v0.76.0)

### What's Already Built

| Feature                  | Status   | Notes                                    |
| ------------------------ | -------- | ---------------------------------------- |
| RFC 8907 TACACS+ Protocol | Complete | Full compliance with hardened semantics |
| RFC 9887 TLS 1.3         | Complete | mTLS on port 300, legacy on port 49      |
| Authentication           | Complete | ASCII, PAP, CHAP, LDAPS                  |
| Authorization            | Complete | JSON policy engine with priority rules   |
| Accounting               | Complete | START/STOP/WATCHDOG records              |
| Policy Ingest Service    | Complete | REST API with PostgreSQL backend         |
| Multi-Location Support   | Complete | Per-location policy/config in ingest     |
| Hot Reload               | Complete | SIGHUP for config/policy refresh         |
| Container Deployment     | Complete | Docker Compose with HAProxy, FRR         |
| Audit Logging            | Complete | Structured tracing with UTC timestamps   |
| Rate Limiting            | Complete | Per-IP, per-user, exponential backoff    |
| Argon2 Password Hashing  | Complete | File-based and inline credentials        |
| Prometheus Metrics       | Complete | `/metrics` endpoint with auth/authz/acct |
| Health Endpoints         | Complete | `/health`, `/ready`, `/live` endpoints   |
| JSON Logging             | Complete | `--log-format json` for ELK/Loki         |
| OpenTelemetry Tracing    | Complete | `--otlp-endpoint` for distributed traces |
| Grafana Dashboard        | Complete | Overview dashboard in `dashboards/`      |

---

## Phase 1: Observability Foundation ✅ COMPLETE

**Priority**: Critical

**Dependency**: None

**Status**: All 5 items complete.

### 1.1 Prometheus Metrics Endpoint ✅ COMPLETE

Add `/metrics` HTTP endpoint to `tacacs-server` exposing:

```text
# Connection metrics
tacacs_connections_active{location="NYC01"}
tacacs_connections_total{location="NYC01", status="success|failed"}

# Authentication metrics
tacacs_authn_requests_total{location="NYC01", method="...", result="pass|fail"}
tacacs_authn_duration_seconds{location="NYC01", quantile="0.5|0.9|0.99"}

# Authorization metrics
tacacs_authz_requests_total{location="NYC01", result="allow|deny"}
tacacs_authz_matched_rule{location="NYC01", rule_id="...", effect="allow|deny"}

# Accounting metrics
tacacs_acct_records_total{location="NYC01", type="start|stop|watchdog"}

# Session metrics
tacacs_sessions_active{location="NYC01"}
tacacs_session_duration_seconds{location="NYC01", quantile="0.5|0.9|0.99"}

# Rate limiting metrics
tacacs_ratelimit_rejections_total{location="NYC01", reason="..."}

# Policy metrics
tacacs_policy_reload_total{location="NYC01", result="success|failed"}
tacacs_policy_rules_count{location="NYC01"}
```

**Implementation**: ~~Add `metrics` feature flag, use `prometheus` crate.~~

**Implemented in**: [metrics.rs](crates/tacacs-server/src/metrics.rs) - Prometheus 0.13 crate with global singleton registry.

### 1.2 Health Check Endpoints ✅ COMPLETE

Add HTTP listener (configurable port, default 8080) with endpoints:

| Endpoint       | Purpose            | Response                                |
| -------------- | ------------------ | --------------------------------------- |
| `GET /health`  | Basic liveness     | `200 OK` if process alive               |
| `GET /ready`   | Readiness probe    | `200` if accepting, `503` if draining   |
| `GET /live`    | Kubernetes liveness | `200` if not deadlocked                |
| `GET /metrics` | Prometheus scrape  | Metrics in Prometheus format            |

**Implemented in**: [http.rs](crates/tacacs-server/src/http.rs) - Axum HTTP server with ServerState for readiness tracking.

**Usage**: `tacacs-server --listen-http 0.0.0.0:8080`

### 1.3 Structured JSON Logging ✅ COMPLETE

Enhance existing tracing output for log aggregation:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "location": "NYC01",
  "event": "authn_pass",
  "session_id": "abc123",
  "peer_ip": "10.1.1.1",
  "user": "admin",
  "method": "ldap",
  "duration_ms": 45,
  "trace_id": "xyz789"
}
```

**Format toggle**: `--log-format json|text`

**Implemented in**: [main.rs](crates/tacacs-server/src/main.rs) - tracing-subscriber with JSON formatter.

**Usage**: `tacacs-server --log-format json`

### 1.4 OpenTelemetry Tracing ✅ COMPLETE

Added optional OTLP exporter for distributed tracing:

- ✅ Trace authentication flows end-to-end
- ✅ Trace authorization decisions with rule matching
- ✅ Trace LDAP queries with latency breakdown
- ✅ Trace policy reload operations

**Implemented in**: [telemetry.rs](crates/tacacs-server/src/telemetry.rs) - OpenTelemetry with OTLP exporter.

**Usage**: `tacacs-server --otlp-endpoint http://jaeger:4317 --otel-service-name tacacs-server --location NYC01`

**Configuration** (CLI arguments):

```text
--otlp-endpoint <URL>      OpenTelemetry OTLP endpoint (e.g., http://jaeger:4317)
--otel-service-name <NAME> Service name for traces (default: tacacs-server)
--location <CODE>          Location identifier for resource attributes
```

### 1.5 Grafana Dashboards ✅ COMPLETE

Created dashboard JSON files for import:

- **Overview Dashboard**: Connection rate, auth success rate, active sessions
- **Authentication Dashboard**: Methods breakdown, failure reasons, LDAP latency
- **Authorization Dashboard**: Allow/deny ratio, top matched rules, reload status
- **Per-Location Dashboard**: Drilldown by location code (future)
- **Alerting Rules**: High failure rate, LDAP timeout, connection exhaustion (future)

**Implemented**: [dashboards/tacacs-overview.json](dashboards/tacacs-overview.json) - Overview dashboard with 7 panels covering connections, authentication, authorization, accounting, sessions, latency, and policy metrics.

---

## Phase 2: Infrastructure as Code ✅ COMPLETE

**Priority**: High

**Dependency**: Phase 1 (health endpoints for Ansible checks)

**Status**: All 4 items complete.

### 2.1 Ansible Roles ✅ COMPLETE

Create `ansible/` directory with roles:

```text
ansible/
├── roles/
│   ├── tacacs_server/
│   │   ├── tasks/main.yml
│   │   ├── handlers/main.yml
│   │   ├── templates/
│   │   │   ├── config.json.j2
│   │   │   ├── policy.json.j2
│   │   │   └── tacacs-server.service.j2
│   │   ├── vars/main.yml
│   │   └── defaults/main.yml
│   ├── tacacs_ha/
│   │   ├── tasks/main.yml
│   │   └── templates/
│   │       ├── keepalived.conf.j2
│   │       └── haproxy.cfg.j2
│   └── tacacs_common/
│       └── tasks/main.yml
├── inventory/
│   ├── production/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       ├── all.yml
│   │       └── locations/
│   │           ├── NYC01.yml
│   │           ├── LAX01.yml
│   │           └── ...
│   └── staging/
├── playbooks/
│   ├── deploy.yml
│   ├── upgrade.yml
│   ├── rollback.yml
│   └── rotate-certs.yml
└── requirements.yml
```

**Role Features**:

- Binary installation from artifact repository
- systemd unit management with hardening
- Config templating with Jinja2
- Certificate deployment
- Health check validation post-deploy
- Graceful restart with connection draining

**Implemented in**: [ansible/](ansible/) - Three roles (tacacs_server, tacacs_ha, tacacs_common) with playbooks for deploy, upgrade, rollback, and certificate rotation.

### 2.2 Terraform Modules ✅ COMPLETE

Create `terraform/` directory:

```text
terraform/
├── modules/
│   ├── tacacs-vm/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── tacacs-network/
│   │   ├── main.tf
│   │   └── variables.tf
│   └── tacacs-dns/
│       └── main.tf
├── environments/
│   ├── production/
│   │   ├── main.tf
│   │   ├── terraform.tfvars
│   │   └── locations/
│   │       ├── nyc01.tf
│   │       └── lax01.tf
│   └── staging/
└── backend.tf
```

**Module Features**:

- VM provisioning (VMware vSphere, Proxmox, or cloud)
- Network configuration (VLANs, firewall rules)
- DNS record management
- Load balancer configuration

**Implemented in**: [terraform/](terraform/) - Three modules (tacacs-vm, tacacs-network, tacacs-dns) with multi-provider support and automatic Ansible inventory generation.

### 2.3 systemd Hardening ✅ COMPLETE

Enhanced service unit template:

```ini
[Unit]
Description=TACACS+ Authentication Server
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/your-org/tacacs-rs

[Service]
Type=notify
User=tacacs
Group=tacacs
ExecStart=/usr/local/bin/tacacs-server --config /etc/tacacs/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
WatchdogSec=30s

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=1G
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tacacs-server

[Install]
WantedBy=multi-user.target
```

**Implemented in**: [ansible/roles/tacacs_server/templates/tacacs-server.service.j2](ansible/roles/tacacs_server/templates/tacacs-server.service.j2) and [packer/files/tacacs-server.service](packer/files/tacacs-server.service) - Hardened systemd unit with NoNewPrivileges, ProtectSystem=strict, SystemCallFilter, and resource limits.

### 2.4 Packer Golden Images ✅ COMPLETE

Create `packer/` directory for VM templates:

```text
packer/
├── tacacs-server.pkr.hcl
├── scripts/
│   ├── base-setup.sh
│   ├── install-tacacs.sh
│   └── harden.sh
└── files/
    └── tacacs-server.service
```

**Implemented in**: [packer/](packer/) - HCL template with multi-provider support (QEMU, vSphere, AWS), security hardening scripts, and pre-installed TACACS+ binary.

---

## Phase 3: High Availability ✅ COMPLETE

**Priority**: High

**Dependency**: Phase 1, Phase 2

**Status**: HAProxy-based load balancing implemented (VRRP/keepalived skipped per project decision).

### 3.1 HAProxy Load Balancing ✅ COMPLETE

Each location runs HAProxy in front of TACACS+ servers for load balancing and failover:

```text
┌─────────────────────────────────────────┐
│              Location NYC01              │
│                                          │
│           ┌─────────────┐               │
│           │   HAProxy   │               │
│           │  :49/:300   │               │
│           └──────┬──────┘               │
│                  │                       │
│         ┌────────┴────────┐             │
│         │                  │             │
│    ┌────┴────┐       ┌────┴────┐        │
│    │ TACACS  │       │ TACACS  │        │
│    │   #1    │       │   #2    │        │
│    └─────────┘       └─────────┘        │
└─────────────────────────────────────────┘
```

**HAProxy Features**:

- HTTP health checks against `/ready` endpoint
- Round-robin or least-connections balancing
- Session persistence via stick tables (optional)
- Stats interface for monitoring
- Graceful reload without dropping connections

**Implemented in**: [ansible/roles/tacacs_ha/](ansible/roles/tacacs_ha/) - HAProxy configuration with health checks, multiple frontends (legacy/TLS/HTTP), and systemd hardening.

### 3.2 PostgreSQL HA (Policy Ingest) ✅ COMPLETE

Deploy PostgreSQL with Patroni for policy-ingest service:

```text
┌───────────────────────────────────────────────────┐
│                  Central Site                      │
│                                                    │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│   │   PG    │  │   PG    │  │   PG    │          │
│   │ Primary │──│ Replica │──│ Replica │          │
│   └────┬────┘  └─────────┘  └─────────┘          │
│        │                                          │
│   ┌────┴────┐                                    │
│   │  etcd   │ (3-node cluster)                   │
│   └─────────┘                                    │
│                                                    │
│   ┌─────────────────────────────────────┐        │
│   │     HAProxy / PgBouncer              │        │
│   │     (connection pooling)             │        │
│   └─────────────────────────────────────┘        │
└───────────────────────────────────────────────────┘
```

**Implemented in**:

- [ansible/roles/etcd/](ansible/roles/etcd/) - 3-node etcd cluster for Patroni DCS
- [ansible/roles/patroni/](ansible/roles/patroni/) - Patroni-managed PostgreSQL with automatic failover
- [ansible/roles/pgbouncer/](ansible/roles/pgbouncer/) - Connection pooling with transaction mode
- [ansible/playbooks/deploy-postgresql-ha.yml](ansible/playbooks/deploy-postgresql-ha.yml) - Full stack deployment

### 3.3 BGP Anycast ✅ COMPLETE

For geographic distribution across 184 locations:

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Anycast VIP: 10.255.255.1                 │
│                                                                  │
│    ┌──────────┐      ┌──────────┐      ┌──────────┐            │
│    │  NYC01   │      │  LAX01   │      │  CHI01   │   ...x184  │
│    │  TACACS  │      │  TACACS  │      │  TACACS  │            │
│    │  + FRR   │      │  + FRR   │      │  + FRR   │            │
│    └────┬─────┘      └────┬─────┘      └────┬─────┘            │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            │                                     │
│                     Core Routers                                 │
│                    (BGP peering)                                 │
└─────────────────────────────────────────────────────────────────┘
```

**FRR Configuration per location**:

- Advertise anycast VIP when healthy
- Withdraw route on health check failure
- Community tagging for traffic engineering
- BFD for fast failover

**Implemented in**:

- [ansible/roles/frr_anycast/](ansible/roles/frr_anycast/) - FRR BGP configuration with health-based route advertisement
- Health check script monitors `/ready` endpoint and withdraws route on failure
- BFD enabled for sub-second failover detection
- Draining mode with lower local-preference during maintenance
- [ansible/playbooks/deploy-bgp-anycast.yml](ansible/playbooks/deploy-bgp-anycast.yml) - Batch deployment across locations

### 3.4 Graceful Shutdown

Implement connection draining in `tacacs-server`:

1. Receive SIGTERM
2. Stop accepting new connections
3. Set `/ready` to return 503
4. Wait for active sessions to complete (configurable timeout)
5. Force-close remaining connections
6. Exit cleanly

**Configuration**:

```json
{
  "shutdown": {
    "drain_timeout_seconds": 30,
    "force_close_after_seconds": 60
  }
}
```

---

## Phase 4: Secrets & Certificate Management

**Priority**: High

**Dependency**: Phase 2 (Ansible)

### 4.1 HashiCorp Vault Integration

Add Vault client to `tacacs-server` for secrets:

```json
{
  "vault": {
    "enabled": true,
    "address": "https://vault.internal:8200",
    "auth_method": "approle",
    "role_id_file": "/etc/tacacs/vault-role-id",
    "secret_id_file": "/etc/tacacs/vault-secret-id",
    "secrets": {
      "shared_secret": "secret/data/tacacs/shared-secret",
      "ldap_bind_password": "secret/data/tacacs/ldap-bind"
    },
    "refresh_interval_seconds": 300
  }
}
```

**Vault Paths**:

```text
secret/
└── tacacs/
    ├── shared-secret          # TACACS+ shared secret
    ├── ldap-bind              # LDAP service account password
    ├── locations/
    │   ├── NYC01/
    │   │   ├── shared-secret  # Per-location override
    │   │   └── nad-secrets    # Per-NAD secrets
    │   └── LAX01/
    └── pki/                   # PKI secrets engine
```

### 4.2 Vault PKI for Certificates

Use Vault PKI secrets engine for automatic TLS:

```bash
vault secrets enable pki
vault write pki/root/generate/internal \
  common_name="TACACS Root CA" \
  ttl=87600h

vault write pki/roles/tacacs-server \
  allowed_domains="tacacs.internal" \
  allow_subdomains=true \
  max_ttl=720h
```

**Auto-renewal in tacacs-server**:

- Request new cert when 70% of TTL elapsed
- Graceful reload on cert refresh
- Alert on renewal failure

### 4.3 SOPS for Secrets in Git

Encrypt secrets in GitOps repo with SOPS:

```yaml
# locations/NYC01/secrets.enc.yaml
shared_secret: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
ldap_bind_password: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  kms:
    - arn: arn:aws:kms:us-east-1:123456789:key/abc-123
  age:
    - recipient: age1...
```

**CI/CD Integration**:

- Decrypt at deploy time
- Never commit plaintext secrets
- Audit log for secret access

---

## Phase 5: GitOps with ArgoCD

**Priority**: High

**Dependency**: Phase 2, Phase 4

### 5.1 Repository Structure

```text
tacacs-gitops/
├── argocd/
│   ├── applicationset.yaml      # Generates 184 apps
│   ├── project.yaml             # ArgoCD project
│   └── rbac.yaml                # ArgoCD RBAC
├── base/
│   ├── config.json              # Base config template
│   ├── policy.json              # Base policy template
│   └── kustomization.yaml
├── overlays/
│   ├── production/
│   │   └── kustomization.yaml
│   └── staging/
├── locations/
│   ├── NYC01/
│   │   ├── config.json          # Location overrides
│   │   ├── policy.json          # Location-specific rules
│   │   └── secrets.enc.yaml     # SOPS encrypted
│   ├── LAX01/
│   └── ... (184 locations)
├── policies/
│   ├── global/
│   │   └── deny-dangerous.json  # Global deny rules
│   └── templates/
│       └── standard-policy.json
└── scripts/
    ├── validate-policy.py       # CI validation
    └── generate-locations.py    # Scaffold new locations
```

### 5.2 ArgoCD ApplicationSet

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: tacacs-locations
  namespace: argocd
spec:
  generators:
    - git:
        repoURL: https://github.com/your-org/tacacs-gitops
        revision: HEAD
        directories:
          - path: locations/*
  template:
    metadata:
      name: 'tacacs-{{path.basename}}'
    spec:
      project: tacacs
      source:
        repoURL: https://github.com/your-org/tacacs-gitops
        targetRevision: HEAD
        path: '{{path}}'
      destination:
        server: https://kubernetes.default.svc  # or external cluster
        namespace: tacacs
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```

### 5.3 Ansible Pull Mode

For on-prem VMs without Kubernetes:

```yaml
# ansible/playbooks/pull-deploy.yml
- name: Deploy TACACS from GitOps
  hosts: tacacs_servers
  vars:
    gitops_repo: https://github.com/your-org/tacacs-gitops
    location: "{{ inventory_hostname | regex_replace('tacacs-', '') }}"
  tasks:
    - name: Clone/update GitOps repo
      git:
        repo: "{{ gitops_repo }}"
        dest: /opt/tacacs-gitops
        version: main

    - name: Decrypt secrets
      command: sops -d locations/{{ location }}/secrets.enc.yaml
      args:
        chdir: /opt/tacacs-gitops
      register: secrets

    - name: Template configuration
      template:
        src: /opt/tacacs-gitops/locations/{{ location }}/config.json
        dest: /etc/tacacs/config.json
      notify: Reload TACACS

    - name: Deploy policy
      copy:
        src: /opt/tacacs-gitops/locations/{{ location }}/policy.json
        dest: /etc/tacacs/policy.json
      notify: Reload TACACS
```

**ArgoCD Webhook Trigger**:

- ArgoCD detects Git change
- Triggers Ansible AWX/Tower job template
- AWX runs `pull-deploy.yml` on affected hosts
- Reports status back to ArgoCD

### 5.4 Policy Validation in CI

```yaml
# .github/workflows/validate.yml
name: Validate Policies
on:
  pull_request:
    paths:
      - 'locations/**'
      - 'policies/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate JSON Schema
        run: |
          for f in locations/*/policy.json; do
            jsonschema -i "$f" schemas/policy.schema.json
          done

      - name: Check for dangerous patterns
        run: |
          python scripts/validate-policy.py locations/

      - name: Dry-run policy compilation
        run: |
          cargo run --bin tacacs-policy-check -- \
            --policies locations/*/policy.json
```

### 5.5 Staged Rollouts

```yaml
# ArgoCD sync waves for canary deployment
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: tacacs-staged-rollout
spec:
  generators:
    - list:
        elements:
          - location: NYC01
            wave: "1"    # Canary
          - location: LAX01
            wave: "2"    # Early adopter
          - location: CHI01
            wave: "3"
          # ... remaining 181 locations in wave 4-10
  template:
    metadata:
      annotations:
        argocd.argoproj.io/sync-wave: '{{wave}}'
```

**Rollout Strategy**:

1. Wave 1 (1 location): Canary - monitor for 1 hour
2. Wave 2 (5 locations): Early adopters - monitor for 4 hours
3. Wave 3 (20 locations): Staged expansion
4. Wave 4+ (remaining): Full rollout

---

## Phase 6: Enterprise Features

**Priority**: Medium

**Dependency**: Phase 1, Phase 5

### 6.1 Management API with RBAC

Add REST API to `tacacs-server` for runtime management:

| Endpoint                | Method | Permission       | Description              |
| ----------------------- | ------ | ---------------- | ------------------------ |
| `/api/v1/status`        | GET    | `read:status`    | Server health and stats  |
| `/api/v1/sessions`      | GET    | `read:sessions`  | Active sessions list     |
| `/api/v1/sessions/{id}` | DELETE | `write:sessions` | Terminate session        |
| `/api/v1/policy`        | GET    | `read:policy`    | Current policy           |
| `/api/v1/policy/reload` | POST   | `write:policy`   | Trigger hot reload       |
| `/api/v1/config`        | GET    | `read:config`    | Running config (sanitized) |
| `/api/v1/metrics`       | GET    | `read:metrics`   | Prometheus metrics       |

**RBAC Configuration**:

```json
{
  "api": {
    "enabled": true,
    "listen": "127.0.0.1:8443",
    "tls_cert": "/etc/tacacs/api-cert.pem",
    "tls_key": "/etc/tacacs/api-key.pem",
    "rbac": {
      "roles": {
        "admin": ["read:*", "write:*"],
        "operator": ["read:*", "write:sessions"],
        "viewer": ["read:status", "read:metrics"]
      },
      "users": {
        "CN=admin.tacacs.internal": "admin",
        "CN=noc.tacacs.internal": "operator"
      }
    }
  }
}
```

### 6.2 Audit Log Forwarding

Forward audit events to SIEM/ELK:

```json
{
  "audit": {
    "syslog": {
      "enabled": true,
      "host": "syslog.internal",
      "port": 6514,
      "protocol": "tcp+tls",
      "facility": "auth",
      "format": "rfc5424"
    },
    "elasticsearch": {
      "enabled": true,
      "hosts": ["https://elk.internal:9200"],
      "index": "tacacs-audit-%Y.%m.%d",
      "api_key": "${ELASTIC_API_KEY}"
    }
  }
}
```

**Audit Event Types**:

- `authn.success`, `authn.failure`
- `authz.allow`, `authz.deny`
- `acct.start`, `acct.stop`, `acct.watchdog`
- `config.reload`, `policy.reload`
- `session.start`, `session.end`
- `ratelimit.triggered`, `lockout.activated`

### 6.3 Compliance Dashboards

Grafana dashboards for compliance reporting:

- **Authentication Success Rate**: Target >99.5%
- **Failed Login Attempts**: By user, by source IP
- **Privileged Command Usage**: `configure terminal`, `reload`, etc.
- **Policy Violations**: Denied commands by rule
- **Session Duration**: Unusual long sessions
- **Geographic Anomalies**: Login from unexpected locations

**Alert Rules**:

- Brute force detection (>5 failures in 1 minute)
- Privilege escalation patterns
- After-hours access
- Dormant account usage

### 6.4 Multi-Tenancy Enhancements

Namespace isolation for multi-tenant deployments:

```json
{
  "tenants": {
    "enabled": true,
    "isolation": "strict",
    "tenants": {
      "corp": {
        "locations": ["NYC01", "LAX01"],
        "policy_path": "/etc/tacacs/tenants/corp/policy.json",
        "ldap_group_prefix": "CN=TACACS-Corp-"
      },
      "retail": {
        "locations": ["STORE001", "STORE002"],
        "policy_path": "/etc/tacacs/tenants/retail/policy.json",
        "ldap_group_prefix": "CN=TACACS-Retail-"
      }
    }
  }
}
```

---

## Phase 7: Operations & Documentation

**Priority**: Medium

**Dependency**: All previous phases

### 7.1 Runbooks

Create `docs/runbooks/` directory:

| Runbook                   | Purpose                        |
| ------------------------- | ------------------------------ |
| `deployment.md`           | Standard deployment procedure  |
| `upgrade.md`              | Version upgrade steps          |
| `rollback.md`             | Emergency rollback procedure   |
| `certificate-rotation.md` | TLS cert renewal process       |
| `secret-rotation.md`      | Shared secret rotation         |
| `disaster-recovery.md`    | Full site recovery             |
| `troubleshooting.md`      | Common issues and solutions    |

### 7.2 Incident Response Playbooks

| Scenario                   | Playbook                    |
| -------------------------- | --------------------------- |
| Authentication outage      | `incident-authn-outage.md`  |
| LDAP connectivity failure  | `incident-ldap-down.md`     |
| Policy misconfiguration    | `incident-policy-error.md`  |
| Certificate expiration     | `incident-cert-expired.md`  |
| Database failure           | `incident-db-down.md`       |
| Security breach suspected  | `incident-security.md`      |

### 7.3 Capacity Planning Guide

Document per-location sizing:

| Metric            | Small Site | Medium Site | Large Site |
| ----------------- | ---------- | ----------- | ---------- |
| Network devices   | <50        | 50-200      | 200+       |
| Auth requests/min | <100       | 100-500     | 500+       |
| CPU cores         | 2          | 4           | 8          |
| RAM               | 2 GB       | 4 GB        | 8 GB       |
| Disk              | 20 GB      | 50 GB       | 100 GB     |

**Scaling Triggers**:

- CPU utilization >70% sustained
- Memory utilization >80%
- Auth latency p99 >100ms
- Connection queue depth >10

### 7.4 Performance Tuning Documentation

| Parameter            | Default | Tuned | Impact          |
| -------------------- | ------- | ----- | --------------- |
| `max_connections`    | 1000    | 5000  | Memory +500MB   |
| `connection_timeout` | 300s    | 120s  | Faster cleanup  |
| `ldap_pool_size`     | 5       | 20    | LDAP throughput |
| `policy_cache_ttl`   | 60s     | 300s  | Reduced I/O     |

---

## Implementation Priority Matrix

| Phase            | Priority | Effort | Dependencies | Business Value            | Status      |
| ---------------- | -------- | ------ | ------------ | ------------------------- | ----------- |
| 1. Observability | Critical | Medium | None         | Visibility into 184 sites | ✅ Complete |
| 2. IaC           | High     | High   | Phase 1      | Consistent deployments    | ✅ Complete |
| 3. HA            | High     | High   | Phase 1, 2   | 99.9% uptime              | ✅ Complete |
| 4. Secrets       | High     | Medium | Phase 2      | Security compliance       | 🔜 Next     |
| 5. GitOps        | High     | Medium | Phase 2, 4   | Centralized management    | Pending     |
| 6. Enterprise    | Medium   | Medium | Phase 1, 5   | Audit/compliance          | Pending     |
| 7. Operations    | Medium   | Low    | All          | Operational excellence    | Pending     |

---

## Quick Wins (Implement First)

These items provide immediate value with minimal effort:

1. ~~**Health endpoints** - Enable HAProxy/keepalived health checks~~ ✅ DONE
2. ~~**JSON logging** - Immediate compatibility with ELK/Loki~~ ✅ DONE
3. ~~**systemd hardening** - Copy-paste security improvements~~ ✅ DONE
4. ~~**Basic Prometheus metrics** - Connection count, auth rate~~ ✅ DONE
5. ~~**Ansible role skeleton** - Standardize deployments~~ ✅ DONE

---

## Success Metrics

| Metric                       | Target       | Measurement               |
| ---------------------------- | ------------ | ------------------------- |
| Deployment time per location | <15 minutes  | CI/CD pipeline duration   |
| Config drift                 | 0 locations  | ArgoCD sync status        |
| MTTR (Mean Time to Recovery) | <30 minutes  | Incident response time    |
| Authentication availability  | 99.95%       | Prometheus SLI            |
| Policy update propagation    | <5 minutes   | Git commit to active      |
| Security posture             | 100% compliant | Audit dashboard         |

---

## Next Steps

1. ~~Begin Phase 1.1 (Prometheus metrics) - highest impact~~ ✅ DONE
2. ~~Create Ansible role skeleton for standardization (Phase 2.1)~~ ✅ DONE
3. Set up GitOps repository structure (Phase 5.1)
4. ~~Deploy Grafana dashboards for existing tracing logs~~ ✅ DONE
5. Document current state baseline for all 184 locations
6. ~~Implement systemd hardening template (Phase 2.3)~~ ✅ DONE
7. ~~Add OpenTelemetry tracing (Phase 1.4)~~ ✅ DONE
8. ~~Implement HAProxy-based high availability (Phase 3)~~ ✅ DONE
9. Implement graceful shutdown with connection draining (Phase 3.4) - code change required
10. Begin Phase 4: Secrets & Certificate Management (Vault integration)
