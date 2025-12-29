---
icon: lucide/box
---

# Container deployment

This repository ships an example container stack for running `usg-tacacs` with L4 load balancing and Anycast BGP advertisement.

## Artifacts

- `container/Dockerfile`: multi-stage Alpine build producing a statically linked `usg-tacacs` binary (musl) exposing TCP 300 (TLS) and 49 (legacy).
- `container/docker-compose.yml`: composes three services on host networking:
  - `frr`: BGP speaker to originate the TACACS+ VIP(s).
  - `haproxy`: TCP load balancer for ports 49/300 (IPv4/IPv6) with stats for health gating.
  - `tacacs`: the TACACS+ server, configured via `/etc/usg-tacacs/config.json`.
- `container/frr/daemons` and `container/frr/frr.conf`: minimal FRR configuration to advertise IPv4 /32 and IPv6 /128 VIPs to an upstream peer.
- `container/frr/health-watch.sh`: polls HAProxy stats; shuts BGP neighbor when HAProxy is unhealthy, re-enables when healthy.
- `container/haproxy/haproxy.cfg`: L4 proxy with health checks and a stats endpoint, forwarding to the local TACACS+ instance.

## How it works

- FRR advertises the service VIPs over BGP (`frr.conf`) to your upstream router(s). Adjust ASNs, neighbors, and VIPs before use.
- HAProxy listens on the VIP (host network) for TCP/49 and TCP/300 and forwards to the local TACACS+ service (`127.0.0.1:49` / `:300`), with TCP health checks. HAProxy exposes stats on `127.0.0.1:8404/stats` for the FRR watcher.
- The TACACS+ container runs with `--config /etc/usg-tacacs/config.json` mounted from the host. Place certs/policy/config under `./certs`, `./policy`, and `config.example.json` (or another config file).

## Quick start (compose)

```sh
cd container
docker compose build
docker compose up -d
```

Make sure to:

- Update `container/frr/frr.conf` with your ASN, neighbor IP(s), and desired VIPs.
- Update `container/haproxy/haproxy.cfg` backends if TACACS+ runs on a different host/port.
- Provide real certs/keys and a proper `config.json` (the compose mounts `config.example.json` by default).

## Customization tips

- **BGP/Anycast**: Change `network` statements and `neighbor` lines in `frr.conf`. Health-based withdraw is wired via `container/frr/health-watch.sh` (toggle neighbor shutdown based on HAProxy stats). Adjust ASN/neighbor name in the script to match your config.
- **Load balancer**: Add more backends or enable PROXY protocol (`send-proxy`) if your TACACS+ server is updated to accept it for client IP preservation.
- **Security**: Use strong secrets, CN/SAN allowlists, and restrict FRR/HAProxy containers’ privileges as your environment allows (FRR needs host net + caps for BGP).

## IPv4 and IPv6

The provided configs bind on both families (`bind ... v4v6` in HAProxy, and IPv4/IPv6 networks in FRR). Ensure your host and upstream routers are configured for dual-stack.

## Hardening guidance

- Use non-root users where possible (HAProxy and tacacs can drop root; FRR typically requires caps/host net for BGP).
- Drop unnecessary capabilities in compose: HAProxy/tacacs can drop `NET_ADMIN`, `NET_RAW`, etc.; keep only what is needed.
- Make filesystems read-only (`read_only: true`) and mount tmpfs for runtime state (e.g., HAProxy PID/run dir) if you adapt the compose.
- Keep secrets out of images: mount certs/keys/policy/config via volumes or Docker secrets; avoid baking them into images.
- Restrict listener exposure with host firewalls; bind stats endpoints to loopback only (already 127.0.0.1:8404).
- Pin image versions (`haproxy:lts-alpine`, `frrouting/frr:10.0.1`, Rust base) and rebuild regularly for patches.
- Set resource limits (`deploy.resources.limits`) and connection caps in HAProxy to reduce DoS blast radius.

### Suggested implementation steps

1) **Non-root users**
   - Update `container/Dockerfile` to create and `USER` switch for tacacs.
   - For HAProxy, extend the service with `user: haproxy` or a custom non-root user if supported by the image.
2) **Capabilities**
   - In `container/docker-compose.yml`, add `cap_drop: [NET_ADMIN, NET_RAW]` for `haproxy` and `tacacs`.
   - Keep FRR privileged or minimally `CAP_NET_ADMIN`/`CAP_NET_RAW` as required for BGP.
3) **Read-only FS + tmpfs**
   - Add `read_only: true` for `haproxy` and `tacacs`.
   - Add `tmpfs` entries for paths that need writes (e.g., `/run/haproxy`, `/tmp`).
4) **Secrets and volumes**
   - Store TLS keys, policy, and config on the host or via Docker secrets.
   - Mount secrets with restrictive permissions; avoid adding them to images or git.
5) **Network exposure**
   - Ensure stats (`127.0.0.1:8404`) stays loopback-only; use host firewall rules to limit inbound ports 49/300.
   - If you don’t need host network for tacacs, consider bridge networking plus PROXY protocol for client IPs.
6) **Resource limits**
   - Add `deploy.resources.limits.memory` and `cpu` to `haproxy` and `tacacs` services.
   - In HAProxy, set `maxconn` and per-backend limits; consider connection rate limits if needed.
7) **Image hygiene**
   - Keep pinned versions and rebuild regularly; run `docker pull` on base images before builds.
   - Consider vulnerability scans (e.g., `trivy`) as part of CI.
