# usg-tacacs

Rust TACACS+ server with:

- RFC 9887 TACACS+ over TLS 1.3 (mTLS only) on TCP/300
- Optional legacy TACACS+ (TCP/49)
- Per-command authorization
- JSON policy with priorities + last-match-wins
- JSON Schema validation + validate-only mode
- SIGHUP hot reload
- Command normalization + regex auto-anchoring

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
