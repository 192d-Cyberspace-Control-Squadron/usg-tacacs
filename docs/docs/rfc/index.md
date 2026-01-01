---
icon: lucide/shield-check
---

# RFC Compliance

This document details how `usg-tacacs` implements the TACACS+ protocol standards.

## Supported RFCs

| RFC | Title | Status |
|-----|-------|--------|
| RFC 8907 | The TACACS+ Protocol | Fully Compliant |
| RFC 9887 | TACACS+ over TLS 1.3 | Fully Compliant |

## RFC 8907: The TACACS+ Protocol

RFC 8907 defines the core TACACS+ protocol for authentication, authorization, and accounting (AAA).

### Packet Structure

The implementation follows the exact packet format specified in RFC 8907 Section 4:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|major  | minor |     type      |     seq_no    |    flags      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          session_id                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            length                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Implementation**: `crates/tacacs-proto/src/header.rs`

### Authentication (Section 5)

Full support for authentication types:

| Type | Value | Status |
|------|-------|--------|
| ASCII | 0x01 | Supported |
| PAP | 0x02 | Supported |
| CHAP | 0x03 | Supported |
| MS-CHAPv1 | 0x04 | Not Supported |
| MS-CHAPv2 | 0x05 | Not Supported |

**Authentication Actions**:
- `TAC_PLUS_AUTHEN_LOGIN` (0x01) - Supported
- `TAC_PLUS_AUTHEN_CHPASS` (0x02) - Not Supported
- `TAC_PLUS_AUTHEN_SENDAUTH` (0x04) - Not Supported

**Authentication Reply Status Codes**:
- `PASS` (0x01) - Authentication successful
- `FAIL` (0x02) - Authentication failed
- `GETDATA` (0x03) - Request additional data
- `GETUSER` (0x04) - Request username
- `GETPASS` (0x05) - Request password
- `RESTART` (0x06) - Restart authentication
- `ERROR` (0x07) - Server error
- `FOLLOW` (0x21) - Redirect to another server

### Authorization (Section 6)

Full support for command authorization per RFC 8907 Section 6.

**Required Attributes**:
- `service=` - Mandatory for all requests
- `cmd=` - For command authorization
- `cmd-arg=` - Command arguments
- `protocol=` - Required for shell service

**Attribute Ordering**: The implementation enforces RFC 8907 Section 6.1 ordering requirements:
- `service=` must precede `protocol=` and `cmd=`
- For shell service, `cmd=` is forbidden in the initial authorization

**Authorization Response Status**:
- `PASS_ADD` (0x01) - Pass, add attributes
- `PASS_REPL` (0x02) - Pass, replace attributes
- `FAIL` (0x10) - Authorization denied
- `ERROR` (0x11) - Server error
- `FOLLOW` (0x21) - Redirect

### Accounting (Section 7)

Full support for accounting records with task_id tracking.

**Accounting Flags**:
- `START` (0x02) - Session start
- `STOP` (0x04) - Session end
- `WATCHDOG` (0x08) - Interim update

**Required Attributes by Flag**:

| Flag | Required Attributes |
|------|---------------------|
| START | `task_id` |
| STOP | `task_id`, `elapsed_time`, `status`, `bytes_in`, `bytes_out` |
| WATCHDOG | `task_id` |

**Task ID Tracking**: Per RFC 8907 Section 7.2, task_id values must be unique within a session. The implementation tracks active task_ids and rejects:
- START records with already-active task_id
- STOP/WATCHDOG records with unknown task_id

### Body Obfuscation (Section 4.5)

MD5-based body obfuscation is implemented per RFC 8907 Section 4.5:

```
pseudo_pad = MD5(session_id || secret || version || seq_no)
           || MD5(session_id || secret || version || seq_no || pseudo_pad[0..16])
           || ...
body_encrypted = body XOR pseudo_pad
```

**Implementation**: `crates/tacacs-proto/src/crypto.rs`

### Sequence Numbers (Section 4.3)

- Client packets use odd sequence numbers (1, 3, 5, ...)
- Server packets use even sequence numbers (2, 4, 6, ...)
- Sequence wraps at 255 using `wrapping_add`
- First packet in session starts at seq_no = 1

### Single-Connect Mode (Section 4.4)

When `TAC_PLUS_SINGLE_CONNECT_FLAG` is set:
- Connection persists across multiple sessions
- User binding is enforced after successful authentication
- Session ID consistency is maintained

## RFC 9887: TACACS+ over TLS 1.3

RFC 9887 defines secure transport for TACACS+ using TLS 1.3.

### TLS Configuration

| Requirement | Implementation |
|-------------|----------------|
| TLS Version | TLS 1.3 only |
| Port | 300 (tacacss) |
| Client Authentication | mTLS required |
| Certificate Validation | Full chain verification |

**Port Warning**: The server logs a warning if TLS is configured on a non-standard port:

```
WARN TLS listener on port 449 instead of RFC 9887 standard port 300 (tacacss)
```

### Obfuscation over TLS

RFC 9887 Section 5.2 states that obfuscation is not required over TLS since TLS provides confidentiality.

**Implementation Choice**: `usg-tacacs` applies MD5 obfuscation even over TLS for defense-in-depth:
- Provides additional layer of protection if TLS is compromised
- No performance impact (MD5 is fast)
- Maintains compatibility with clients that expect obfuscation

This is logged at startup:
```
INFO TLS mode: MD5 obfuscation applied for defense-in-depth (RFC 9887 permits TLS-only encryption)
```

### Certificate Requirements

Per RFC 9887 Section 4:

1. **Server Certificate**:
   - Valid X.509 certificate
   - Key usage: digitalSignature, keyEncipherment
   - Extended key usage: serverAuth

2. **Client Certificate**:
   - Valid X.509 certificate
   - Key usage: digitalSignature
   - Extended key usage: clientAuth
   - Subject/SAN identifies the network device

3. **Trust Chain**:
   - Both parties must validate the full certificate chain
   - Revocation checking should be enabled (CRL/OCSP)

### ALPN

RFC 9887 does not define an ALPN protocol identifier. The implementation sets an empty ALPN list.

## Compliance Verification

### Testing Authentication

```bash
# Test PAP authentication
tacacs_client -s 127.0.0.1:300 -k secret \
  -u testuser -p testpass -t pap

# Test ASCII authentication
tacacs_client -s 127.0.0.1:300 -k secret \
  -u testuser -p testpass -t ascii
```

### Testing Authorization

```bash
# Test command authorization
tacacs_client -s 127.0.0.1:300 -k secret \
  -u testuser --author \
  --service=shell --cmd=show --cmd-arg=version
```

### Testing Accounting

```bash
# Send accounting record
tacacs_client -s 127.0.0.1:300 -k secret \
  -u testuser --acct-start --task-id=12345

tacacs_client -s 127.0.0.1:300 -k secret \
  -u testuser --acct-stop --task-id=12345 \
  --elapsed-time=60 --bytes-in=1000 --bytes-out=500
```

### Packet Capture Analysis

```bash
# Capture TACACS+ traffic
tcpdump -i eth0 -w tacacs.pcap port 49 or port 300

# Analyze with Wireshark
wireshark -r tacacs.pcap -Y "tacplus"
```

## Known Limitations

### Not Implemented

1. **MS-CHAP**: MS-CHAPv1 and MS-CHAPv2 authentication types are not supported
2. **SENDAUTH**: The SENDAUTH authentication action is not implemented
3. **CHPASS**: Password change requests are not supported
4. **FOLLOW**: Server redirection responses are parsed but not acted upon by clients

### Deliberate Deviations

1. **TLS Obfuscation**: MD5 obfuscation is applied over TLS for defense-in-depth, though RFC 9887 permits omitting it. This provides an additional security layer with negligible overhead.

## References

- [RFC 8907 - The TACACS+ Protocol](https://datatracker.ietf.org/doc/html/rfc8907)
- [RFC 9887 - TACACS+ over TLS 1.3](https://datatracker.ietf.org/doc/html/rfc9887)
- [IANA TACACS+ Parameters](https://www.iana.org/assignments/tacacs/tacacs.xhtml)
