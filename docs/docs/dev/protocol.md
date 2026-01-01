---
icon: lucide/file-code
---

# Protocol Implementation

This document details how `usg-tacacs` implements the TACACS+ protocol per RFC 8907 and RFC 9887.

## Packet Structure

### Header Format (12 bytes)

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

### Implementation

```rust
// crates/tacacs-proto/src/header.rs
pub struct Header {
    pub version: u8,      // 0xC0 (major 12, minor 0) or 0xC1 (minor 1)
    pub packet_type: u8,  // 1=authen, 2=author, 3=acct
    pub seq_no: u8,       // Sequence number (odd=client, even=server)
    pub flags: u8,        // TAC_PLUS_UNENCRYPTED_FLAG, etc.
    pub session_id: u32,  // Random session identifier
    pub length: u32,      // Body length
}
```

## Packet Types

### Authentication (TYPE_AUTHEN = 0x01)

Used for verifying user identity.

**Start Packet** (client → server):

```rust
pub struct AuthenStart {
    pub header: Header,
    pub action: u8,        // LOGIN, CHPASS, SENDAUTH
    pub priv_lvl: u8,      // Privilege level (0-15)
    pub authen_type: u8,   // ASCII, PAP, CHAP, etc.
    pub service: u8,       // LOGIN, ENABLE, PPP, etc.
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub data: Vec<u8>,     // Initial data (e.g., password for PAP)
}
```

**Reply Packet** (server → client):

```rust
pub struct AuthenReply {
    pub status: u8,        // PASS, FAIL, GETDATA, GETUSER, GETPASS, ERROR
    pub flags: u8,         // NOECHO
    pub server_msg: String,
    pub data: Vec<u8>,
}
```

**Continue Packet** (client → server):

```rust
pub struct AuthenContinue {
    pub header: Header,
    pub flags: u8,         // ABORT flag
    pub user_msg: Vec<u8>,
    pub data: Vec<u8>,
}
```

### Authorization (TYPE_AUTHOR = 0x02)

Used for command authorization.

**Request Packet**:

```rust
pub struct AuthorizationRequest {
    pub header: Header,
    pub authen_method: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub authen_service: u8,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub args: Vec<String>,  // service=, cmd=, cmd-arg=, etc.
}
```

**Response Packet**:

```rust
pub struct AuthorizationResponse {
    pub status: u8,         // PASS_ADD, PASS_REPL, FAIL, ERROR
    pub args: Vec<String>,  // Attributes to add/replace
    pub server_msg: String,
    pub data: String,
}
```

### Accounting (TYPE_ACCT = 0x03)

Used for session logging.

**Request Packet**:

```rust
pub struct AccountingRequest {
    pub header: Header,
    pub flags: u8,          // START, STOP, WATCHDOG
    pub authen_method: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub authen_service: u8,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub args: Vec<String>,  // task_id=, elapsed_time=, etc.
}
```

**Response Packet**:

```rust
pub struct AccountingResponse {
    pub status: u8,         // SUCCESS, ERROR
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}
```

## Obfuscation

### MD5-Based Body Encryption

Per RFC 8907 Section 4.5:

```rust
// crates/tacacs-proto/src/crypto.rs
pub fn apply_body_crypto(header: &Header, body: &mut [u8], secret: Option<&[u8]>) -> Result<()> {
    let Some(secret) = secret else {
        return Ok(());
    };

    // Generate pseudo-pad
    let mut pad = Vec::new();
    let mut prev_hash = compute_initial_hash(secret, header);

    while pad.len() < body.len() {
        pad.extend_from_slice(&prev_hash);
        prev_hash = md5::compute(&[secret, &prev_hash].concat()).0;
    }

    // XOR body with pad
    for (b, p) in body.iter_mut().zip(pad.iter()) {
        *b ^= p;
    }

    Ok(())
}
```

### Initial Hash Computation

```rust
fn compute_initial_hash(secret: &[u8], header: &Header) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(&header.session_id.to_be_bytes());
    hasher.update(secret);
    hasher.update(&[header.version]);
    hasher.update(&[header.seq_no]);
    hasher.finalize().into()
}
```

## Sequence Number Handling

### Rules

1. First packet in session: `seq_no = 1`
2. Client packets: odd sequence numbers
3. Server packets: even sequence numbers
4. Increment by 1 for each packet
5. Wrap at 255 (use `wrapping_add`)

### Implementation

```rust
// Validate client packet
pub fn validate_request_header(header: &Header) -> Result<()> {
    ensure!(header.seq_no % 2 == 1, "client packets must have odd seq_no");
    Ok(())
}

// Prepare server response
pub fn prepare_server_reply(request_header: &Header) -> Header {
    Header {
        seq_no: request_header.seq_no.wrapping_add(1),
        ..request_header.response(0)
    }
}
```

## Session State

### Authentication Session

```rust
pub struct AuthSessionState {
    pub header: Header,
    pub authen_type: Option<u8>,
    pub username: Option<String>,
    pub username_raw: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    pub last_seq: u8,
    // ... ASCII flow state
}
```

### Single-Connect Mode

When `FLAG_SINGLE_CONNECT` is set:

1. First successful authentication binds user to connection
2. Subsequent requests must match bound user
3. Session ID must remain consistent
4. Connection persists until timeout or error

```rust
pub struct SingleConnectState {
    pub user: Option<String>,
    pub active: bool,
    pub locked: bool,
    pub session: Option<u32>,
}
```

## Attribute Validation

### Authorization Attributes

Required validation per RFC 8907:

```rust
pub fn validate_author_request(req: &AuthorizationRequest) -> Result<()> {
    // service= is mandatory
    ensure!(has_service_attr(&req.args), "service attribute required");

    // For shell service, protocol= required, cmd= forbidden
    if is_shell_service(&req.args) {
        ensure!(has_protocol_attr(&req.args), "protocol required for shell");
        ensure!(!has_cmd_attr(&req.args), "cmd forbidden for shell");
    }

    // service= must precede protocol= and cmd=
    validate_attribute_order(&req.args)?;

    Ok(())
}
```

### Accounting Attributes

```rust
pub fn validate_accounting_request(req: &AccountingRequest) -> Result<()> {
    // START requires task_id
    if is_start(req.flags) {
        ensure!(has_task_id(&req.args), "START requires task_id");
    }

    // STOP requires task_id, elapsed_time, status, bytes_in, bytes_out
    if is_stop(req.flags) {
        ensure!(has_task_id(&req.args), "STOP requires task_id");
        ensure!(has_elapsed_time(&req.args), "STOP requires elapsed_time");
        ensure!(has_status(&req.args), "STOP requires status");
        ensure!(has_bytes_in(&req.args), "STOP requires bytes_in");
        ensure!(has_bytes_out(&req.args), "STOP requires bytes_out");
    }

    Ok(())
}
```

## Error Handling

### Status Codes

Authentication:
- `AUTHEN_STATUS_PASS` (0x01) - Success
- `AUTHEN_STATUS_FAIL` (0x02) - Failure
- `AUTHEN_STATUS_GETDATA` (0x03) - Need more data
- `AUTHEN_STATUS_GETUSER` (0x04) - Need username
- `AUTHEN_STATUS_GETPASS` (0x05) - Need password
- `AUTHEN_STATUS_ERROR` (0x07) - Server error

Authorization:
- `AUTHOR_STATUS_PASS_ADD` (0x01) - Pass, add attrs
- `AUTHOR_STATUS_PASS_REPL` (0x02) - Pass, replace attrs
- `AUTHOR_STATUS_FAIL` (0x10) - Denied
- `AUTHOR_STATUS_ERROR` (0x11) - Error

Accounting:
- `ACCT_STATUS_SUCCESS` (0x01) - Recorded
- `ACCT_STATUS_ERROR` (0x02) - Failed

### Error Responses

When errors occur, the server returns appropriate status with diagnostic information:

```rust
let response = AuthorizationResponse {
    status: AUTHOR_STATUS_ERROR,
    server_msg: "service attribute required".to_string(),
    data: "reason=rfc-validate;detail=missing service".to_string(),
    args: vec![],
};
```

## Testing Protocol Compliance

### Packet Capture

```sh
# Capture TACACS+ traffic
tcpdump -i eth0 -w tacacs.pcap port 49 or port 300

# Analyze with Wireshark
wireshark tacacs.pcap
```

### Validation Tests

```rust
#[test]
fn test_sequence_number_validation() {
    // Client packets must be odd
    let header = Header { seq_no: 1, ..default() };
    assert!(validate_request_header(&header).is_ok());

    let header = Header { seq_no: 2, ..default() };
    assert!(validate_request_header(&header).is_err());
}

#[test]
fn test_attribute_order() {
    // service= must precede cmd=
    let args = vec!["cmd=show", "service=shell"];
    assert!(validate_attribute_order(&args).is_err());
}
```

## Performance Considerations

### Connection Handling

- Uses Tokio async runtime
- Per-connection task spawning
- Connection limiting per IP
- Single-connect mode reduces overhead

### Memory Management

- Zero-copy parsing where possible
- Bounded packet sizes (configurable maximum)
- Connection state cleanup on timeout

### Crypto Performance

- MD5 for legacy obfuscation (required by RFC)
- TLS 1.3 for transport security
- Argon2 for password hashing (configurable)
