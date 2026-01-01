---
icon: lucide/user
---

# User Guide

This guide is for network engineers and operators who use `usg-tacacs` for device authentication and authorization.

## What is TACACS+?

TACACS+ (Terminal Access Controller Access-Control System Plus) is a protocol that provides:

- **Authentication** - Verifying user identity
- **Authorization** - Determining what commands users can execute
- **Accounting** - Logging user activities

## How It Works

```
                                    ┌─────────────────┐
                                    │   LDAP Server   │
                                    │  (Optional)     │
                                    └────────┬────────┘
                                             │
┌──────────────┐     TACACS+      ┌──────────┴─────────┐
│   Network    │◄────────────────►│    usg-tacacs      │
│   Device     │   (TLS/TCP)      │    Server          │
└──────────────┘                  └──────────┬─────────┘
                                             │
                                    ┌────────┴────────┐
                                    │  Policy Engine  │
                                    │  (JSON Rules)   │
                                    └─────────────────┘
```

1. You connect to a network device (router, switch, firewall)
2. The device contacts the TACACS+ server
3. The server verifies your credentials (local or LDAP)
4. The server checks if you're allowed to run commands
5. The server logs your session and commands

## Authentication Methods

### Username/Password (PAP)

The most common method. Enter your credentials when prompted:

```
Username: admin
Password: ********
```

### ASCII Interactive

Some devices use multi-step prompts:

```
Username: admin
Password: ********
Enter verification code: 123456
```

### CHAP (Challenge-Handshake)

Used by some devices for enhanced security. Works automatically - no user action required.

## Authorization

After authentication, every command you run is checked against the policy:

```
router# show running-config     ← Allowed
router# configure terminal      ← May be denied based on policy
```

### Understanding Denials

If a command is denied, you'll see a message from the device:

```
router# reload
% Authorization denied
```

Contact your administrator if you need access to denied commands.

## Best Practices

### Secure Your Credentials

1. **Use strong passwords** - At least 12 characters, mixed case, numbers, symbols
2. **Never share credentials** - Each user should have their own account
3. **Report compromises immediately** - If you suspect your password is exposed

### Session Management

1. **Log out when done** - Don't leave sessions open
2. **Use single-connection mode** - If your device supports it, for efficiency
3. **Be aware of timeouts** - Sessions may disconnect after inactivity

### Command Authorization

1. **Know your role** - Understand what commands you're authorized to use
2. **Request access properly** - Follow your organization's change process
3. **Review before executing** - Double-check destructive commands

## Troubleshooting

### "Authentication Failed"

Possible causes:

- Incorrect username or password
- Account locked due to too many failures
- LDAP server unavailable
- Your account is not in a required group

Actions:

- Verify credentials carefully
- Wait a few minutes if locked out
- Contact your administrator

### "Authorization Denied"

Possible causes:

- Command not permitted for your user/group
- Policy doesn't cover this command
- Service/protocol mismatch

Actions:

- Check if the command is appropriate for your role
- Contact your administrator to request access

### "Connection Timeout"

Possible causes:

- TACACS+ server unreachable
- Network issues between device and server
- Firewall blocking port 300 (TLS) or 49 (legacy)

Actions:

- Use local authentication if available
- Report the issue to your network team

### "Certificate Error"

Possible causes:

- Device certificate not trusted by server
- Certificate expired
- Clock skew between device and server

Actions:

- Report to your network administrator
- They may need to update certificates

## Session Types

### Single-Connection Mode

If enabled, your device maintains one connection for multiple requests:

- More efficient
- Faster command execution
- Session bound to initial user

### Standard Mode

Each request uses a new connection:

- More overhead
- May be required for some devices

## Accounting Records

Your activities are logged for auditing:

| Event | What's Logged |
|-------|---------------|
| Login | Username, source IP, time |
| Commands | Full command text, result |
| Logout | Session duration, bytes transferred |

These logs help with:

- Security audits
- Troubleshooting
- Compliance requirements

## Getting Help

If you encounter issues:

1. Note the exact error message
2. Record the time and device name
3. Check if others have the same issue
4. Contact your network administrator

## Glossary

| Term | Definition |
|------|------------|
| AAA | Authentication, Authorization, and Accounting |
| mTLS | Mutual TLS - both client and server present certificates |
| NAD | Network Access Device - router, switch, etc. |
| PAP | Password Authentication Protocol |
| CHAP | Challenge-Handshake Authentication Protocol |
| Single-Connect | Mode where device maintains persistent connection |
