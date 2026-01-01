---
icon: lucide/router
---

# Device Configuration Examples

This guide shows how to configure common network devices to use `usg-tacacs` for authentication and authorization.

## Cisco IOS/IOS-XE

### TLS Mode (Recommended)

```
! Enable AAA
aaa new-model

! Configure TACACS+ server group
aaa group server tacacs+ TACACS-TLS
 server name tacacs-primary
 server name tacacs-secondary

! Configure authentication
aaa authentication login default group TACACS-TLS local
aaa authentication enable default group TACACS-TLS enable

! Configure authorization
aaa authorization config-commands
aaa authorization exec default group TACACS-TLS local if-authenticated
aaa authorization commands 1 default group TACACS-TLS local if-authenticated
aaa authorization commands 15 default group TACACS-TLS local if-authenticated

! Configure accounting
aaa accounting exec default start-stop group TACACS-TLS
aaa accounting commands 1 default start-stop group TACACS-TLS
aaa accounting commands 15 default start-stop group TACACS-TLS

! Define TACACS+ servers
tacacs server tacacs-primary
 address ipv4 192.0.2.10
 key 0 your-shared-secret
 port 300
 timeout 5
 single-connection

tacacs server tacacs-secondary
 address ipv4 192.0.2.11
 key 0 your-shared-secret
 port 300
 timeout 5
 single-connection

! VTY configuration
line vty 0 15
 login authentication default
 authorization exec default
 authorization commands 1 default
 authorization commands 15 default
 accounting exec default
 accounting commands 1 default
 accounting commands 15 default
 transport input ssh
```

### Legacy Mode (TCP/49)

```
tacacs server tacacs-legacy
 address ipv4 192.0.2.10
 key 0 your-shared-secret
 port 49
 timeout 5
```

## Cisco NX-OS

```
! Enable TACACS+ feature
feature tacacs+

! Configure TACACS+ server
tacacs-server host 192.0.2.10 port 300 key your-shared-secret

! Configure AAA
aaa authentication login default group tacacs+ local
aaa authorization config-commands default group tacacs+ local
aaa authorization commands default group tacacs+ local
aaa accounting default group tacacs+
```

## Arista EOS

```
! Configure TACACS+ servers
tacacs-server host 192.0.2.10 port 300 key your-shared-secret
tacacs-server host 192.0.2.11 port 300 key your-shared-secret

! Configure AAA
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa authorization commands all default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands all default start-stop group tacacs+
```

## Juniper Junos

```
system {
    authentication-order [ tacplus password ];
    tacplus-server {
        192.0.2.10 {
            port 300;
            secret "your-shared-secret";
            timeout 5;
            single-connection;
        }
        192.0.2.11 {
            port 300;
            secret "your-shared-secret";
            timeout 5;
            single-connection;
        }
    }
    accounting {
        events [ login change-log interactive-commands ];
        destination {
            tacplus {
                server {
                    192.0.2.10 {
                        port 300;
                        secret "your-shared-secret";
                    }
                }
            }
        }
    }
}
```

## Palo Alto PAN-OS

Navigate to: **Device > Server Profiles > TACACS+**

Create a TACACS+ server profile:

| Field | Value |
|-------|-------|
| Name | tacacs-servers |
| Server | 192.0.2.10 |
| Port | 300 |
| Secret | your-shared-secret |
| Timeout | 5 |

Configure authentication profile:

Navigate to: **Device > Authentication Profile**

| Field | Value |
|-------|-------|
| Name | tacacs-auth |
| Type | TACACS+ |
| Server Profile | tacacs-servers |

## Fortinet FortiGate

```
config system admin
    edit "tacacs"
    set type tacacs+
    set two-factor disable
    set accprofile super_admin
    set vdom root
    set tacacs-server "tacacs-primary"
    next
end

config user tacacs+
    edit "tacacs-primary"
    set server 192.0.2.10
    set key your-shared-secret
    set port 300
    set authorization enable
    set authen-type chap
    next
end
```

## Checkpoint Gaia

```bash
# Configure TACACS+ authentication
tacacs-server host 192.0.2.10 key your-shared-secret port 300

# Enable TACACS+ for admin access
aaa authentication login tacacs-primary tacacs+ local
```

## Linux (via pam_tacplus)

Install pam_tacplus and configure `/etc/pam.d/sshd`:

```
auth       required     pam_tacplus.so server=192.0.2.10 secret=your-shared-secret
account    required     pam_tacplus.so server=192.0.2.10 secret=your-shared-secret
session    required     pam_tacplus.so server=192.0.2.10 secret=your-shared-secret
```

## Testing Configuration

### Verify Connectivity

From the network device, test TACACS+ server reachability:

```
! Cisco IOS
test aaa group tacacs+ admin password new-code

! Arista EOS
test tacacs-server authentication admin password

! Juniper
request system login user admin
```

### Check Authentication

1. SSH to the device
2. Enter TACACS+ credentials
3. Verify login succeeds

### Check Authorization

1. Login successfully
2. Try various commands
3. Verify allowed commands work
4. Verify denied commands are blocked

### Check Accounting

1. Perform login/logout
2. Run some commands
3. Check TACACS+ server logs for records

## Troubleshooting Device Issues

### "Server Not Responding"

```
! Check connectivity
ping 192.0.2.10

! Check port reachability
! (from a system with netcat)
nc -zv 192.0.2.10 300
```

### "Authentication Failed"

- Verify shared secret matches on both ends
- Check if user exists in LDAP/local database
- Review TACACS+ server logs

### "Authorization Denied"

- Check policy rules for user/group
- Verify command pattern matches
- Review authorization logs

### "Accounting Not Working"

- Verify accounting configuration
- Check network path to server
- Review accounting logs on server
