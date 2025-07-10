# System Monitoring Example

This example demonstrates how to use the CEL Go Scanner's SystemFetcher to monitor system health, services, and security on real machines.

## Overview

The SystemFetcher allows you to:
- Execute safe system commands
- Monitor service status (systemd/SysV)
- Gather system information 
- Perform security compliance checks
- All with built-in security controls

## Running the Example

```bash
cd examples/system-monitoring
go run main.go
```

## What This Example Demonstrates

### 1. 🔧 Basic System Commands
- Hostname verification
- System command execution through CEL rules
- Basic pass/fail evaluation

### 2. 🔧 Service Status Monitoring  
- SSH service status checking
- systemd service monitoring
- Service state evaluation

### 3. 📊 System Information Gathering
- System uptime collection
- Information availability verification
- Data presence validation

### 4. ⚡ Direct Fetcher Usage
- **Command Execution**: Direct system command execution
- **Service Checks**: Service status without CEL rules
- **Security Monitoring**: Security-focused system checks
- **Helper Functions**: Using convenience functions

## Security Features

### Safe Command Allowlist
The SystemFetcher includes a comprehensive allowlist of safe commands:

**✅ Allowed Commands:**
- `systemctl`, `service` - Service management
- `ps`, `top`, `htop` - Process monitoring  
- `free`, `df`, `du` - Resource monitoring
- `ip`, `netstat`, `ss` - Network information
- `uname`, `hostname`, `uptime` - System information
- `who`, `w`, `last` - User session monitoring
- `grep`, `awk`, `sed`, `cat` - Text processing
- `ls`, `find`, `which` - File operations (read-only)
- `lscpu`, `lsmem`, `lsblk` - Hardware information
- `getenforce`, `sestatus` - SELinux status
- `docker`, `podman`, `kubectl` - Container/K8s tools

**❌ Blocked Commands:**
- `rm`, `dd`, `mkfs` - Destructive operations
- `sudo`, `su` - Privilege escalation  
- `chmod`, `chown` - Permission changes
- `mount`, `umount` - Filesystem operations
- `reboot`, `poweroff` - System control

### Security Configuration
```go
// Safe mode (default) - only allowlisted commands
fetcher := NewSystemFetcher(30*time.Second, false)

// Unsafe mode - allows arbitrary commands (use with caution)
fetcher := NewSystemFetcher(30*time.Second, true)
```

## Example Outputs

### System Command Execution
```
🔹 System Info:
   ✅ Linux fedora-33 5.14.10-300.fc35.x86_64 #1 SMP x86_64 GNU/Linux

🔹 Memory Info:  
   ✅               total        used        free      shared  buff/cache   available
       Mem:          15Gi       2.1Gi        11Gi       318Mi       2.2Gi        13Gi
       Swap:        8.0Gi          0B       8.0Gi
```

### Service Status Monitoring
```
🔹 sshd Service:
   ✅ Status: active
   📊 Active:  active (running) since Mon 2024-01-01 12:00:00 UTC; 2h ago

🔹 NetworkManager Service:
   ✅ Status: active
   📊 Active:  active (running) since Mon 2024-01-01 10:00:00 UTC; 4h ago
```

### Security Checks
```
🔹 SELinux Status:
   ✅ Enforcing

🔹 Firewall Status:
   ✅ active

🔹 Active Sessions:
   ✅ user     pts/0        2024-01-01 12:00 (192.168.1.100)
```

## Integration Patterns

### 1. CEL Rules with System Commands
```go
rule := celscanner.NewRuleBuilder("security-check").
    WithSystemInput("selinux", "", "getenforce", []string{}).
    WithSystemInput("firewall", "", "systemctl", []string{"is-active", "firewalld"}).
    SetExpression(`selinux.success && firewall.success`).
    WithName("Security Baseline Check").
    Build()
```

### 2. Direct Fetcher Usage
```go
systemFetcher := fetchers.NewSystemFetcher(30*time.Second, false)
input := celscanner.NewSystemInput("cmd", "", "hostname", []string{})
data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)
```

### 3. Helper Functions
```go
// Check service status
active := fetchers.IsServiceActive("sshd")
enabled := fetchers.IsServiceEnabled("sshd")

// Execute safe commands
result, err := fetchers.ExecuteCommand("uptime", []string{})

// Get system information
sysInfo, err := fetchers.GetSystemInfo()
```

## Use Cases

### 1. **Infrastructure Monitoring**
- System health dashboards
- Service availability monitoring
- Resource utilization tracking
- Performance baseline establishment

### 2. **Security Compliance**
- CIS benchmark validation
- STIG compliance checking
- Security configuration verification
- Access control validation

### 3. **Operational Automation**
- Pre-deployment health checks
- Post-deployment verification
- Incident response automation
- Change validation

### 4. **Audit and Reporting**
- Compliance reporting
- System state documentation
- Change tracking
- Security assessments

## Error Handling

The example demonstrates comprehensive error handling:

```go
if err != nil {
    fmt.Printf("❌ Error: %v\n", err)
    return
}

if result.Success {
    fmt.Printf("✅ %s\n", result.Output)
} else {
    fmt.Printf("❌ Command failed: %s\n", result.Error)
}
```

## Best Practices

1. **Always use safe mode** unless you specifically need arbitrary commands
2. **Validate command output** before making decisions
3. **Handle errors gracefully** - commands may fail on different systems
4. **Use helper functions** for common operations
5. **Set appropriate timeouts** for long-running commands
6. **Log security-relevant operations** for audit trails

## Platform Compatibility

This example works on:
- ✅ Linux (systemd and SysV)
- ✅ Unix-like systems 
- ⚠️ Windows (limited - some commands may not be available)

## Next Steps

- Explore the [Live Kubernetes Example](../live-kubernetes/) for cluster monitoring
- Check out [Basic Examples](../basic/) for fundamental concepts
- Review [Complex Examples](../complex/) for advanced CEL expressions
- See [Filesystem Examples](../filesystem/) for file-based monitoring 