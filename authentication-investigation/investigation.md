# Authentication Attack Investigation

## Objective

Simulate repeated failed SMB authentication attempts from a Kali Linux
attacker VM against a Windows 11 victim VM and investigate the resulting
security telemetry using Wazuh.

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux | Attacker / security testing |
| Windows 11 | Victim / monitored endpoint |
| Wazuh | SIEM / security monitoring |
| Sysmon | Windows endpoint telemetry |

## Network

- Kali Linux: 192.168.251.128
- Windows 11: 192.168.251.133

## Attack Simulation

From Kali Linux, I attempted SMB authentication against the Windows
endpoint using an intentionally incorrect password.

Command:

```bash
smbclient //192.168.251.133/IPC$ -U Administrator%WrongPassword123!
