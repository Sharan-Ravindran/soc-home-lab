# SOC Home Lab

Hands-on SOC lab built to learn security monitoring, detection and incident
investigation using Wazuh, Sysmon, Windows 11 and Kali Linux.

## Lab Architecture

Kali Linux → Windows 11 → Wazuh SIEM

- Kali Linux: attacker/security testing VM
- Windows 11: monitored endpoint
- Wazuh: SIEM and centralized security monitoring
- Sysmon: endpoint telemetry

## Completed Investigations

### 1. SMB Authentication Failure

Simulated repeated failed SMB authentication attempts from Kali Linux
against the Windows endpoint.

Investigated:

- Windows Event ID 4625
- Failed authentication
- Source IP identification
- Target account identification
- Logon Type
- NTLM authentication
- Wazuh detection
- MITRE ATT&CK mapping

[Read the investigation](02-authentication-investigation/investigation.md)

## Current Status

- [x] Wazuh SIEM deployed
- [x] Windows endpoint connected
- [x] Sysmon deployed
- [x] Windows event collection configured
- [x] SMB authentication telemetry tested
- [x] First authentication investigation completed
- [ ] Successful authentication investigation
- [ ] PowerShell telemetry investigation
- [ ] Process execution investigation
- [ ] Network activity investigation
- [ ] Full incident timeline
