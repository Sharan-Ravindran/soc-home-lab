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
```
The authentication failed as expected.

I repeated the controlled test four times to generate authentication
telemetry.

## Detection

Windows generated Security Event ID 4625 for each failed authentication.
Wazuh successfully collected and displayed the events.

## Important Event Details
Event ID: 4625
Target username: Administrator
Source IP: 192.168.251.128
Source workstation: KALI
Target host: Test_lab
Logon Type: 3 (Network)
Logon Process: NtLmSsp
Status: 0xc000006d
SubStatus: 0xc000006a
Wazuh rule level: 5

## Analysis

The event indicates that a network authentication attempt was made against
the Windows endpoint using the Administrator account. Windows rejected the
authentication because the supplied password was incorrect.

The source workstation was identified as KALI, linking the authentication
attempt to the Kali Linux testing VM.

Four controlled failed authentication attempts were generated during the
test.

## MITRE ATT&CK

The observed behavior is consistent with the Brute Force technique family,
specifically:

| T1110 - Brute Force 
| T1110.001 - Password Guessing

The Wazuh event displayed T1531 (Account Access Removal), but this does not
match the behavior performed during this test. The MITRE mapping provided
by a SIEM rule should therefore be validated against the actual event and
investigation context rather than treated as proof of attacker behavior.

## Conclusion

The lab successfully demonstrated the complete telemetry pipeline:

Kali Linux
→ SMB authentication attempt
→ Windows Event 4625
→ Wazuh Agent
→ Wazuh SIEM

This confirms that the lab can detect and investigate controlled
authentication activity originating from the Kali Linux VM.
