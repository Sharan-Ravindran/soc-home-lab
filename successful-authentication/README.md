# Successful Authentication Investigation

## Scenario

A successful SMB authentication was performed from the Kali Linux VM to the Windows 11 endpoint using a valid local account.

The purpose of this investigation was to understand how successful remote authentication appears in Wazuh and how a SOC analyst should interpret the associated Windows security telemetry.

---

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux | Security testing / analyst VM |
| Windows 11 | Monitored endpoint |
| Wazuh | SIEM / security monitoring |
| Sysmon | Endpoint telemetry |

---

## Activity Performed

From Kali Linux, I connected to the Windows endpoint using SMB:

```bash
smbclient //192.168.251.132/IPC$ -U socuser
```
Authentication was successful and an SMB session was established.

## Detection

Wazuh detected a successful remote logon.

## Windows Event ID

4624 — An account was successfully logged on.

## Observed details
- Target account: socuser
- Logon Type: 3 — Network
- Authentication: NTLM
- Source: Kali Linux VM
- Destination: Windows 11 endpoint
- Protocol: SMB

The successful authentication generated additional Windows security events related to the logon, including special privileges being assigned and the account later logging off.

## MITRE ATT&CK Analysis

Wazuh mapped the detection to:

- T1550.002 — Pass the Hash
- T1078.002 — Domain Accounts
- T1021.001 — Remote Services: RDP

However, the MITRE mappings were not treated as proof that these techniques occurred.

## Analyst Assessment

The test used a valid plaintext password for a local Windows account.
Therefore:

**Pass the Hash (T1550.002)**: Not demonstrated. No NTLM hash was supplied directly.
**Domain Accounts (T1078.002)**: Not applicable to this test because socuser was a local account.
**RDP (T1021.001)**: Not performed. The connection was made through SMB.

The observed activity is more closely associated with:

- T1021.002 — SMB/Windows Admin Shares
- T1078.003 — Local Accounts

These mappings describe the observed behavior more accurately, although the event alone does not establish malicious intent.
