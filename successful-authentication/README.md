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

## Investigation
**1. Identify the authentication event**

Windows Event ID 4624 confirmed that authentication was successful.

**2. Determine the logon type**

Logon Type 3 indicates a network logon.
This is consistent with the SMB connection initiated from Kali.

**3. Identify the account**

The target account was:
```bash
socuser
```
This was a local Windows account created specifically for the lab.

**4. Identify the source**

The source IP corresponded to the Kali Linux VM.
This established the direction of the authentication:

Kali Linux
     |
     | SMB authentication
     v
Windows 11

**5. Assess the MITRE mapping**

The Wazuh rule contained several MITRE ATT&CK mappings, but the raw event and the activity performed in the lab did not support all of those techniques.

This demonstrates why a SOC analyst should validate SIEM detections against the underlying telemetry and surrounding context rather than treating an automated MITRE mapping as conclusive evidence.

## Analyst Verdict

**Severity**: Low / Informational

**Classification**: Successful network authentication

**Malicious activity confirmed**: No

**Reason**: The authentication was intentionally performed using a known local lab account from the Kali VM.

The event demonstrates how a legitimate successful SMB authentication can generate Windows security telemetry and how SIEM analysts can investigate the source, account, logon type, authentication protocol, and MITRE metadata.

## Key Learning

This investigation demonstrated:

Windows Event ID 4624  
Network Logon (Type 3)  
NTLM authentication  
SMB authentication  
Local Windows accounts  
Wazuh event investigation  
MITRE ATT&CK technique validation  
Differentiating SIEM rule metadata from confirmed attacker behavior  
Building an investigation from raw security telemetry  

### Screenshots
<img width="1687" height="82" alt="image" src="https://github.com/user-attachments/assets/3199bc58-a53a-4b8c-b716-5128fbe79d6f" />
