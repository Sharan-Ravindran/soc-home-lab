# PowerShell Process Activity Analysis

## Overview

This investigation analyzes PowerShell activity detected through Sysmon and monitored by Wazuh.

The objective was to determine:

- Which user launched PowerShell
- How PowerShell was started
- What command line was used
- Which process was the parent
- Why Wazuh generated a high-severity alert related to a PowerShell temporary file
- Whether the activity showed signs of malicious execution

The investigation demonstrates an important SOC principle:

> An alert is an indication for investigation, not proof of malicious activity.

---

## Lab Environment

- **Endpoint:** Windows 11 Pro
- **Endpoint Hostname:** `Test_lab`
- **Wazuh Agent:** `001`
- **Endpoint IP:** `192.168.251.132`
- **Monitoring:** Wazuh
- **Telemetry:** Microsoft Sysmon
- **User:** `Test_lab\SOCuser`

---

## Investigation Scenario

PowerShell activity generated telemetry on the Windows endpoint.

Wazuh generated a Level 15 alert:

<img width="1886" height="127" alt="image" src="https://github.com/user-attachments/assets/3589254d-1c3a-412b-aef2-fc36bd229448" />


- **Wazuh Rule:** `92213`
- **Event ID:** `11`
- **Description:** `Executable file dropped in folder commonly used by malware`
- **MITRE ATT&CK:** `T1105 - Ingress Tool Transfer`

The alert was associated with PowerShell creating a temporary `.ps1` file:

```text
C:\Users\SOCuser\AppData\Local\Temp\__PSScriptPolicyTest_wths2qej.l2u.ps1
```
Because PowerShell is frequently abused by attackers, the activity required investigation rather than being dismissed based only on the alert description.

---

## Initial Alert

**Wazuh Alert**
- Rule ID: 92213
- Level: 15
- Event ID: 11

**Relevant telemetry:**

Image:
```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
Process ID:
```text
11396
```
User:
```text
Test_lab\SOCuser
```
Target Filename:
```text
C:\Users\SOCuser\AppData\Local\Temp\__PSScriptPolicyTest_wths2qej.l2u.ps1
```
The alert was triggered because a .ps1 file was created in the user's temporary directory.

## Sysmon Event ID 1 — PowerShell Process Creation

A separate Sysmon Event ID 1 was used to analyze PowerShell process creation.

Relevant event:

<img width="1647" height="492" alt="image" src="https://github.com/user-attachments/assets/f7ecf223-d148-4e72-a6e5-05d471638a30" />

The executable was identified as:
```bash
Windows PowerShell
Microsoft Corporation
```

## Child Process Correlation

Additional Sysmon telemetry showed whoami.exe being executed by PowerShell.

<img width="1668" height="479" alt="image" src="https://github.com/user-attachments/assets/18704fb8-f54f-4383-8241-156bf26e520a" />

This established the following process relationship:

powershell.exe (PID 11396)  
    |  
    └── whoami.exe (PID 10824)  

The whoami command was manually executed during the investigation to generate and verify telemetry.

## Wazuh Alert Correlation

The PowerShell process itself was successfully recorded by Sysmon as Event ID 1.

However, searching the Wazuh alert index for the specific Event ID 1 PowerShell process did not return an alert.

This demonstrates an important distinction between telemetry and alerts:

Sysmon Event  
      |  
      v  
Wazuh Agent  
      |  
      +----> Event collected  
      |  
      +----> Detection rule matched → Wazuh Alert  

Not every collected Sysmon event necessarily produces a Wazuh alert.

The manually launched PowerShell process did not generate a corresponding Wazuh alert because there was no detection rule match for that benign process creation.

## MITRE ATT&CK Assessment

Wazuh mapped Rule 92213 to:

- T1105 — Ingress Tool Transfer
- Tactic: Command and Control

However, the observed telemetry did not provide evidence that a malicious payload was transferred into the system.

The presence of a .ps1 file in a temporary directory alone is insufficient to establish T1105.

This investigation therefore treats the automated MITRE mapping as a detection classification requiring validation, rather than proof that the technique occurred.

## Analyst Verdict

- **Verdict:** Likely Benign / False Positive

The available telemetry is consistent with normal PowerShell activity performed by the lab user.

**Evidence supporting this assessment:**

- PowerShell ran under the expected SOCuser account.  
- The PowerShell executable was located in the standard Windows directory.  
- The executable was identified as Microsoft Windows PowerShell.  
- PowerShell was launched from explorer.exe.  
- The command line contained no suspicious arguments.  
- The associated temporary .ps1 file followed a PowerShell script-policy test naming pattern.  
- No evidence of malicious payload transfer or additional suspicious execution was identified from the available telemetry.  

The verdict is classified as **likely benign* rather than definitively benign because the investigation was limited to the available Sysmon and Wazuh telemetry.
