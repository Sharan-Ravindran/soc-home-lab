# Investigation 4 — PowerShell Process Activity Analysis

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
```bash
UtcTime:
2026-09-15 10:53:21.498

ProcessId:
7408

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

User:
Test_lab\SOCuser

IntegrityLevel:
High

ParentProcessId:
1324

ParentImage:
C:\Windows\explorer.exe

ParentCommandLine:
C:\WINDOWS\Explorer.EXE

ParentUser:
Test_lab\SOCuser
```
The executable was identified as:
```bash
Windows PowerShell
Microsoft Corporation
```

Child Process Correlation

Additional Sysmon telemetry showed whoami.exe being executed by PowerShell.

<img width="1668" height="479" alt="image" src="https://github.com/user-attachments/assets/18704fb8-f54f-4383-8241-156bf26e520a" />

This established the following process relationship:

powershell.exe (PID 11396)  
    |  
    └── whoami.exe (PID 10824)  

The whoami command was manually executed during the investigation to generate and verify telemetry.
