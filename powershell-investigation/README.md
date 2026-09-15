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

- **Wazuh Rule:** `92213`
- **Event ID:** `11`
- **Description:** `Executable file dropped in folder commonly used by malware`
- **MITRE ATT&CK:** `T1105 - Ingress Tool Transfer`

The alert was associated with PowerShell creating a temporary `.ps1` file:

```text
C:\Users\SOCuser\AppData\Local\Temp\__PSScriptPolicyTest_wths2qej.l2u.ps1
```

