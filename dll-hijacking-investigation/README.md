# Possible DLL Search Order Hijacking Investigation

## Scenario

Wazuh generated multiple alerts for possible DLL Search Order Hijacking and DLL Side-Loading activity on the monitored Windows 11 endpoint.

The alerts were generated after Sysmon detected a DLL being created in a temporary Windows directory.

The purpose of this investigation was to determine whether the activity represented malicious DLL hijacking or legitimate Windows system activity.

---

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux | Security testing VM |
| Windows 11 | Monitored endpoint |
| Wazuh | SIEM / security monitoring |
| Sysmon | Endpoint telemetry |

---

## Initial Alert

Wazuh generated the following alert:

- **Rule ID:** `92219`
- **Severity:** `6`
- **Description:** Possible DLL search order hijack
- **Sysmon Event ID:** `11`
- **Event Type:** File Create

<img width="1862" height="210" alt="image" src="https://github.com/user-attachments/assets/8017a4ae-c666-4282-9641-a935c464ce7b" />


The alert was triggered after the following file was created:

```text
C:\Windows\SystemTemp\{GUID}\ssshim.dll
```
Wazuh mapped the activity to:

- T1574.001 — DLL Search Order Hijacking
- T1574.002 — DLL Side-Loading

However, these mappings were treated as detection metadata and not as proof that either technique had occurred.

## Initial Telemetry

**The Sysmon event showed:**

| Field |	Value |
|---|---|
| Event ID | 11 |
| Event Type | File Create |
| Creating Process | C:\Windows\System32\svchost.exe |
| Process ID | 6068 |
| User | NT AUTHORITY\SYSTEM |
| Created File | ssshim.dll |
| Location | C:\Windows\SystemTemp\{GUID}\ |

The alert had fired multiple times, indicating repeated activity.

## Investigation

**1. Identify the Creating Process**

The Sysmon event identified the creating process as:
```text
C:\Windows\System32\svchost.exe
```
The process was running under:
```text
NT AUTHORITY\SYSTEM
```
The process was then investigated using its Process ID.

Get-CimInstance Win32_Process -Filter "ProcessId = 6068" |
Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId

The result showed:

ProcessId       : 6068
Name            : svchost.exe
ExecutablePath  : C:\WINDOWS\system32\svchost.exe
CommandLine     : C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s wuauserv
ParentProcessId : 864
