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
```bash
Get-CimInstance Win32_Process -Filter "ProcessId = 6068" |
Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId
```
The result showed:

<img width="970" height="152" alt="image" src="https://github.com/user-attachments/assets/0c133634-622d-405a-b6c2-6344c67bf45d" />

**2. Investigate the Hosted Service**

The svchost.exe command line contained:
```text
-s wuauserv
```
This indicated that the process was hosting the Windows Update service.

The service was verified using:
```bash
Get-Service wuauserv | Select-Object Name, Status, StartType
```
Result:


<img width="691" height="93" alt="image" src="https://github.com/user-attachments/assets/72874d1e-a937-49c6-9126-bcff449d959c" />


This showed that the Windows Update service was actively running when the DLL creation event occurred.

**3. Investigate the DLL**

The Wazuh alert referenced:
```bash
C:\Windows\SystemTemp\{GUID}\ssshim.dll
```
When the file was investigated later, it no longer existed.

This is consistent with the file being created in a temporary directory and later removed.

The known Windows copy of the DLL was then checked:
```bash
Get-AuthenticodeSignature "C:\Windows\System32\ssshim.dll"
```
The result showed:

**Status** : Valid

This confirmed that the System32 copy of ssshim.dll had a valid digital signature.

## MITRE ATT&CK Analysis

Wazuh mapped the alert to:

- T1574.001 — DLL Search Order Hijacking
- T1574.002 — DLL Side-Loading

  <img width="801" height="110" alt="image" src="https://github.com/user-attachments/assets/a0ba4664-8c2f-4ae7-9fe2-8bf349a237a5" />


However, the investigation did not find evidence that a malicious DLL was loaded or that a legitimate application was manipulated into loading an attacker-controlled DLL.

The raw telemetry only confirmed that:

- A DLL was created.
- The creating process was svchost.exe.
- The process was hosting the Windows Update service.
- The file was created inside a temporary Windows directory.
- The temporary file was later removed.

Therefore, the MITRE mappings were not considered confirmation that DLL hijacking or side-loading had occurred.

## Analyst Verdict

**Classification:** Benign / Likely False Positive

**Severity:** Low

**Malicious activity confirmed:** No

- Reason

The investigation traced the file creation event back to:

svchost.exe
    |
    +-- wuauserv
        |
        +-- Windows Update activity

The process was running from the legitimate Windows System32 directory under NT AUTHORITY\SYSTEM.

The Windows Update service was active, and the DLL was created inside a temporary Windows directory before later being removed.

No evidence was identified showing that the DLL was maliciously loaded, that an application was hijacked, or that DLL side-loading occurred.
