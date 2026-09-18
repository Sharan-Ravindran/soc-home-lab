# Web Application Attack Detection with Wazuh

## Overview

This investigation extends my SOC home lab by adding a deliberately vulnerable Flask web application and monitoring its activity with Wazuh.

The goal was to understand how a security event moves through a SOC monitoring pipeline:

```text
HTTP Request
     ↓
Flask Web Application
     ↓
Application Log
     ↓
Wazuh Agent
     ↓
Wazuh Manager
     ↓
Custom Decoder
     ↓
Detection Rule
     ↓
Security Alert
     ↓
Investigation
     ↓
Python Analysis
```
The lab was used to generate controlled SQL injection and Cross-Site Scripting (XSS) requests and observe how Wazuh collects, parses, detects, and reports the activity.

## Lab Environment
| Component |	Role |
|-----|-----|
| Kali Linux | Attacker / test machine |
| Windows |	Flask application host and Wazuh Agent |
| Flask |	Deliberately vulnerable web application |
| Wazuh Agent |	Log collection |
| Wazuh Manager |	Security monitoring and detection |
| Wazuh Dashboard |	Alert investigation and visualization |
| Python |	Alert analysis and basic correlation |

## Network
```text
Kali Linux
192.168.251.128

        ↓ HTTP

Windows / Flask
192.168.251.132

        ↓ Wazuh Agent

Wazuh Manager
192.168.251.131
```

## Objective

**The main objectives of this investigation were:**

Create application-level HTTP request logging.
Forward application logs to Wazuh.
Understand raw Wazuh events before parsing them.
Create a custom Wazuh decoder.
Extract useful fields from Flask logs.
Create custom detection rules for SQL injection and XSS.
Generate controlled attack traffic from Kali.
Investigate the resulting alerts in Wazuh.
Visualize the detected activity in the Wazuh Dashboard.
Use Python to perform basic alert analysis and correlation.

## 1. Application Logging

The Flask application records HTTP requests to:
```bash
C:\Users\SOCuser\Desktop\soc-vulnerable-webapp\logs\webapp.log
```
**Each request contains:**

Timestamp
HTTP method
Requested path
Source IP
User-Agent

Example:

<img width="1668" height="161" alt="image" src="https://github.com/user-attachments/assets/0a984fd5-ea73-4926-8517-6e7f92411230" />


This gives the monitoring system useful application-level telemetry that would not necessarily be available from endpoint logs alone.

## 2. Wazuh Log Collection

The Windows Wazuh Agent was configured to monitor the Flask application's log file.

- The event flow is:
```text
Flask
  ↓
webapp.log
  ↓
Wazuh Agent
  ↓
Wazuh Manager
```
The received events were verified in Wazuh's archived logs before creating any custom detection logic.

This helped separate log collection problems from parsing and detection problems.

## 3. Custom Wazuh Decoder

Initially, Wazuh received the Flask events as raw log data.

The event contained the original request inside:
```
full_log
```
but the application-specific values were not yet extracted into separate fields.

A custom decoder was created to parse the Flask log format.

- Decoder
  
<img width="1166" height="127" alt="image" src="https://github.com/user-attachments/assets/97794d58-8658-4989-a92c-786d679fa4ff" />

The decoder extracts:

- method
- url
- srcip
- user_agent

**For example, the raw event:**
```text
method=GET | path=/login/OR 1=1 | ip=192.168.251.128 | user_agent=curl/8.21.0
```
**is decoded into fields such as:**
```text
method      GET
url         /login/OR 1=1
srcip       192.168.251.128
user_agent  curl/8.21.0
```
**The decoder was tested using:**
wazuh-logtest

## 4. Custom Detection Rules

After the decoder was working, custom Wazuh rules were created to detect suspicious web requests.

**Base rule**

<img width="856" height="137" alt="image" src="https://github.com/user-attachments/assets/f9a28210-453e-4f93-a241-21c615c310d7" />

This identifies normal Flask application requests.

**SQL Injection detection**

<img width="1207" height="152" alt="image" src="https://github.com/user-attachments/assets/6b7312e0-8a4c-4b43-9aa8-ce0856657a3d" />

**XSS detection**

<img width="1172" height="152" alt="image" src="https://github.com/user-attachments/assets/c7532f46-d014-42ba-9129-1181362733ed" />

These rules generate severity level 10 alerts when the corresponding patterns are detected.

## 5. Controlled Attack Simulation

Testing was performed from the Kali Linux machine.
```bash
Normal request
curl "http://192.168.251.132:5000/"
Login request
curl "http://192.168.251.132:5000/login"
SQL Injection test
curl "http://192.168.251.132:5000/login/OR%201=1"
XSS test
curl "http://192.168.251.132:5000/login/<script>alert(1)</script>"
```
These requests were intentionally generated inside the isolated home lab.

## 6. Alert Investigation

- The SQL injection request produced a Wazuh alert similar to:
```text
Rule ID:     100101
Severity:    10
Source IP:   192.168.251.128
Method:      GET
URL:         /login/OR 1=1
```
- The XSS request produced:
```text
Rule ID:     100102
Severity:    10
Source IP:   192.168.251.128
Method:      GET
URL:         /login/<script>alert(1)</script>
```
**An important distinction during investigation is:**
 agent.ip

**represents the monitored Windows host:**
 192.168.251.132

**while:**
 data.srcip

**represents the source of the HTTP request:**
 192.168.251.128

This allows the analyst to distinguish between the endpoint being monitored and the source generating the web traffic.

## 7. Detection vs Exploitation

The alerts confirm that the request matched the configured detection rule.

- For example:

Possible SQL injection attempt detected

does not by itself prove that the application was successfully compromised.

- Likewise:

Possible XSS injection attempt detected

shows that an XSS-like payload was detected, but does not by itself prove that JavaScript executed successfully.

This distinction is **important** during SOC investigations because a detection identifies suspicious activity that requires investigation; it is not automatically proof of successful exploitation.

## 8. Wazuh Dashboard

The Wazuh Dashboard was used to visually investigate the generated alerts.

<img width="1920" height="871" alt="image" src="https://github.com/user-attachments/assets/ccade94a-e5cb-490d-960f-bf420622c346" />

The dashboard provides a visual view of the same telemetry that can also be inspected directly in Wazuh events.

## 9. Python SOC Analyzer

A small Python program was created as an additional analysis layer.

The Python program reads alerts generated by Wazuh from:
```bash
/var/ossec/logs/alerts/alerts.json
```
It identifies new Flask-related alerts and extracts information such as:
```text
Source IP
HTTP Method
URL
Severity
Detection Description
```
It also performs basic correlation of alerts.

Example:

<img width="576" height="292" alt="image" src="https://github.com/user-attachments/assets/e665c875-4f61-46ae-9dc0-29c6474f63d7" />

The Python analyzer is not the SIEM. Wazuh performs the log collection, decoding, detection, and alert generation. Python is used as a separate learning exercise for alert analysis and basic incident correlation.

## 10. Investigation Workflow

The completed workflow can be summarized as:
```text
1. Generate HTTP activity
        ↓
2. Flask writes the request to a log
        ↓
3. Wazuh Agent collects the log
        ↓
4. Wazuh Manager receives the event
        ↓
5. Custom decoder extracts fields
        ↓
6. Detection rules inspect the decoded data
        ↓
7. Suspicious requests generate alerts
        ↓
8. Alerts are investigated in Wazuh
        ↓
9. Dashboard visualizes the activity
        ↓
10. Python performs additional analysis
```
## 11. Key Findings

**This investigation demonstrated the difference between:**

- Log collection
- Getting the Flask event into Wazuh.
- Log parsing
- Using a decoder to extract fields such as:
```
method
url
srcip
user_agent
Detection
```

- Using Wazuh rules to identify suspicious patterns.
- Investigation
- Examining the resulting alerts and determining:
```
Who?
What?
When?
Which host?
Which URL?
Which detection rule?
Correlation
```

- Grouping related alerts together to understand a sequence of activity rather than viewing every alert in isolation.

## 12. Skills Demonstrated
```
Wazuh SIEM
Security event monitoring
Log collection
Custom Wazuh decoders
Regular expressions
Detection rules
Alert triage
Web application security
SQL injection detection
XSS detection
SOC investigation
Basic incident correlation
Python scripting
Security telemetry analysis
Wazuh Dashboard visualization
```

## Conclusion

This investigation extended my SOC home lab from endpoint monitoring into application-level security monitoring.

I built a complete pipeline in which controlled web requests generated application logs, Wazuh collected and decoded those logs, custom rules detected SQL injection and XSS patterns, alerts were investigated through the Wazuh Dashboard, and Python was used for additional alert analysis.

This provided practical experience with the basic workflow of collecting security telemetry, detecting suspicious activity, and investigating security alerts.
