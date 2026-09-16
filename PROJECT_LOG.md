# SOC Home Lab — Project Log

## Project Overview

This project is a personal SOC home lab designed to simulate a small security monitoring environment.

The goal is to understand how security events move from an application and endpoint into a SIEM, and eventually how those events can be detected, investigated, and visualized.

The lab currently uses:

* Kali Linux — attacker/test machine
* Flask — intentionally vulnerable web application
* Windows — victim/application host
* Wazuh Agent — endpoint log collection
* Wazuh Manager — security monitoring/SIEM
* Wazuh Dashboard — planned for investigation and visualization

---

# Architecture

Current architecture:

```text
Kali Linux
192.168.251.128
       |
       | HTTP requests
       v
Flask Web Application
       |
       | application logging
       v
webapp.log
       |
       | Wazuh Agent
       v
Wazuh Manager
       |
       v
archives.json
```

The Flask application is currently running on the Windows host and writes HTTP request information to:

```text
C:\Users\SOCuser\Desktop\soc-vulnerable-webapp\logs\webapp.log
```

---

# Phase 1 — Application Logging

## Objective

Before adding security detections, I wanted to establish reliable application logging.

The Flask application records HTTP requests containing information such as:

* HTTP method
* requested path
* source IP
* User-Agent
* timestamp

Example:

```text
2026-09-16 17:01:10,492 | INFO | REQUEST | method=GET | path=/ | ip=192.168.251.128 | user_agent=curl/8.21.0
```

---

# Phase 2 — Wazuh Log Collection

## Objective

The next step was getting the application's log file into Wazuh.

The Windows Wazuh Agent monitors the Flask application's `webapp.log` file and forwards the events to the Wazuh Manager.

I verified that the events were successfully reaching the Wazuh Manager.

---

# Phase 3 — Raw Event Verification

## Verification

I searched the Wazuh archive directly for the application's `REQUEST` events.

A received event contained:

```json
{
  "agent": {
    "id": "001",
    "name": "Test_lab",
    "ip": "192.168.251.132"
  },
  "manager": {
    "name": "wazuh-server"
  },
  "full_log": "2026-09-16 17:01:10,492 | INFO | REQUEST | method=GET | path=/ | ip=192.168.251.128 | user_agent=curl/8.21.0",
  "location": "C:\\Users\\SOCuser\\Desktop\\soc-vulnerable-webapp\\logs\\webapp.log"
}
```

This confirmed that the complete pipeline was functioning:

```text
HTTP request
    ↓
Flask
    ↓
webapp.log
    ↓
Wazuh Agent
    ↓
Wazuh Manager
    ↓
archives.json
```

---

# Important Observation

The event currently contains:

```json
"decoder": {}
```

This means Wazuh is receiving the event, but it has not yet been parsed using a custom application-specific decoder.

The request information is currently contained inside `full_log`.

The next objective is therefore to create a custom Wazuh decoder that can extract useful fields from the Flask log.

Potential fields include:

```text
event_type
method
path
source IP
user agent
```

---

# Current Progress

* [x] Create Flask web application
* [x] Establish application request logging
* [x] Generate requests from Kali
* [x] Configure Wazuh Agent to collect application logs
* [x] Confirm events reach Wazuh Manager
* [x] Confirm events appear in archives.json
* [ ] Create custom Wazuh decoder
* [ ] Test decoder using wazuh-logtest
* [ ] Create custom detection rules
* [ ] Generate controlled security events
* [ ] Verify alerts
* [ ] Investigate alerts
* [ ] Build SOC dashboard/visualizations
* [ ] Document detection scenarios
* [ ] Complete final project documentation

---

# Lessons Learned

### Raw log collection vs detection

A log successfully reaching Wazuh does not automatically mean Wazuh understands the security meaning of that log.

The current pipeline proves that the event is being collected.

The next stage is parsing the event into meaningful fields and then creating detection logic based on those fields.

### Why archives.json was useful

Searching the Wazuh archive allowed me to verify that the original Flask event was actually reaching the manager.

This helped separate a log-collection problem from a parsing/detection problem.

### Current challenge

The Flask event is currently visible as a raw event, but the application-specific fields have not yet been decoded.

The next phase will focus on understanding Wazuh decoders before implementing the custom decoder.

---

# Next Objective

Create and test a custom Wazuh decoder for the Flask application's `REQUEST` log format.

Before implementing it, I want to understand:

1. What a Wazuh decoder does
2. How Wazuh identifies a log
3. How regular expressions are used to extract fields
4. How decoded fields are represented in Wazuh
5. How `wazuh-logtest` can be used to test the decoder
