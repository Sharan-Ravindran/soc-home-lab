```python
import json
import time
from datetime import datetime


# -----------------------------
# Configuration
# -----------------------------

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
PROCESSED_FILE = "/home/wazuhadmin/soc-incident-analyzer/processed_ids.txt"

POLL_INTERVAL = 5
INCIDENT_TIMEOUT = 300


# -----------------------------
# Load Wazuh alerts
# -----------------------------

def load_alerts():
    alerts = []

    try:
        with open(ALERTS_FILE, "r") as file:
            for line in file:
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        print("Could not find Wazuh alerts file.")

    return alerts


# -----------------------------
# Processed alert IDs
# -----------------------------

def load_processed_ids():
    processed_ids = set()

    try:
        with open(PROCESSED_FILE, "r") as file:
            for line in file:
                processed_ids.add(line.strip())

    except FileNotFoundError:
        pass

    return processed_ids


def save_processed_ids(alerts):
    with open(PROCESSED_FILE, "a") as file:

        for alert in alerts:

            alert_id = alert.get("id")

            if alert_id:
                file.write(alert_id + "\n")


# -----------------------------
# Find new Flask alerts
# -----------------------------

def get_new_flask_alerts(alerts, processed_ids):

    new_alerts = []

    for alert in alerts:

        alert_id = alert.get("id")

        decoder = alert.get("decoder", {}).get("name")

        if decoder != "flask-webapp":
            continue

        if alert_id in processed_ids:
            continue

        new_alerts.append(alert)

    return new_alerts


# -----------------------------
# Display alert information
# -----------------------------

def analyze_alert(alert):

    data = alert.get("data", {})
    rule = alert.get("rule", {})

    source_ip = data.get("srcip", "Unknown")
    method = data.get("method", "Unknown")
    url = data.get("url", "Unknown")
    user_agent = data.get("user_agent", "Unknown")

    severity = rule.get("level", 0)
    description = rule.get("description", "Unknown")

    print("\nNEW ALERT")
    print("--------------------------------")
    print("Source IP :", source_ip)
    print("Method    :", method)
    print("URL       :", url)
    print("User-Agent:", user_agent)
    print("Severity  :", severity)
    print("Detection :", description)

    return {
        "source_ip": source_ip,
        "url": url,
        "method": method,
        "severity": severity,
        "description": description,
        "timestamp": data.get("timestamp")
    }


# -----------------------------
# Determine attack type
# -----------------------------

def get_attack_type(description):

    description = description.lower()

    if "sql" in description:
        return "SQL Injection"

    if "xss" in description:
        return "XSS"

    return "Other"


# -----------------------------
# Simple incident correlation
# -----------------------------

def correlate_alerts(alerts):

    if not alerts:
        return

    print("\nINCIDENT SUMMARY")
    print("--------------------------------")

    source_ips = set()
    attack_types = set()
    urls = set()

    highest_severity = 0

    for alert in alerts:

        data = alert.get("data", {})
        rule = alert.get("rule", {})

        source_ip = data.get("srcip")

        description = rule.get("description", "")
        severity = rule.get("level", 0)
        url = data.get("url")

        if source_ip:
            source_ips.add(source_ip)

        if url:
            urls.add(url)

        attack_types.add(get_attack_type(description))

        if severity > highest_severity:
            highest_severity = severity

    print("Source IP(s) :", ", ".join(source_ips))
    print("Attack types :", ", ".join(attack_types))
    print("URLs visited :", len(urls))
    print("Alert count  :", len(alerts))
    print("Max severity :", highest_severity)


# -----------------------------
# Main analyzer
# -----------------------------

def main():

    alerts = load_alerts()

    processed_ids = load_processed_ids()

    new_alerts = get_new_flask_alerts(
        alerts,
        processed_ids
    )

    if not new_alerts:
        return

    print("\n================================")
    print("SOC INCIDENT ANALYZER")
    print("================================")

    analyzed_alerts = []

    for alert in new_alerts:

        result = analyze_alert(alert)

        analyzed_alerts.append(alert)

    correlate_alerts(analyzed_alerts)

    save_processed_ids(new_alerts)


# -----------------------------
# Continuous monitoring
# -----------------------------

if __name__ == "__main__":

    print("\nSOC INCIDENT ANALYZER")
    print("==============================")
    print("Monitoring Wazuh alerts...")
    print("Press Ctrl+C to stop.\n")

    while True:

        main()
        time.sleep(POLL_INTERVAL)
```
