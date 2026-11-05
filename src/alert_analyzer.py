import json
import sqlite3
import hashlib
from pathlib import Path
from collections import Counter

EVE_LOG = Path("/var/log/suricata/eve.json")
DB_PATH = Path("database/nidrs.db")
CUSTOM_RULE_ID = 1000001


def analyze_alerts():
    alerts = []

    with EVE_LOG.open("r") as file:
        for line in file:
            try:
                event = json.loads(line)

                if event.get("event_type") != "alert":
                    continue

                alert_data = event.get("alert", {})

                alert = {
                    "timestamp": event.get("timestamp"),
                    "source_ip": event.get("src_ip"),
                    "destination_ip": event.get("dest_ip"),
                    "protocol": event.get("proto"),
                    "signature": alert_data.get("signature"),
                    "severity": alert_data.get("severity"),
                    "signature_id": alert_data.get("signature_id"),
                    "event_key": hashlib.sha256(
                        line.strip().encode("utf-8")
                    ).hexdigest()
                }

                alerts.append(alert)

            except json.JSONDecodeError:
                continue

    return alerts


def save_to_database(alerts):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    inserted = 0

    for alert in alerts:
        cursor.execute("""
            INSERT OR IGNORE INTO alerts (
                timestamp, source_ip, destination_ip,
                protocol, signature, severity,
                signature_id, event_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["protocol"],
            alert["signature"],
            alert["severity"],
            alert["signature_id"],
            alert["event_key"]
        ))

        inserted += cursor.rowcount

    connection.commit()
    connection.close()

    print(f"\nNew alerts saved: {inserted}")
    print(f"Duplicate alerts skipped: {len(alerts) - inserted}")


def display_summary(alerts):
    protocols = Counter(alert["protocol"] for alert in alerts)

    custom_alerts = sum(
        1 for alert in alerts
        if alert["signature_id"] == CUSTOM_RULE_ID
    )

    print("\n========== NIDRS ALERT SUMMARY ==========")
    print(f"Total Alerts        : {len(alerts)}")
    print(f"Custom Rule Alerts  : {custom_alerts}")
    print(f"Other Rule Alerts   : {len(alerts) - custom_alerts}")

    print("\nProtocol Statistics:")

    for protocol, count in protocols.items():
        print(f"{protocol:<18}: {count}")


if __name__ == "__main__":
    detected_alerts = analyze_alerts()
    display_summary(detected_alerts)
    save_to_database(detected_alerts)
