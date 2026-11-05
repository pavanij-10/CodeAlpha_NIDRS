from flask import Flask, render_template, request
import sqlite3
from pathlib import Path
from alert_analyzer import analyze_alerts, save_to_database

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "nidrs.db"


def get_database_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def dashboard():
    new_alerts = analyze_alerts()
    save_to_database(new_alerts)

    connection = get_database_connection()

    source_ip = request.args.get("source_ip", "").strip()
    selected_protocol = request.args.get("protocol", "").strip()
    selected_severity = request.args.get("severity", "").strip()

    conditions = []
    parameters = []

    if source_ip:
        conditions.append("source_ip LIKE ?")
        parameters.append(f"%{source_ip}%")

    if selected_protocol:
        conditions.append("protocol = ?")
        parameters.append(selected_protocol)

    if selected_severity:
        conditions.append("severity = ?")
        parameters.append(selected_severity)

    where_clause = ""

    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)

    total_alerts = connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    protocol_stats = connection.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM alerts
        GROUP BY protocol
    """).fetchall()

    severity_stats = connection.execute("""
        SELECT severity, COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        ORDER BY severity
    """).fetchall()

    protocol_options = connection.execute("""
        SELECT DISTINCT protocol
        FROM alerts
        ORDER BY protocol
    """).fetchall()

    severity_options = connection.execute("""
        SELECT DISTINCT severity
        FROM alerts
        ORDER BY severity
    """).fetchall()

    filtered_count = connection.execute(
        "SELECT COUNT(*) FROM alerts" + where_clause,
        parameters
    ).fetchone()[0]

    recent_alerts = connection.execute(
        """
        SELECT *
        FROM alerts
        """ + where_clause + """
        ORDER BY id DESC
        LIMIT 10
        """,
        parameters
    ).fetchall()

    connection.close()

    return render_template(
        "index.html",
        total_alerts=total_alerts,
        protocol_stats=protocol_stats,
        severity_stats=severity_stats,
        protocol_options=protocol_options,
        severity_options=severity_options,
        recent_alerts=recent_alerts,
        filtered_count=filtered_count,
        source_ip=source_ip,
        selected_protocol=selected_protocol,
        selected_severity=selected_severity
    )


if __name__ == "__main__":
    app.run(debug=True)
