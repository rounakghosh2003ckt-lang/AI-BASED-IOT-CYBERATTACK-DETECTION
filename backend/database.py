import sqlite3
import os
import io
import csv
from datetime import datetime, timedelta
import random

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "backend", "iot_cybersecurity.db")

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        confidence REAL NOT NULL,
        details TEXT,
        status TEXT DEFAULT 'New',
        mitre_id TEXT
    );
    """)

    # Detection History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detection_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        confidence REAL NOT NULL,
        severity TEXT NOT NULL,
        protocol TEXT NOT NULL,
        flow_duration REAL,
        total_packets INTEGER,
        total_bytes REAL,
        is_simulated INTEGER DEFAULT 0
    );
    """)

    # System Status / Key-Value Settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)

    conn.commit()
    conn.close()

def add_detection(source_ip, destination_ip, attack_type, confidence, severity, protocol="TCP", flow_duration=100.0, total_packets=1, total_bytes=64.0, is_simulated=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO detection_history (timestamp, source_ip, destination_ip, attack_type, confidence, severity, protocol, flow_duration, total_packets, total_bytes, is_simulated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, source_ip, destination_ip, attack_type, confidence, severity, protocol, flow_duration, total_packets, total_bytes, is_simulated))
    history_id = cursor.lastrowid

    # If attack is not normal traffic, automatically log as a security alert as well
    alert_id = None
    if attack_type != "Normal Traffic":
        from config import Config
        meta = Config.ATTACK_METADATA.get(attack_type, {})
        mitre = meta.get("mitre_id", "N/A")
        desc = meta.get("description", f"Detected malicious {attack_type} pattern.")
        
        cursor.execute("""
            INSERT INTO alerts (timestamp, attack_type, severity, source_ip, destination_ip, protocol, confidence, details, status, mitre_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New', ?)
        """, (ts, attack_type, severity, source_ip, destination_ip, protocol, confidence, desc, mitre))
        alert_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return {"history_id": history_id, "alert_id": alert_id, "timestamp": ts}

def get_alerts(severity=None, status=None, attack_type=None, search=None, limit=50, offset=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
    if status and status != "All":
        query += " AND status = ?"
        params.append(status)
    if attack_type and attack_type != "All":
        query += " AND attack_type = ?"
        params.append(attack_type)
    if search:
        search_like = f"%{search}%"
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR details LIKE ? OR attack_type LIKE ?)"
        params.extend([search_like, search_like, search_like, search_like])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]

    # Total count query for pagination
    count_query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
    count_params = params[:-2]
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]

    conn.close()
    return {"alerts": rows, "total": total_count}

def update_alert_status(alert_id, new_status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
    conn.commit()
    conn.close()
    return True

def batch_update_alerts(action, alert_ids=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if action == "acknowledge_all":
        cursor.execute("UPDATE alerts SET status = 'Acknowledged' WHERE status = 'New'")
    elif action == "resolve_all":
        cursor.execute("UPDATE alerts SET status = 'Resolved' WHERE status != 'Resolved'")
    elif action == "clear_resolved":
        cursor.execute("DELETE FROM alerts WHERE status = 'Resolved'")
    elif alert_ids and len(alert_ids) > 0:
        placeholders = ",".join("?" for _ in alert_ids)
        if action == "acknowledge":
            cursor.execute(f"UPDATE alerts SET status = 'Acknowledged' WHERE id IN ({placeholders})", alert_ids)
        elif action == "resolve":
            cursor.execute(f"UPDATE alerts SET status = 'Resolved' WHERE id IN ({placeholders})", alert_ids)
        elif action == "delete":
            cursor.execute(f"DELETE FROM alerts WHERE id IN ({placeholders})", alert_ids)
    conn.commit()
    conn.close()
    return True

def get_alert_counts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END) as new_count,
            SUM(CASE WHEN severity = 'Critical' AND status = 'New' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN severity = 'High' AND status = 'New' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN severity = 'Medium' AND status = 'New' THEN 1 ELSE 0 END) as medium_count,
            SUM(CASE WHEN severity = 'Low' AND status = 'New' THEN 1 ELSE 0 END) as low_count
        FROM alerts
    """)
    res = dict(cursor.fetchone())
    conn.close()
    return res

def get_detection_history(attack_type=None, severity=None, search=None, limit=50, offset=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM detection_history WHERE 1=1"
    params = []

    if attack_type and attack_type != "All":
        query += " AND attack_type = ?"
        params.append(attack_type)
    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
    if search:
        search_like = f"%{search}%"
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ? OR protocol LIKE ?)"
        params.extend([search_like, search_like, search_like, search_like])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]

    # Count
    count_query = "SELECT COUNT(*) FROM detection_history WHERE 1=1"
    count_params = params[:-2]
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]

    conn.close()
    return {"history": rows, "total": total_count}

def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Aggregates from history
    cursor.execute("""
        SELECT 
            COUNT(*) as total_flows,
            SUM(total_packets) as total_packets,
            SUM(total_bytes) as total_bytes,
            SUM(CASE WHEN attack_type = 'Normal Traffic' THEN 1 ELSE 0 END) as normal_count,
            SUM(CASE WHEN attack_type != 'Normal Traffic' THEN 1 ELSE 0 END) as attack_count
        FROM detection_history
    """)
    flow_row = dict(cursor.fetchone())

    # Active threat alerts (New or Acknowledged critical/high alerts)
    cursor.execute("""
        SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Acknowledged') AND severity IN ('Critical', 'High')
    """)
    active_threats = cursor.fetchone()[0]

    # Threat level evaluation
    if active_threats > 5:
        soc_status = "ELEVATED THREAT"
        soc_color = "danger"
    elif active_threats > 0:
        soc_status = "GUARDED"
        soc_color = "warning"
    else:
        soc_status = "OPTIMAL - SECURE"
        soc_color = "success"

    # Recent 5 alerts
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5")
    recent_alerts = [dict(r) for r in cursor.fetchall()]

    conn.close()

    total_packets = flow_row["total_packets"] or 0
    total_bytes = flow_row["total_bytes"] or 0
    total_flows = flow_row["total_flows"] or 0
    normal_count = flow_row["normal_count"] or 0
    attack_count = flow_row["attack_count"] or 0

    return {
        "total_packets": int(total_packets),
        "total_traffic_bytes": round(float(total_bytes) / 1024, 2), # KB
        "total_flows": int(total_flows),
        "normal_count": int(normal_count),
        "attack_count": int(attack_count),
        "active_threats": int(active_threats),
        "soc_status": soc_status,
        "soc_color": soc_color,
        "recent_alerts": recent_alerts
    }

def get_traffic_trend():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get detections grouped by recent time slots
    cursor.execute("""
        SELECT 
            strftime('%H:%M', timestamp) as time_slot,
            SUM(CASE WHEN attack_type = 'Normal Traffic' THEN 1 ELSE 0 END) as normal_pkts,
            SUM(CASE WHEN attack_type != 'Normal Traffic' THEN 1 ELSE 0 END) as attack_pkts
        FROM detection_history
        GROUP BY time_slot
        ORDER BY id DESC
        LIMIT 12
    """)
    rows = cursor.fetchall()
    conn.close()

    if rows:
        rows = list(reversed(rows))
        labels = [r["time_slot"] for r in rows]
        normal_data = [int(r["normal_pkts"]) for r in rows]
        attack_data = [int(r["attack_pkts"]) for r in rows]
    else:
        now = datetime.now()
        labels = [(now - timedelta(minutes=(5 - i) * 2)).strftime("%H:%M") for i in range(6)]
        normal_data = [0] * 6
        attack_data = [0] * 6

    return {
        "labels": labels,
        "normal": normal_data,
        "attacks": attack_data
    }

def get_attack_distribution():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM detection_history 
        GROUP BY attack_type 
        ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    distribution = {r["attack_type"]: r["count"] for r in rows}
    # Ensure default classes present
    for k in ["Normal Traffic", "DDoS Attack", "DoS Attack", "Port Scanning", "Brute Force", "Botnet"]:
        if k not in distribution:
            distribution[k] = 0

    return distribution

def export_history_as_csv_string():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, source_ip, destination_ip, attack_type, confidence, severity, protocol, flow_duration, total_packets, total_bytes, is_simulated FROM detection_history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Source IP", "Destination IP", "Attack Type", "Confidence (%)", "Severity", "Protocol", "Flow Duration (ms)", "Total Packets", "Total Bytes", "Is Simulated"])

    for r in rows:
        writer.writerow(list(r))

    output.seek(0)
    return output.getvalue()

def clear_all_telemetry():
    """Wipes all alerts and detection history to reset to a pristine live state."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM detection_history")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'detection_history')")
    conn.commit()
    conn.close()
    return True

