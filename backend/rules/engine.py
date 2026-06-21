# backend/rules/engine.py
# Detection rule engine — fires alerts when attack patterns match

from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import Event, EndpointTelemetry, Alert


# ─────────────────────────────────────────
# SIEM RULES — Log based detections
# ─────────────────────────────────────────

def run_siem_rules(event, db: Session):
    alerts = []

    # ── Rule 1: Brute Force (T1110) ──
    if event.event_type == "failed_login":
        window = datetime.utcnow() - timedelta(seconds=60)
        count = db.query(func.count(Event.id)).filter(
            Event.event_type == "failed_login",
            Event.source_ip  == event.source_ip,
            Event.timestamp  >= window
        ).scalar()

        if count >= 5:
            alert = create_alert(db,
                rule_name    = "Brute Force Detected",
                mitre_id     = "T1110",
                mitre_tactic = "Credential Access",
                severity     = "HIGH",
                source       = "SIEM",
                hostname     = event.hostname,
                username     = event.username,
                source_ip    = event.source_ip,
                description  = f"Brute force detected — {count} failed logins in 60s from {event.source_ip}"
            )
            alerts.append(alert)

    # ── Rule 2: Off-Hours Login (T1078) ──
    if event.event_type == "success_login":
        hour = datetime.utcnow().hour
        if hour >= 23 or hour <= 5:
            alert = create_alert(db,
                rule_name    = "Off-Hours Login",
                mitre_id     = "T1078",
                mitre_tactic = "Initial Access",
                severity     = "MEDIUM",
                source       = "SIEM",
                hostname     = event.hostname,
                username     = event.username,
                source_ip    = event.source_ip,
                description  = f"Successful login at unusual hour ({hour}:00) by {event.username}"
            )
            alerts.append(alert)

    # ── Rule 3: Lateral Movement (T1021) ──
    if event.event_type == "success_login" and event.username:
        window = datetime.utcnow() - timedelta(minutes=10)
        machines = db.query(Event.hostname).filter(
            Event.event_type == "success_login",
            Event.username   == event.username,
            Event.timestamp  >= window
        ).distinct().count()

        if machines >= 3:
            alert = create_alert(db,
                rule_name    = "Lateral Movement Detected",
                mitre_id     = "T1021",
                mitre_tactic = "Lateral Movement",
                severity     = "CRITICAL",
                source       = "SIEM",
                hostname     = event.hostname,
                username     = event.username,
                source_ip    = event.source_ip,
                description  = f"User {event.username} logged into {machines} machines in 10 minutes"
            )
            alerts.append(alert)

    return alerts


# ─────────────────────────────────────────
# EDR RULES — Endpoint telemetry detections
# ─────────────────────────────────────────

def run_edr_rules(telemetry, db: Session):
    alerts = []

    # ── Rule 4: Suspicious Process (T1059) ──
    suspicious = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
    safe_parents = ["explorer.exe", "cmd.exe", "powershell.exe",
                    "WindowsTerminal.exe", "Code.exe"]

    if (telemetry.event_type == "process_created" and
        telemetry.process_name in suspicious and
        telemetry.parent_process not in safe_parents):

        alert = create_alert(db,
            rule_name    = "Suspicious Command Interpreter",
            mitre_id     = "T1059",
            mitre_tactic = "Execution",
            severity     = "HIGH",
            source       = "EDR",
            hostname     = telemetry.hostname,
            username     = telemetry.username,
            source_ip    = None,
            description  = f"{telemetry.process_name} spawned by {telemetry.parent_process} on {telemetry.hostname}"
        )
        alerts.append(alert)

    # ── Rule 5: Ransomware Behavior (T1486) ──
    if telemetry.event_type == "file_renamed":
        window = datetime.utcnow() - timedelta(seconds=60)
        count = db.query(func.count(EndpointTelemetry.id)).filter(
            EndpointTelemetry.agent_id    == telemetry.agent_id,
            EndpointTelemetry.event_type  == "file_renamed",
            EndpointTelemetry.timestamp   >= window
        ).scalar()

        if count >= 20:
            alert = create_alert(db,
                rule_name    = "Ransomware Behavior Detected",
                mitre_id     = "T1486",
                mitre_tactic = "Impact",
                severity     = "CRITICAL",
                source       = "EDR",
                hostname     = telemetry.hostname,
                username     = telemetry.username,
                source_ip    = None,
                description  = f"Mass file rename detected — {count} files renamed in 60s on {telemetry.hostname}"
            )
            alerts.append(alert)

    # ── Rule 6: Reverse Shell (T1071) ──
    shell_processes = ["cmd.exe", "bash", "sh", "powershell.exe"]
    if (telemetry.event_type == "network_conn" and
        telemetry.process_name in shell_processes and
        telemetry.dest_port in [4444, 4445, 1234, 9001]):

        alert = create_alert(db,
            rule_name    = "Reverse Shell Detected",
            mitre_id     = "T1071",
            mitre_tactic = "Command and Control",
            severity     = "CRITICAL",
            source       = "EDR",
            hostname     = telemetry.hostname,
            username     = telemetry.username,
            source_ip    = telemetry.dest_ip,
            description  = f"{telemetry.process_name} making outbound connection to {telemetry.dest_ip}:{telemetry.dest_port}"
        )
        alerts.append(alert)

    # ── Rule 7: Executable Dropped (T1105) ──
    if (telemetry.event_type == "file_created" and
        telemetry.file_path and
        telemetry.file_path.endswith(".exe") and
        any(p in telemetry.file_path for p in ["Temp", "temp", "Downloads", "AppData"])):

        alert = create_alert(db,
            rule_name    = "Suspicious Executable Dropped",
            mitre_id     = "T1105",
            mitre_tactic = "Command and Control",
            severity     = "HIGH",
            source       = "EDR",
            hostname     = telemetry.hostname,
            username     = telemetry.username,
            source_ip    = None,
            description  = f"New executable dropped at suspicious path: {telemetry.file_path}"
        )
        alerts.append(alert)

    return alerts


# ─────────────────────────────────────────
# HELPER — Create and save alert
# ─────────────────────────────────────────

def create_alert(db: Session, rule_name, mitre_id, mitre_tactic,
                 severity, source, hostname, username, source_ip, description):

    alert = Alert(
        rule_name    = rule_name,
        mitre_id     = mitre_id,
        mitre_tactic = mitre_tactic,
        severity     = severity,
        source       = source,
        hostname     = hostname,
        username     = username,
        source_ip    = source_ip,
        description  = description,
        status       = "OPEN"
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    print(f"[ALERT] 🚨 {severity} — {rule_name} | {mitre_id} | {description[:60]}")
    return {
        "alert_id"     : alert.id,
        "rule_name"    : rule_name,
        "mitre_id"     : mitre_id,
        "severity"     : severity,
        "description"  : description
    }