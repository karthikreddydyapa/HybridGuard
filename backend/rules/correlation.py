# backend/rules/correlation.py
# Correlation Engine — links SIEM + EDR alerts into unified incidents

from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timedelta
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import Alert, Incident


# ─────────────────────────────────────────
# MITRE TACTIC ORDER
# Defines the kill chain sequence
# ─────────────────────────────────────────

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

# ─────────────────────────────────────────
# ATTACK CHAIN PATTERNS
# Known multi-step attack sequences
# ─────────────────────────────────────────

ATTACK_PATTERNS = [
    {
        "name"       : "Brute Force to Execution",
        "mitre_chain": ["T1110", "T1078", "T1059"],
        "severity"   : "CRITICAL",
        "description": "Attacker brute forced credentials, logged in, then executed commands"
    },
    {
        "name"       : "Initial Access to C2",
        "mitre_chain": ["T1078", "T1059", "T1071"],
        "severity"   : "CRITICAL",
        "description": "Valid account used to execute commands and establish C2 channel"
    },
    {
        "name"       : "Execution to Ransomware",
        "mitre_chain": ["T1059", "T1105", "T1486"],
        "severity"   : "CRITICAL",
        "description": "Command execution led to payload drop and ransomware behavior"
    },
    {
        "name"       : "Full Attack Chain",
        "mitre_chain": ["T1110", "T1059", "T1105"],
        "severity"   : "CRITICAL",
        "description": "Complete attack: credential access → execution → payload delivery"
    },
    {
        "name"       : "Lateral Movement Chain",
        "mitre_chain": ["T1078", "T1021", "T1059"],
        "severity"   : "CRITICAL",
        "description": "Account abuse enabling lateral movement across systems"
    },
    {
        "name"       : "Credential Access to Exfil",
        "mitre_chain": ["T1110", "T1078", "T1048"],
        "severity"   : "CRITICAL",
        "description": "Brute force succeeded and data exfiltration followed"
    }
]


# ─────────────────────────────────────────
# MAIN CORRELATION FUNCTION
# Run after every new alert is created
# ─────────────────────────────────────────

def run_correlation(db: Session, time_window_minutes: int = 120):
    """
    Look at recent alerts and check if any
    match known attack chain patterns
    """
    incidents_created = []

    # Get alerts from last N minutes
    window = datetime.utcnow() - timedelta(minutes=time_window_minutes)
    recent_alerts = db.query(Alert).filter(
        Alert.timestamp >= window,
        Alert.status    != "CORRELATED"
    ).order_by(Alert.timestamp).all()

    if len(recent_alerts) < 2:
        return incidents_created

    # Group alerts by hostname
    by_host = {}
    for alert in recent_alerts:
        key = alert.hostname or "unknown"
        if key not in by_host:
            by_host[key] = []
        by_host[key].append(alert)

    # Also group by source_ip
    by_ip = {}
    for alert in recent_alerts:
        key = alert.source_ip or "unknown"
        if key not in by_ip:
            by_ip[key] = []
        by_ip[key].append(alert)

    # Check each group against attack patterns
    for group_key, alerts in {**by_host, **by_ip}.items():
        if group_key == "unknown":
            continue

        mitre_ids = [a.mitre_id for a in alerts if a.mitre_id]

        for pattern in ATTACK_PATTERNS:
            if matches_pattern(mitre_ids, pattern["mitre_chain"]):

                # Check if incident already exists for this pattern + host
                existing = db.query(Incident).filter(
                    Incident.title    == pattern["name"],
                    Incident.hostname == group_key,
                    Incident.timestamp >= window
                ).first()

                if existing:
                    continue

                # Get matching alerts
                matched_alerts = get_matched_alerts(alerts, pattern["mitre_chain"])
                alert_ids      = ",".join([str(a.id) for a in matched_alerts])

                # Build tactic chain
                tactics = []
                for a in matched_alerts:
                    if a.mitre_tactic and a.mitre_tactic not in tactics:
                        tactics.append(a.mitre_tactic)

                # Calculate confidence score
                confidence = calculate_confidence(matched_alerts, pattern)

                # Get common fields
                hostname   = matched_alerts[0].hostname
                username   = matched_alerts[0].username
                source_ip  = matched_alerts[0].source_ip

                # Create incident
                incident = Incident(
                    title         = pattern["name"],
                    severity      = pattern["severity"],
                    status        = "OPEN",
                    mitre_chain   = " → ".join(pattern["mitre_chain"]),
                    tactic_chain  = " → ".join(tactics),
                    linked_alerts = alert_ids,
                    hostname      = hostname,
                    username      = username,
                    source_ip     = source_ip,
                    confidence    = confidence,
                    description   = pattern["description"]
                )
                db.add(incident)
                db.commit()
                db.refresh(incident)

                # Mark alerts as correlated
                for a in matched_alerts:
                    a.status = "CORRELATED"
                db.commit()

                print(f"[CORRELATION] 🔗 Incident created: {pattern['name']}")
                print(f"[CORRELATION]    Chain: {' → '.join(pattern['mitre_chain'])}")
                print(f"[CORRELATION]    Host: {hostname} | Confidence: {confidence:.0f}%")

                incidents_created.append({
                    "incident_id" : incident.id,
                    "title"       : incident.title,
                    "severity"    : incident.severity,
                    "mitre_chain" : incident.mitre_chain,
                    "confidence"  : incident.confidence,
                    "hostname"    : incident.hostname
                })

    return incidents_created


# ─────────────────────────────────────────
# PATTERN MATCHING
# Check if alert list contains chain pattern
# ─────────────────────────────────────────

def matches_pattern(mitre_ids: list, pattern_chain: list) -> bool:
    """Check if all techniques in pattern exist in alert list"""
    return all(technique in mitre_ids for technique in pattern_chain)


def get_matched_alerts(alerts: list, pattern_chain: list) -> list:
    """Get alerts that match the pattern techniques"""
    matched = []
    seen_techniques = set()

    for technique in pattern_chain:
        for alert in alerts:
            if alert.mitre_id == technique and technique not in seen_techniques:
                matched.append(alert)
                seen_techniques.add(technique)
                break

    return matched


# ─────────────────────────────────────────
# CONFIDENCE SCORING
# How confident are we this is a real attack
# ─────────────────────────────────────────

def calculate_confidence(alerts: list, pattern: dict) -> float:
    score = 50.0  # base score

    # More alerts = higher confidence
    score += min(len(alerts) * 5, 20)

    # CRITICAL alerts boost confidence
    critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    score += critical_count * 8

    # Mixed SIEM + EDR = higher confidence (hybrid detection)
    sources = set(a.source for a in alerts)
    if len(sources) > 1:
        score += 15
        print(f"[CORRELATION]    ✅ Hybrid detection — SIEM + EDR both triggered")

    # Same hostname = more suspicious
    hostnames = set(a.hostname for a in alerts if a.hostname)
    if len(hostnames) == 1:
        score += 5

    return min(score, 99.0)  # cap at 99


# ─────────────────────────────────────────
# GET INCIDENTS
# ─────────────────────────────────────────

def get_incidents(db: Session, limit: int = 20) -> list:
    incidents = db.query(Incident)\
        .order_by(desc(Incident.timestamp))\
        .limit(limit).all()

    return [{
        "id"           : i.id,
        "timestamp"    : i.timestamp.isoformat(),
        "title"        : i.title,
        "severity"     : i.severity,
        "status"       : i.status,
        "mitre_chain"  : i.mitre_chain,
        "tactic_chain" : i.tactic_chain,
        "hostname"     : i.hostname,
        "username"     : i.username,
        "source_ip"    : i.source_ip,
        "confidence"   : i.confidence,
        "description"  : i.description,
        "linked_alerts": i.linked_alerts
    } for i in incidents]