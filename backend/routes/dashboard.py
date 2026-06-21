# backend/routes/dashboard.py
# Dashboard data endpoints — feeds the frontend UI

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_db, Event, EndpointTelemetry, Alert, Agent, Incident

router = APIRouter()


# ─────────────────────────────────────────
# GET /dashboard/summary
# Main stats for overview page
# ─────────────────────────────────────────

@router.get("/summary")
def get_summary(db: Session = Depends(get_db)):
    today = datetime.utcnow() - timedelta(hours=24)

    total_events   = db.query(func.count(Event.id)).filter(Event.timestamp >= today).scalar()
    total_telemetry= db.query(func.count(EndpointTelemetry.id)).filter(EndpointTelemetry.timestamp >= today).scalar()
    open_alerts    = db.query(func.count(Alert.id)).filter(Alert.status == "OPEN").scalar()
    critical_alerts= db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL", Alert.status == "OPEN").scalar()
    online_agents  = db.query(func.count(Agent.id)).filter(Agent.status == "ONLINE").scalar()
    open_incidents = db.query(func.count(Incident.id)).filter(Incident.status == "OPEN").scalar()

    # Severity breakdown
    severity_counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = db.query(func.count(Alert.id)).filter(Alert.severity == sev).scalar()
        severity_counts[sev] = count

    # Top MITRE techniques
    top_techniques = db.query(
        Alert.mitre_id,
        func.count(Alert.id).label("count")
    ).group_by(Alert.mitre_id).order_by(desc("count")).limit(5).all()

    return {
        "total_events_24h"  : total_events + total_telemetry,
        "open_alerts"       : open_alerts,
        "critical_alerts"   : critical_alerts,
        "online_agents"     : online_agents,
        "open_incidents"    : open_incidents,
        "severity_breakdown": severity_counts,
        "top_techniques"    : [{"mitre_id": t[0], "count": t[1]} for t in top_techniques]
    }


# ─────────────────────────────────────────
# GET /dashboard/alerts
# All alerts with pagination
# ─────────────────────────────────────────

@router.get("/alerts")
def get_alerts(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    alerts = db.query(Alert)\
        .order_by(desc(Alert.timestamp))\
        .offset(offset).limit(limit).all()

    return [{
        "id"          : a.id,
        "timestamp"   : a.timestamp.isoformat(),
        "rule_name"   : a.rule_name,
        "mitre_id"    : a.mitre_id,
        "mitre_tactic": a.mitre_tactic,
        "severity"    : a.severity,
        "source"      : a.source,
        "hostname"    : a.hostname,
        "username"    : a.username,
        "source_ip"   : a.source_ip,
        "description" : a.description,
        "status"      : a.status
    } for a in alerts]


# ─────────────────────────────────────────
# GET /dashboard/events
# Recent raw events feed
# ─────────────────────────────────────────

@router.get("/events")
def get_events(limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(Event)\
        .order_by(desc(Event.timestamp))\
        .limit(limit).all()

    return [{
        "id"        : e.id,
        "timestamp" : e.timestamp.isoformat(),
        "source_ip" : e.source_ip,
        "hostname"  : e.hostname,
        "username"  : e.username,
        "event_type": e.event_type,
        "log_source": e.log_source,
        "severity"  : e.severity,
        "mitre_id"  : e.mitre_id
    } for e in events]


# ─────────────────────────────────────────
# GET /dashboard/telemetry
# Recent EDR telemetry feed
# ─────────────────────────────────────────

@router.get("/telemetry")
def get_telemetry(limit: int = 100, db: Session = Depends(get_db)):
    items = db.query(EndpointTelemetry)\
        .order_by(desc(EndpointTelemetry.timestamp))\
        .limit(limit).all()

    return [{
        "id"            : t.id,
        "timestamp"     : t.timestamp.isoformat(),
        "agent_id"      : t.agent_id,
        "hostname"      : t.hostname,
        "event_type"    : t.event_type,
        "process_name"  : t.process_name,
        "parent_process": t.parent_process,
        "file_path"     : t.file_path,
        "dest_ip"       : t.dest_ip,
        "dest_port"     : t.dest_port,
        "mitre_id"      : t.mitre_id
    } for t in items]


# ─────────────────────────────────────────
# GET /dashboard/agents
# All registered agents
# ─────────────────────────────────────────

@router.get("/agents")
def get_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()

    return [{
        "id"        : a.id,
        "agent_id"  : a.agent_id,
        "hostname"  : a.hostname,
        "ip_address": a.ip_address,
        "os"        : a.os,
        "status"    : a.status,
        "last_seen" : a.last_seen.isoformat()
    } for a in agents]


# ─────────────────────────────────────────
# PATCH /dashboard/alerts/{id}/acknowledge
# Acknowledge an alert
# ─────────────────────────────────────────

@router.patch("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"error": "Alert not found"}
    alert.status = "ACKNOWLEDGED"
    db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}
# ─────────────────────────────────────────
# GET /dashboard/incidents
# All correlated incidents
# ─────────────────────────────────────────

@router.get("/incidents")
def get_incidents(db: Session = Depends(get_db)):
    from rules.correlation import get_incidents
    return get_incidents(db)


# ─────────────────────────────────────────
# POST /dashboard/correlate
# Manually trigger correlation engine
# ─────────────────────────────────────────

@router.post("/correlate")
def trigger_correlation(db: Session = Depends(get_db)):
    from rules.correlation import run_correlation
    incidents = run_correlation(db, time_window_minutes=60)
    return {
        "status"           : "correlation complete",
        "incidents_created": len(incidents),
        "incidents"        : incidents
    }