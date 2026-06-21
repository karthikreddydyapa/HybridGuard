# backend/routes/ingest.py
# Endpoints that receive logs and telemetry — heart of the SIEM+EDR

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import get_db, Event, EndpointTelemetry, Agent
from models.schemas import LogIngest, TelemetryIngest, AgentRegister
from rules.engine import run_siem_rules, run_edr_rules

router = APIRouter()


# ─────────────────────────────────────────
# POST /ingest/log
# Receives logs from any SIEM source
# ─────────────────────────────────────────

@router.post("/log")
def ingest_log(log: LogIngest, db: Session = Depends(get_db)):

    # Save raw event to database
    event = Event(
        source_ip  = log.source_ip,
        hostname   = log.hostname,
        username   = log.username,
        event_type = log.event_type,
        log_source = log.log_source,
        raw_log    = log.raw_log,
        severity   = log.severity,
        mitre_id   = log.mitre_id
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Run SIEM detection rules against this event
    alerts_fired = run_siem_rules(event, db)

    print(f"[SIEM] Event received: {log.event_type} from {log.source_ip or log.hostname}")

    # Run correlation engine after every new alert
    from rules.correlation import run_correlation
    incidents = run_correlation(db)

    return {
        "status"          : "received",
        "event_id"        : event.id,
        "alerts_fired"    : len(alerts_fired),
        "alerts"          : alerts_fired,
        "incidents_created": len(incidents),
        "incidents"       : incidents
    }


# ─────────────────────────────────────────
# POST /ingest/telemetry
# Receives telemetry from EDR agent
# ─────────────────────────────────────────

@router.post("/telemetry")
def ingest_telemetry(data: TelemetryIngest, db: Session = Depends(get_db)):

    # Save telemetry to database
    telemetry = EndpointTelemetry(
        agent_id       = data.agent_id,
        hostname       = data.hostname,
        event_type     = data.event_type,
        process_name   = data.process_name,
        process_pid    = data.process_pid,
        parent_process = data.parent_process,
        file_path      = data.file_path,
        dest_ip        = data.dest_ip,
        dest_port      = data.dest_port,
        username       = data.username,
        raw_data       = data.raw_data,
        mitre_id       = data.mitre_id
    )
    db.add(telemetry)
    db.commit()
    db.refresh(telemetry)

    # Update agent last seen
    agent = db.query(Agent).filter(Agent.agent_id == data.agent_id).first()
    if agent:
        agent.last_seen = datetime.utcnow()
        agent.status = "ONLINE"
        db.commit()

    # Run EDR detection rules
    alerts_fired = run_edr_rules(telemetry, db)

    print(f"[EDR] Telemetry received: {data.event_type} from {data.hostname}")

    # Run correlation engine after every new alert
    from rules.correlation import run_correlation
    incidents = run_correlation(db)

    return {
        "status"           : "received",
        "telemetry_id"     : telemetry.id,
        "alerts_fired"     : len(alerts_fired),
        "alerts"           : alerts_fired,
        "incidents_created": len(incidents),
        "incidents"        : incidents
    }


# ─────────────────────────────────────────
# POST /ingest/agent/register
# Registers a new EDR agent
# ─────────────────────────────────────────

@router.post("/agent/register")
def register_agent(data: AgentRegister, db: Session = Depends(get_db)):

    # Check if agent already exists
    existing = db.query(Agent).filter(Agent.agent_id == data.agent_id).first()

    if existing:
        existing.status    = "ONLINE"
        existing.last_seen = datetime.utcnow()
        db.commit()
        return {"status": "updated", "agent_id": data.agent_id}

    # Register new agent
    agent = Agent(
        agent_id   = data.agent_id,
        hostname   = data.hostname,
        ip_address = data.ip_address,
        os         = data.os,
        status     = "ONLINE"
    )
    db.add(agent)
    db.commit()

    print(f"[EDR] New agent registered: {data.hostname} ({data.agent_id})")

    return {"status": "registered", "agent_id": data.agent_id}