# backend/models/schemas.py
# Data shapes for incoming requests — Pydantic validates everything automatically

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ─────────────────────────────────────────
# SIEM — Incoming Log Schema
# ─────────────────────────────────────────

class LogIngest(BaseModel):
    source_ip:   Optional[str] = None
    hostname:    Optional[str] = None
    username:    Optional[str] = None
    event_type:  str                    # failed_login, success_login, file_created, etc.
    log_source:  str                    # windows, syslog, apache, firewall
    raw_log:     str                    # original raw log string
    severity:    Optional[str] = "LOW"
    mitre_id:    Optional[str] = None


# ─────────────────────────────────────────
# EDR — Incoming Telemetry Schema
# ─────────────────────────────────────────

class TelemetryIngest(BaseModel):
    agent_id:       str
    hostname:       str
    event_type:     str               # process_created, file_created, network_conn
    process_name:   Optional[str] = None
    process_pid:    Optional[int] = None
    parent_process: Optional[str] = None
    file_path:      Optional[str] = None
    dest_ip:        Optional[str] = None
    dest_port:      Optional[int] = None
    username:       Optional[str] = None
    raw_data:       str
    mitre_id:       Optional[str] = None


# ─────────────────────────────────────────
# AGENT — Registration Schema
# ─────────────────────────────────────────

class AgentRegister(BaseModel):
    agent_id:   str
    hostname:   str
    ip_address: str
    os:         str                   # Windows, Linux, Mac


# ─────────────────────────────────────────
# ALERT — Response Schema
# ─────────────────────────────────────────

class AlertResponse(BaseModel):
    id:           int
    timestamp:    datetime
    rule_name:    str
    mitre_id:     str
    mitre_tactic: str
    severity:     str
    source:       str
    hostname:     Optional[str]
    username:     Optional[str]
    source_ip:    Optional[str]
    description:  str
    status:       str

    class Config:
        from_attributes = True