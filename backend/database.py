# backend/database.py

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Event(Base):
    __tablename__ = "events"
    id         = Column(Integer, primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.now)
    source_ip  = Column(String, nullable=True)
    hostname   = Column(String, nullable=True)
    username   = Column(String, nullable=True)
    event_type = Column(String)
    log_source = Column(String)
    raw_log    = Column(Text)
    severity   = Column(String, default="LOW")
    mitre_id   = Column(String, nullable=True)


class EndpointTelemetry(Base):
    __tablename__ = "endpoint_telemetry"
    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.now)
    agent_id       = Column(String)
    hostname       = Column(String)
    event_type     = Column(String)
    process_name   = Column(String, nullable=True)
    process_pid    = Column(Integer, nullable=True)
    parent_process = Column(String, nullable=True)
    file_path      = Column(String, nullable=True)
    dest_ip        = Column(String, nullable=True)
    dest_port      = Column(Integer, nullable=True)
    username       = Column(String, nullable=True)
    raw_data       = Column(Text)
    mitre_id       = Column(String, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.now)
    rule_name     = Column(String)
    mitre_id      = Column(String)
    mitre_tactic  = Column(String)
    severity      = Column(String)
    source        = Column(String)
    hostname      = Column(String, nullable=True)
    username      = Column(String, nullable=True)
    source_ip     = Column(String, nullable=True)
    description   = Column(Text)
    status        = Column(String, default="OPEN")
    linked_events = Column(Text, nullable=True)


class Agent(Base):
    __tablename__ = "agents"
    id         = Column(Integer, primary_key=True, index=True)
    agent_id   = Column(String, unique=True)
    hostname   = Column(String)
    ip_address = Column(String)
    os         = Column(String)
    status     = Column(String, default="ONLINE")
    last_seen  = Column(DateTime, default=datetime.now)
    registered = Column(DateTime, default=datetime.now)


class Incident(Base):
    __tablename__ = "incidents"
    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.now)
    title         = Column(String)
    severity      = Column(String)
    status        = Column(String, default="OPEN")
    mitre_chain   = Column(Text)
    tactic_chain  = Column(Text)
    linked_alerts = Column(Text)
    hostname      = Column(String, nullable=True)
    username      = Column(String, nullable=True)
    source_ip     = Column(String, nullable=True)
    confidence    = Column(Float, default=0.0)
    description   = Column(Text)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    print("[HybridGuard] Database initialized successfully")
    print("[HybridGuard] Tables created: events, endpoint_telemetry, alerts, agents, incidents")


if __name__ == "__main__":
    init_db()