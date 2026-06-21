# backend/rules/log_parser.py
# Parses different log formats into normalized structure

import re
import json
from datetime import datetime


# ─────────────────────────────────────────
# NORMALIZE — converts any log to standard dict
# ─────────────────────────────────────────

def parse_log(raw_log: str, log_source: str) -> dict:
    """Parse raw log string into normalized fields"""

    if log_source == "windows":
        return parse_windows_log(raw_log)
    elif log_source == "syslog":
        return parse_syslog(raw_log)
    elif log_source == "apache":
        return parse_apache_log(raw_log)
    elif log_source == "json":
        return parse_json_log(raw_log)
    else:
        return parse_generic(raw_log)


# ─────────────────────────────────────────
# WINDOWS EVENT LOG PARSER
# Example: "EventID=4625 Account=admin IP=192.168.1.50"
# ─────────────────────────────────────────

def parse_windows_log(raw: str) -> dict:
    result = {
        "event_id" : None,
        "username" : None,
        "source_ip": None,
        "hostname" : None,
        "action"   : None
    }

    # Extract EventID
    match = re.search(r'EventID[=:\s]+(\d+)', raw, re.IGNORECASE)
    if match:
        eid = int(match.group(1))
        result["event_id"] = eid
        # Map Windows Event IDs to actions
        event_map = {
            4625: "failed_login",
            4624: "success_login",
            4648: "explicit_credential_use",
            4720: "account_created",
            4728: "admin_group_add",
            4698: "scheduled_task_created",
            4663: "file_access",
            7045: "service_installed"
        }
        result["action"] = event_map.get(eid, "unknown")

    # Extract username
    match = re.search(r'(?:Account|User|Username)[=:\s]+(\S+)', raw, re.IGNORECASE)
    if match:
        result["username"] = match.group(1)

    # Extract IP
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw)
    if match:
        result["source_ip"] = match.group(1)

    return result


# ─────────────────────────────────────────
# SYSLOG PARSER
# Example: "Jan 1 12:00:00 server sshd: Failed password for admin"
# ─────────────────────────────────────────

def parse_syslog(raw: str) -> dict:
    result = {
        "hostname" : None,
        "service"  : None,
        "username" : None,
        "source_ip": None,
        "action"   : None
    }

    # Failed SSH login
    if "Failed password" in raw or "authentication failure" in raw:
        result["action"] = "failed_login"
        match = re.search(r'for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)', raw)
        if match:
            result["username"]  = match.group(1)
            result["source_ip"] = match.group(2)

    # Successful SSH login
    elif "Accepted password" in raw or "Accepted publickey" in raw:
        result["action"] = "success_login"
        match = re.search(r'for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)', raw)
        if match:
            result["username"]  = match.group(1)
            result["source_ip"] = match.group(2)

    # sudo usage
    elif "sudo" in raw:
        result["action"] = "privilege_escalation"
        match = re.search(r'(\S+)\s*:\s*TTY', raw)
        if match:
            result["username"] = match.group(1)

    return result


# ─────────────────────────────────────────
# APACHE ACCESS LOG PARSER
# Example: '192.168.1.1 - - [01/Jan/2024] "GET /admin HTTP/1.1" 200'
# ─────────────────────────────────────────

def parse_apache_log(raw: str) -> dict:
    result = {
        "source_ip": None,
        "method"   : None,
        "path"     : None,
        "status"   : None,
        "action"   : "web_request"
    }

    match = re.match(
        r'(\d+\.\d+\.\d+\.\d+).*"(\w+)\s+(\S+)\s+HTTP.*"\s+(\d+)', raw
    )
    if match:
        result["source_ip"] = match.group(1)
        result["method"]    = match.group(2)
        result["path"]      = match.group(3)
        result["status"]    = int(match.group(4))

        # Detect suspicious paths
        suspicious_paths = ["/admin", "/wp-admin", "/.env",
                           "/etc/passwd", "/shell", "/cmd"]
        if any(p in result["path"] for p in suspicious_paths):
            result["action"] = "suspicious_web_request"

    return result


# ─────────────────────────────────────────
# JSON LOG PARSER
# For structured logs from apps/firewalls
# ─────────────────────────────────────────

def parse_json_log(raw: str) -> dict:
    try:
        data = json.loads(raw)
        return {
            "username" : data.get("user") or data.get("username"),
            "source_ip": data.get("src_ip") or data.get("source_ip") or data.get("ip"),
            "hostname" : data.get("host") or data.get("hostname"),
            "action"   : data.get("action") or data.get("event_type"),
            "status"   : data.get("status") or data.get("result")
        }
    except:
        return parse_generic(raw)


# ─────────────────────────────────────────
# GENERIC FALLBACK PARSER
# ─────────────────────────────────────────

def parse_generic(raw: str) -> dict:
    result = {"source_ip": None, "username": None, "action": "unknown"}

    # Try to extract IP
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw)
    if match:
        result["source_ip"] = match.group(1)

    # Detect keywords
    raw_lower = raw.lower()
    if "fail" in raw_lower or "invalid" in raw_lower or "denied" in raw_lower:
        result["action"] = "failed_login"
    elif "success" in raw_lower or "accepted" in raw_lower:
        result["action"] = "success_login"

    return result