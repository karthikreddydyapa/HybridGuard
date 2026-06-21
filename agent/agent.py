# agent/agent.py
# HybridGuard EDR Agent — runs on endpoint, sends telemetry to server

import psutil
import requests
import schedule
import time
import json
import uuid
import socket
import platform
import os
import urllib.parse
import urllib.request
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
SERVER_URL  = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
WATCH_PATH  = os.getenv("WATCH_PATH", "C:\\Users")
AGENT_ID    = str(uuid.uuid4())
HOSTNAME    = socket.gethostname()
OS_NAME     = platform.system()

WHITELIST_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "spoolsv.exe", "explorer.exe",
    "SearchIndexer.exe", "WmiPrvSE.exe", "taskhostw.exe",
    "RuntimeBroker.exe", "ShellExperienceHost.exe",
    "StartMenuExperienceHost.exe", "SecurityHealthService.exe"
]

seen_pids = set()
seen_connections = set()

# ── CHANGE 1: Token variable ──
AGENT_TOKEN = None


# ─────────────────────────────────────────
# CHANGE 2: Get JWT Token
# ─────────────────────────────────────────

def get_agent_token():
    global AGENT_TOKEN
    try:
        data = urllib.parse.urlencode({
            'username': 'admin',
            'password': 'hybridguard123'
        }).encode()
        req = urllib.request.Request(
            f"{SERVER_URL}/auth/login",
            data=data
        )
        with urllib.request.urlopen(req) as r:
            AGENT_TOKEN = json.loads(r.read())['access_token']
            print(f"[AGENT] ✅ Token acquired")
    except Exception as e:
        print(f"[AGENT] ❌ Auth failed: {e}")


# ─────────────────────────────────────────
# CHANGE 3: Register Agent (with token)
# ─────────────────────────────────────────

def register_agent():
    global AGENT_TOKEN
    try:
        get_agent_token()
        ip = socket.gethostbyname(HOSTNAME)
        payload = {
            "agent_id"  : AGENT_ID,
            "hostname"  : HOSTNAME,
            "ip_address": ip,
            "os"        : OS_NAME
        }
        headers = {'Authorization': f'Bearer {AGENT_TOKEN}'}
        r = requests.post(
            f"{SERVER_URL}/ingest/agent/register",
            json=payload,
            headers=headers,
            timeout=5
        )
        if r.status_code == 200:
            print(f"[AGENT] ✅ Registered with server | ID: {AGENT_ID[:8]}...")
        else:
            print(f"[AGENT] ⚠️ Registration failed: {r.status_code}")
    except Exception as e:
        print(f"[AGENT] ❌ Cannot reach server: {e}")


# ─────────────────────────────────────────
# CHANGE 4: Send Telemetry (with token)
# ─────────────────────────────────────────

def send_telemetry(payload):
    global AGENT_TOKEN
    try:
        headers = {'Authorization': f'Bearer {AGENT_TOKEN}'}
        r = requests.post(
            f"{SERVER_URL}/ingest/telemetry",
            json=payload,
            headers=headers,
            timeout=5
        )
        if r.status_code == 401:
            print(f"[AGENT] 🔄 Token expired — refreshing...")
            get_agent_token()
            return
        if r.status_code == 200:
            data = r.json()
            if data.get("alerts_fired", 0) > 0:
                for alert in data.get("alerts", []):
                    print(f"[ALERT] 🚨 {alert['severity']} — {alert['rule_name']} | {alert['mitre_id']}")
    except Exception as e:
        print(f"[AGENT] ❌ Failed to send telemetry: {e}")


# ─────────────────────────────────────────
# MONITOR 1 — PROCESS MONITOR
# ─────────────────────────────────────────

def monitor_processes():
    global seen_pids
    current_pids = set()

    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'exe']):
        try:
            info = proc.info
            pid  = info['pid']
            name = info['name'] or "unknown"
            current_pids.add(pid)

            if pid in seen_pids:
                continue
            if name in WHITELIST_PROCESSES:
                seen_pids.add(pid)
                continue

            try:
                parent = psutil.Process(info['ppid'])
                parent_name = parent.name()
            except:
                parent_name = "unknown"

            print(f"[EDR] 🔍 New process: {name} (PID:{pid}) spawned by {parent_name}")

            payload = {
                "agent_id"      : AGENT_ID,
                "hostname"      : HOSTNAME,
                "event_type"    : "process_created",
                "process_name"  : name,
                "process_pid"   : pid,
                "parent_process": parent_name,
                "username"      : info.get('username', 'unknown'),
                "raw_data"      : json.dumps(info, default=str),
                "mitre_id"      : "T1059"
            }
            send_telemetry(payload)
            seen_pids.add(pid)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    seen_pids = seen_pids.intersection(current_pids)


# ─────────────────────────────────────────
# MONITOR 2 — NETWORK MONITOR
# ─────────────────────────────────────────

def monitor_network():
    global seen_connections
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED':
                continue
            if not conn.raddr:
                continue

            key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port)
            if key in seen_connections:
                continue
            seen_connections.add(key)

            proc_name = "unknown"
            try:
                if conn.pid:
                    proc_name = psutil.Process(conn.pid).name()
            except:
                pass

            dest_ip   = conn.raddr.ip
            dest_port = conn.raddr.port

            if dest_ip.startswith("127.") or dest_ip.startswith("192.168."):
                continue

            print(f"[EDR] 🌐 Network: {proc_name} → {dest_ip}:{dest_port}")

            payload = {
                "agent_id"    : AGENT_ID,
                "hostname"    : HOSTNAME,
                "event_type"  : "network_conn",
                "process_name": proc_name,
                "dest_ip"     : dest_ip,
                "dest_port"   : dest_port,
                "raw_data"    : json.dumps({
                    "dest_ip"  : dest_ip,
                    "dest_port": dest_port,
                    "process"  : proc_name
                })
            }
            send_telemetry(payload)

    except Exception as e:
        print(f"[AGENT] Network monitor error: {e}")


# ─────────────────────────────────────────
# MONITOR 3 — FILE SYSTEM MONITOR
# ─────────────────────────────────────────

class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        print(f"[EDR] 📄 File created: {path}")
        payload = {
            "agent_id"  : AGENT_ID,
            "hostname"  : HOSTNAME,
            "event_type": "file_created",
            "file_path" : path,
            "raw_data"  : json.dumps({"path": path, "action": "created"}),
            "mitre_id"  : "T1105"
        }
        send_telemetry(payload)

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".exe") or event.src_path.endswith(".bat"):
            path = event.src_path
            print(f"[EDR] ✏️ Executable modified: {path}")
            payload = {
                "agent_id"  : AGENT_ID,
                "hostname"  : HOSTNAME,
                "event_type": "file_modified",
                "file_path" : path,
                "raw_data"  : json.dumps({"path": path, "action": "modified"})
            }
            send_telemetry(payload)

    def on_moved(self, event):
        if event.is_directory:
            return
        print(f"[EDR] 🔄 File renamed: {event.src_path} → {event.dest_path}")
        payload = {
            "agent_id"  : AGENT_ID,
            "hostname"  : HOSTNAME,
            "event_type": "file_renamed",
            "file_path" : event.dest_path,
            "raw_data"  : json.dumps({
                "from": event.src_path,
                "to"  : event.dest_path
            }),
            "mitre_id"  : "T1486"
        }
        send_telemetry(payload)


# ─────────────────────────────────────────
# START FILE SYSTEM WATCHER
# ─────────────────────────────────────────

def start_file_monitor():
    handler  = FileMonitorHandler()
    observer = Observer()
    observer.schedule(handler, path=WATCH_PATH, recursive=False)
    observer.start()
    print(f"[AGENT] 📁 File monitor started on {WATCH_PATH}")
    return observer


# ─────────────────────────────────────────
# CHANGE 5: Heartbeat (with token)
# ─────────────────────────────────────────

def send_heartbeat():
    global AGENT_TOKEN
    try:
        payload = {
            "agent_id"  : AGENT_ID,
            "hostname"  : HOSTNAME,
            "event_type": "heartbeat",
            "raw_data"  : json.dumps({
                "cpu"   : psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent,
                "time"  : datetime.utcnow().isoformat()
            })
        }
        headers = {'Authorization': f'Bearer {AGENT_TOKEN}'}
        requests.post(
            f"{SERVER_URL}/ingest/telemetry",
            json=payload,
            headers=headers,
            timeout=5
        )
        print(f"[AGENT] 💓 Heartbeat | CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%")
    except:
        print("[AGENT] ⚠️ Heartbeat failed")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("   HybridGuard EDR Agent v1.0")
    print(f"   Host     : {HOSTNAME}")
    print(f"   OS       : {OS_NAME}")
    print(f"   Agent ID : {AGENT_ID[:8]}...")
    print(f"   Server   : {SERVER_URL}")
    print("=" * 55)

    register_agent()
    observer = start_file_monitor()

    for proc in psutil.process_iter(['pid']):
        try:
            seen_pids.add(proc.info['pid'])
        except:
            continue
    print(f"[AGENT] 📋 Baseline captured — {len(seen_pids)} existing processes ignored")

    schedule.every(5).seconds.do(monitor_processes)
    schedule.every(10).seconds.do(monitor_network)
    schedule.every(30).seconds.do(send_heartbeat)

    print("[AGENT] 🚀 Agent running — monitoring your endpoint...")
    print("[AGENT] Press Ctrl+C to stop\n")

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[AGENT] Stopping agent...")
        observer.stop()
        observer.join()
        print("[AGENT] Agent stopped.")