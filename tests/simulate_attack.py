# tests/simulate_attack.py
# Simulates a full kill chain attack against HybridGuard
# Safe — only sends HTTP requests to your own server

import requests
import time

SERVER = "http://127.0.0.1:8000"

print("=" * 60)
print("  HybridGuard Attack Simulation")
print("  Simulating: Full Kill Chain")
print("  Target: DESKTOP-VICTIM")
print("=" * 60)
print()

# ── STAGE 1: RECONNAISSANCE ──
print("[*] Stage 1 — Reconnaissance")
print("[*] Attacker scanning target network...")
time.sleep(1)
print("[+] Found open port 22 (SSH) on 192.168.1.100")
print("[+] Found open port 80 (HTTP) on 192.168.1.100")
print()

# ── STAGE 2: BRUTE FORCE ──
print("[*] Stage 2 — Credential Access (T1110)")
print("[*] Hydra brute forcing SSH...")

for i in range(6):
    r = requests.post(f"{SERVER}/ingest/log", json={
        "source_ip"  : "192.168.50.100",
        "hostname"   : "DESKTOP-VICTIM",
        "username"   : "admin",
        "event_type" : "failed_login",
        "log_source" : "windows",
        "raw_log"    : f"Failed password attempt {i+1} for admin from 192.168.50.100",
        "severity"   : "MEDIUM"
    })
    data = r.json()
    if data.get("alerts_fired", 0) > 0:
        print(f"[!] ALERT FIRED: Brute Force Detected — attempt {i+1}")
    else:
        print(f"[-] Attempt {i+1} — no alert yet")
    time.sleep(0.5)

print()

# ── STAGE 3: SUCCESSFUL LOGIN ──
print("[*] Stage 3 — Initial Access (T1078)")
print("[*] Password found: admin:password123")
time.sleep(0.5)

r = requests.post(f"{SERVER}/ingest/log", json={
    "source_ip"  : "192.168.50.100",
    "hostname"   : "DESKTOP-VICTIM",
    "username"   : "admin",
    "event_type" : "success_login",
    "log_source" : "windows",
    "raw_log"    : "Successful login for admin from 192.168.50.100 at 02:30",
    "severity"   : "LOW"
})
print(f"[+] Login successful — alerts: {r.json().get('alerts_fired',0)}")
print()

# ── STAGE 4: EXECUTION ──
print("[*] Stage 4 — Execution (T1059)")
print("[*] Attacker spawning command shell...")
time.sleep(0.5)

r = requests.post(f"{SERVER}/ingest/telemetry", json={
    "agent_id"      : "sim-agent-001",
    "hostname"      : "DESKTOP-VICTIM",
    "event_type"    : "process_created",
    "process_name"  : "cmd.exe",
    "parent_process": "malware.exe",
    "username"      : "admin",
    "raw_data"      : '{"action":"process_created","suspicious":true}'
})
print(f"[+] cmd.exe spawned — alerts: {r.json().get('alerts_fired',0)}")
print()

# ── STAGE 5: PAYLOAD DROP ──
print("[*] Stage 5 — C2 Payload Delivery (T1105)")
print("[*] Dropping payload to disk...")
time.sleep(0.5)

r = requests.post(f"{SERVER}/ingest/telemetry", json={
    "agent_id"  : "sim-agent-001",
    "hostname"  : "DESKTOP-VICTIM",
    "event_type": "file_created",
    "file_path" : "C:\\Users\\admin\\AppData\\Local\\Temp\\svchost32.exe",
    "username"  : "admin",
    "raw_data"  : '{"action":"file_created","path":"C:\\\\Temp\\\\svchost32.exe"}'
})
print(f"[+] Payload dropped — alerts: {r.json().get('alerts_fired',0)}")
print()

# ── STAGE 6: REVERSE SHELL ──
print("[*] Stage 6 — Command & Control (T1071)")
print("[*] Establishing reverse shell to C2 server...")
time.sleep(0.5)

r = requests.post(f"{SERVER}/ingest/telemetry", json={
    "agent_id"    : "sim-agent-001",
    "hostname"    : "DESKTOP-VICTIM",
    "event_type"  : "network_conn",
    "process_name": "cmd.exe",
    "dest_ip"     : "185.220.101.50",
    "dest_port"   : 4444,
    "username"    : "admin",
    "raw_data"    : '{"action":"network_conn","suspicious":true}'
})
print(f"[+] Reverse shell established — alerts: {r.json().get('alerts_fired',0)}")
print()

# ── STAGE 7: RANSOMWARE ──
print("[*] Stage 7 — Impact (T1486)")
print("[*] Deploying ransomware — encrypting files...")
time.sleep(0.5)

for i in range(25):
    requests.post(f"{SERVER}/ingest/telemetry", json={
        "agent_id"  : "sim-agent-001",
        "hostname"  : "DESKTOP-VICTIM",
        "event_type": "file_renamed",
        "file_path" : f"C:\\Users\\admin\\Documents\\file_{i}.locked",
        "username"  : "admin",
        "raw_data"  : f'{{"file":"document_{i}.docx","renamed_to":"document_{i}.locked"}}'
    })

print(f"[+] 25 files encrypted — ransomware alert should fire!")
print()

# ── STAGE 8: CORRELATION ──
print("[*] Stage 8 — Triggering Correlation Engine...")
time.sleep(1)

r = requests.post(f"{SERVER}/dashboard/correlate")
data = r.json()
print(f"[+] Correlation complete!")
print(f"[+] Incidents created: {data.get('incidents_created', 0)}")

if data.get('incidents'):
    for inc in data['incidents']:
        print(f"")
        print(f"  🚨 INCIDENT: {inc['title']}")
        print(f"     Chain: {inc['mitre_chain']}")
        print(f"     Severity: {inc['severity']}")
        print(f"     Confidence: {inc['confidence']:.0f}%")

print()
print("=" * 60)
print("  Simulation Complete!")
print("  Check your dashboard for the full attack chain")
print("  http://127.0.0.1:8000/docs")
print("=" * 60)