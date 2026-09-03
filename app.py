import os
import re
import json
import time
import requests
import eventlet
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

LOG_FILE = "/var/log/apache2/access.log"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

# In-Memory SIEM Event Store
INCIDENT_LOGS = []
BLOCKED_IPS = set()

LOG_REGEX = re.compile(
    r'(?:.*(?:apache_access|apache|syslog):\s*)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[0-9.]+"\s+(?P<status>\d+)'
)

def query_ollama_ai(log_line):
    """Hybrid Signature Engine + AI Fallback"""
    if any(pattern in log_line.upper() for pattern in ["UNION", "SELECT", "PASSWORD", "' OR ", "DROP"]):
        return {
            "threat_type": "SQL Injection",
            "confidence": "High",
            "explanation": "Malicious SQL query parameters identified.",
            "action": "Isolate IP"
        }
    elif "<script>" in log_line.lower() or "javascript:" in log_line.lower():
        return {
            "threat_type": "Cross-Site Scripting (XSS)",
            "confidence": "High",
            "explanation": "Script payload embedded in URL path.",
            "action": "Isolate IP"
        }

    try:
        prompt = f"Analyze log for security threats: {log_line}\nRespond ONLY in valid JSON: {{\"threat_type\":\"...\", \"confidence\":\"...\", \"explanation\":\"...\", \"action\":\"...\"}}"
        resp = requests.post(OLLAMA_URL, json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}, timeout=1.5)
        if resp.status_code == 200:
            match = re.search(r'\{.*\}', resp.json().get('response', ''), re.DOTALL)
            if match:
                return json.loads(match.group(0))
    except Exception:
        pass

    return {
        "threat_type": "Normal Traffic",
        "confidence": "None",
        "explanation": "Standard HTTP GET request.",
        "action": "Monitor"
    }

def enforce_soar_isolation(ip_address):
    """Applies system iptables block rule."""
    try:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        BLOCKED_IPS.add(ip_address)
        return f"BLOCKED ({ip_address})"
    except Exception as e:
        return f"Error: {e}"

def tail_access_log():
    """Background Log Reader Stream"""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                socketio.sleep(0.1)
                continue

            match = LOG_REGEX.search(line)
            if match:
                data = match.groupdict()
                src_ip = data['ip']
                triage = query_ollama_ai(line)

                enforcement = "Monitored"
                if triage.get("action") == "Isolate IP":
                    enforcement = enforce_soar_isolation(src_ip)

                event = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "threat_type": triage.get("threat_type", "Unknown"),
                    "confidence": triage.get("confidence", "Low"),
                    "explanation": triage.get("explanation", "Event logged."),
                    "enforcement": enforcement,
                    "path": data['path'],
                    "raw": line.strip()
                }

                INCIDENT_LOGS.append(event)
                socketio.emit('new_incident', event)
                socketio.sleep(0)

# Page Routes
@app.route('/')
def live_triage():
    return render_template('triage.html', events=INCIDENT_LOGS[::-1])

@app.route('/executive')
def executive_dashboard():
    total = len(INCIDENT_LOGS)
    threats = sum(1 for e in INCIDENT_LOGS if e['threat_type'] != "Normal Traffic")
    return render_template('executive.html', total=total, threats=threats, blocked=len(BLOCKED_IPS))

@app.route('/hunting')
def threat_hunting():
    return render_template('hunting.html', events=INCIDENT_LOGS)

@app.route('/soar')
def soar_dashboard():
    return render_template('soar.html', blocked_ips=list(BLOCKED_IPS))

if __name__ == '__main__':
    socketio.start_background_task(target=tail_access_log)
    print("[*] Enterprise SIEM Running at http://0.0.0.0:8000")
    socketio.run(app, host='0.0.0.0', port=8000, debug=False)