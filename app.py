import os
import re
import time
import requests
import eventlet
from flask import Flask, render_template
from flask_socketio import SocketIO

# Initialize eventlet for asynchronous background tasks
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Path to the log file on Ubuntu
LOG_FILE = "/var/log/apache2/access.log"

# Ollama API Endpoint (Local AI)
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"  # Replace with your local model name if different (e.g., mistral, llama2)

# Flexible Regex matching both standard Apache logs and Syslog-wrapped headers
LOG_REGEX = re.compile(
    r'(?:.*apache_access:\s*)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[0-9.]+"\s+(?P<status>\d+)'
)

def query_ollama_ai(log_line):
    """Sends log line to local Ollama AI to determine threat classification."""
    prompt = f"""
Analyze the following Web Server Access Log line for security threats (e.g., SQL Injection, XSS, Command Injection, Directory Traversal, or Normal Traffic).

Log Line: {log_line}

Respond ONLY in JSON format with no additional text:
{{
    "threat_type": "<SQL Injection | XSS | Command Injection | Path Traversal | Normal>",
    "confidence": "<High | Medium | Low | None>",
    "explanation": "<Short 1-sentence triage summary>",
    "action": "<Isolate IP | Monitor | Ignore>"
}}
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=5
        )
        if response.status_code == 200:
            result = response.json().get('response', '')
            # Extract JSON from model output
            import json
            match = re.search(r'\{.*\}', result, re.DOTALL)
            if match:
                return json.loads(match.group(0))
    except Exception as e:
        print(f"[!] Ollama API Error: {e}")

    # Fallback basic rule-based detection if Ollama fails or times out
    if "UNION" in log_line.upper() or "SELECT" in log_line.upper() or "'" in log_line:
        return {
            "threat_type": "SQL Injection",
            "confidence": "High",
            "explanation": "Detected SQL keywords/syntax in query parameters.",
            "action": "Isolate IP"
        }
    return {
        "threat_type": "Normal Traffic",
        "confidence": "None",
        "explanation": "Standard HTTP GET request.",
        "action": "Monitor"
    }

def enforce_soar_isolation(ip_address):
    """Automated SOAR action: Blocks hostile IP using iptables."""
    try:
        print(f"[SOAR ENFORCEMENT] Blocking malicious IP: {ip_address}")
        # Command executes iptables drop rule
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        return f"BLOCKED ({ip_address})"
    except Exception as e:
        return f"Failed: {e}"

def tail_access_log():
    """Background task reading /var/log/apache2/access.log in real-time."""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    with open(LOG_FILE, "r") as f:
        # Move pointer to end of file on startup
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                socketio.sleep(0.2)
                continue

            match = LOG_REGEX.search(line)
            if match:
                log_data = match.groupdict()
                src_ip = log_data['ip']
                req_path = log_data['path']

                # Analyze line via Local AI Engine
                ai_triage = query_ollama_ai(line)

                # SOAR Enforcement if threat detected
                enforcement_status = "None"
                if ai_triage.get("action") == "Isolate IP":
                    enforcement_status = enforce_soar_isolation(src_ip)

                # Construct event payload for Web UI
                incident_event = {
                    "source_ip": src_ip,
                    "threat_type": ai_triage.get("threat_type", "Unknown"),
                    "confidence": ai_triage.get("confidence", "Low"),
                    "explanation": ai_triage.get("explanation", "No analysis provided."),
                    "enforcement": enforcement_status,
                    "raw_path": req_path
                }

                # Push event live to Web SIEM UI
                socketio.emit('new_incident', incident_event)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print("[+] Client Dashboard Connected")

if __name__ == '__main__':
    # Start background log parser thread
    socketio.start_background_task(target=tail_access_log)
    print("[*] Starting Local AI SIEM Server on http://0.0.0.0:8000...")
    socketio.run(app, host='0.0.0.0', port=8000, debug=False)