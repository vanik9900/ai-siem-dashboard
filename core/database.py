import sqlite3
import os

DB_PATH = "data/siem_events.db"

def init_db():
    os.makedirs("data",exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        threat_type TEXT,
        confidence INTEGER,
        explanation TEXT,
        action_taken TEXT,
        raw_log TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_alert(ip: str, threat_type: str, confidence: int, explanation: str,action: str, raw_log: str):
    conn = sqlite3.connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INFO alerts (source_ip, threat_type, confidence, explanation, action_taken, raw_log)
        VALUES(?, ?, ?, ?, ?, ?)
    """,(ip, threat_type, confidence, explanation, action, raw_log))
    conn.commit()
    conn.close()