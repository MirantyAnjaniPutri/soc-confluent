import sqlite3
import json

DB_NAME = "siem_events.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Store dynamic key-value payload entries for real-time reads
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS siem_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT,
            payload TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def store_event(topic, record):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO siem_events (topic, payload) VALUES (?, ?)",
        (topic, json.dumps(record))
    )
    conn.commit()
    conn.close()

def get_events(topic):
    if not topic:
        return []
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT payload FROM siem_events WHERE topic = ? ORDER BY id DESC LIMIT 2000", 
        (topic,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]

init_db()