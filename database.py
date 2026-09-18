import sqlite3
import json
import hashlib
from datetime import datetime


DB_FILE = "siem_data.db"


def get_connection():
    conn = sqlite3.connect(
        DB_FILE,
        check_same_thread=False
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            topic TEXT NOT NULL,

            event_id TEXT NOT NULL,

            event_time INTEGER,

            received_at TEXT NOT NULL,

            payload TEXT NOT NULL,

            UNIQUE(topic, event_id)
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_topic
        ON events(topic)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_event_time
        ON events(event_time)
    """)

    conn.commit()

    return conn


def generate_event_id(topic, record):

    # Use the actual IDs where available

    id_fields = [
        "alert_id",
        "anomaly_id",
        "incident_id"
    ]

    for field in id_fields:

        if record.get(field):

            return str(
                record[field]
            )

    # Metrics doesn't have an ID,
    # so create a deterministic hash.

    raw = json.dumps(
        record,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        f"{topic}:{raw}".encode()
    ).hexdigest()


def store_event(topic, record):

    conn = get_connection()

    event_id = generate_event_id(
        topic,
        record
    )

    event_time = (
        record.get("event_time")
        or record.get("incident_time")
        or record.get("window_start")
    )

    received_at = datetime.utcnow().isoformat()

    try:

        conn.execute(
            """
            INSERT OR IGNORE INTO events
            (
                topic,
                event_id,
                event_time,
                received_at,
                payload
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                topic,
                event_id,
                event_time,
                received_at,
                json.dumps(
                    record,
                    default=str
                )
            )
        )

        conn.commit()

    finally:

        conn.close()


def get_events(topic):

    conn = get_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                event_id,
                event_time,
                received_at,
                payload
            FROM events
            WHERE topic = ?
            ORDER BY
                COALESCE(event_time, 0) DESC
            """,
            (topic,)
        ).fetchall()

    finally:

        conn.close()

    records = []

    for row in rows:

        records.append(
            json.loads(row[3])
        )

    return records


def get_event_count(topic):

    conn = get_connection()

    try:

        result = conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE topic = ?
            """,
            (topic,)
        ).fetchone()

    finally:

        conn.close()

    return result[0]