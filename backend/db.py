import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            service TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            password TEXT,
            request_path TEXT,
            payload TEXT,
            result TEXT,
            severity TEXT NOT NULL DEFAULT 'LOW',
            session_id INTEGER,
            fingerprint TEXT,
            country TEXT,
            threat_score INTEGER DEFAULT 0,
            prev_hash TEXT,
            event_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            service TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            event_count INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW'
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ip_stats (
            source_ip TEXT PRIMARY KEY,
            total_events INTEGER DEFAULT 0,
            failed_logins INTEGER DEFAULT 0,
            services_hit INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            country TEXT,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS honeytokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_name TEXT UNIQUE NOT NULL,
            secret_value TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            triggered_at TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        """)
        db.executemany(
            "INSERT OR IGNORE INTO users(username,password,role) VALUES(?,?,?)",
            [
                ("admin", "honeytrap-admin", "admin"),
                ("viewer", "honeytrap-viewer", "viewer"),
            ],
        )
        tokens = [
            ("demo_api_key", "HT-DEMO-API-7F3A-LOCAL"),
            ("decoy_password", "HT-DECOY-PASS-92B1"),
        ]
        for name, value in tokens:
            db.execute(
                "INSERT OR IGNORE INTO honeytokens(token_name,secret_value,created_at) VALUES(?,?,?)",
                (name, value, utc_now()),
            )
        db.commit()


def recent_events(limit=50):
    with connect() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        ]


def recent_alerts(limit=30):
    with connect() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        ]


def stats():
    with connect() as db:
        total = db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        alerts = db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        high = db.execute(
            "SELECT COUNT(*) c FROM events WHERE severity='HIGH'"
        ).fetchone()["c"]
        ips = db.execute("SELECT COUNT(*) c FROM ip_stats").fetchone()["c"]
        by_service = [
            dict(r)
            for r in db.execute(
                "SELECT service, COUNT(*) count FROM events GROUP BY service ORDER BY count DESC"
            )
        ]
        top_ips = [
            dict(r)
            for r in db.execute(
                "SELECT source_ip,total_events,failed_logins,services_hit,threat_score,last_seen "
                "FROM ip_stats ORDER BY threat_score DESC, total_events DESC LIMIT 10"
            )
        ]
        return {
            "total_events": total,
            "alerts": alerts,
            "high_severity": high,
            "unique_ips": ips,
            "by_service": by_service,
            "top_ips": top_ips,
        }


def sessions(limit=30):
    with connect() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        ]


def all_events():
    with connect() as db:
        return [
            dict(r) for r in db.execute("SELECT * FROM events ORDER BY id").fetchall()
        ]
