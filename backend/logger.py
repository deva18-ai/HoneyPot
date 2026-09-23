import hashlib
import json
import threading

from detector.engine import analyze_event

from .db import connect, utc_now

_LOCK = threading.Lock()


def _canonical(event):
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash, event):
    raw = (prev_hash or "") + _canonical(event)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _last_hash(db):
    row = db.execute(
        "SELECT event_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["event_hash"] if row else None


def log_event(
    source_ip,
    service,
    event_type,
    username=None,
    password=None,
    request_path=None,
    payload=None,
    result=None,
    session_id=None,
    fingerprint=None,
    country=None,
):
    base = {
        "timestamp": utc_now(),
        "source_ip": source_ip,
        "service": service,
        "event_type": event_type,
        "username": username,
        "password": password,
        "request_path": request_path,
        "payload": payload,
        "result": result,
        "session_id": session_id,
        "fingerprint": fingerprint,
        "country": country,
    }
    decision = analyze_event(base)
    with _LOCK, connect() as db:
        prev = _last_hash(db)
        event_hash = _hash(prev, {**base, **decision})
        cur = db.execute(
            """
            INSERT INTO events(
              timestamp,source_ip,service,event_type,username,password,request_path,
              payload,result,severity,session_id,fingerprint,country,threat_score,
              prev_hash,event_hash
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
            (
                base["timestamp"],
                source_ip,
                service,
                event_type,
                username,
                password,
                request_path,
                payload,
                result,
                decision["severity"],
                session_id,
                fingerprint,
                country,
                decision["threat_score"],
                prev,
                event_hash,
            ),
        )
        event_id = cur.lastrowid

        # Update/create session
        if session_id:
            db.execute(
                "UPDATE sessions SET event_count=event_count+1,risk_level=? WHERE id=?",
                (decision["severity"], session_id),
            )

        row = db.execute(
            "SELECT * FROM ip_stats WHERE source_ip=?", (source_ip,)
        ).fetchone()
        if row:
            services = db.execute(
                "SELECT COUNT(DISTINCT service) c FROM events WHERE source_ip=?",
                (source_ip,),
            ).fetchone()["c"]
            db.execute(
                """
                UPDATE ip_stats
                SET total_events=total_events+1,
                    failed_logins=failed_logins+?,
                    services_hit=?,
                    threat_score=?,
                    country=COALESCE(?,country),
                    last_seen=?
                WHERE source_ip=?
            """,
                (
                    1 if result == "FAIL" else 0,
                    services,
                    decision["threat_score"],
                    country,
                    base["timestamp"],
                    source_ip,
                ),
            )
        else:
            db.execute(
                """
                INSERT INTO ip_stats(
                  source_ip,total_events,failed_logins,services_hit,threat_score,country,last_seen
                ) VALUES(?,?,?,?,?,?,?)
            """,
                (
                    source_ip,
                    1,
                    1 if result == "FAIL" else 0,
                    1,
                    decision["threat_score"],
                    country,
                    base["timestamp"],
                ),
            )

        for alert in decision["alerts"]:
            db.execute(
                "INSERT INTO alerts(event_id,alert_type,message,created_at) VALUES(?,?,?,?)",
                (event_id, alert["type"], alert["message"], base["timestamp"]),
            )

        # Honeytoken trigger detection
        text = " ".join(
            str(base.get(k) or "")
            for k in ("payload", "password", "request_path", "username")
        )
        token = db.execute(
            "SELECT * FROM honeytokens WHERE secret_value=?", (text,)
        ).fetchone()
        if token:
            db.execute(
                "UPDATE honeytokens SET triggered_at=? WHERE id=?",
                (base["timestamp"], token["id"]),
            )
            db.execute(
                "INSERT INTO alerts(event_id,alert_type,message,created_at) VALUES(?,?,?,?)",
                (
                    event_id,
                    "HONEYTOKEN_TRIGGERED",
                    f"Honeytoken '{token['token_name']}' was presented by {source_ip}",
                    base["timestamp"],
                ),
            )
            db.execute(
                "UPDATE events SET severity='HIGH',threat_score=100 WHERE id=?",
                (event_id,),
            )

        db.commit()
    return event_id, decision
