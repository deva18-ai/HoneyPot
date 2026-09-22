from collections import Counter
from datetime import datetime, timezone, timedelta
import ipaddress
from backend.config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, SCAN_SERVICE_THRESHOLD, SCAN_WINDOW
from backend.db import connect

def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z","+00:00"))

def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True

def _recent_for_ip(db, ip, seconds):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    return db.execute(
        "SELECT * FROM events WHERE source_ip=? AND timestamp>=?",
        (ip, cutoff)
    ).fetchall()

def fingerprint_for(service, payload="", user_agent=""):
    text = f"{payload} {user_agent}".lower()
    if "curl" in text:
        return "curl"
    if "python" in text:
        return "python-client"
    if "nmap" in text:
        return "nmap-like"
    if "hydra" in text:
        return "hydra-like"
    if "mozilla" in text or "chrome" in text or "safari" in text:
        return "browser"
    if service in {"SSH","FTP","TELNET"}:
        return "unknown-socket-client"
    return "unknown"

def country_for_ip(ip):
    # Intentionally conservative: no external geolocation is required.
    # Private lab addresses are labelled LOCAL-LAB.
    return "LOCAL-LAB" if _is_private(ip) else "UNKNOWN"

def analyze_event(event):
    ip = event["source_ip"]
    service = event["service"]
    event_type = event["event_type"]
    payload = str(event.get("payload") or "")
    path = str(event.get("request_path") or "")
    severity = "LOW"
    labels = []
    alerts = []
    score = 5

    with connect() as db:
        recent_login = _recent_for_ip(db, ip, BRUTE_FORCE_WINDOW)
        failed = sum(1 for r in recent_login if r["result"] == "FAIL" and r["event_type"] == "AUTH_ATTEMPT")
        services = {r["service"] for r in _recent_for_ip(db, ip, SCAN_WINDOW)}

    if event_type == "AUTH_ATTEMPT":
        labels.append("AUTH_ATTEMPT")
        score += 10

    if failed >= BRUTE_FORCE_THRESHOLD:
        labels.append("BRUTE_FORCE")
        severity = "HIGH"
        score += 45
        alerts.append({
            "type": "BRUTE_FORCE",
            "message": f"Brute-force pattern detected from {ip}: {failed} failed attempts in {BRUTE_FORCE_WINDOW}s"
        })
    elif failed >= 3:
        severity = "MEDIUM"
        score += 20

    suspicious_paths = ["/admin", "/backup", "/.env", "/config", "/phpmyadmin", "/wp-admin"]
    if any(x in path.lower() for x in suspicious_paths):
        labels.append("SUSPICIOUS_REQUEST")
        severity = max_severity(severity, "MEDIUM")
        score += 20

    if len(services) >= SCAN_SERVICE_THRESHOLD:
        labels.append("SCAN")
        severity = "HIGH"
        score += 30
        alerts.append({
            "type": "MULTI_SERVICE_SCAN",
            "message": f"Multi-service scan pattern from {ip}: {len(services)} services in {SCAN_WINDOW}s"
        })

    if event_type in {"PATH_REQUEST","CONNECTION"} and payload:
        if any(term in payload.lower() for term in ("scanner","probe","automated")):
            labels.append("SCAN")
            score += 15

    # Simple anomaly rule: many recent events in one minute.
    with connect() as db:
        recent_count = len(_recent_for_ip(db, ip, 60))
    if recent_count >= 15:
        labels.append("ANOMALY_SPIKE")
        severity = "HIGH"
        score += 25
        alerts.append({
            "type": "ANOMALY_SPIKE",
            "message": f"Traffic spike detected from {ip}: {recent_count} events in 60s"
        })

    if not labels:
        labels.append("NORMAL")

    score = min(100, score)
    return {
        "event_type": "|".join(labels),
        "severity": severity,
        "threat_score": score,
        "fingerprint": fingerprint_for(service, payload, event.get("user_agent","")),
        "country": country_for_ip(ip),
        "alerts": alerts,
    }

def max_severity(a,b):
    order = {"LOW":0,"MEDIUM":1,"HIGH":2}
    return a if order[a] >= order[b] else b
