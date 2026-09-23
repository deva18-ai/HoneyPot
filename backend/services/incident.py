from datetime import datetime, timezone


def generate_incident_id() -> str:
    now = datetime.now(timezone.utc)
    return f"HT-{now.year}-{now.strftime('%m%d%H%M%S')}"


def calculate_risk_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def classify_attack(event_data: dict, recent_events: list) -> dict:
    classifications = []
    score = 0

    event_type = event_data.get("event_type", "")
    payload = str(event_data.get("payload") or "").lower()
    path = str(event_data.get("request_path") or "").lower()
    result = event_data.get("result", "")
    source_ip = event_data.get("source_ip", "")

    failed_logins = sum(
        1
        for e in recent_events
        if e.get("source_ip") == source_ip
        and e.get("event_type") == "AUTH_ATTEMPT"
        and e.get("result") == "FAIL"
    )

    services_hit = len(
        {e.get("service") for e in recent_events if e.get("source_ip") == source_ip}
    )

    if event_type == "AUTH_ATTEMPT" and result == "FAIL":
        classifications.append("AUTH_ATTEMPT")
        score += 10

    if failed_logins >= 5:
        classifications.append("BRUTE_FORCE")
        score += 50
    elif failed_logins >= 3:
        classifications.append("BRUTE_FORCE_ATTEMPT")
        score += 25

    suspicious_paths = [
        "/admin",
        "/backup",
        "/.env",
        "/config",
        "/phpmyadmin",
        "/wp-admin",
        "/wp-login",
        "/administrator",
    ]
    if any(p in path for p in suspicious_paths):
        classifications.append("WEB_RECON")
        score += 25

    if services_hit >= 3:
        classifications.append("SERVICE_SCAN")
        score += 35
    elif services_hit >= 2:
        classifications.append("MULTI_SERVICE_ACCESS")
        score += 15

    exploit_patterns = [
        "exploit",
        "shell",
        "cmd",
        "exec",
        "eval",
        "system(",
        "passthru",
        "base64_decode",
        "wget ",
        "curl ",
        "nc -e",
        "/bin/sh",
        "/bin/bash",
        "powershell",
        "cmd.exe",
    ]
    if any(p in payload for p in exploit_patterns):
        classifications.append("EXPLOIT_ATTEMPT")
        score += 60

    if "hydra" in payload or "medusa" in payload or "ncrack" in payload:
        classifications.append("BRUTE_FORCE_TOOL")
        score += 30

    if "nmap" in payload or "masscan" in payload or "zmap" in payload:
        classifications.append("PORT_SCAN_TOOL")
        score += 30

    if not classifications:
        classifications.append("NORMAL")
        score = 5

    score = min(100, max(0, score))

    return {
        "classification": "|".join(classifications),
        "threat_score": score,
        "risk_level": calculate_risk_level(score),
    }


def map_to_mitre(classification: str) -> list:
    mitre_map = {
        "BRUTE_FORCE": ["T1110.001", "T1110.003"],
        "BRUTE_FORCE_ATTEMPT": ["T1110.001"],
        "BRUTE_FORCE_TOOL": ["T1110.001", "T1110.003"],
        "CREDENTIAL_STUFFING": ["T1110.004"],
        "WEB_RECON": ["T1590.005", "T1590.001"],
        "SERVICE_SCAN": ["T1590.001", "T1595.001"],
        "MULTI_SERVICE_ACCESS": ["T1590.001"],
        "PORT_SCAN": ["T1595.001"],
        "PORT_SCAN_TOOL": ["T1595.001"],
        "EXPLOIT_ATTEMPT": ["T1190", "T1203"],
        "COMMAND_AND_CONTROL": ["T1071", "T1105"],
        "DATA_EXFIL": ["T1041", "T1048"],
        "LATERAL_MOVEMENT": ["T1021", "T1550"],
        "PRIVILEGE_ESCALATION": ["T1068", "T1548"],
        "DEFENSE_EVASION": ["T1070", "T1222"],
    }

    techniques = set()
    for cls in classification.split("|"):
        if cls in mitre_map:
            techniques.update(mitre_map[cls])

    return list(techniques)
