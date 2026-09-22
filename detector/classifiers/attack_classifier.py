from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
import re


class AttackCategory(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    PORT_SCAN = "PORT_SCAN"
    SERVICE_SCAN = "SERVICE_SCAN"
    WEB_RECON = "WEB_RECON"
    EXPLOIT_ATTEMPT = "EXPLOIT_ATTEMPT"
    CREDENTIAL_ABUSE = "CREDENTIAL_ABUSE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFIL = "DATA_EXFIL"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    PERSISTENCE = "PERSISTENCE"
    NORMAL = "NORMAL"


@dataclass
class ClassificationRule:
    category: AttackCategory
    patterns: List[str]
    conditions: List[str]
    weight: int
    description: str


CLASSIFICATION_RULES = [
    ClassificationRule(
        category=AttackCategory.BRUTE_FORCE,
        patterns=["AUTH_ATTEMPT"],
        conditions=["failed_logins >= 5"],
        weight=50,
        description="Multiple failed authentication attempts"
    ),
    ClassificationRule(
        category=AttackCategory.BRUTE_FORCE,
        patterns=["AUTH_ATTEMPT"],
        conditions=["failed_logins >= 3"],
        weight=25,
        description="Several failed authentication attempts"
    ),
    ClassificationRule(
        category=AttackCategory.CREDENTIAL_STUFFING,
        patterns=["AUTH_ATTEMPT"],
        conditions=["known_breached_credentials"],
        weight=60,
        description="Known breached credentials used"
    ),
    ClassificationRule(
        category=AttackCategory.PORT_SCAN,
        patterns=["CONNECTION"],
        conditions=["rapid_port_connections >= 10"],
        weight=40,
        description="Rapid connection attempts to multiple ports"
    ),
    ClassificationRule(
        category=AttackCategory.SERVICE_SCAN,
        patterns=["CONNECTION", "AUTH_ATTEMPT", "BANNER_PROBE"],
        conditions=["unique_services >= 3"],
        weight=35,
        description="Connection attempts to multiple services"
    ),
    ClassificationRule(
        category=AttackCategory.WEB_RECON,
        patterns=["PATH_REQUEST", "HTTP_REQUEST"],
        conditions=["suspicious_paths"],
        weight=30,
        description="Suspicious web path requests (admin, backup, .env, etc.)"
    ),
    ClassificationRule(
        category=AttackCategory.EXPLOIT_ATTEMPT,
        patterns=["PATH_REQUEST", "HTTP_REQUEST", "PAYLOAD"],
        conditions=["exploit_signatures"],
        weight=60,
        description="Known exploit payloads or patterns detected"
    ),
    ClassificationRule(
        category=AttackCategory.CREDENTIAL_ABUSE,
        patterns=["AUTH_ATTEMPT", "HONEYTOKEN"],
        conditions=["honeytoken_triggered", "default_credentials"],
        weight=80,
        description="Honeytoken usage or default credential attempts"
    ),
    ClassificationRule(
        category=AttackCategory.LATERAL_MOVEMENT,
        patterns=["CONNECTION", "AUTH_ATTEMPT"],
        conditions=["internal_network_scan", "smb_access", "rdp_access"],
        weight=50,
        description="Internal network lateral movement attempts"
    ),
    ClassificationRule(
        category=AttackCategory.DATA_EXFIL,
        patterns=["HTTP_REQUEST", "FILE_TRANSFER"],
        conditions=["large_outbound_transfer", "unusual_protocol"],
        weight=55,
        description="Potential data exfiltration activity"
    ),
    ClassificationRule(
        category=AttackCategory.COMMAND_AND_CONTROL,
        patterns=["CONNECTION", "DNS_QUERY", "HTTP_REQUEST"],
        conditions=["beaconing_pattern", "dns_tunneling", "encrypted_channel"],
        weight=55,
        description="Command and control communication patterns"
    ),
]


SUSPICIOUS_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/config", "/backup", "/.git", "/.svn", "/.htaccess",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/test.php", "/shell.php", "/cmd.php", "/c99.php", "/r57.php",
    "/wp-content", "/wp-includes", "/xmlrpc.php", "/install.php",
    "/setup.php", "/config.php", "/database.sql", "/dump.sql",
]

EXPLOIT_SIGNATURES = [
    r"union\s+select", r"select\s+.*\s+from", r"insert\s+into", r"drop\s+table",
    r"exec\s*\(", r"system\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
    r"eval\s*\(", r"base64_decode\s*\(", r"gzinflate\s*\(", r"str_rot13\s*\(",
    r"wget\s+http", r"curl\s+http", r"nc\s+-e", r"/bin/sh", r"/bin/bash",
    r"powershell\s+-enc", r"cmd\.exe\s+/c", r"certutil\s+-decode",
    r"bitsadmin\s+/transfer", r"regsvr32\s+/s", r"mshta\s+http",
    r"rundll32\s+javascript", r"wscript\s+shell", r"cscript\s+shell",
]


class AttackClassifier:
    def __init__(self):
        self.rules = CLASSIFICATION_RULES
        self.compiled_exploits = [re.compile(p, re.IGNORECASE) for p in EXPLOIT_SIGNATURES]
    
    def classify(self, event_data: Dict[str, Any], recent_events: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        recent_events = recent_events or []
        
        event_type = event_data.get("event_type", "")
        service = event_data.get("service", "")
        payload = str(event_data.get("payload") or "").lower()
        path = str(event_data.get("request_path") or "").lower()
        result = event_data.get("result", "")
        source_ip = event_data.get("source_ip", "")
        
        failed_logins = sum(1 for e in recent_events 
                           if e.get("source_ip") == source_ip 
                           and e.get("event_type") == "AUTH_ATTEMPT" 
                           and e.get("result") == "FAIL")
        
        services_hit = len(set(e.get("service") for e in recent_events if e.get("source_ip") == source_ip))
        
        rapid_connections = sum(1 for e in recent_events 
                               if e.get("source_ip") == source_ip 
                               and e.get("event_type") == "CONNECTION")
        
        suspicious_path_match = any(p in path for p in SUSPICIOUS_PATHS)
        
        exploit_match = any(pattern.search(payload) or pattern.search(path) 
                           for pattern in self.compiled_exploits)
        
        honeytoken_triggered = event_data.get("honeytoken_triggered", False)
        
        matched_categories = []
        total_score = 0
        
        for rule in self.rules:
            if self._matches_rule(rule, {
                "event_type": event_type,
                "service": service,
                "payload": payload,
                "path": path,
                "result": result,
                "source_ip": source_ip,
                "failed_logins": failed_logins,
                "services_hit": services_hit,
                "rapid_connections": rapid_connections,
                "suspicious_path_match": suspicious_path_match,
                "exploit_match": exploit_match,
                "honeytoken_triggered": honeytoken_triggered,
            }):
                matched_categories.append(rule.category.value)
                total_score += rule.weight
        
        if not matched_categories:
            matched_categories.append(AttackCategory.NORMAL.value)
            total_score = 5
        
        total_score = min(100, max(0, total_score))
        
        return {
            "classification": "|".join(matched_categories),
            "threat_score": total_score,
            "risk_level": self._calculate_risk_level(total_score),
            "categories": matched_categories,
        }
    
    def _matches_rule(self, rule: ClassificationRule, context: Dict[str, Any]) -> bool:
        for pattern in rule.patterns:
            if pattern not in context.get("event_type", ""):
                return False
        
        for condition in rule.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        
        return True
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        if condition == "failed_logins >= 5":
            return context.get("failed_logins", 0) >= 5
        if condition == "failed_logins >= 3":
            return context.get("failed_logins", 0) >= 3
        if condition == "known_breached_credentials":
            return False
        if condition == "rapid_port_connections >= 10":
            return context.get("rapid_connections", 0) >= 10
        if condition == "unique_services >= 3":
            return context.get("services_hit", 0) >= 3
        if condition == "suspicious_paths":
            return context.get("suspicious_path_match", False)
        if condition == "exploit_signatures":
            return context.get("exploit_match", False)
        if condition == "honeytoken_triggered":
            return context.get("honeytoken_triggered", False)
        if condition == "default_credentials":
            username = context.get("username", "").lower()
            password = context.get("password", "").lower()
            defaults = ["admin", "root", "administrator", "user", "test", "guest", "oracle", "postgres", "mysql"]
            return username in defaults or password in defaults
        if condition == "internal_network_scan":
            return False
        if condition == "smb_access":
            return context.get("service", "") == "SMB"
        if condition == "rdp_access":
            return context.get("service", "") == "RDP"
        if condition == "large_outbound_transfer":
            return False
        if condition == "unusual_protocol":
            return False
        if condition == "beaconing_pattern":
            return False
        if condition == "dns_tunneling":
            return False
        if condition == "encrypted_channel":
            return False
        
        return False
    
    def _calculate_risk_level(self, score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"


classifier = AttackClassifier()


def classify_attack(event_data: Dict[str, Any], recent_events: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    return classifier.classify(event_data, recent_events)