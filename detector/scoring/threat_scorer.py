from typing import Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScoringFactor:
    name: str
    weight: float
    description: str
    max_score: int = 100


SCORING_FACTORS = [
    ScoringFactor("base_attack_type", 0.30, "Base score from attack classification", 100),
    ScoringFactor("velocity", 0.15, "Event frequency/velocity from source", 100),
    ScoringFactor("source_reputation", 0.15, "IP reputation/threat intelligence", 100),
    ScoringFactor("target_sensitivity", 0.10, "Criticality of targeted service", 100),
    ScoringFactor("success_rate", 0.10, "Ratio of successful to failed attempts", 100),
    ScoringFactor("honeytoken_trigger", 0.10, "Honeytoken interaction (auto-high)", 100),
    ScoringFactor("mitre_severity", 0.10, "Severity of mapped MITRE techniques", 100),
]


TARGET_SENSITIVITY = {
    "SSH": 80,
    "RDP": 90,
    "SMB": 85,
    "FTP": 60,
    "TELNET": 50,
    "DB": 70,
    "HTTP": 55,
    "HTTPS": 55,
    "REDIS": 75,
    "MYSQL": 75,
    "POSTGRES": 75,
    "MONGODB": 75,
    "ELASTICSEARCH": 70,
}

DEFAULT_SENSITIVITY = 50


class ThreatScorer:
    def __init__(self):
        self.factors = SCORING_FACTORS
    
    def calculate_score(
        self,
        classification_result: Dict[str, Any],
        event_data: Dict[str, Any],
        recent_events: List[Dict[str, Any]] = None,
        ip_reputation: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        recent_events = recent_events or []
        ip_reputation = ip_reputation or {}
        
        scores = {}
        
        scores["base_attack_type"] = classification_result.get("threat_score", 5)
        
        scores["velocity"] = self._calculate_velocity(event_data, recent_events)
        
        scores["source_reputation"] = self._calculate_reputation(ip_reputation)
        
        scores["target_sensitivity"] = self._calculate_target_sensitivity(event_data)
        
        scores["success_rate"] = self._calculate_success_rate(event_data, recent_events)
        
        scores["honeytoken_trigger"] = self._calculate_honeytoken(event_data)
        
        scores["mitre_severity"] = self._calculate_mitre_severity(classification_result)
        
        weighted_score = sum(
            scores[factor.name] * factor.weight
            for factor in self.factors
        )
        
        final_score = min(100, max(0, int(weighted_score)))
        
        risk_level = self._calculate_risk_level(final_score)
        
        confidence = self._calculate_confidence(scores, classification_result)
        
        return {
            "threat_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "factor_scores": scores,
            "factor_weights": {f.name: f.weight for f in self.factors},
        }
    
    def _calculate_velocity(self, event_data: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> int:
        source_ip = event_data.get("source_ip", "")
        if not source_ip:
            return 0
        
        ip_events = [e for e in recent_events if e.get("source_ip") == source_ip]
        count = len(ip_events)
        
        if count >= 50:
            return 100
        elif count >= 20:
            return 80
        elif count >= 10:
            return 60
        elif count >= 5:
            return 40
        elif count >= 2:
            return 20
        else:
            return 10
    
    def _calculate_reputation(self, ip_reputation: Dict[str, Any]) -> int:
        if not ip_reputation:
            return 50
        
        reputation_score = ip_reputation.get("reputation_score", 50)
        is_malicious = ip_reputation.get("is_malicious", False)
        is_tor = ip_reputation.get("is_tor", False)
        is_proxy = ip_reputation.get("is_proxy", False)
        
        score = reputation_score
        
        if is_malicious:
            score = min(100, score + 30)
        if is_tor:
            score = min(100, score + 20)
        if is_proxy:
            score = min(100, score + 10)
        
        return score
    
    def _calculate_target_sensitivity(self, event_data: Dict[str, Any]) -> int:
        service = event_data.get("service", "")
        return TARGET_SENSITIVITY.get(service, DEFAULT_SENSITIVITY)
    
    def _calculate_success_rate(self, event_data: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> int:
        source_ip = event_data.get("source_ip", "")
        if not source_ip:
            return 50
        
        ip_events = [e for e in recent_events if e.get("source_ip") == source_ip]
        if not ip_events:
            return 50
        
        total = len(ip_events)
        successful = sum(1 for e in ip_events if e.get("result") == "SUCCESS")
        
        if total == 0:
            return 50
        
        rate = successful / total
        
        if rate >= 0.8:
            return 90
        elif rate >= 0.5:
            return 70
        elif rate >= 0.2:
            return 50
        elif rate >= 0.1:
            return 30
        else:
            return 10
    
    def _calculate_honeytoken(self, event_data: Dict[str, Any]) -> int:
        if event_data.get("honeytoken_triggered", False):
            return 100
        return 0
    
    def _calculate_mitre_severity(self, classification_result: Dict[str, Any]) -> int:
        mitre_techniques = classification_result.get("mitre_techniques", [])
        if not mitre_techniques:
            return 30
        
        high_severity_techniques = [
            "T1190", "T1110", "T1068", "T1003", "T1486", "T1490", "T1021"
        ]
        
        for tech in mitre_techniques:
            base_tech = tech.split(".")[0]
            if base_tech in high_severity_techniques:
                return 80
        
        return 50
    
    def _calculate_risk_level(self, score: int) -> str:
        if score >= 90:
            return RiskLevel.CRITICAL
        elif score >= 70:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_confidence(self, scores: Dict[str, int], classification_result: Dict[str, Any]) -> str:
        high_confidence_factors = 0
        total_factors = len(self.factors)
        
        if scores.get("base_attack_type", 0) > 50:
            high_confidence_factors += 1
        if scores.get("honeytoken_trigger", 0) > 0:
            high_confidence_factors += 1
        if scores.get("source_reputation", 0) > 70:
            high_confidence_factors += 1
        if scores.get("velocity", 0) > 60:
            high_confidence_factors += 1
        if classification_result.get("mitre_techniques"):
            high_confidence_factors += 1
        
        confidence_ratio = high_confidence_factors / total_factors
        
        if confidence_ratio >= 0.6:
            return "HIGH"
        elif confidence_ratio >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"


scorer = ThreatScorer()


def calculate_threat_score(
    classification_result: Dict[str, Any],
    event_data: Dict[str, Any],
    recent_events: List[Dict[str, Any]] = None,
    ip_reputation: Dict[str, Any] = None,
) -> Dict[str, Any]:
    return scorer.calculate_score(classification_result, event_data, recent_events, ip_reputation)