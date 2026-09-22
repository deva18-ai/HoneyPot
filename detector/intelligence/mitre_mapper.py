from typing import Dict, List, Any, Optional
from backend.db.session import async_session_maker
from backend.models import MitreTechnique
from sqlalchemy import select


MITRE_CATEGORY_MAP = {
    "BRUTE_FORCE": ["T1110.001", "T1110.003"],
    "CREDENTIAL_STUFFING": ["T1110.004"],
    "PORT_SCAN": ["T1595.001"],
    "SERVICE_SCAN": ["T1590.001", "T1595.001"],
    "WEB_RECON": ["T1590.005", "T1590.001"],
    "EXPLOIT_ATTEMPT": ["T1190", "T1203"],
    "CREDENTIAL_ABUSE": ["T1110.004", "T1556.002"],
    "LATERAL_MOVEMENT": ["T1021.004", "T1021.001", "T1021.002", "T1550.002"],
    "DATA_EXFIL": ["T1041", "T1048.003", "T1567.002"],
    "COMMAND_AND_CONTROL": ["T1071.001", "T1071.004", "T1105", "T1573.001"],
    "PRIVILEGE_ESCALATION": ["T1068", "T1548.003"],
    "DEFENSE_EVASION": ["T1070.004", "T1222.002", "T1562.001"],
    "PERSISTENCE": ["T1505.003", "T1505.004", "T1098"],
}


class MitreMapper:
    def __init__(self):
        self.category_map = MITRE_CATEGORY_MAP
        self._technique_cache: Dict[str, Dict] = {}
    
    async def map_classification(self, classification: str) -> List[str]:
        techniques = set()
        
        for category in classification.split("|"):
            if category in self.category_map:
                techniques.update(self.category_map[category])
        
        return list(techniques)
    
    async def get_technique_details(self, technique_ids: List[str]) -> List[Dict]:
        details = []
        
        for tech_id in technique_ids:
            if tech_id in self._technique_cache:
                details.append(self._technique_cache[tech_id])
                continue
            
            async with async_session_maker() as db:
                result = await db.execute(
                    select(MitreTechnique).where(MitreTechnique.technique_id == tech_id)
                )
                technique = result.scalar_one_or_none()
                
                if technique:
                    detail = {
                        "technique_id": technique.technique_id,
                        "name": technique.name,
                        "tactic": technique.tactic,
                        "description": technique.description,
                        "detection": technique.detection,
                        "mitigation": technique.mitigation,
                        "platform": technique.platform,
                        "is_subtechnique": technique.is_subtechnique,
                        "parent_technique": technique.parent_technique,
                    }
                    self._technique_cache[tech_id] = detail
                    details.append(detail)
                else:
                    details.append({
                        "technique_id": tech_id,
                        "name": "Unknown",
                        "tactic": "Unknown",
                        "description": "Technique not found in database",
                    })
        
        return details
    
    async def get_tactics_for_incident(self, classification: str) -> List[str]:
        techniques = await self.map_classification(classification)
        tactics = set()
        
        for tech_id in techniques:
            detail = await self.get_technique_details([tech_id])
            if detail and detail[0].get("tactic"):
                tactics.add(detail[0]["tactic"])
        
        return list(tactics)
    
    def get_category_mapping(self) -> Dict[str, List[str]]:
        return self.category_map.copy()


mapper = MitreMapper()


async def map_to_mitre(classification: str) -> List[str]:
    return await mapper.map_classification(classification)


async def get_mitre_details(technique_ids: List[str]) -> List[Dict]:
    return await mapper.get_technique_details(technique_ids)