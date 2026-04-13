from typing import Any, List
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from onyx_api.routers.dashboard import _PEDAGOGY

router = APIRouter()

TA_PROFILES = [
    {"id": "TA0001", "name": "APT29", "description": "Russian Nexus", "techniques": ["T1598", "T1133", "T1059", "T1071", "T1485", "T1078"]},
    {"id": "TA0002", "name": "Volt Typhoon", "description": "Chinese Nexus", "techniques": ["T1190", "T1133", "T1047", "T1136", "T1490", "T1078", "T1021"]},
    {"id": "TA0003", "name": "Lazarus Group", "description": "DPRK Nexus", "techniques": ["T1566", "T1055", "T1059", "T1036"]},
    {"id": "TA0004", "name": "Scattered Spider", "description": "Financially Motivated", "techniques": ["T1586", "T1189", "T1531", "T1567", "T1537", "T1078"]},
    {"id": "TA0005", "name": "Initial Access Brokers", "description": "Ecosystem Enablers", "techniques": ["T1190", "T1110", "T1078", "T1133"]}
]

class TechniqueInfo(BaseModel):
    id: str
    name: str
    description: str
    objective: str
    example: str | None = None

class LiveIOC(BaseModel):
    id: str
    value: str
    type: str
    severity: str
    source: str
    confidence: int

class ThreatActorRef(BaseModel):
    id: str
    name: str
    description: str

class MitreCorrelationResponse(BaseModel):
    technique_info: TechniqueInfo
    live_iocs: List[LiveIOC]
    threat_actors: List[ThreatActorRef]
    mitigation: str

@router.get("/mitre/technique/{technique_id}", response_model=MitreCorrelationResponse, summary="Deep correlation for a MITRE technique")
async def get_mitre_technique_deep_dive(request: Request, technique_id: str) -> MitreCorrelationResponse:
    # 1. Fetch Technique Info (using local pedagogy mapping, or defaulting)
    pedagogy = _PEDAGOGY.get(technique_id.upper(), None)
    if pedagogy:
        t_info = TechniqueInfo(
            id=technique_id.upper(),
            name=pedagogy["name"],
            description=pedagogy["explanation"],
            objective=pedagogy["impact"],
            example=pedagogy.get("example")
        )
        mitigation = pedagogy.get("mitigation", "Implement zero-trust least privilege controls.")
    else:
        t_info = TechniqueInfo(
            id=technique_id.upper(),
            name=f"Technique {technique_id.upper()}",
            description="A generic technique mapping without explicit pedagogy attached.",
            objective="Potential network traversal or lateral manipulation."
        )
        mitigation = "Standard anomaly detection and endpoint containment recommended."

    # 2. Correlate with live IOCs
    all_iocs = getattr(request.app.state, "armed_iocs", [])
    active_live_iocs = []
    
    for ioc in all_iocs:
        techs = ioc.get("related_mitre_techniques", []) 
        if not techs:
            techs = ioc.get("mitre_techniques", [])
            
        if technique_id.upper() in techs:
            active_live_iocs.append(LiveIOC(
                id=ioc.get("ioc_id", "unknown"),
                value=ioc.get("value", "unknown"),
                type=ioc.get("type", "unknown"),
                severity=ioc.get("severity", "medium"),
                source=ioc.get("source", "unknown"),
                confidence=ioc.get("confidence", 50)
            ))
            
    # Cap to max 50 to prevent massive payloads lagging the UI
    active_live_iocs = active_live_iocs[:50]

    # 3. Find known Threat Actors utilizing this
    related_actors = []
    for ta in TA_PROFILES:
        if technique_id.upper() in ta["techniques"]:
            related_actors.append(ThreatActorRef(
                id=ta["id"],
                name=ta["name"],
                description=ta["description"]
            ))

    return MitreCorrelationResponse(
        technique_info=t_info,
        live_iocs=active_live_iocs,
        threat_actors=related_actors,
        mitigation=mitigation
    )
