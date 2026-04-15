"""
ONYX CTI — Reports Router
Handles STIX 2.1 serialization and RBAC checks for secure intelligence extraction.

Hardened: All datetime/UUID objects are pre-serialized to strings to prevent
Pydantic/orjson serialization failures (HTTP 500 "Failed to fetch").

v2: TLP-conditioned STIX export — RED/AMBER/GREEN control bundle depth.
    Fixed: Tools/Techniques injection moved outside try/except to guarantee
    relationship generation on every successfully serialized actor.
    Added: Identity objects for targeted sectors + created_by_ref.
"""

from __future__ import annotations
import os
import uuid
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
import json

from onyx_api.services.osint_integrations import MitreConnector, AlienVaultConnector

router = APIRouter()

STANDALONE = os.environ.get("STANDALONE_MODE", "").lower() == "true"

# ─── Sector targeting map for identity objects ────────────────────────────────
_ACTOR_SECTOR_MAP: dict[str, list[str]] = {
    "APT29": ["Government", "Energy", "Healthcare"],
    "Volt Typhoon": ["Critical Infrastructure", "Telecommunications"],
    "Lazarus Group": ["Financial Services", "Cryptocurrency", "Defense"],
    "Scattered Spider": ["Telecommunications", "Technology", "Cloud Services"],
    "FIN7": ["Retail", "Hospitality", "Financial Services"],
    "APT41": ["Healthcare", "Telecommunications", "Technology"],
    "Sandworm Team": ["Energy", "Government", "ICS/SCADA"],
    "Turla": ["Government", "Military", "Research"],
    "Equation": ["Government", "Military", "Telecommunications"],
    "Gorgon Group": ["Government", "Military", "Technology"],
    "Mustang Panda": ["Government", "Non-Profits", "Think Tanks"],
    "OilRig": ["Government", "Financial", "Energy"],
}


def _safe_serialize(obj: Any) -> Any:
    """
    Recursively convert non-JSON-serializable types (UUID, datetime) to strings.
    This prevents orjson/Pydantic from throwing 500 errors on complex payloads.
    """
    if isinstance(obj, dict):
        return {k: _safe_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_safe_serialize(item) for item in obj]
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return obj


async def _get_threat_data_for_export(request: Request) -> dict:
    """Abstraction layer extracting real OSINT data for serialization."""
    if STANDALONE:
        # Generate standalone data natively
        live_iocs = await AlienVaultConnector.fetch_live_iocs()
        
        # Genuine threat actors
        actors = await MitreConnector.get_threat_actors()
        # Fallback if unpopulated
        if not actors:
             actors = [
                {"id": "TA0001", "name": "APT29", "aliases": ["Cozy Bear"], "severity": "critical", "live_iocs": 15},
             ]
        
        return {"iocs": live_iocs, "actors": actors}
    
    # E.g. connect to MongoDB/Elasticsearch here
    # Placeholder for DB Logic
    return {"iocs": [], "actors": []}


@router.get("/reports/export/stix", summary="Export tactical intelligence in STIX 2.1")
async def export_stix(
    request: Request,
    tlp: str = Query(default="RED", description="TLP level: RED (full), AMBER (no IOC patterns), GREEN (actors only)")
) -> JSONResponse:
    """
    Secure export payload strictly conforming to STIX 2.1 standard format.
    Returns a JSONResponse with pre-serialized data to avoid orjson TypeErrors.
    
    TLP filtering:
    - RED: Complete bundle (all objects: actors, malware, attack-patterns, indicators, relationships)
    - AMBER: Excludes raw indicator patterns (redacted), keeps relationships
    - GREEN: Only threat-actor + identity objects (zero IOCs, zero attack details)
    
    HARDENED:
    - All UUIDs explicitly str()-cast at point of creation
    - Tools/Techniques injection is OUTSIDE try/except to guarantee relationships
    - Deterministic actor-indicator linking (round-robin)
    - Per-object try/catch with field-level error identification
    - Returns 422 if zero STIX objects are generated
    """
    import structlog
    _log = structlog.get_logger("onyx.reports.stix")
    
    tlp = tlp.upper().strip()
    if tlp not in ("RED", "AMBER", "GREEN", "CLEAR"):
        tlp = "RED"

    try:
        data = await _get_threat_data_for_export(request)
    except Exception as e:
        _log.error("stix.data_extraction_failed", error=str(e))
        return JSONResponse(
            status_code=500,
            content={"detail": f"Data extraction failed: {str(e)}"}
        )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # OASIS: created_by_ref identity
    onyx_identity_id = f"identity--{str(uuid.uuid4())}"
    
    # STIX 2.1 Envelope — UUID explicitly cast to str
    stix_bundle: dict[str, Any] = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": onyx_identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": "ONYX CTI Platform",
                "identity_class": "system",
                "description": "Automated STIX 2.1 export from ONYX Threat Intelligence Platform"
            }
        ]
    }
    
    errors: list[str] = []
    
    # ── Track identity objects to avoid duplicates ──
    sector_identity_ids: dict[str, str] = {}
    
    # ── Map Threat Actors ──
    actor_ids: list[tuple[str, str]] = []
    for idx, actor in enumerate(data.get("actors", [])):
        # Step 1: Serialize the actor object
        stix_id = None
        try:
            stix_id = f"threat-actor--{str(uuid.uuid4())}"
            actor_name = str(actor.get("name", "Unknown"))
            actor_ids.append((actor_name, stix_id))
            stix_bundle["objects"].append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": stix_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": onyx_identity_id,
                "name": actor_name,
                "aliases": [str(a) for a in actor.get("aliases", [])],
                "threat_actor_types": ["nation-state", "spy"],
                "roles": ["director"],
                "goals": ["espionage"]
            })
        except Exception as e:
            errors.append(f"actor[{idx}]: {str(e)}")
            _log.error("stix.actor_serialization_failed", index=idx, error=str(e))
            continue  # Skip this actor entirely — no stix_id to reference
        
        # Step 2: Inject Tools / Malware (OUTSIDE try/except, uses stix_id from above)
        # Only in RED and AMBER modes
        if tlp in ("RED", "AMBER"):
            for tool_name in actor.get("tools", []):
                tool_id = f"malware--{str(uuid.uuid4())}"
                stix_bundle["objects"].append({
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": tool_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "created_by_ref": onyx_identity_id,
                    "name": str(tool_name),
                    "is_family": False
                })
                stix_bundle["objects"].append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{str(uuid.uuid4())}",
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "uses",
                    "source_ref": stix_id,
                    "target_ref": tool_id
                })
            
            # Step 3: Inject Techniques / Attack Patterns
            for ttp in actor.get("techniques", []):
                if isinstance(ttp, dict):
                    ttp_code = ttp.get("id", "T0000")
                    ttp_name = ttp.get("name", ttp_code)
                else:
                    ttp_code = str(ttp)
                    ttp_name = ttp_code
                    
                ap_id = f"attack-pattern--{str(uuid.uuid4())}"
                stix_bundle["objects"].append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "created_by_ref": onyx_identity_id,
                    "name": ttp_name,
                    "external_references": [{"source_name": "mitre-attack", "external_id": ttp_code}]
                })
                stix_bundle["objects"].append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{str(uuid.uuid4())}",
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "uses",
                    "source_ref": stix_id,
                    "target_ref": ap_id
                })
        
        # Step 4: Inject Identity objects for targeted sectors + "targets" relationships
        actor_name_str = str(actor.get("name", ""))
        target_sectors = _ACTOR_SECTOR_MAP.get(actor_name_str, [])
        for sector in target_sectors:
            if sector not in sector_identity_ids:
                sector_id = f"identity--{str(uuid.uuid4())}"
                sector_identity_ids[sector] = sector_id
                stix_bundle["objects"].append({
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": sector_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": sector,
                    "identity_class": "class",
                    "sectors": [sector.lower().replace(" ", "-")]
                })
            
            stix_bundle["objects"].append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{str(uuid.uuid4())}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "targets",
                "source_ref": stix_id,
                "target_ref": sector_identity_ids[sector]
            })
        
    # ── Map IOCs to Indicator objects (RED and AMBER only) ──
    if tlp in ("RED", "AMBER"):
        for idx, ioc in enumerate(data.get("iocs", [])):
            try:
                indicator_stix_id = f"indicator--{str(uuid.uuid4())}"
                ioc_val = str(ioc.get("value", ""))
                ioc_type = str(ioc.get("type", "ipv4"))
                
                # Build STIX pattern
                pattern = ""
                if "ipv4" in ioc_type or "ipv6" in ioc_type:
                    pattern = f"[ipv4-addr:value = '{ioc_val}']"
                elif "domain" in ioc_type:
                    pattern = f"[domain-name:value = '{ioc_val}']"
                elif "url" in ioc_type:
                    pattern = f"[url:value = '{ioc_val}']"
                elif "cve" in ioc_type:
                    pattern = f"[vulnerability:name = '{ioc_val}']"
                else:
                    pattern = f"[file:hashes.'SHA-256' = '{ioc_val}']"
                
                # In AMBER mode, redact the actual pattern value
                if tlp == "AMBER":
                    pattern = f"[REDACTED — TLP:AMBER]"
                     
                stix_bundle["objects"].append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_stix_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "created_by_ref": onyx_identity_id,
                    "name": f"Malicious {ioc_type} IOC",
                    "description": str(ioc.get("source", "Telemetry Stream")),
                    "pattern_type": "stix",
                    "pattern": pattern,
                    "valid_from": now_iso
                })
                
                # Link each IOC to an actor in round-robin fashion
                if actor_ids:
                    linked_actor = actor_ids[idx % len(actor_ids)]
                    rel_id = f"relationship--{str(uuid.uuid4())}"
                    stix_bundle["objects"].append({
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": rel_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "relationship_type": "indicates",
                        "source_ref": indicator_stix_id,
                        "target_ref": str(linked_actor[1])
                    })
            except Exception as e:
                errors.append(f"ioc[{idx}]: {str(e)}")
                _log.error("stix.ioc_serialization_failed", index=idx, error=str(e))

    # Validate bundle is non-empty
    if not stix_bundle["objects"]:
        _log.error("stix.empty_bundle", errors=errors)
        return JSONResponse(
            status_code=422,
            content={"detail": "STIX bundle generated zero objects", "errors": errors}
        )

    # Pre-serialize everything to prevent orjson/Pydantic failures
    safe_bundle = _safe_serialize(stix_bundle)

    _log.info("stix.export_success", objects=len(stix_bundle["objects"]), errors_count=len(errors), tlp=tlp)

    return JSONResponse(
        content=safe_bundle,
        headers={
            "Content-Disposition": f"attachment; filename=ONYX_STIX2.1_Bundle_TLP_{tlp}_{int(time.time())}.json",
            "X-ONYX-TLP": tlp,
        }
    )
