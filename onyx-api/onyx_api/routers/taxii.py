"""
ONYX CTI — TAXII 2.1 Server (RFC-Compliant)
Implements the OASIS TAXII 2.1 specification for machine-to-machine CTI sharing.

Endpoints per spec (https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html):
  - GET  /taxii2/            → Discovery (§4.1)
  - GET  /taxii2/{api_root}/ → API Root Info (§4.2)
  - GET  /taxii2/{api_root}/collections/                  → Get Collections (§5.1)
  - GET  /taxii2/{api_root}/collections/{id}/              → Get Collection (§5.2)
  - GET  /taxii2/{api_root}/collections/{id}/objects/      → Get Objects (§5.3)
  - POST /taxii2/{api_root}/collections/{id}/objects/      → Add Objects (§5.4)
  - GET  /taxii2/{api_root}/collections/{id}/manifest/     → Get Manifest (§5.5)
  - DELETE /taxii2/{api_root}/collections/{id}/objects/{obj_id}/ → Delete Object (§5.7)
  - GET  /taxii2/status/{id}                               → Get Status (§4.3)

Pattern source: OASIS Medallion cti-taxii-server collections.py + OpenCTI TAXII module.
Adapted from Flask to FastAPI with async MongoDB backend.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse

from onyx_core.services.mongodb import MongoDBService
from onyx_api.auth.jwt import get_current_user, UserPayload

router = APIRouter()

# TAXII 2.1 Media Type (OASIS spec §1.6.8)
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

# Server metadata
ONYX_TAXII_TITLE = "ONYX CTI TAXII 2.1 Server"
ONYX_TAXII_DESCRIPTION = "Sovereign Cyber Threat Intelligence — Automated IOC Distribution"
ONYX_TAXII_CONTACT = "onyx-cti@sovereign.local"
ONYX_API_ROOT_ID = "onyx-cti"
ONYX_SERVER_VERSION = "3.0.0"

# Predefined TAXII Collections (mapped to internal data stores)
TAXII_COLLECTIONS = {
    "ioc-indicators": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "title": "IOC Indicators",
        "description": "Curated indicators of compromise from dark web & OSINT sources",
        "can_read": True,
        "can_write": True,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "threat-actors": {
        "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        "title": "Threat Actor Intelligence",
        "description": "Ransomware groups, APTs, and threat actor profiles",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "malware-analysis": {
        "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
        "title": "Malware Analysis Reports",
        "description": "Malware family reports, samples, and behavioral analysis",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "vulnerabilities": {
        "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
        "title": "Vulnerability Intelligence",
        "description": "CVE tracking and exploit intelligence",
        "can_read": True,
        "can_write": True,
        "media_types": ["application/stix+json;version=2.1"],
    },
}

# Lookup by UUID
COLLECTION_BY_ID = {v["id"]: {**v, "slug": k} for k, v in TAXII_COLLECTIONS.items()}


def _taxii_response(data: dict, status: int = 200) -> JSONResponse:
    """Return a response with the correct TAXII 2.1 Content-Type."""
    return JSONResponse(content=data, status_code=status, media_type=TAXII_CONTENT_TYPE)


def _validate_accept(accept: str | None = Header(default=None)) -> None:
    """
    Validate Accept header per TAXII 2.1 spec §1.6.8.
    Clients MUST send Accept: application/taxii+json;version=2.1
    We are lenient: also accept application/json and */*
    """
    if accept and "application/taxii+json" not in accept and "application/json" not in accept and "*/*" not in accept:
        raise HTTPException(
            status_code=406,
            detail="Not Acceptable. Required: Accept: application/taxii+json;version=2.1",
        )


# ============================================================================
# §4.1 — Discovery
# ============================================================================
@router.get("/taxii2/", summary="TAXII Discovery (§4.1)")
async def taxii_discovery(accept: str | None = Header(default=None)):
    """
    TAXII Discovery Resource.
    Returns server title, description, and available API Roots.
    """
    _validate_accept(accept)
    return _taxii_response({
        "title": ONYX_TAXII_TITLE,
        "description": ONYX_TAXII_DESCRIPTION,
        "contact": ONYX_TAXII_CONTACT,
        "default": f"/taxii2/{ONYX_API_ROOT_ID}/",
        "api_roots": [f"/taxii2/{ONYX_API_ROOT_ID}/"],
    })


# ============================================================================
# §4.2 — API Root Information
# ============================================================================
@router.get("/taxii2/{api_root}/", summary="API Root Info (§4.2)")
async def taxii_api_root(api_root: str, accept: str | None = Header(default=None)):
    """
    Get information about a specific API Root.
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail=f"API Root '{api_root}' not found")

    return _taxii_response({
        "title": ONYX_TAXII_TITLE,
        "description": ONYX_TAXII_DESCRIPTION,
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,  # 10MB
    })


# ============================================================================
# §5.1 — Get Collections
# ============================================================================
@router.get("/taxii2/{api_root}/collections/", summary="Get Collections (§5.1)")
async def get_collections(
    api_root: str,
    accept: str | None = Header(default=None),
    user: UserPayload = Depends(get_current_user),
):
    """
    Return all available TAXII Collections for this API Root.
    Pattern source: Medallion collections_bp.get_collections()
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail="API Root not found")

    collections = [
        {
            "id": col["id"],
            "title": col["title"],
            "description": col["description"],
            "can_read": col["can_read"],
            "can_write": col["can_write"],
            "media_types": col["media_types"],
        }
        for col in TAXII_COLLECTIONS.values()
    ]

    return _taxii_response({"collections": collections})


# ============================================================================
# §5.2 — Get a Collection
# ============================================================================
@router.get("/taxii2/{api_root}/collections/{collection_id}/", summary="Get Collection (§5.2)")
async def get_collection(
    api_root: str,
    collection_id: str,
    accept: str | None = Header(default=None),
    user: UserPayload = Depends(get_current_user),
):
    """
    Return information about a specific Collection.
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail="API Root not found")

    col = COLLECTION_BY_ID.get(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found")

    return _taxii_response({
        "id": col["id"],
        "title": col["title"],
        "description": col["description"],
        "can_read": col["can_read"],
        "can_write": col["can_write"],
        "media_types": col["media_types"],
    })


# ============================================================================
# §5.3 — Get Objects
# ============================================================================
@router.get("/taxii2/{api_root}/collections/{collection_id}/objects/", summary="Get Objects (§5.3)")
async def get_objects(
    api_root: str,
    collection_id: str,
    added_after: str | None = Query(default=None, description="Only return objects added after this timestamp"),
    limit: int = Query(default=100, ge=1, le=10000),
    match_type: str | None = Query(default=None, alias="match[type]", description="Filter by STIX object type"),
    match_id: str | None = Query(default=None, alias="match[id]", description="Filter by STIX object ID"),
    match_version: str | None = Query(default=None, alias="match[version]"),
    accept: str | None = Header(default=None),
    user: UserPayload = Depends(get_current_user),
):
    """
    Return STIX objects from a Collection.
    Implements pagination, filtering by type/id, and added_after.
    Pattern source: Medallion objects.py + OpenCTI TAXII module.
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail="API Root not found")

    col = COLLECTION_BY_ID.get(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    if not col["can_read"]:
        raise HTTPException(status_code=403, detail="Read access denied for this collection")

    # Build MongoDB query
    mongo = MongoDBService()
    query: dict[str, Any] = {}

    # Map collection to STIX types
    collection_type_map = {
        "ioc-indicators": ["indicator"],
        "threat-actors": ["threat-actor", "intrusion-set", "campaign"],
        "malware-analysis": ["malware", "tool", "report"],
        "vulnerabilities": ["vulnerability"],
    }
    slug = col.get("slug", "")
    allowed_types = collection_type_map.get(slug, [])
    if allowed_types:
        query["type"] = {"$in": allowed_types}

    if match_type:
        query["type"] = match_type

    if match_id:
        query["id"] = match_id

    if added_after:
        query["created"] = {"$gt": added_after}

    # Fetch from MongoDB
    objects = await mongo.find_stix_objects(query=query, limit=limit)

    # Build STIX Bundle envelope
    envelope = {
        "more": len(objects) == limit,
        "objects": objects,
    }

    response = _taxii_response(envelope)
    # Add TAXII pagination headers
    if objects:
        response.headers["X-TAXII-Date-Added-First"] = objects[0].get("created", "")
        response.headers["X-TAXII-Date-Added-Last"] = objects[-1].get("created", "")

    return response


# ============================================================================
# §5.4 — Add Objects
# ============================================================================
@router.post("/taxii2/{api_root}/collections/{collection_id}/objects/", summary="Add Objects (§5.4)", status_code=202)
async def add_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    accept: str | None = Header(default=None),
    user: UserPayload = Depends(get_current_user),
):
    """
    Add STIX 2.1 objects to a Collection.
    Returns a Status resource with processing results.
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail="API Root not found")

    col = COLLECTION_BY_ID.get(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    if not col["can_write"]:
        raise HTTPException(status_code=403, detail="Write access denied for this collection")

    body = await request.json()
    objects = body.get("objects", [])
    if not objects:
        raise HTTPException(status_code=422, detail="No objects provided in STIX bundle")

    # Process and store objects
    mongo = MongoDBService()
    status_id = str(uuid.uuid4())
    successes = []
    failures = []

    for obj in objects:
        try:
            stix_id = obj.get("id", "")
            stix_type = obj.get("type", "")
            if not stix_id or not stix_type:
                failures.append({"id": stix_id or "unknown", "message": "Missing required fields: id, type"})
                continue
            await mongo.upsert_stix_object(obj)
            successes.append(stix_id)
        except Exception as e:
            failures.append({"id": obj.get("id", "unknown"), "message": str(e)})

    # Build Status resource (§4.3.1)
    status = {
        "id": status_id,
        "status": "complete",
        "request_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_count": len(objects),
        "success_count": len(successes),
        "failure_count": len(failures),
        "pending_count": 0,
        "successes": [{"id": s, "version": datetime.now(timezone.utc).isoformat()} for s in successes],
        "failures": failures,
    }

    return _taxii_response(status, status=202)


# ============================================================================
# §5.5 — Get Object Manifest
# ============================================================================
@router.get("/taxii2/{api_root}/collections/{collection_id}/manifest/", summary="Get Manifest (§5.5)")
async def get_manifest(
    api_root: str,
    collection_id: str,
    added_after: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
    accept: str | None = Header(default=None),
    user: UserPayload = Depends(get_current_user),
):
    """
    Return manifest entries for objects in a Collection (lightweight metadata).
    """
    _validate_accept(accept)
    if api_root != ONYX_API_ROOT_ID:
        raise HTTPException(status_code=404, detail="API Root not found")

    col = COLLECTION_BY_ID.get(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")

    mongo = MongoDBService()
    query: dict[str, Any] = {}
    slug = col.get("slug", "")
    collection_type_map = {
        "ioc-indicators": ["indicator"],
        "threat-actors": ["threat-actor", "intrusion-set", "campaign"],
        "malware-analysis": ["malware", "tool", "report"],
        "vulnerabilities": ["vulnerability"],
    }
    allowed_types = collection_type_map.get(slug, [])
    if allowed_types:
        query["type"] = {"$in": allowed_types}
    if added_after:
        query["created"] = {"$gt": added_after}

    objects = await mongo.find_stix_objects(query=query, limit=limit, projection={"id": 1, "type": 1, "created": 1, "modified": 1, "spec_version": 1})

    manifest_entries = [
        {
            "id": obj.get("id", ""),
            "date_added": obj.get("created", ""),
            "version": obj.get("modified", obj.get("created", "")),
            "media_type": "application/stix+json;version=2.1",
        }
        for obj in objects
    ]

    return _taxii_response({"more": len(manifest_entries) == limit, "objects": manifest_entries})
