"""
ONYX CTI — IOC Router
REST API v1 endpoints for IOC management: CRUD, search, bulk operations.
Designed for machine-to-machine integration with SIEM/Firewall/SOAR.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from onyx_core.services import ElasticsearchService, RedisService

router = APIRouter()


# ============================================================================
# Armed IOCs endpoint — serves pre-ingested OSINT data to the dashboard
# ============================================================================

@router.get("/iocs/armed", summary="Get armed in-memory OSINT IOCs")
async def get_armed_iocs(request: Request) -> dict:
    """
    Returns all IOCs armed at startup from MISP, abuse.ch Feodo, URLhaus.
    This is the primary real-time data source for the dashboard.
    """
    iocs = getattr(request.app.state, "armed_iocs", [])
    by_source = getattr(request.app.state, "armed_iocs_by_source", {})
    return {
        "total": len(iocs),
        "by_source": by_source,
        "iocs": iocs,
        "as_of": __import__('datetime').datetime.utcnow().isoformat() + "Z",
    }


@router.get("/iocs/armed/stats", summary="Armed IOC statistics by source")
async def get_armed_stats(request: Request) -> dict:
    iocs = getattr(request.app.state, "armed_iocs", [])
    by_type: dict = {}
    by_severity: dict = {}
    by_source: dict = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        s = ioc.get("severity", "medium")
        src = ioc.get("source", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
        by_severity[s] = by_severity.get(s, 0) + 1
        by_source[src] = by_source.get(src, 0) + 1
    return {"total": len(iocs), "by_type": by_type, "by_severity": by_severity, "by_source": by_source}


# ============================================================================
# Request/Response Models
# ============================================================================

class IOCCreateRequest(BaseModel):
    """Request body for creating a single IOC."""
    type: str = Field(..., description="IOC type: ipv4, ipv6, domain, url, md5, sha1, sha256, email, cve")
    value: str = Field(..., min_length=1, description="IOC value")
    source: str = Field(default="manual", description="Source identifier")
    source_url: str | None = Field(default=None)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: str = Field(default="medium", description="critical/high/medium/low/info")
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tlp: str = Field(default="TLP:GREEN")
    context: str | None = Field(default=None, description="Context text where the IOC was found")
    raw_text: str | None = Field(default=None)
    geo: dict[str, float] | None = Field(default=None, description='{"lat": 0.0, "lon": 0.0}')
    country_code: str | None = Field(default=None)
    enrichment: dict[str, Any] | None = Field(default=None)


class IOCBulkRequest(BaseModel):
    """Request body for bulk IOC ingestion."""
    iocs: list[IOCCreateRequest] = Field(..., min_length=1, max_length=10000)


class IOCResponse(BaseModel):
    """Single IOC response."""
    ioc_id: str
    type: str
    value: str
    source: str
    confidence: int
    severity: str
    tags: list[str]
    mitre_techniques: list[str]
    tlp: str
    first_seen: str | None = None
    last_seen: str | None = None
    is_active: bool = True
    geo: dict[str, float] | None = None
    country_code: str | None = None
    enrichment: dict[str, Any] | None = None


class IOCSearchResponse(BaseModel):
    """Paginated IOC search response with aggregations."""
    total: int
    hits: list[dict[str, Any]]
    aggregations: dict[str, Any]
    page: int
    page_size: int


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/iocs", status_code=201, summary="Create IOC")
async def create_ioc(request: IOCCreateRequest) -> dict[str, Any]:
    """
    Create a single IOC. Upserts by value (idempotent).
    Emits an 'ioc.created' event to the Redis event stream.
    """
    import hashlib
    es = ElasticsearchService()
    redis_svc = RedisService()

    # Generate deterministic IOC ID from type + value
    ioc_id = f"ioc-{hashlib.sha256(f'{request.type}:{request.value}'.encode()).hexdigest()[:16]}"

    now = datetime.utcnow().isoformat() + "Z"
    ioc_data = {
        "ioc_id": ioc_id,
        "type": request.type,
        "value": request.value.lower().strip(),
        "source": request.source,
        "source_url": request.source_url,
        "confidence": request.confidence,
        "severity": request.severity,
        "tags": request.tags,
        "mitre_techniques": request.mitre_techniques,
        "tlp": request.tlp,
        "context": request.context,
        "raw_text": request.raw_text,
        "first_seen": now,
        "last_seen": now,
        "is_active": True,
        "country_code": request.country_code,
        "enrichment": request.enrichment or {},
    }

    if request.geo:
        ioc_data["geo"] = request.geo

    doc_id = await es.index_ioc(ioc_data)

    # Publish real-time event
    await redis_svc.publish_event(
        stream="onyx:events:iocs",
        event_type="ioc.created",
        data={"ioc_id": doc_id, "type": request.type, "value": request.value, "severity": request.severity},
    )

    # Invalidate dashboard cache
    await redis_svc.cache_delete("dashboard:stats")

    return {"status": "created", "ioc_id": doc_id}


@router.post("/iocs/bulk", status_code=201, summary="Bulk create IOCs")
async def bulk_create_iocs(request: IOCBulkRequest) -> dict[str, Any]:
    """
    Bulk ingest IOCs (up to 10,000 per request).
    Uses Elasticsearch bulk API for high-throughput ingestion.
    """
    import hashlib
    es = ElasticsearchService()
    redis_svc = RedisService()
    now = datetime.utcnow().isoformat() + "Z"

    ioc_docs = []
    for ioc in request.iocs:
        ioc_id = f"ioc-{hashlib.sha256(f'{ioc.type}:{ioc.value}'.encode()).hexdigest()[:16]}"
        doc = {
            "ioc_id": ioc_id,
            "type": ioc.type,
            "value": ioc.value.lower().strip(),
            "source": ioc.source,
            "source_url": ioc.source_url,
            "confidence": ioc.confidence,
            "severity": ioc.severity,
            "tags": ioc.tags,
            "mitre_techniques": ioc.mitre_techniques,
            "tlp": ioc.tlp,
            "context": ioc.context,
            "raw_text": ioc.raw_text,
            "first_seen": now,
            "last_seen": now,
            "is_active": True,
            "country_code": ioc.country_code,
            "enrichment": ioc.enrichment or {},
        }
        if ioc.geo:
            doc["geo"] = ioc.geo
        ioc_docs.append(doc)

    count = await es.bulk_index_iocs(ioc_docs)

    # Publish bulk event
    await redis_svc.publish_event(
        stream="onyx:events:iocs",
        event_type="ioc.bulk_created",
        data={"count": count, "source": request.iocs[0].source if request.iocs else "unknown"},
    )

    await redis_svc.cache_delete("dashboard:stats")

    return {"status": "created", "count": count, "total_submitted": len(request.iocs)}


@router.get("/iocs/search", summary="Search IOCs")
async def search_iocs(
    q: str | None = Query(default=None, description="Full-text search query"),
    type: str | None = Query(default=None, description="IOC type filter"),
    severity: str | None = Query(default=None, description="Severity filter"),
    tags: str | None = Query(default=None, description="Comma-separated tag filter"),
    mitre: str | None = Query(default=None, description="Comma-separated ATT&CK technique filter"),
    date_from: datetime | None = Query(default=None, description="Start date filter"),
    date_to: datetime | None = Query(default=None, description="End date filter"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    sort: str = Query(default="last_seen", description="Sort field"),
    order: str = Query(default="desc", description="Sort order: asc/desc"),
) -> IOCSearchResponse:
    """
    Search IOCs with multi-dimensional filtering, pagination, and aggregations.
    Supports full-text search, type/severity/tag filters, and date ranges.
    """
    es = ElasticsearchService()

    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    mitre_list = [t.strip() for t in mitre.split(",")] if mitre else None

    result = await es.search_iocs(
        query=q,
        ioc_type=type,
        severity=severity,
        tags=tag_list,
        mitre_techniques=mitre_list,
        date_from=date_from,
        date_to=date_to,
        size=page_size,
        offset=(page - 1) * page_size,
        sort_field=sort,
        sort_order=order,
    )

    return IOCSearchResponse(
        total=result["total"],
        hits=result["hits"],
        aggregations=result["aggregations"],
        page=page,
        page_size=page_size,
    )


@router.get("/iocs/{ioc_id}", summary="Get IOC by ID")
async def get_ioc(ioc_id: str) -> dict[str, Any]:
    """Retrieve a single IOC by its ID."""
    es = ElasticsearchService()
    result = await es.get_ioc_by_id(ioc_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")
    return result


@router.get("/iocs/lookup/{value:path}", summary="Lookup IOC by value")
async def lookup_ioc(value: str) -> dict[str, Any]:
    """
    Exact-match lookup of an IOC by its raw value.
    Optimized for SIEM integration (sub-ms response on keyword field).
    """
    es = ElasticsearchService()
    redis_svc = RedisService()

    # Check cache first
    cache_key = f"ioc:lookup:{value.lower()}"
    cached = await redis_svc.cache_get(cache_key)
    if cached:
        return cached

    result = await es.get_ioc_by_value(value)
    if result is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {value}")

    # Cache for 5 minutes
    await redis_svc.cache_set(cache_key, result, ttl_seconds=300)

    return result
