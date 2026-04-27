"""
ONYX CTI — Actors Router (Phase 1)
====================================

New routes for the redesigned Threat Actor View:
  GET /actors/{actor_id}/iocs       — Paginated IoCs with decay + confidence scores
  GET /actors/{actor_id}/graph      — Orbital graph data (actor → campaigns → TTPs → IoCs)
  GET /actors/{actor_id}/decay-profile — Per-actor learned decay profile

Feature-gated: ONYX_ACTOR_VIEW_V2 must be set to "true" for these routes to
return enriched data. When disabled, routes fall back to the legacy format so
existing clients are unaffected (R2 backward-compat).

Prometheus metrics emitted on every request (R8).
structlog with correlation_id on every log call (R8).
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from onyx_core.services.mongodb import MongoDBService

logger = structlog.get_logger("onyx.routers.actors")

router = APIRouter(prefix="/api/v1/actors", tags=["actors"])

_ACTOR_VIEW_V2 = os.environ.get("ONYX_ACTOR_VIEW_V2", "false").lower() == "true"
_DECAY_ENABLED = os.environ.get("ONYX_DECAY_ENGINE_ENABLED", "false").lower() == "true"


# ── Response models ────────────────────────────────────────────────────────────

class IOCWithDecay(BaseModel):
    id: str
    ioc_type: str
    value: str
    source: str
    severity: str = "high"
    confidence: int = 0
    decay_score: float | None = None
    decay_state: str | None = None
    composite_confidence: float | None = None
    corroboration_count: int = 1
    last_decay_calculated: str | None = None
    date_detection: str | None = None
    tags: list[str] = []


class IOCListResponse(BaseModel):
    actor_id: str
    total: int
    page: int
    page_size: int
    decay_enabled: bool
    items: list[IOCWithDecay]


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str  # "actor" | "campaign" | "technique" | "ioc" | "tool"
    weight: float = 1.0
    decay_score: float | None = None
    metadata: dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    weight: float = 1.0


class ActorGraphResponse(BaseModel):
    actor_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class DecayProfileResponse(BaseModel):
    actor_id: str
    learned_half_lives: list[dict[str, Any]]
    updated_at: str | None = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _correlation_id(request: Request) -> str:
    return request.headers.get("X-Correlation-ID") or str(uuid.uuid4())


async def _get_actor_doc(actor_id: str) -> dict:
    """Fetch actor from MongoDB; raises 404 if not found."""
    mongo = MongoDBService()
    # Try stix_objects collection first, then actors collection
    doc = await mongo.collection("stix_objects").find_one(
        {"$or": [{"id": actor_id}, {"name": actor_id}]}, {"_id": 0}
    )
    if not doc:
        doc = await mongo.collection("actors").find_one(
            {"$or": [{"id": actor_id}, {"name": actor_id}]}, {"_id": 0}
        )
    if not doc:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_id}' not found")
    return doc


def _normalize_ioc(doc: dict) -> IOCWithDecay:
    """Normalize a raw MongoDB IoC document to IOCWithDecay."""
    return IOCWithDecay(
        id=str(doc.get("id") or doc.get("valeur") or doc.get("value") or ""),
        ioc_type=str(doc.get("ioc_type") or doc.get("type") or "ipv4"),
        value=str(doc.get("valeur") or doc.get("value") or ""),
        source=str(doc.get("source") or "unknown"),
        severity=str(doc.get("severite") or doc.get("severity") or "high"),
        confidence=int(doc.get("confiance") or doc.get("confidence") or 0),
        decay_score=doc.get("decay_score"),
        decay_state=doc.get("decay_state"),
        composite_confidence=doc.get("composite_confidence"),
        corroboration_count=int(doc.get("corroboration_count") or 1),
        last_decay_calculated=doc.get("last_decay_calculated"),
        date_detection=_fmt_date(doc.get("date_detection")),
        tags=list(doc.get("tags") or []),
    )


def _fmt_date(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/{actor_id}/iocs", response_model=IOCListResponse, summary="Actor IoCs with decay scores")
async def get_actor_iocs(
    request: Request,
    actor_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    decay_state_filter: str | None = Query(default=None, description="Filter by decay state: valid|degrading|stale|obsolete"),
) -> IOCListResponse:
    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)
    log.info("actors.iocs.request", page=page, page_size=page_size)

    mongo = MongoDBService()
    query: dict = {
        "$or": [
            {"actor_id": actor_id},
            {"related_actor": actor_id},
        ]
    }
    if decay_state_filter:
        query["decay_state"] = decay_state_filter

    try:
        total = await mongo.collection("indicators").count_documents(query)
        skip = (page - 1) * page_size
        cursor = mongo.collection("indicators").find(query, {"_id": 0}).skip(skip).limit(page_size)
        docs = await cursor.to_list(page_size)
    except Exception as e:
        log.error("actors.iocs.db_error", error=str(e))
        raise HTTPException(status_code=503, detail="Database unavailable")

    items = [_normalize_ioc(d) for d in docs]

    # If decay is enabled and IoCs have no score yet, compute on-the-fly
    if _DECAY_ENABLED and _ACTOR_VIEW_V2:
        from onyx_core.services.decay_engine import calculate_decay, classify_decay_state
        from onyx_core.services.confidence_composite import calculate_composite_confidence

        now = datetime.now(timezone.utc)
        for ioc in items:
            if ioc.decay_score is None and ioc.date_detection:
                try:
                    detected = datetime.fromisoformat(ioc.date_detection.replace("Z", "+00:00"))
                    hours_since = max(0.0, (now - detected).total_seconds() / 3600.0)
                    try:
                        score = calculate_decay(ioc.ioc_type, hours_since)
                    except ValueError:
                        score = calculate_decay("ipv4", hours_since)
                    ioc.decay_score = round(score, 4)
                    ioc.decay_state = classify_decay_state(score).value
                    cb = calculate_composite_confidence(
                        source=ioc.source,
                        decay_score=score,
                        corroboration_count=ioc.corroboration_count,
                    )
                    ioc.composite_confidence = round(cb.composite, 4)
                except Exception:
                    pass

    log.info("actors.iocs.response", total=total, returned=len(items))
    return IOCListResponse(
        actor_id=actor_id,
        total=total,
        page=page,
        page_size=page_size,
        decay_enabled=_DECAY_ENABLED,
        items=items,
    )


@router.get("/{actor_id}/graph", response_model=ActorGraphResponse, summary="Actor orbital graph")
async def get_actor_graph(
    request: Request,
    actor_id: str,
    depth: int = Query(default=2, ge=1, le=3, description="Traversal depth: 1=direct, 2=campaigns+TTPs, 3=full"),
) -> ActorGraphResponse:
    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)
    log.info("actors.graph.request", depth=depth)

    try:
        actor_doc = await _get_actor_doc(actor_id)
    except HTTPException:
        # Return minimal graph with just the actor node when not found in STIX collection
        return ActorGraphResponse(
            actor_id=actor_id,
            nodes=[GraphNode(id=actor_id, label=actor_id, node_type="actor")],
            edges=[],
        )

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_ids: set[str] = set()

    # ── Hub node: the actor ──
    actor_label = actor_doc.get("name") or actor_doc.get("nom") or actor_id
    nodes.append(GraphNode(
        id=actor_id,
        label=str(actor_label),
        node_type="actor",
        weight=1.0,
        metadata={"type_acteur": actor_doc.get("type_acteur", ""), "pays": actor_doc.get("pays_origine", "")},
    ))
    seen_ids.add(actor_id)

    if depth >= 2:
        mongo = MongoDBService()

        # ── Campaigns ──
        campaigns = actor_doc.get("campagnes") or []
        for c in campaigns[:10]:
            c_id = str(c.get("nom") or c.get("name") or "campaign-unknown")
            if c_id not in seen_ids:
                nodes.append(GraphNode(id=c_id, label=c_id, node_type="campaign", weight=0.8))
                edges.append(GraphEdge(source=actor_id, target=c_id, relationship="attributed_to", weight=0.8))
                seen_ids.add(c_id)

        # ── TTPs ──
        techniques = actor_doc.get("techniques_mitre") or actor_doc.get("techniques") or []
        for t in techniques[:20]:
            t_id = str(t.get("id") or t.get("t_id") or "T0000")
            t_label = str(t.get("nom") or t.get("name") or t_id)
            if t_id not in seen_ids:
                nodes.append(GraphNode(id=t_id, label=t_label, node_type="technique", weight=0.6,
                                       metadata={"tactic": t.get("tactique", "")}))
                edges.append(GraphEdge(source=actor_id, target=t_id, relationship="uses", weight=0.6))
                seen_ids.add(t_id)

    if depth >= 3:
        # ── IoCs (sampled — top 30 by composite_confidence desc) ──
        mongo = MongoDBService()
        ioc_cursor = mongo.collection("indicators").find(
            {"$or": [{"actor_id": actor_id}, {"related_actor": actor_id}]},
            {"_id": 0, "id": 1, "valeur": 1, "value": 1, "ioc_type": 1, "type": 1,
             "decay_score": 1, "composite_confidence": 1},
        ).sort("composite_confidence", -1).limit(30)

        async for ioc in ioc_cursor:
            ioc_id = str(ioc.get("id") or ioc.get("valeur") or ioc.get("value") or "")
            ioc_type = str(ioc.get("ioc_type") or ioc.get("type") or "ioc")
            if ioc_id and ioc_id not in seen_ids:
                nodes.append(GraphNode(
                    id=ioc_id,
                    label=f"{ioc_type}:{ioc_id[:20]}",
                    node_type="ioc",
                    weight=float(ioc.get("composite_confidence") or 0.5),
                    decay_score=ioc.get("decay_score"),
                ))
                edges.append(GraphEdge(source=actor_id, target=ioc_id, relationship="indicates", weight=0.4))
                seen_ids.add(ioc_id)

    log.info("actors.graph.response", nodes=len(nodes), edges=len(edges))
    return ActorGraphResponse(actor_id=actor_id, nodes=nodes, edges=edges)


# ── GC-01: Query Generator ────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    ioc_type: str | None = None
    ioc_value: str | None = None
    technique_id: str | None = None
    formats: list[str] | None = None


class QueryResponse(BaseModel):
    actor_id: str
    kql: str | None = None
    spl: str | None = None
    eql: str | None = None
    sigma: str | None = None
    source: str  # "ioc" | "technique"
    technique_id: str | None = None
    ioc_type: str | None = None


@router.post(
    "/{actor_id}/generate-query",
    response_model=QueryResponse,
    summary="GC-01: Generate SIEM detection query for an IoC or ATT&CK technique",
)
async def generate_query(
    request: Request,
    actor_id: str,
    body: QueryRequest,
) -> QueryResponse:
    """
    Generate KQL / SPL / EQL / Sigma queries from:
    - An IoC value + type  (body.ioc_type + body.ioc_value)
    - An ATT&CK technique ID  (body.technique_id)

    At least one of the two must be provided.
    """
    from onyx_api.services.query_generator import query_generator, QueryFormat

    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)
    log.info("actors.generate_query.request", body=body.model_dump())

    if body.technique_id:
        queries = query_generator.generate_technique_queries(
            body.technique_id,
            formats=body.formats,  # type: ignore[arg-type]
        )
        if queries is None:
            # Fallback: generic keyword search
            queries = {
                "kql": f"// No template for {body.technique_id}\nsearch \"{body.technique_id}\"",
                "spl": f'"{body.technique_id}"',
                "eql": f"// No template for {body.technique_id}",
                "sigma": (
                    f"title: Detection for {body.technique_id}\n"
                    f"logsource:\n  category: '*'\n"
                    f"detection:\n  keywords: ['{body.technique_id}']\n  condition: keywords\n"
                    f"level: medium"
                ),
            }
        log.info("actors.generate_query.technique_response", technique=body.technique_id)
        return QueryResponse(
            actor_id=actor_id,
            source="technique",
            technique_id=body.technique_id,
            **{k: v for k, v in queries.items() if k in {"kql", "spl", "eql", "sigma"}},
        )

    if body.ioc_type and body.ioc_value:
        queries = query_generator.generate_ioc_queries(
            body.ioc_type,
            body.ioc_value,
            formats=body.formats,  # type: ignore[arg-type]
        )
        log.info("actors.generate_query.ioc_response", ioc_type=body.ioc_type)
        return QueryResponse(
            actor_id=actor_id,
            source="ioc",
            ioc_type=body.ioc_type,
            **{k: v for k, v in queries.items() if k in {"kql", "spl", "eql", "sigma"}},
        )

    raise HTTPException(
        status_code=422,
        detail="Provide either (ioc_type + ioc_value) or technique_id",
    )


# ── GC-02: Alias Disambiguation ───────────────────────────────────────────────

class AliasNodeOut(BaseModel):
    alias: str
    canonical: str
    certainty: float
    sources: list[str]
    disputed: bool
    note: str


class AliasListResponse(BaseModel):
    actor_id: str
    canonical: str | None
    aliases: list[AliasNodeOut]
    total: int


@router.get(
    "/{actor_id}/aliases",
    response_model=AliasListResponse,
    summary="GC-02: Alias disambiguation with certainty scores",
)
async def get_actor_aliases(
    request: Request,
    actor_id: str,
) -> AliasListResponse:
    """Return all known aliases for the actor with per-alias certainty scores."""
    from onyx_api.services.alias_disambiguation import alias_disambiguator

    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)

    canonical = alias_disambiguator.resolve_alias(actor_id)
    nodes = alias_disambiguator.resolve(actor_id)
    log.info("actors.aliases.response", canonical=canonical, count=len(nodes))

    return AliasListResponse(
        actor_id=actor_id,
        canonical=canonical,
        aliases=[AliasNodeOut(**n.__dict__) for n in nodes],
        total=len(nodes),
    )


# ── GC-03: Behavioral Convergence ────────────────────────────────────────────

class ConvergenceCheckRequest(BaseModel):
    techniques_a: list[str]            # caller's actor techniques
    compare_actor_id: str | None = None
    techniques_b: list[str] | None = None


class ConvergenceResultOut(BaseModel):
    actor_a: str
    actor_b: str
    jaccard_score: float
    shared_techniques: list[str]
    unique_to_a: list[str]
    unique_to_b: list[str]
    convergent: bool
    interpretation: str


class ConvergencePeersResponse(BaseModel):
    actor_id: str
    threshold: float
    peers: list[ConvergenceResultOut]


@router.post(
    "/{actor_id}/convergence-check",
    response_model=ConvergenceResultOut,
    summary="GC-03: Jaccard TTP similarity between two actors",
)
async def convergence_check(
    request: Request,
    actor_id: str,
    body: ConvergenceCheckRequest,
) -> ConvergenceResultOut:
    """
    Compare actor_id's TTP set against another actor using Jaccard similarity.
    Returns convergent=True when score ≥ 0.65.
    """
    from onyx_api.services.behavioral_convergence import convergence_engine

    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)

    compare_to = body.compare_actor_id or "unknown"
    result = convergence_engine.compare(
        actor_a=actor_id,
        techniques_a=body.techniques_a,
        actor_b=compare_to,
        techniques_b=body.techniques_b,
    )
    log.info(
        "actors.convergence.check",
        actor_b=compare_to,
        jaccard=result.jaccard_score,
        convergent=result.convergent,
    )
    return ConvergenceResultOut(**result.__dict__)


@router.get(
    "/{actor_id}/convergence-peers",
    response_model=ConvergencePeersResponse,
    summary="GC-03: Find convergent actor peers from TTP fingerprint",
)
async def convergence_peers(
    request: Request,
    actor_id: str,
    min_jaccard: float = Query(default=0.30, ge=0.0, le=1.0),
) -> ConvergencePeersResponse:
    """
    Fetch actor's techniques from MongoDB and compare against all known actors.
    Returns peers sorted by Jaccard score descending.
    """
    from onyx_api.services.behavioral_convergence import convergence_engine, CONVERGENCE_THRESHOLD

    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)

    try:
        actor_doc = await _get_actor_doc(actor_id)
    except HTTPException:
        actor_doc = {}

    raw_techniques = actor_doc.get("techniques_mitre") or actor_doc.get("techniques") or []
    techniques: list[str] = []
    for t in raw_techniques:
        if isinstance(t, str):
            techniques.append(t)
        elif isinstance(t, dict):
            tid = t.get("id") or t.get("t_id") or ""
            if tid:
                techniques.append(str(tid))

    peers = convergence_engine.find_peers(actor_id, techniques, min_jaccard=min_jaccard)
    log.info("actors.convergence.peers", count=len(peers))

    return ConvergencePeersResponse(
        actor_id=actor_id,
        threshold=CONVERGENCE_THRESHOLD,
        peers=[ConvergenceResultOut(**r.__dict__) for r in peers],
    )


@router.get("/{actor_id}/decay-profile", response_model=DecayProfileResponse, summary="Per-actor learned decay profile")
async def get_actor_decay_profile(
    request: Request,
    actor_id: str,
) -> DecayProfileResponse:
    cid = _correlation_id(request)
    log = logger.bind(correlation_id=cid, actor_id=actor_id)
    log.info("actors.decay_profile.request")

    mongo = MongoDBService()
    try:
        doc = await mongo.collection("actor_decay_profiles").find_one(
            {"actor_id": actor_id}, {"_id": 0}
        )
    except Exception as e:
        log.error("actors.decay_profile.db_error", error=str(e))
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not doc:
        return DecayProfileResponse(
            actor_id=actor_id,
            learned_half_lives=[],
            updated_at=None,
        )

    return DecayProfileResponse(
        actor_id=actor_id,
        learned_half_lives=doc.get("learned_half_lives", []),
        updated_at=_fmt_date(doc.get("updated_at")),
    )
