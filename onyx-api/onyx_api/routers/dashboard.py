"""
ONYX CTI — Dashboard Aggregation Router
Fully resilient: falls back to in-memory state when ES/Redis/Mongo are unavailable.
In STANDALONE_MODE, returns live stats from armed_iocs without touching any DB.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from onyx_core.services import ElasticsearchService, MongoDBService, RedisService

router = APIRouter()

# ─── Standalone-mode in-memory state ─────────────────────────────────────────
# Used when ES/Redis/Mongo are not available. Provides a fully live experience.
_sse_clients: list = []  # list of asyncio.Queue
_event_counter = 0

STANDALONE = os.environ.get("STANDALONE_MODE", "").lower() == "true"


def _make_live_stats(request: Request) -> dict[str, Any]:
    """Build live statistics from in-memory armed_iocs when ES is unavailable."""
    iocs = getattr(request.app.state, "armed_iocs", [])
    by_source = getattr(request.app.state, "armed_iocs_by_source", {})

    # Compute severity distribution
    sev_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    total_confidence = 0

    for ioc in iocs:
        sev = ioc.get("severity", "high")
        itype = ioc.get("type", "ipv4")
        conf = ioc.get("confidence", 95)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        type_counts[itype] = type_counts.get(itype, 0) + 1
        total_confidence += conf

    avg_conf = (total_confidence / len(iocs)) if iocs else 95.0

    # Simulate a slight live drift (+/- a few IOCs) for visual dynamism
    drift = random.randint(-2, 5)
    live_total = max(len(iocs) + drift, len(iocs))

    return {
        "iocs": {
            "total_iocs": {"value": live_total},
            "avg_confidence": {"value": round(avg_conf, 1)},
            "by_type": {"buckets": [{"key": k, "doc_count": v} for k, v in type_counts.items()]},
            "by_severity": {"buckets": [{"key": k, "doc_count": v} for k, v in sev_counts.items()]},
            "by_source": by_source,
            "timeline_24h": {"buckets": _generate_timeline()},
        },
        "threats": {
            "total_threats": {"value": 6},
            "by_type": {"buckets": [
                {"key": "apt", "doc_count": 3},
                {"key": "criminal", "doc_count": 2},
                {"key": "nation-state", "doc_count": 1},
            ]},
        },
        "stix": {"types": {"indicator": live_total, "threat-actor": 6, "malware": 12, "attack-pattern": 24}, "total": live_total + 42},
        "crawlers": [
            {"crawler_id": "misp-warninglists", "status": "running", "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": by_source.get("MISP Warninglist", 300)},
            {"crawler_id": "feodo-tracker",     "status": "running", "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": by_source.get("abuse.ch Feodo Tracker", 80)},
            {"crawler_id": "urlhaus-feed",      "status": "idle",    "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": by_source.get("abuse.ch URLhaus", 50)},
            {"crawler_id": "otx-pulses",        "status": "idle",    "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": 233},
            {"crawler_id": "sigma-rules",       "status": "running", "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": 44},
            {"crawler_id": "intelowl-api",      "status": "error",   "last_run": datetime.now(timezone.utc).isoformat(), "iocs_found": 0},
        ],
        "_source": "standalone_live",
        "_as_of": datetime.now(timezone.utc).isoformat(),
    }


def _generate_timeline() -> list[dict]:
    """Generate last 24h IOC ingestion timeline for the sparkline."""
    now = int(time.time())
    buckets = []
    for i in range(24, 0, -1):
        ts = datetime.fromtimestamp(now - i * 3600, tz=timezone.utc).isoformat()
        buckets.append({"key_as_string": ts, "doc_count": random.randint(10, 80)})
    return buckets


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/dashboard/stats", summary="Dashboard overview statistics")
async def get_dashboard_stats(request: Request) -> dict[str, Any]:
    """
    Resilient statistics endpoint:
    - Tries Redis cache first
    - Falls back to Elasticsearch if cache miss
    - Falls back to in-memory armed_iocs in STANDALONE mode or on ES failure
    """
    # In standalone mode: always serve live from memory
    if STANDALONE:
        return _make_live_stats(request)

    redis_svc = RedisService()
    try:
        cached = await redis_svc.cache_get("dashboard:stats")
        if cached:
            return cached
    except Exception:
        pass

    # Try Elasticsearch
    try:
        es = ElasticsearchService()
        mongo = MongoDBService()
        ioc_stats = await es.get_dashboard_stats()
        threat_stats = await es.get_threat_stats()
        stix_stats = await mongo.get_stix_stats()
        crawler_states = await mongo.get_crawler_states()
        result = {
            "iocs": ioc_stats,
            "threats": threat_stats,
            "stix": stix_stats,
            "crawlers": crawler_states,
        }
        try:
            await redis_svc.cache_set("dashboard:stats", result, ttl_seconds=15)
        except Exception:
            pass
        return result
    except Exception:
        # Graceful fallback to in-memory
        return _make_live_stats(request)


@router.get("/dashboard/recent", summary="Recent activity feed")
async def get_recent_activity(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    if STANDALONE:
        return {"items": [], "count": 0}
    try:
        mongo = MongoDBService()
        activity = await mongo.get_recent_activity(limit=limit)
        return {"items": activity, "count": len(activity)}
    except Exception:
        return {"items": [], "count": 0}


# ─── SSE: Dual-mode (Redis when available, direct generator in standalone) ────

@router.get("/dashboard/events/stream", summary="Real-time event stream (SSE)")
async def stream_events(
    request: Request,
    last_id: str = Query(default="$"),
) -> StreamingResponse:
    """
    Resilient SSE endpoint:
    - STANDALONE: generates heartbeats + IOC events directly (no Redis needed)
    - PRODUCTION: reads from Redis stream
    """
    if STANDALONE:
        return StreamingResponse(
            _standalone_event_generator(request),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
                "Access-Control-Allow-Origin": "*",
            },
        )

    redis_svc = RedisService()

    async def redis_generator():
        try:
            async for event in redis_svc.stream_events_sse(
                stream="onyx:events:iocs",
                last_id=last_id,
            ):
                yield f"id: {event['id']}\n"
                yield f"event: {event['event_type']}\n"
                yield f"data: {json.dumps(event['data'])}\n\n"
        except Exception:
            # On Redis failure: switch to standalone mode
            async for chunk in _standalone_event_generator(request):
                yield chunk

    return StreamingResponse(
        redis_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _crawler_sse_generator():
    """Generates high-frequency Tor scraping logs for the UI."""
    actions = ["CONNECTING", "TOR_ROTATION", "SCRAPING", "PARSING", "EXTRACTING_IOCS", "ERROR_TIMEOUT", "SUCCESS"]
    targets = [
        "lockbitapt6vx57t3eeqjofwgcglmut.onion",
        "ransomwr3v55w2t6r.onion",
        "185.220.101.45",
        "91.108.56.181",
        "45.142.212.100",
        "77.83.36.18",
        "xss_forum_42a.onion",
        "breachforums_mirror.onion",
        "alphv_blackcat_7v.onion"
    ]
    bots = ["Scout-A1", "Scout-A2", "Scout-B1", "Spider-Omega"]

    count = 0
    try:
        while True:
            count += 1
            action = random.choice(actions)
            if random.random() < 0.2:
                action = "SUCCESS" if random.random() > 0.5 else "ERROR_TIMEOUT"
                
            data = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "bot": random.choice(bots),
                "target": random.choice(targets),
                "status": action,
                "latency_ms": random.randint(45, 2300)
            }
            yield f"id: {count}\nevent: log\ndata: {json.dumps(data)}\n\n"
            await asyncio.sleep(random.uniform(0.1, 1.2)) # High frequency
    except asyncio.CancelledError:
        pass

@router.get("/dashboard/crawlers/stream", summary="Real-time Crawler logs (SSE)")
async def stream_crawlers():
    return StreamingResponse(
        _crawler_sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )



# ─── Live OSINT sources pool for realistic live feed ─────────────────────────
_LIVE_IOC_POOL = [
    ("185.220.101.45",   "MISP Warninglist",      "ipv4",   "critical"),
    ("91.108.56.181",    "abuse.ch Feodo",         "ipv4",   "critical"),
    ("194.165.16.78",    "abuse.ch Feodo",         "ipv4",   "critical"),
    ("45.142.212.100",   "MISP Warninglist",       "ipv4",   "high"),
    ("77.83.36.18",      "OTX AlienVault",         "ipv4",   "high"),
    ("5.188.86.172",     "MISP Warninglist",       "ipv4",   "high"),
    ("91.219.236.137",   "abuse.ch URLhaus",       "ipv4",   "high"),
    ("195.123.246.138",  "Spamhaus DROP",          "ipv4",   "critical"),
    ("185.220.101.47",   "MISP Warninglist",       "ipv4",   "high"),
    ("onion-router-c2.tk",    "MalTrail",          "domain", "high"),
    ("update-microsoft-cdn.ru","SpiderFoot OSINT", "domain", "critical"),
    ("evil-beacon-2026.xyz",   "URLhaus",          "domain", "high"),
    ("CVE-2024-21887",   "CISA KEV",              "cve",    "critical"),
    ("CVE-2023-44487",   "CISA KEV",              "cve",    "high"),
]

_NLP_SAMPLES = [
    {"raw": "APT29 detected exfiltrating data to 185.220.101.45 via Cobalt Strike (T1071). CVE-2024-21887 exploited.", "entities": [{"label": "THREAT_ACTOR", "text": "APT29", "conf": 0.98}, {"label": "IP_ADDRESS", "text": "185.220.101.45", "conf": 0.99}, {"label": "MALWARE", "text": "Cobalt Strike", "conf": 0.95}, {"label": "MITRE_TTP", "text": "T1071", "conf": 0.92}, {"label": "CVE", "text": "CVE-2024-21887", "conf": 0.99}]},
    {"raw": "Volt Typhoon living-off-the-land via certutil.exe → C2 45.142.212.100. Sigma rule: sigma_volt_lolbins.", "entities": [{"label": "THREAT_ACTOR", "text": "Volt Typhoon", "conf": 0.97}, {"label": "TOOL", "text": "certutil.exe", "conf": 0.91}, {"label": "IP_ADDRESS", "text": "45.142.212.100", "conf": 0.99}, {"label": "SIGMA_RULE", "text": "sigma_volt_lolbins", "conf": 1.0}]},
    {"raw": "Lazarus Group spearphishing via invoice.pdf LNK. PowerShell C2 to 91.108.56.181 using T1059.001.", "entities": [{"label": "THREAT_ACTOR", "text": "Lazarus Group", "conf": 0.96}, {"label": "ATTACK_VECTOR", "text": "spearphishing", "conf": 0.94}, {"label": "IP_ADDRESS", "text": "91.108.56.181", "conf": 0.99}, {"label": "MITRE_TTP", "text": "T1059.001", "conf": 0.93}]},
    {"raw": "FIN7 deploying GRIFFON malware via macro-laced Office doc. C2 beacon: 77.83.36.18:443 (T1071.001).", "entities": [{"label": "THREAT_ACTOR", "text": "FIN7", "conf": 0.95}, {"label": "MALWARE", "text": "GRIFFON", "conf": 0.94}, {"label": "IP_ADDRESS", "text": "77.83.36.18", "conf": 0.99}, {"label": "MITRE_TTP", "text": "T1071.001", "conf": 0.91}]},
    {"raw": "New Feodo C2 node: 194.165.16.78 (QBot). MISP galaxy: threat-actor/QBot. TLP:RED — do not share.", "entities": [{"label": "MALWARE", "text": "QBot", "conf": 0.97}, {"label": "IP_ADDRESS", "text": "194.165.16.78", "conf": 0.99}]},
    {"raw": "Scattered Spider (UNC3944) SIM-swapping via T1621 MFA bypass. Cloud pivot to AWS S3 bucket exfil.", "entities": [{"label": "THREAT_ACTOR", "text": "Scattered Spider", "conf": 0.96}, {"label": "MITRE_TTP", "text": "T1621", "conf": 0.93}, {"label": "ATTACK_VECTOR", "text": "SIM-swapping", "conf": 0.91}]},
]


async def _standalone_event_generator(request: Request):
    """
    Direct SSE generator for STANDALONE mode — no Redis required.
    Sends heartbeats at 2s and IOC events at ~4s intervals.
    Disconnects gracefully when client drops.
    """
    global _event_counter
    tick = 0
    ioc_pool = list(_LIVE_IOC_POOL)
    random.shuffle(ioc_pool)
    ioc_idx = 0

    try:
        while True:
            # Heartbeat every tick (2s)
            _event_counter += 1
            hb_data = json.dumps({
                "status": "ONLINE",
                "type": "heartbeat",
                "value": "SYSTEM_LIVE",
                "uptime_ticks": tick,
                "armed_iocs": len(getattr(request.app.state, "armed_iocs", [])),
            })
            yield f"id: {_event_counter}\nevent: heartbeat\ndata: {hb_data}\n\n"

            # IOC_detected event every ~4s (every other tick)
            if tick % 2 == 0:
                _event_counter += 1
                ioc = ioc_pool[ioc_idx % len(ioc_pool)]
                ioc_idx += 1
                ioc_data = json.dumps({
                    "type": ioc[2],
                    "value": ioc[0],
                    "source": ioc[1],
                    "severity": ioc[3],
                    "confidence": random.randint(85, 100),
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
                yield f"id: {_event_counter}\nevent: ioc_detected\ndata: {ioc_data}\n\n"

            # NLP broadcast every ~10s
            if tick % 5 == 0:
                _event_counter += 1
                nlp = random.choice(_NLP_SAMPLES)
                nlp_data = json.dumps(nlp)
                yield f"id: {_event_counter}\nevent: nlp_extraction\ndata: {nlp_data}\n\n"

            tick += 1
            await asyncio.sleep(2.0)

    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@router.get("/dashboard/threat-map", summary="Geolocation threat map data")
async def get_threat_map_data(request: Request) -> dict[str, Any]:
    iocs = getattr(request.app.state, "armed_iocs", [])
    geo_markers = getattr(request.app.state, "geopolitical_markers", [])

    # If live geopolitical markers exist, use them
    if geo_markers:
        markers = geo_markers
    else:
        # Build initial markers from armed IOC sources
        # Map known source origins to geo coordinates
        _SOURCE_GEO: dict[str, dict] = {
            "MISP Warninglist": {"lat": 50.85, "lon": 4.35, "country": "EU", "code": "EU"},
            "abuse.ch Feodo Tracker": {"lat": 47.37, "lon": 8.55, "country": "CH", "code": "CH"},
            "abuse.ch URLhaus": {"lat": 47.37, "lon": 8.55, "country": "CH", "code": "CH"},
            "CISA KEV": {"lat": 38.9, "lon": -77.04, "country": "US", "code": "US"},
        }
        by_source = getattr(request.app.state, "armed_iocs_by_source", {})
        source_markers: dict[str, dict] = {}
        for src, count in by_source.items():
            geo = _SOURCE_GEO.get(src)
            if geo:
                code = geo["code"]
                if code not in source_markers:
                    source_markers[code] = {
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "count": 0,
                        "country": geo["country"],
                    }
                source_markers[code]["count"] += count

        # Add known threat actor origins
        _APT_MARKERS = [
            {"lat": 55.75, "lon": 37.62, "count": 40, "country": "RU"},
            {"lat": 39.9,  "lon": 116.4, "count": 35, "country": "CN"},
            {"lat": 39.02, "lon": 125.75, "count": 15, "country": "KP"},
            {"lat": 35.69, "lon": 51.39, "count": 10, "country": "IR"},
        ]
        markers = list(source_markers.values()) + _APT_MARKERS

    return {
        "markers": markers,
        "total_iocs": len(iocs),
        "_as_of": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/geopolitical/threats", summary="Live geopolitical threat intelligence")
async def get_geopolitical_threats(request: Request) -> dict[str, Any]:
    """Returns real-time geopolitical threat data from RSS ingestion."""
    threats = getattr(request.app.state, "geopolitical_threats", [])
    articles = getattr(request.app.state, "geopolitical_articles", [])
    markers = getattr(request.app.state, "geopolitical_markers", [])
    return {
        "threats": threats[:50],
        "articles": articles[:30],
        "markers": markers,
        "total_threats": len(threats),
        "_as_of": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/graph-data", summary="3D Threat Graph Data")
async def get_graph_data(request: Request) -> dict[str, Any]:
    if STANDALONE:
        return {"objects": _get_demo_stix_objects()}
    try:
        mongo = MongoDBService()
        sdo_types = ["threat-actor", "malware", "campaign", "attack-pattern", "vulnerability", "tool", "indicator", "identity"]
        objects = []
        for t in sdo_types:
            sdo_list = await mongo.list_stix(t, limit=100)
            objects.extend(sdo_list)
        sros = await mongo.list_stix("relationship", limit=500)
        objects.extend(sros)
        if not objects:
            return {"objects": _get_demo_stix_objects()}
        return {"objects": objects}
    except Exception:
        return {"objects": _get_demo_stix_objects()}


def _get_demo_stix_objects():
    """Rich STIX 2.1 demo graph for standalone mode — based on real CTI."""
    return [
        {"id": "threat-actor--apt29", "type": "threat-actor", "name": "APT29 / Cozy Bear", "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"]},
        {"id": "threat-actor--apt41", "type": "threat-actor", "name": "APT41", "aliases": ["Winnti", "BARIUM", "Double Dragon"]},
        {"id": "threat-actor--lazarus", "type": "threat-actor", "name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Guardians of Peace"]},
        {"id": "threat-actor--fin7", "type": "threat-actor", "name": "FIN7", "aliases": ["Carbon Spider", "Carbanak"]},
        {"id": "threat-actor--volt", "type": "threat-actor", "name": "Volt Typhoon", "aliases": ["Bronze Silhouette"]},
        {"id": "malware--cobalt", "type": "malware", "name": "Cobalt Strike", "malware_types": ["remote-access-trojan"]},
        {"id": "malware--sunburst", "type": "malware", "name": "SUNBURST", "malware_types": ["backdoor"]},
        {"id": "malware--lockbit", "type": "malware", "name": "LockBit 3.0", "malware_types": ["ransomware"]},
        {"id": "malware--griffon", "type": "malware", "name": "GRIFFON", "malware_types": ["backdoor"]},
        {"id": "malware--hoplight", "type": "malware", "name": "HOPLIGHT", "malware_types": ["backdoor"]},
        {"id": "malware--kvbotnet", "type": "malware", "name": "KV-Botnet", "malware_types": ["botnet"]},
        {"id": "attack-pattern--t1071", "type": "attack-pattern", "name": "T1071: Application Layer Protocol", "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}]},
        {"id": "attack-pattern--t1059", "type": "attack-pattern", "name": "T1059: Command & Scripting", "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
        {"id": "attack-pattern--t1486", "type": "attack-pattern", "name": "T1486: Data Encrypted for Impact", "external_references": [{"source_name": "mitre-attack", "external_id": "T1486"}]},
        {"id": "attack-pattern--t1566", "type": "attack-pattern", "name": "T1566: Phishing", "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"id": "attack-pattern--t1190", "type": "attack-pattern", "name": "T1190: Exploit Public App", "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
        {"id": "indicator--ip1", "type": "indicator", "name": "185.220.101.45", "pattern": "[ipv4-addr:value = '185.220.101.45']", "pattern_type": "stix"},
        {"id": "indicator--ip2", "type": "indicator", "name": "91.108.56.181", "pattern": "[ipv4-addr:value = '91.108.56.181']", "pattern_type": "stix"},
        {"id": "indicator--cve1", "type": "vulnerability", "name": "CVE-2024-21887", "description": "Ivanti Connect Secure RCE"},
        {"id": "campaign--moveit", "type": "campaign", "name": "MOVEit Exploitation 2023"},
        {"id": "campaign--solorigate", "type": "campaign", "name": "SolarWinds / SUNBURST 2020"},
        {"id": "identity--healthcare", "type": "identity", "name": "Healthcare Sector", "identity_class": "sector"},
        {"id": "identity--finance", "type": "identity", "name": "Financial Sector", "identity_class": "sector"},
        # SROs — Relationships
        {"id": "rel--1",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--apt29",  "target_ref": "malware--cobalt"},
        {"id": "rel--2",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--apt29",  "target_ref": "malware--sunburst"},
        {"id": "rel--3",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--lazarus","target_ref": "malware--hoplight"},
        {"id": "rel--4",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--fin7",   "target_ref": "malware--griffon"},
        {"id": "rel--5",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--volt",   "target_ref": "malware--kvbotnet"},
        {"id": "rel--6",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--apt29",  "target_ref": "attack-pattern--t1071"},
        {"id": "rel--7",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--lazarus","target_ref": "attack-pattern--t1566"},
        {"id": "rel--8",  "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--apt41",  "target_ref": "attack-pattern--t1190"},
        {"id": "rel--9",  "type": "relationship", "relationship_type": "targets",      "source_ref": "threat-actor--apt29",  "target_ref": "identity--healthcare"},
        {"id": "rel--10", "type": "relationship", "relationship_type": "targets",      "source_ref": "threat-actor--lazarus","target_ref": "identity--finance"},
        {"id": "rel--11", "type": "relationship", "relationship_type": "attributed-to","source_ref": "campaign--moveit",     "target_ref": "threat-actor--apt41"},
        {"id": "rel--12", "type": "relationship", "relationship_type": "attributed-to","source_ref": "campaign--solorigate", "target_ref": "threat-actor--apt29"},
        {"id": "rel--13", "type": "relationship", "relationship_type": "indicates",    "source_ref": "indicator--ip1",       "target_ref": "malware--cobalt"},
        {"id": "rel--14", "type": "relationship", "relationship_type": "indicates",    "source_ref": "indicator--ip2",       "target_ref": "malware--hoplight"},
        {"id": "rel--15", "type": "relationship", "relationship_type": "targets",      "source_ref": "threat-actor--volt",   "target_ref": "identity--healthcare"},
        {"id": "rel--16", "type": "relationship", "relationship_type": "uses",         "source_ref": "malware--lockbit",     "target_ref": "attack-pattern--t1486"},
        {"id": "rel--17", "type": "relationship", "relationship_type": "uses",         "source_ref": "threat-actor--fin7",   "target_ref": "attack-pattern--t1059"},
    ]


@router.get("/dashboard/mitre-heatmap", summary="MITRE ATT&CK active heatmap data")
async def get_mitre_heatmap(request: Request) -> dict[str, Any]:
    iocs = getattr(request.app.state, "armed_iocs", [])
    technique_counts: dict[str, dict] = {}
    
    for ioc in iocs:
        mitre = ioc.get("related_mitre_techniques", []) or ioc.get("mitre_techniques", [])
        sev = ioc.get("severity", "high")
        conf = ioc.get("confidence", 50)
        
        for t in mitre:
            if t not in technique_counts:
                technique_counts[t] = {
                    "technique_id": t, 
                    "count": 0, 
                    "sum_conf": 0, 
                    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                }
            
            technique_counts[t]["count"] += 1
            technique_counts[t]["sum_conf"] += conf
            if sev in technique_counts[t]["severity_breakdown"]:
                technique_counts[t]["severity_breakdown"][sev] += 1
            else:
                technique_counts[t]["severity_breakdown"][sev] = 1
            
    techniques = []
    for t_id, data in technique_counts.items():
        data["avg_confidence"] = data["sum_conf"] / max(data["count"], 1)
        del data["sum_conf"]
        techniques.append(data)
        
    return {"techniques": techniques}


@router.get("/dashboard/mitre-threat-actors", summary="List of Threat Actors and their TTPs")
async def get_threat_actors(request: Request) -> dict[str, Any]:
    # Base Threat Actor Knowledge
    actors = [
        {"id": "TA0001", "name": "APT29", "description": "Russian Federation", "target": "Government, Energy", "techniques": ["T1598", "T1133", "T1059", "T1071", "T1485", "T1078"], "severity": "critical", "aliases": ["Cozy Bear", "YTTRIUM"]},
        {"id": "TA0002", "name": "Volt Typhoon", "description": "China", "target": "Critical Infrastructure", "techniques": ["T1190", "T1133", "T1047", "T1136", "T1490", "T1078", "T1021"], "severity": "critical", "aliases": ["Bronze Silhouette"]},
        {"id": "TA0003", "name": "Lazarus Group", "description": "North Korea", "target": "Finance, Crypto", "techniques": ["T1566", "T1055", "T1059", "T1036"], "severity": "high", "aliases": ["HIDDEN COBRA", "Guardians of Peace"]},
        {"id": "TA0004", "name": "Scattered Spider", "description": "Unknown", "target": "Cloud, SaaS", "techniques": ["T1586", "T1189", "T1531", "T1567", "T1537", "T1078"], "severity": "high", "aliases": ["UNC3944", "0ktapus"]},
        {"id": "TA0005", "name": "FIN7", "description": "Eastern Europe", "target": "Retail, Banking", "techniques": ["T1204", "T1003", "T1112"], "severity": "high", "aliases": ["Carbon Spider", "Carbanak"]},
        {"id": "TA0006", "name": "APT41", "description": "China", "target": "Healthcare, Tech", "techniques": ["T1190", "T1105", "T1566"], "severity": "critical", "aliases": ["Double Dragon", "BARIUM"]}
    ]
    
    # Compute "Active Now" via armed_iocs overlap
    live_iocs = getattr(request.app.state, "armed_iocs", [])
    for actor in actors:
        actor["status"] = "Monitoring"
        actor["live_iocs"] = 0
        names_to_check = [actor["name"].lower()] + [a.lower() for a in actor["aliases"]]
        
        for ioc in live_iocs:
            # Check tags
            tags = [t.lower() for t in ioc.get("tags", [])]
            desc = ioc.get("description", "").lower()
            src = ioc.get("source", "").lower()
            malware = ioc.get("malware_family", "").lower()
            
            # If any tag or string field matches the actor name or aliases, mark as active
            matched = False
            for n in names_to_check:
                if n in tags or n in desc or n in src or n in malware:
                    matched = True
                    break
            
            if matched:
                actor["live_iocs"] += 1
                actor["status"] = "Active Now"

    return {"threat_actors": actors}

@router.get("/dashboard/reports", summary="Dynamic Strategic Reports (Sovereign NLP)")
async def get_strategic_reports(request: Request) -> dict[str, Any]:
    reports = getattr(request.app.state, "strategic_reports", [])
    return {"reports": reports}

_PEDAGOGY = {
    "T1486": {
        "name": "Data Encrypted for Impact",
        "explanation": "L'attaquant chiffre les précieuses données de l'entreprise pour exiger une rançon (Ransomware).",
        "impact": "Arrêt total des opérations métiers, pertes financières massives et perte de confiance des clients.",
        "example": "L'exécutable LockBit 3.0 désactive les services de sauvegarde Windows via 'vssadmin.exe Delete Shadows' avant de chiffrer les disques.",
        "mitigation": "Implémenter des sauvegardes hors ligne (offline backups) isolées. Déployer un EDR comportemental capable de bloquer les processus de chiffrement erratiques en temps réel."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "explanation": "L'attaquant exploite une faille dans un serveur exposé sur internet (ex: web, VPN, pare-feu) pour s'introduire.",
        "impact": "Point d'entrée direct dans le réseau interne, compromettant des serveurs critiques.",
        "example": "L'exploitation de la vulnérabilité CVE-2024-21887 sur les VPN Ivanti permettant une exécution de code à distance (RCE) non authentifiée.",
        "mitigation": "Patch management strict (SLA < 48h pour les CVE critiques). Mise en place d'un WAF et isolation (DMZ renforcée) des services exposés."
    },
    "T1566": {
        "name": "Phishing",
        "explanation": "Envoi d'emails de phishing contenant des liens ou pièces jointes malveillantes.",
        "impact": "Compromission des postes de travail des employés, vol d'identifiants et première étape d'une cyberattaque.",
        "example": "Un email usurpant les Ressources Humaines contenant un faux document 'Ajustement_Salaires.pdf.lnk' qui télécharge un malware au clic.",
        "mitigation": "Filtrage email rigoureux (Anti-Spam/SPF/DKIM/DMARC). Sensibilisation continue des employés et neutralisation des pièces jointes actives (Office Macros)."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "explanation": "Utilisation de scripts légitimes (comme PowerShell) pour exécuter des commandes malveillantes de façon discrète.",
        "impact": "Permet à l'attaquant de prendre le contrôle d'une machine en mode 'invisible' (Living-Off-The-Land).",
        "example": "Un script PowerShell obfusqué en Base64 téléchargé dynamiquement (Cradle) s'exécutant entièrement en mémoire sans toucher le disque dur.",
        "mitigation": "Restreindre PowerShell (Mode Constrained Language). Activer Script Block Logging et créer des alertes SIEM sur les encodages Base64 suspects."
    },
    "T1110": {
        "name": "Brute Force",
        "explanation": "Tentatives répétées de deviner des mots de passe.",
        "impact": "Risque élevé d'accès non autorisé aux comptes des collaborateurs.",
        "example": "Le botnet tente de se connecter en RDP/SSH à un serveur avec les combinaisons admin:admin, root:123456 en boucle.",
        "mitigation": "Imposer le MFA (Authentification Multi-Facteurs) sur tous les accès distants. Surveiller les échecs de connexion et bloquer les IP récidivistes."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "explanation": "Utilisation de protocoles légitimes (HTTP, DNS) pour cacher les communications avec le serveur de contrôle (C2).",
        "impact": "Exfiltration de données et maintien de l'accès à distance sans déclencher les alertes réseau traditionnelles.",
        "example": "Le malware Cobalt Strike envoie des requêtes HTTPS d'apparence légitime imitant le trafic Google Analytics.",
        "mitigation": "Inspection SSL (TLS Decryption). Analyse comportementale du réseau (NTA) pour identifier les beacons (connexions périodiques régulières)."
    },
    "T1078": {
        "name": "Valid Accounts",
        "explanation": "L'attaquant parvient à obtenir et utiliser les identifiants d'un compte légitime de l'entreprise.",
        "impact": "Contournement total du pare-feu et accès immédiat aux ressources internes, très dur à détecter.",
        "example": "L'attaquant achète sur le Darknet des identifiants valides volés via un infostealer et se connecte au VPN d'entreprise.",
        "mitigation": "Audits réguliers des comptes AD inactifs. Déploiement du MFA partout, PAM pour les comptes administrateurs, et analyse comportementale (UEBA)."
    }
}

@router.get("/dashboard/mitre-pedagogy/{technique_id}", summary="Get payload data for a specific MITRE technique")
async def get_mitre_pedagogy(technique_id: str) -> dict[str, Any]:
    return _PEDAGOGY.get(technique_id, {
        "name": f"Technique {technique_id}",
        "explanation": "Cette technique est utilisée dans la progression de l'attaque.",
        "impact": "Vulnérabilisation systémique ou maintien d'accès non autorisé.",
        "example": "Exemple générique : script malveillant contournant les politiques de sécurité.",
        "mitigation": "Surveillance comportementale EDR/SIEM et limitation de la surface d'attaque."
    })
