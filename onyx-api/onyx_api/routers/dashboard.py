"""
ONYX CTI — Dashboard Aggregation Router
Provides pre-computed statistics and real-time metrics for the Next.js dashboard.
All endpoints are optimized with Redis caching for sub-50ms response times.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from onyx_core.services import ElasticsearchService, MongoDBService, RedisService

router = APIRouter()


@router.get("/dashboard/stats", summary="Dashboard overview statistics")
async def get_dashboard_stats() -> dict[str, Any]:
    """
    Aggregated statistics for the main dashboard view.
    Includes IOC counts, severity distribution, top sources, timeline, and threat stats.
    Cached for 30 seconds for real-time freshness without overloading ES.
    """
    redis_svc = RedisService()

    # Check cache (30s TTL for near-real-time without hammering ES)
    cached = await redis_svc.cache_get("dashboard:stats")
    if cached:
        return cached

    es = ElasticsearchService()
    mongo = MongoDBService()

    # Parallel aggregation from both stores
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

    await redis_svc.cache_set("dashboard:stats", result, ttl_seconds=30)
    return result


@router.get("/dashboard/recent", summary="Recent activity feed")
async def get_recent_activity(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """
    Get the most recent STIX object modifications for the activity feed widget.
    """
    mongo = MongoDBService()
    activity = await mongo.get_recent_activity(limit=limit)
    return {"items": activity, "count": len(activity)}


@router.get("/dashboard/events/stream", summary="Real-time event stream (SSE)")
async def stream_events(
    last_id: str = Query(default="$", description="Last event ID for resumption"),
) -> StreamingResponse:
    """
    Server-Sent Events (SSE) endpoint for real-time dashboard updates.
    Streams IOC creation events, crawler status changes, and system alerts.
    
    Usage from frontend:
        const es = new EventSource('/api/v1/dashboard/events/stream');
        es.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    import json

    redis_svc = RedisService()

    async def event_generator():
        async for event in redis_svc.stream_events_sse(
            stream="onyx:events:iocs",
            last_id=last_id,
        ):
            yield f"id: {event['id']}\n"
            yield f"event: {event['event_type']}\n"
            yield f"data: {json.dumps(event['data'])}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/dashboard/threat-map", summary="Geolocation threat map data")
async def get_threat_map_data() -> dict[str, Any]:
    """
    Geolocation data for the 3D globe visualization.
    Returns IOC geographic distribution with attack vectors.
    """
    es = ElasticsearchService()
    redis_svc = RedisService()

    cached = await redis_svc.cache_get("dashboard:threatmap")
    if cached:
        return cached

    # Aggregate geolocated IOCs
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [{"exists": {"field": "geo"}}],
                "filter": [{"term": {"is_active": True}}],
            }
        },
        "aggs": {
            "geo_grid": {
                "geotile_grid": {
                    "field": "geo",
                    "precision": 5,
                },
                "aggs": {
                    "geo_centroid": {"geo_centroid": {"field": "geo"}},
                    "by_severity": {"terms": {"field": "severity"}},
                    "by_type": {"terms": {"field": "type"}},
                },
            },
            "top_countries": {
                "terms": {"field": "country_code", "size": 50},
                "aggs": {
                    "by_severity": {"terms": {"field": "severity"}},
                },
            },
        },
    }

    result = await es.client.search(index=es._cfg.ioc_index, body=body)
    aggs = result.get("aggregations", {})

    # Transform geo_grid buckets to map markers
    markers = []
    for bucket in aggs.get("geo_grid", {}).get("buckets", []):
        centroid = bucket.get("geo_centroid", {}).get("location", {})
        markers.append({
            "lat": centroid.get("lat", 0),
            "lon": centroid.get("lon", 0),
            "count": bucket["doc_count"],
            "severity_breakdown": {
                b["key"]: b["doc_count"]
                for b in bucket.get("by_severity", {}).get("buckets", [])
            },
        })

    geo_data = {
        "markers": markers,
        "countries": {
            b["key"]: {
                "count": b["doc_count"],
                "severity": {
                    s["key"]: s["doc_count"]
                    for s in b.get("by_severity", {}).get("buckets", [])
                },
            }
            for b in aggs.get("top_countries", {}).get("buckets", [])
        },
    }

    await redis_svc.cache_set("dashboard:threatmap", geo_data, ttl_seconds=60)
    return geo_data


@router.get("/dashboard/mitre-heatmap", summary="MITRE ATT&CK heatmap data")
async def get_mitre_heatmap() -> dict[str, Any]:
    """
    ATT&CK technique frequency data for the heatmap visualization.
    Aggregates all IOCs by their mapped MITRE techniques.
    """
    es = ElasticsearchService()
    redis_svc = RedisService()

    cached = await redis_svc.cache_get("dashboard:mitre-heatmap")
    if cached:
        return cached

    body = {
        "size": 0,
        "query": {"term": {"is_active": True}},
        "aggs": {
            "techniques": {
                "terms": {"field": "mitre_techniques", "size": 200},
                "aggs": {
                    "avg_confidence": {"avg": {"field": "confidence"}},
                    "by_severity": {"terms": {"field": "severity"}},
                    "latest": {"max": {"field": "last_seen"}},
                },
            }
        },
    }

    result = await es.client.search(index=es._cfg.ioc_index, body=body)
    techniques = result.get("aggregations", {}).get("techniques", {}).get("buckets", [])

    heatmap_data = {
        "techniques": [
            {
                "technique_id": t["key"],
                "count": t["doc_count"],
                "avg_confidence": t.get("avg_confidence", {}).get("value", 0),
                "latest": t.get("latest", {}).get("value_as_string", ""),
                "severity_breakdown": {
                    s["key"]: s["doc_count"]
                    for s in t.get("by_severity", {}).get("buckets", [])
                },
            }
            for t in techniques
        ],
    }

    await redis_svc.cache_set("dashboard:mitre-heatmap", heatmap_data, ttl_seconds=60)
    return heatmap_data

@router.get("/dashboard/graph-data", summary="3D Threat Graph Data")
async def get_graph_data() -> dict[str, Any]:
    """
    Returns all STIX objects and relationships to power the ThreatGraph.
    Queries the MongoDB backend directly to extract the active SDOs/SROs.
    """
    mongo = MongoDBService()
    
    # We query an aggregate list of stix objects and relationships 
    # to feed the react-force-graph-3d structure.
    # In a true prod scale environment, this would be highly filtered, 
    # but for standalone/exhibitions we return the global state.
    
    # Retrieve top 500 active objects
    sdo_types = ["threat-actor", "malware", "campaign", "attack-pattern", "vulnerability", "tool", "indicator", "identity"]
    objects = []
    
    for t in sdo_types:
        sdo_list = await mongo.list_stix(t, limit=100)
        objects.extend(sdo_list)
        
    sros = await mongo.list_stix("relationship", limit=500)
    objects.extend(sros)
    
    return {"objects": objects}

