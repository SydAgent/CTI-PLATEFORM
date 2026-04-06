"""
ONYX CTI — Standalone In-Memory Mock Services
Bypasses Docker, Elasticsearch, MongoDB, and Redis for zero-latency execution.
"""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator
from datetime import datetime, timezone

logger = logging.getLogger("onyx.standalone")

# Global In-Memory Stores
GLOBAL_STIX_STORE: dict[str, Any] = {}
GLOBAL_RELATIONSHIPS: list[dict[str, Any]] = []
GLOBAL_CACHE: dict[str, Any] = {}

class _MockConfig:
    def __init__(self):
        self.ioc_index = "onyx-iocs"
        self.threats_index = "onyx-threats"
        self.audit_index = "onyx-audit"
        self.metrics_index = "onyx-metrics"

class MockAsyncElasticsearchClient:
    async def search(self, index: str, body: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Intercepts specific aggregations to compute them against in-memory STIX objects."""
        aggs = body.get("aggs", {})
        
        # 1. Dashboard Threat Map (Geo)
        if "geo_grid" in aggs:
            return {
                "aggregations": {
                    "geo_grid": {"buckets": []},
                    "top_countries": {"buckets": []}
                }
            }
            
        # 2. MITRE Heatmap
        if "techniques" in aggs:
            # We look in GLOBAL_STIX_STORE for attack-patterns and their connections
            technique_counts: dict[str, int] = {}
            for ap in [v for v in GLOBAL_STIX_STORE.values() if v.get("type") == "attack-pattern"]:
                ext_refs = ap.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        if tid:
                            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            
            # Plus simulated counts from indicators mapped to mitre_techniques
            for ind in [v for v in GLOBAL_STIX_STORE.values() if v.get("type") == "indicator"]:
                for tid in ind.get("mitre_techniques", []):
                    technique_counts[tid] = technique_counts.get(tid, 0) + 1

            # Give a high baseline so it looks saturated if we have any data
            buckets = []
            for tid, count in technique_counts.items():
                buckets.append({
                    "key": tid,
                    "doc_count": max(15, count * 5),  # Amplified for exhibition
                    "avg_confidence": {"value": 85},
                    "latest": {"value_as_string": datetime.now(timezone.utc).isoformat()},
                    "by_severity": {"buckets": [{"key": "critical", "doc_count": 5}]}
                })
                
            return {"aggregations": {"techniques": {"buckets": buckets}}}
            
        # Default empty fallback
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
        
    async def get(self, index: str, id: str) -> dict[str, Any]:
        return {"_source": {}}
        
    async def index(self, index: str, document: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return {"result": "created"}
        
    async def cluster_health(self) -> dict[str, Any]:
        return {"status": "green"}

class MockElasticsearchService:
    _instance: MockElasticsearchService | None = None
    _cfg = _MockConfig()

    def __new__(cls) -> MockElasticsearchService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls.client = MockAsyncElasticsearchClient()
        return cls._instance
        
    @property
    def client(self) -> MockAsyncElasticsearchClient:
        return self._instance.client # type: ignore

    async def initialize(self) -> None:
        logger.info("[MockElasticsearch] Initialized in Standalone mode.")

    async def close(self) -> None:
        pass

    async def health(self) -> dict[str, Any]:
        return {"status": "green"}

    # Mock Methods
    async def get_dashboard_stats(self) -> dict[str, Any]:
        # Provide base stats to prevent UI errors
        return {
            "total_threats": {"value": len(GLOBAL_STIX_STORE)},
            "top_actors": {
                "buckets": [
                    {"key": act.get("name", "Unknown"), "ioc_count": {"value": 150}}
                    for act in GLOBAL_STIX_STORE.values() if act.get("type") == "threat-actor"
                ]
            }
        }
        
    async def get_threat_stats(self) -> dict[str, Any]:
        return {"total_threats": {"value": len(GLOBAL_STIX_STORE)}}
        
    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> int:
        return len(iocs)

class MockMongoDBService:
    _instance: MockMongoDBService | None = None

    def __new__(cls) -> MockMongoDBService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        logger.info("[MockMongoDB] Initialized in Standalone mode.")

    async def close(self) -> None:
        pass

    async def health(self) -> dict[str, Any]:
        return {"status": "ok"}
        
    async def create_stix(self, stix_obj: Any) -> str:
        # Expected stix_obj to be a Pydantic model with `.model_dump()` or a dict
        data = stix_obj.model_dump(mode="json") if hasattr(stix_obj, "model_dump") else stix_obj
        GLOBAL_STIX_STORE[data["id"]] = data
        return data["id"]
        
    async def bulk_create_stix(self, objects: list[Any]) -> int:
        for obj in objects:
            await self.create_stix(obj)
        return len(objects)

    async def get_stix(self, stix_id: str) -> Any | None:
        return GLOBAL_STIX_STORE.get(stix_id)

    async def list_stix(self, stix_type: str, limit: int = 50, **kwargs) -> list[dict[str, Any]]:
        return [v for v in GLOBAL_STIX_STORE.values() if v.get("type") == stix_type][:limit]

    async def get_relationships(self, stix_id: str, limit: int = 100, **kwargs) -> list[dict[str, Any]]:
        rels = []
        for rel in GLOBAL_STIX_STORE.values():
            if rel.get("type") == "relationship":
                if rel.get("source_ref") == stix_id or rel.get("target_ref") == stix_id:
                    rels.append(rel)
        return rels[:limit]

    async def get_neighbors(self, stix_id: str, max_depth: int = 2, **kwargs) -> dict[str, Any]:
        """In-memory graph traversal approx."""
        nodes = []
        edges = []
        node_ids = {stix_id}
        
        # Super simplified depth-1 traversal for demo purposes
        for obj in GLOBAL_STIX_STORE.values():
            if obj.get("type") in ("relationship", "sighting"):
                src = obj.get("source_ref")
                tgt = obj.get("target_ref")
                if src == stix_id or tgt == stix_id:
                    edges.append({
                        "source": src,
                        "target": tgt,
                        "type": obj.get("relationship_type", "related-to")
                    })
                    node_ids.add(src)
                    node_ids.add(tgt)
                    
        for nid in node_ids:
            if nid in GLOBAL_STIX_STORE:
                obj = GLOBAL_STIX_STORE[nid]
                nodes.append({
                    "id": obj["id"],
                    "type": obj["type"],
                    "name": obj.get("name", obj["id"])
                })
                
        return {"nodes": nodes, "edges": edges, "root": stix_id}

    async def get_stix_stats(self) -> dict[str, Any]:
        counts = {}
        for obj in GLOBAL_STIX_STORE.values():
            t = obj.get("type")
            counts[t] = counts.get(t, 0) + 1
        return {"types": counts, "total": len(GLOBAL_STIX_STORE)}
        
    async def get_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        return list(GLOBAL_STIX_STORE.values())[:limit]
        
    async def get_crawler_states(self) -> list[dict[str, Any]]:
        return []
        
    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        # Mock admin user to allow login
        if username == "admin":
            return {
                "username": "admin",
                "roles": ["admin"],
                "password_hash": "$2b$12$Z0H99D7qM8aQ81yQ9S.K.OUv3B5N.v/gP6n9J3Z5I9M7q8Z9C8K.O", # onyx_admin_2026!
                "api_key_hash": "mock",
                "is_active": True
            }
        return None

class MockRedisService:
    _instance: MockRedisService | None = None

    def __new__(cls) -> MockRedisService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        logger.info("[MockRedis] Initialized in Standalone mode.")

    async def close(self) -> None:
        pass

    async def health(self) -> dict[str, Any]:
        return {"status": "ok"}
        
    async def check_rate_limit(self, identifier: str, limit: int = 100, window_seconds: int = 60) -> bool:
        return True
        
    async def cache_get(self, key: str) -> Any | None:
        return GLOBAL_CACHE.get(key)
        
    async def cache_set(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        GLOBAL_CACHE[key] = value
        
    async def cache_delete(self, key: str) -> None:
        GLOBAL_CACHE.pop(key, None)
        
    async def publish_event(self, stream: str, event_type: str, data: dict[str, Any]) -> str:
        # In standalone mode we don't need real sub delivery, we just ignore it
        return "123456-0"
        
    async def stream_events_sse(self, stream: str, last_id: str = "$") -> AsyncIterator[dict[str, Any]]:
        # Dummy generator that holds forever without sending data
        import asyncio
        while True:
            await asyncio.sleep(10)
            yield {}
            
    async def publish_ws(self, channel: str, message: dict[str, Any]) -> None:
        pass

