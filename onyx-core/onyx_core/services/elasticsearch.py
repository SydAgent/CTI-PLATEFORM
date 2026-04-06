"""
ONYX CTI — Elasticsearch Service
Async Elasticsearch client with IOC index management, bulk operations,
and search abstractions. Designed for sub-millisecond IOC lookups.

Pattern source: OpenCTI's database layer + IntelOwl's analyzables_manager.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError
from elasticsearch.helpers import async_bulk
from tenacity import retry, stop_after_attempt, wait_exponential

from onyx_core.config import ElasticsearchConfig, get_config

logger = logging.getLogger("onyx.elasticsearch")

# ============================================================================
# Index Templates — Elasticsearch Mappings
# ============================================================================

IOC_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 0,  # Single-node; set to 1 in production cluster
        "refresh_interval": "5s",
        "analysis": {
            "analyzer": {
                "ioc_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "trim"],
                },
                "defang_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "char_filter": ["defang_filter"],
                    "filter": ["lowercase"],
                },
            },
            "char_filter": {
                "defang_filter": {
                    "type": "pattern_replace",
                    "pattern": r"\[(\.|dot)\]",
                    "replacement": ".",
                }
            },
        },
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "ioc_id": {"type": "keyword", "doc_values": True},
            "stix_id": {"type": "keyword", "doc_values": True},
            "type": {
                "type": "keyword",
                "doc_values": True,
                "fields": {"text": {"type": "text"}},
            },
            "value": {
                "type": "keyword",
                "doc_values": True,
                "normalizer": "lowercase",
                "fields": {
                    "search": {"type": "text", "analyzer": "ioc_analyzer"},
                    "defanged": {"type": "text", "analyzer": "defang_analyzer"},
                },
            },
            "source": {"type": "keyword", "doc_values": True},
            "source_url": {"type": "keyword", "index": False},
            "confidence": {"type": "integer"},
            "severity": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "tags": {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "geo": {"type": "geo_point"},
            "country_code": {"type": "keyword"},
            "asn": {"type": "keyword"},
            "as_org": {"type": "keyword"},
            "raw_text": {"type": "text", "analyzer": "english"},
            "context": {"type": "text", "analyzer": "standard"},
            "related_indicators": {"type": "keyword"},
            "kill_chain_phases": {"type": "keyword"},
            "is_active": {"type": "boolean"},
            "expiration": {"type": "date"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "enrichment": {
                "type": "object",
                "enabled": True,
                "dynamic": True,
            },
        },
    },
}

THREATS_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "10s",
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "threat_id": {"type": "keyword"},
            "stix_id": {"type": "keyword"},
            "type": {"type": "keyword"},
            "name": {
                "type": "text",
                "analyzer": "standard",
                "fields": {"keyword": {"type": "keyword"}},
            },
            "description": {"type": "text", "analyzer": "english"},
            "aliases": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "confidence": {"type": "integer"},
            "severity": {"type": "keyword"},
            "country_of_origin": {"type": "keyword"},
            "targeted_sectors": {"type": "keyword"},
            "targeted_countries": {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "ioc_count": {"type": "integer"},
            "tags": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
        },
    },
}

AUDIT_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "30s",
    },
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "user_id": {"type": "keyword"},
            "username": {"type": "keyword"},
            "action": {"type": "keyword"},
            "resource_type": {"type": "keyword"},
            "resource_id": {"type": "keyword"},
            "method": {"type": "keyword"},
            "path": {"type": "keyword"},
            "status_code": {"type": "integer"},
            "ip_address": {"type": "ip"},
            "user_agent": {"type": "keyword"},
            "details": {"type": "object", "dynamic": True},
            "duration_ms": {"type": "float"},
        },
    },
}

METRICS_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "60s",
        "index.lifecycle.name": "onyx-metrics-policy",
    },
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "metric_name": {"type": "keyword"},
            "metric_value": {"type": "double"},
            "dimensions": {"type": "object", "dynamic": True},
            "source": {"type": "keyword"},
        },
    },
}


class ElasticsearchService:
    """
    Async Elasticsearch service for IOC indexing, search, and analytics.
    Thread-safe singleton pattern for connection reuse.
    """

    _instance: ElasticsearchService | None = None
    _client: AsyncElasticsearch | None = None

    def __new__(cls) -> ElasticsearchService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._client is not None:
            return
        cfg: ElasticsearchConfig = get_config().elasticsearch
        self._client = AsyncElasticsearch(
            hosts=[cfg.url],
            basic_auth=(cfg.user, cfg.password),
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        self._cfg = cfg

    @property
    def client(self) -> AsyncElasticsearch:
        assert self._client is not None, "Elasticsearch client not initialized"
        return self._client

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, max=30))
    async def initialize(self) -> None:
        """Create index templates if they don't exist. Idempotent."""
        indices = {
            self._cfg.ioc_index: IOC_INDEX_SETTINGS,
            self._cfg.threats_index: THREATS_INDEX_SETTINGS,
            self._cfg.audit_index: AUDIT_INDEX_SETTINGS,
            self._cfg.metrics_index: METRICS_INDEX_SETTINGS,
        }
        for index_name, settings in indices.items():
            exists = await self.client.indices.exists(index=index_name)
            if not exists:
                await self.client.indices.create(index=index_name, body=settings)
                logger.info("Created index: %s", index_name)
            else:
                logger.debug("Index already exists: %s", index_name)
        logger.info("Elasticsearch initialization complete — %d indices ready", len(indices))

    async def close(self) -> None:
        """Close the Elasticsearch client connection."""
        if self._client:
            await self._client.close()
            self._client = None
            ElasticsearchService._instance = None
            logger.info("Elasticsearch connection closed")

    async def health(self) -> dict[str, Any]:
        """Get cluster health status."""
        return await self.client.cluster.health()  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # IOC Operations
    # ------------------------------------------------------------------

    async def index_ioc(self, ioc_data: dict[str, Any]) -> str:
        """
        Index a single IOC document. Uses ioc_id as document ID for upsert behavior.

        Args:
            ioc_data: IOC document conforming to IOC_INDEX_SETTINGS mapping.

        Returns:
            The document ID.
        """
        doc_id = ioc_data.get("ioc_id", ioc_data.get("stix_id", ""))
        now = datetime.now(timezone.utc).isoformat()
        ioc_data.setdefault("created_at", now)
        ioc_data["updated_at"] = now
        ioc_data.setdefault("is_active", True)

        result = await self.client.index(
            index=self._cfg.ioc_index,
            id=doc_id,
            document=ioc_data,
            refresh="wait_for",
        )
        logger.debug("Indexed IOC %s (result: %s)", doc_id, result.get("result"))
        return doc_id

    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> int:
        """
        Bulk index IOC documents for high-throughput ingestion.

        Args:
            iocs: List of IOC documents.

        Returns:
            Number of successfully indexed documents.
        """
        now = datetime.now(timezone.utc).isoformat()
        actions = []
        for ioc in iocs:
            doc_id = ioc.get("ioc_id", ioc.get("stix_id", ""))
            ioc.setdefault("created_at", now)
            ioc["updated_at"] = now
            ioc.setdefault("is_active", True)
            actions.append(
                {
                    "_index": self._cfg.ioc_index,
                    "_id": doc_id,
                    "_source": ioc,
                }
            )

        success, errors = await async_bulk(
            self.client, actions, raise_on_error=False, refresh="wait_for"
        )
        if errors:
            logger.warning("Bulk index errors: %d failures out of %d", len(errors), len(iocs))
        logger.info("Bulk indexed %d IOCs successfully", success)
        return success

    async def search_iocs(
        self,
        query: str | None = None,
        ioc_type: str | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        size: int = 50,
        offset: int = 0,
        sort_field: str = "last_seen",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """
        Search IOCs with multi-filter support.

        Returns:
            Dict with 'total', 'hits', and 'aggregations' keys.
        """
        must_clauses: list[dict[str, Any]] = []
        filter_clauses: list[dict[str, Any]] = [{"term": {"is_active": True}}]

        if query:
            must_clauses.append(
                {
                    "multi_match": {
                        "query": query,
                        "fields": ["value^3", "value.search^2", "raw_text", "context", "tags"],
                        "type": "best_fields",
                        "fuzziness": "AUTO",
                    }
                }
            )

        if ioc_type:
            filter_clauses.append({"term": {"type": ioc_type}})
        if severity:
            filter_clauses.append({"term": {"severity": severity}})
        if tags:
            filter_clauses.append({"terms": {"tags": tags}})
        if mitre_techniques:
            filter_clauses.append({"terms": {"mitre_techniques": mitre_techniques}})
        if date_from or date_to:
            range_filter: dict[str, Any] = {}
            if date_from:
                range_filter["gte"] = date_from.isoformat()
            if date_to:
                range_filter["lte"] = date_to.isoformat()
            filter_clauses.append({"range": {"last_seen": range_filter}})

        body: dict[str, Any] = {
            "query": {
                "bool": {
                    "must": must_clauses or [{"match_all": {}}],
                    "filter": filter_clauses,
                }
            },
            "sort": [{sort_field: {"order": sort_order}}],
            "from": offset,
            "size": size,
            "aggs": {
                "by_type": {"terms": {"field": "type", "size": 20}},
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_source": {"terms": {"field": "source", "size": 20}},
                "timeline": {
                    "date_histogram": {
                        "field": "last_seen",
                        "calendar_interval": "day",
                    }
                },
            },
        }

        result = await self.client.search(index=self._cfg.ioc_index, body=body)
        return {
            "total": result["hits"]["total"]["value"],
            "hits": [hit["_source"] for hit in result["hits"]["hits"]],
            "aggregations": result.get("aggregations", {}),
        }

    async def get_ioc_by_value(self, value: str) -> dict[str, Any] | None:
        """Exact-match lookup of an IOC by its value. O(1) via keyword field."""
        result = await self.client.search(
            index=self._cfg.ioc_index,
            body={"query": {"term": {"value": value.lower()}}, "size": 1},
        )
        hits = result["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    async def get_ioc_by_id(self, ioc_id: str) -> dict[str, Any] | None:
        """Fetch a single IOC by its document ID."""
        try:
            result = await self.client.get(index=self._cfg.ioc_index, id=ioc_id)
            return result["_source"]
        except NotFoundError:
            return None

    # ------------------------------------------------------------------
    # Threat Operations
    # ------------------------------------------------------------------

    async def index_threat(self, threat_data: dict[str, Any]) -> str:
        """Index a threat entity (threat actor, malware, campaign, etc.)."""
        doc_id = threat_data.get("threat_id", threat_data.get("stix_id", ""))
        now = datetime.now(timezone.utc).isoformat()
        threat_data.setdefault("created_at", now)
        threat_data["updated_at"] = now

        await self.client.index(
            index=self._cfg.threats_index,
            id=doc_id,
            document=threat_data,
            refresh="wait_for",
        )
        return doc_id

    # ------------------------------------------------------------------
    # Audit Operations
    # ------------------------------------------------------------------

    async def log_audit(self, audit_entry: dict[str, Any]) -> None:
        """Append an audit log entry (immutable, append-only)."""
        audit_entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        await self.client.index(
            index=self._cfg.audit_index,
            document=audit_entry,
        )

    # ------------------------------------------------------------------
    # Metrics / Dashboard Aggregations
    # ------------------------------------------------------------------

    async def get_dashboard_stats(self) -> dict[str, Any]:
        """
        Generate real-time dashboard statistics via ES aggregations.
        Returns counts, severity distribution, timeline, top sources.
        """
        body = {
            "size": 0,
            "query": {"term": {"is_active": True}},
            "aggs": {
                "total_iocs": {"value_count": {"field": "ioc_id"}},
                "by_type": {"terms": {"field": "type", "size": 20}},
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_source": {"terms": {"field": "source", "size": 20}},
                "by_country": {"terms": {"field": "country_code", "size": 30}},
                "by_mitre": {"terms": {"field": "mitre_techniques", "size": 30}},
                "timeline_24h": {
                    "date_histogram": {
                        "field": "last_seen",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    }
                },
                "timeline_30d": {
                    "date_histogram": {
                        "field": "last_seen",
                        "calendar_interval": "day",
                        "min_doc_count": 0,
                    }
                },
                "avg_confidence": {"avg": {"field": "confidence"}},
                "latest_ioc": {"max": {"field": "last_seen"}},
            },
        }

        result = await self.client.search(index=self._cfg.ioc_index, body=body)
        return result.get("aggregations", {})

    async def get_threat_stats(self) -> dict[str, Any]:
        """Aggregate threat entity statistics for the dashboard."""
        body = {
            "size": 0,
            "aggs": {
                "total_threats": {"value_count": {"field": "threat_id"}},
                "by_type": {"terms": {"field": "type", "size": 20}},
                "top_actors": {
                    "terms": {"field": "name.keyword", "size": 10},
                    "aggs": {
                        "ioc_count": {"sum": {"field": "ioc_count"}},
                    },
                },
                "by_sector": {"terms": {"field": "targeted_sectors", "size": 20}},
                "by_country": {"terms": {"field": "targeted_countries", "size": 30}},
            },
        }
        result = await self.client.search(index=self._cfg.threats_index, body=body)
        return result.get("aggregations", {})
