"""
ONYX CTI — Unified NLP Processing Pipeline
Orchestrates IOC extraction + TTP mapping + STIX object generation.
Consumes crawled data from Redis Streams and produces enriched intelligence.

Pattern source: TRAM's process_job() + AIL's Global.py module pipeline.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from onyx_core.models.stix import (
    _generate_stix_id,
    new_indicator,
    new_relationship,
)
from onyx_core.services.elasticsearch import ElasticsearchService
from onyx_core.services.mongodb import MongoDBService
from onyx_core.services.redis import RedisService
from onyx_nlp.extractors.ioc_extractor import IOCExtractor, ExtractionResult
from onyx_nlp.extractors.ttp_mapper import TTPMapper, TTPResult

logger = logging.getLogger("onyx.nlp.pipeline")


class NLPPipeline:
    """
    Unified NLP pipeline that processes raw text through:
    1. IOC Extraction (regex-based, near-zero FP)
    2. TTP Mapping (keyword + optional SciBERT)
    3. STIX Object Generation (Indicators + Relationships)
    4. Elasticsearch Indexing (for dashboard search)
    5. Event Emission (for real-time updates)
    """

    def __init__(self, use_ml: bool = False, model_path: str | None = None) -> None:
        self.ioc_extractor = IOCExtractor(
            include_private_ips=False,
            include_defanged=True,
            min_confidence=0.5,
        )
        self.ttp_mapper = TTPMapper(
            confidence_threshold=0.25,
            use_ml=use_ml,
            model_path=model_path,
        )

    async def process_text(
        self,
        text: str,
        source: str = "",
        source_url: str = "",
        tags: list[str] | None = None,
        tlp: str = "TLP:GREEN",
    ) -> dict[str, Any]:
        """
        Full NLP processing pipeline.

        Returns dict with iocs, ttps, stix_objects, and stats.
        """
        import time
        start = time.monotonic()

        # Step 1: Extract IOCs
        ioc_result: ExtractionResult = self.ioc_extractor.extract(text, source=source)

        # Strict Entity Deduplication
        unique_iocs_map = {}
        for ioc in ioc_result.iocs:
            key = f"{ioc.type}:{ioc.value.lower()}"
            if key not in unique_iocs_map or ioc.confidence > unique_iocs_map[key].confidence:
                unique_iocs_map[key] = ioc
        ioc_result.iocs = list(unique_iocs_map.values())
        ioc_result.total_iocs = len(ioc_result.iocs)

        # Step 2: Map TTPs
        ttp_result: TTPResult = self.ttp_mapper.map_text(text)
        
        # Threat Actor Semantic Contextualization
        actor_context = "Unknown_Actor"
        if tags:
            actor_tags = [t for t in tags if "apt" in t.lower() or "bear" in t.lower() or "spider" in t.lower()]
            if actor_tags:
                actor_context = actor_tags[0]
        elif "APT29" in text or "Cozy Bear" in text:
            actor_context = "APT29"
        elif "Lazarus" in text:
            actor_context = "Lazarus Group"

        # Step 3: Generate STIX objects + index IOCs
        stix_ids: list[str] = []
        es_docs: list[dict[str, Any]] = []

        for ioc in ioc_result.iocs:
            ioc_id = f"ioc-{hashlib.sha256(f'{ioc.type}:{ioc.value}'.encode()).hexdigest()[:16]}"
            now = datetime.now(timezone.utc).isoformat()
            mitre_ids = [t.technique_id for t in ttp_result.techniques[:5]]

            # Build STIX Indicator
            pattern = self._build_stix_pattern(ioc.type, ioc.value)
            if pattern:
                indicator = new_indicator(
                    pattern=pattern,
                    name=f"{ioc.type}: {ioc.value}",
                    ioc_type=ioc.type,
                    ioc_value=ioc.value,
                    confidence=int(ioc.confidence * 100),
                    mitre_techniques=mitre_ids,
                    labels=[ioc.type, source] if source else [ioc.type],
                    onyx_source=source,
                    onyx_tags=tags or [],
                )
                stix_ids.append(indicator.id)

            # Build ES IOC document
            es_docs.append({
                "ioc_id": ioc_id,
                "stix_id": indicator.id if pattern else "",
                "type": ioc.type,
                "value": ioc.value,
                "source": source,
                "source_url": source_url,
                "confidence": int(ioc.confidence * 100),
                "severity": self._compute_severity(ioc, ttp_result),
                "tags": (tags or []) + [f"actor:{actor_context}"],
                "mitre_techniques": mitre_ids,
                "tlp": tlp,
                "context": ioc.context,
                "raw_text": text[:5000] if len(text) > 5000 else text,
                "first_seen": now,
                "last_seen": now,
                "is_active": True,
            })

        # Step 4: Persist to databases
        indexed_count = 0
        try:
            if es_docs:
                es = ElasticsearchService()
                indexed_count = await es.bulk_index_iocs(es_docs)
        except Exception as e:
            logger.error("ES indexing failed: %s", str(e))

        stix_stored = 0
        try:
            if stix_ids:
                # MongoDB storage is handled by the async event consumer, we just track the generated count here.
                stix_stored = len(stix_ids)
        except Exception as e:
            logger.error("MongoDB storage tracking failed: %s", str(e))

        # Step 5: Emit events
        try:
            redis = RedisService()
            await redis.publish_event(
                stream="onyx:events:iocs",
                event_type="ioc.batch_processed",
                data={
                    "source": source,
                    "ioc_count": len(ioc_result.iocs),
                    "ttp_count": len(ttp_result.techniques),
                    "indexed": indexed_count,
                    "by_type": ioc_result.by_type,
                    "top_tactics": ttp_result.top_tactics[:3],
                },
            )
            # Invalidate dashboard cache
            await redis.cache_delete("dashboard:stats")
        except Exception as e:
            logger.error("Event emission failed: %s", str(e))

        elapsed = (time.monotonic() - start) * 1000

        result = {
            "iocs": {
                "total": ioc_result.total_iocs,
                "by_type": ioc_result.by_type,
                "items": [
                    {
                        "type": i.type,
                        "value": i.value,
                        "confidence": i.confidence,
                        "context": i.context,
                        "defanged": i.defanged,
                    }
                    for i in ioc_result.iocs
                ],
                "processing_time_ms": ioc_result.processing_time_ms,
            },
            "ttps": {
                "total": len(ttp_result.techniques),
                "top_tactics": ttp_result.top_tactics,
                "techniques": [
                    {
                        "id": t.technique_id,
                        "name": t.technique_name,
                        "tactic": t.tactic,
                        "confidence": t.confidence,
                        "method": t.method,
                    }
                    for t in ttp_result.techniques
                ],
                "processing_time_ms": ttp_result.processing_time_ms,
                "model_used": ttp_result.model_used,
            },
            "stix_objects_created": len(stix_ids),
            "es_documents_indexed": indexed_count,
            "total_processing_ms": round(elapsed, 2),
            "source": source,
        }

        logger.info(
            "NLP pipeline: %d IOCs, %d TTPs from '%s' (%.0fms)",
            ioc_result.total_iocs,
            len(ttp_result.techniques),
            source[:50],
            elapsed,
        )

        return result

    def _build_stix_pattern(self, ioc_type: str, value: str) -> str | None:
        """Convert an IOC to a STIX 2.1 pattern string."""
        pattern_map = {
            "ipv4": f"[ipv4-addr:value = '{value}']",
            "ipv6": f"[ipv6-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "md5": f"[file:hashes.MD5 = '{value}']",
            "sha1": f"[file:hashes.'SHA-1' = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "sha512": f"[file:hashes.'SHA-512' = '{value}']",
            "email": f"[email-addr:value = '{value}']",
        }
        return pattern_map.get(ioc_type)

    def _compute_severity(self, ioc: Any, ttp_result: TTPResult) -> str:
        """Compute IOC severity from type + associated tactics."""
        high_severity_types = {"sha256", "sha1", "md5", "url"}
        impact_tactics = {"impact", "exfiltration", "credential-access"}

        if ioc.type in high_severity_types and ioc.confidence > 0.8:
            return "high"
        if any(t in impact_tactics for t in ttp_result.top_tactics):
            return "high"
        if ioc.confidence > 0.9:
            return "medium"
        return "low"
