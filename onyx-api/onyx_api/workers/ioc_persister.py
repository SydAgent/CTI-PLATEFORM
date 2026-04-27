"""
ONYX CTI v5.0 SOVEREIGN — IOC Persister Worker
================================================

Worker asynchrone autonome chargé de consommer le bus d'événements
(Redis Stream) et de persister les IOCs et données enrichies dans
Elasticsearch (Stockage à long terme).

C'est ici que s'opère le découplage : les connecteurs OSINT publient
rapidement sur Redis, le Persister dépile à son rythme vers Elasticsearch.

Phase 1 addition: recalculate_decay_all() — hourly batch loop that recomputes
decay_score + composite_confidence for every IoC in MongoDB and writes results
back. Feature-gated by ONYX_DECAY_ENGINE_ENABLED.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any

from structlog import get_logger

from onyx_core.services.redis import RedisService
from onyx_core.services.elasticsearch import ElasticsearchService
from onyx_core.services.event_bus import EventBus
from onyx_core.services.mongodb import MongoDBService

logger = get_logger("onyx.workers.persister")

STREAM_IOCS = "onyx:events:iocs"
GROUP_NAME = "es_persister_group"
CONSUMER_NAME = "worker_1"
_DECAY_ENABLED = os.environ.get("ONYX_DECAY_ENGINE_ENABLED", "false").lower() == "true"
_DECAY_BATCH_SIZE = 200
_DECAY_RECALC_INTERVAL_SECONDS = 3600  # 1 hour


async def run_ioc_persister() -> None:
    """Boucle principale du worker de persistance."""
    logger.info("ioc_persister.starting", stream=STREAM_IOCS)

    redis_svc = RedisService()
    try:
        await redis_svc.initialize()
    except Exception as e:
        logger.error("ioc_persister.redis_init_failed", error=str(e))
        return

    es_svc = ElasticsearchService()
    try:
        await es_svc.initialize()
    except Exception as e:
        logger.error("ioc_persister.es_init_failed", error=str(e))
        return

    bus = EventBus(redis_svc)
    logger.info("ioc_persister.ready", group=GROUP_NAME)

    try:
        async for msg_id, event_type, data in bus.consume(STREAM_IOCS, GROUP_NAME, CONSUMER_NAME):
            if event_type == "ioc_detected":
                try:
                    doc_id = data.get("id") or data.get("value")
                    if doc_id:
                        await es_svc.index_document("onyx-iocs", doc_id, data)
                        logger.debug("ioc_persister.saved", doc_id=doc_id, msg_id=msg_id)
                    await bus.acknowledge(STREAM_IOCS, GROUP_NAME, msg_id)
                except Exception as save_err:
                    logger.error("ioc_persister.save_error", msg_id=msg_id, error=str(save_err))
            else:
                await bus.acknowledge(STREAM_IOCS, GROUP_NAME, msg_id)

    except asyncio.CancelledError:
        logger.info("ioc_persister.stopped")


async def recalculate_decay_all() -> dict[str, Any]:
    """
    Batch recalculate decay_score + composite_confidence for all IoCs in MongoDB.

    Reads every document from the `indicators` collection, computes fresh
    decay scores using the current timestamp, and writes the results back
    with a partial $set (no field deletions — R2 backward-compat).

    Returns a summary dict for Gate 1 reporting.
    Feature-gated: no-ops when ONYX_DECAY_ENGINE_ENABLED=false.
    """
    if not _DECAY_ENABLED:
        logger.info("ioc_persister.decay_recalc.skipped", reason="ONYX_DECAY_ENGINE_ENABLED=false")
        return {"status": "skipped", "processed": 0}

    from onyx_core.services.decay_engine import calculate_decay, classify_decay_state
    from onyx_core.services.confidence_composite import calculate_composite_confidence

    mongo = MongoDBService()
    now = datetime.now(timezone.utc)
    processed = updated = errors = 0
    t_start = asyncio.get_event_loop().time()

    try:
        coll = mongo.collection("indicators")
        cursor = coll.find({}, {"_id": 0})

        batch: list[dict] = []
        async for doc in cursor:
            batch.append(doc)
            if len(batch) >= _DECAY_BATCH_SIZE:
                u = await _process_decay_batch(batch, now, coll, calculate_decay,
                                               classify_decay_state, calculate_composite_confidence)
                updated += u["updated"]
                errors += u["errors"]
                processed += len(batch)
                batch = []

        if batch:
            u = await _process_decay_batch(batch, now, coll, calculate_decay,
                                           classify_decay_state, calculate_composite_confidence)
            updated += u["updated"]
            errors += u["errors"]
            processed += len(batch)

    except Exception as e:
        logger.error("ioc_persister.decay_recalc.failed", error=str(e))
        return {"status": "error", "error": str(e), "processed": processed}

    elapsed_ms = int((asyncio.get_event_loop().time() - t_start) * 1000)
    logger.info(
        "ioc_persister.decay_recalc.complete",
        processed=processed,
        updated=updated,
        errors=errors,
        elapsed_ms=elapsed_ms,
    )
    return {
        "status": "ok",
        "processed": processed,
        "updated": updated,
        "errors": errors,
        "elapsed_ms": elapsed_ms,
        "timestamp": now.isoformat(),
    }


async def _process_decay_batch(
    batch: list[dict],
    now: datetime,
    coll: Any,
    calculate_decay: Any,
    classify_decay_state: Any,
    calculate_composite_confidence: Any,
) -> dict[str, int]:
    """Apply decay recalculation to one batch and bulk-write results back."""
    updated = errors = 0
    for doc in batch:
        try:
            ioc_type = doc.get("ioc_type") or doc.get("type") or "ipv4"
            detected_raw = doc.get("date_detection") or doc.get("first_seen")
            if not detected_raw:
                continue

            if isinstance(detected_raw, str):
                detected = datetime.fromisoformat(detected_raw.replace("Z", "+00:00"))
            elif isinstance(detected_raw, datetime):
                detected = detected_raw
            else:
                continue

            hours_since = max(0.0, (now - detected).total_seconds() / 3600.0)

            try:
                decay_score = calculate_decay(ioc_type, hours_since)
            except ValueError:
                decay_score = calculate_decay("ipv4", hours_since)

            decay_state = classify_decay_state(decay_score).value
            cb = calculate_composite_confidence(
                source=doc.get("source", "unknown"),
                decay_score=decay_score,
                corroboration_count=int(doc.get("corroboration_count", 1)),
            )

            doc_id = doc.get("id") or doc.get("valeur") or doc.get("value")
            if not doc_id:
                continue

            await coll.update_one(
                {"$or": [{"id": doc_id}, {"valeur": doc_id}, {"value": doc_id}]},
                {"$set": {
                    "decay_score": round(decay_score, 4),
                    "decay_state": decay_state,
                    "composite_confidence": round(cb.composite, 4),
                    "last_decay_calculated": now.isoformat(),
                }},
            )
            updated += 1
        except Exception as e:
            logger.warning("ioc_persister.decay_recalc.doc_error", error=str(e))
            errors += 1

    return {"updated": updated, "errors": errors}


async def run_decay_recalc_loop() -> None:
    """Hourly loop that calls recalculate_decay_all() indefinitely."""
    logger.info("ioc_persister.decay_loop.starting", interval_s=_DECAY_RECALC_INTERVAL_SECONDS)
    try:
        while True:
            await recalculate_decay_all()
            await asyncio.sleep(_DECAY_RECALC_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        logger.info("ioc_persister.decay_loop.stopped")


if __name__ == "__main__":
    asyncio.run(run_ioc_persister())
