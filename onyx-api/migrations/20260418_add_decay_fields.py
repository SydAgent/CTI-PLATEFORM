"""
Migration: 20260418_add_decay_fields
=====================================

Adds decay engine fields to existing IoC documents in the `indicators` collection
and creates the `actor_decay_profiles` collection with its indexes.

Changes:
  - indicators: add decay_score, decay_state, composite_confidence,
    corroboration_count, last_decay_calculated (all optional — no existing
    document is mutated to break backward compatibility)
  - actor_decay_profiles: new collection with unique index on actor_id
  - indicators: compound index (actor_id, decay_score) for fast actor-scoped queries

Run:
  python -m onyx_api.migrations.20260418_add_decay_fields

Idempotent: safe to run multiple times.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, IndexModel

logger = logging.getLogger("onyx.migrations.20260418")


async def up() -> dict:
    """Apply migration."""
    from onyx_core.services.mongodb import MongoDBService

    mongo = MongoDBService()
    await mongo.initialize()
    results: dict[str, str] = {}

    # ── 1. indicators — add default decay fields to documents that lack them ──
    indicators = mongo.collection("indicators")
    result = await indicators.update_many(
        {"decay_score": {"$exists": False}},
        {"$set": {
            "decay_score": None,
            "decay_state": None,
            "composite_confidence": None,
            "corroboration_count": 1,
            "last_decay_calculated": None,
        }},
    )
    results["indicators.decay_fields_added"] = str(result.modified_count)
    logger.info("indicators: %d documents updated with decay fields", result.modified_count)

    # ── 2. indicators — compound index for actor-scoped decay queries ──
    existing_indexes = await indicators.index_information()
    idx_name = "actor_id_decay_score"
    if idx_name not in existing_indexes:
        await indicators.create_index(
            [("actor_id", ASCENDING), ("decay_score", DESCENDING)],
            name=idx_name,
            background=True,
        )
        results["indicators.index_created"] = idx_name
        logger.info("Created index %s on indicators", idx_name)
    else:
        results["indicators.index_skipped"] = idx_name

    # ── 3. actor_decay_profiles — create collection + unique index ──
    profiles = mongo.collection("actor_decay_profiles")
    existing_indexes = await profiles.index_information()
    profile_idx = "actor_id_unique"
    if profile_idx not in existing_indexes:
        await profiles.create_index(
            [("actor_id", ASCENDING)],
            name=profile_idx,
            unique=True,
            background=True,
        )
        results["actor_decay_profiles.index_created"] = profile_idx
        logger.info("Created unique index %s on actor_decay_profiles", profile_idx)
    else:
        results["actor_decay_profiles.index_skipped"] = profile_idx

    results["status"] = "ok"
    results["applied_at"] = datetime.now(timezone.utc).isoformat()
    return results


async def down() -> dict:
    """
    Reverse migration.

    Removes the decay indexes. Does NOT remove decay fields from documents
    (data removal is irreversible — callers must explicitly opt in).
    """
    from onyx_core.services.mongodb import MongoDBService

    mongo = MongoDBService()
    results: dict[str, str] = {}

    try:
        await mongo.collection("indicators").drop_index("actor_id_decay_score")
        results["indicators.index_dropped"] = "actor_id_decay_score"
    except Exception as e:
        results["indicators.index_drop_error"] = str(e)

    try:
        await mongo.collection("actor_decay_profiles").drop_index("actor_id_unique")
        results["actor_decay_profiles.index_dropped"] = "actor_id_unique"
    except Exception as e:
        results["actor_decay_profiles.index_drop_error"] = str(e)

    results["status"] = "reverted"
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = asyncio.run(up())
    print(result)
