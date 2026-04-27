"""
ONYX CTI — Decay Learning Worker
=================================

Daily background job that analyzes historical IoC rotation data per actor
and updates the ActorDecayProfile with learned half-lives.

Algorithm (per actor, per IoC type):
  1. Collect all IoCs of this type attributed to the actor, sorted by date_detection.
  2. For consecutive pairs (detection_i, decay_score_i), estimate the point at
     which decay_score would have reached 0.5 — that is the empirical half-life.
     Derivation: 0.5 = exp(-ln2 × Δt / t_half) → t_half = Δt (when Δt = observed gap).
  3. Average the observed gaps using exponential moving average (α=0.3) against
     the stored profile value.
  4. Write back via ActorDecayProfile.update_half_life().

Feature-gated by ONYX_DECAY_ENGINE_ENABLED.
"""

from __future__ import annotations

import asyncio
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from structlog import get_logger

from onyx_core.models.actor_decay_profile import ActorDecayProfile, LearnedHalfLife
from onyx_core.services.mongodb import MongoDBService

logger = get_logger("onyx.workers.decay_learning")

_DECAY_ENABLED = os.environ.get("ONYX_DECAY_ENGINE_ENABLED", "false").lower() == "true"
_LEARNING_INTERVAL_SECONDS = 86400  # 24 hours
_LN2 = math.log(2)
_MIN_SAMPLES = 3  # require at least 3 IoC observations before updating a half-life


async def run_decay_learning_loop() -> None:
    """24-hour loop that updates per-actor learned half-lives."""
    logger.info("decay_learning.starting", interval_s=_LEARNING_INTERVAL_SECONDS)
    try:
        while True:
            await _run_once()
            await asyncio.sleep(_LEARNING_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        logger.info("decay_learning.stopped")


async def _run_once() -> dict[str, Any]:
    """Single learning pass over all actors. Returns summary for observability."""
    if not _DECAY_ENABLED:
        logger.info("decay_learning.skipped", reason="ONYX_DECAY_ENGINE_ENABLED=false")
        return {"status": "skipped"}

    mongo = MongoDBService()
    now = datetime.now(timezone.utc)
    actors_updated = 0
    errors = 0

    try:
        # ── Load all indicators with actor attribution ──
        ioc_coll = mongo.collection("indicators")
        cursor = ioc_coll.find(
            {"actor_id": {"$exists": True}, "date_detection": {"$exists": True}},
            {"_id": 0, "actor_id": 1, "ioc_type": 1, "type": 1, "date_detection": 1},
        )

        # Group by (actor_id, ioc_type)
        grouped: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))
        async for doc in cursor:
            actor_id = doc.get("actor_id")
            ioc_type = doc.get("ioc_type") or doc.get("type", "ipv4")
            raw_date = doc.get("date_detection")
            if not actor_id or not raw_date:
                continue
            try:
                if isinstance(raw_date, str):
                    dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                elif isinstance(raw_date, datetime):
                    dt = raw_date
                else:
                    continue
                grouped[actor_id][ioc_type].append(dt)
            except Exception:
                continue

        # ── Per-actor, per-type: estimate half-life from observation gaps ──
        profile_coll = mongo.collection("actor_decay_profiles")

        for actor_id, type_map in grouped.items():
            try:
                raw_profile = await profile_coll.find_one({"actor_id": actor_id}, {"_id": 0})
                if raw_profile:
                    profile = _load_profile(raw_profile)
                else:
                    profile = ActorDecayProfile(
                        actor_id=actor_id,
                        learned_half_lives=[],
                        created_at=now,
                        updated_at=now,
                    )

                changed = False
                for ioc_type, dates in type_map.items():
                    if len(dates) < _MIN_SAMPLES:
                        continue
                    observed_hl = _estimate_half_life_hours(sorted(dates))
                    if observed_hl is None:
                        continue
                    profile = profile.update_half_life(ioc_type, observed_hl, now)
                    changed = True

                if changed:
                    await profile_coll.update_one(
                        {"actor_id": actor_id},
                        {"$set": profile.model_dump(mode="json")},
                        upsert=True,
                    )
                    actors_updated += 1

            except Exception as e:
                logger.warning("decay_learning.actor_error", actor_id=actor_id, error=str(e))
                errors += 1

    except Exception as e:
        logger.error("decay_learning.failed", error=str(e))
        return {"status": "error", "error": str(e)}

    logger.info(
        "decay_learning.complete",
        actors_updated=actors_updated,
        errors=errors,
        timestamp=now.isoformat(),
    )
    return {"status": "ok", "actors_updated": actors_updated, "errors": errors}


def _estimate_half_life_hours(dates: list[datetime]) -> float | None:
    """
    Estimate empirical half-life from a sorted list of detection timestamps.

    Uses the median inter-observation gap as a proxy for the half-life:
    if an actor rotates an IP every N hours on average, the functional
    half-life is approximately N hours (decay reaches ~0.5 at the typical
    rotation interval).
    """
    if len(dates) < 2:
        return None

    gaps_hours = []
    for i in range(1, len(dates)):
        delta = (dates[i] - dates[i - 1]).total_seconds() / 3600.0
        if delta > 0:
            gaps_hours.append(delta)

    if not gaps_hours:
        return None

    gaps_hours.sort()
    mid = len(gaps_hours) // 2
    median_gap = gaps_hours[mid]

    # Clamp to a reasonable operational range: 1h – 8760h (1 year)
    return max(1.0, min(8760.0, median_gap))


def _load_profile(raw: dict) -> ActorDecayProfile:
    """Reconstruct an ActorDecayProfile from a raw MongoDB document."""
    half_lives = []
    for hl in raw.get("learned_half_lives", []):
        try:
            lu = hl.get("last_updated")
            if isinstance(lu, str):
                lu = datetime.fromisoformat(lu.replace("Z", "+00:00"))
            half_lives.append(LearnedHalfLife(
                ioc_type=hl["ioc_type"],
                half_life_hours=float(hl["half_life_hours"]),
                sample_count=int(hl.get("sample_count", 1)),
                last_updated=lu or datetime.now(timezone.utc),
            ))
        except Exception:
            continue

    created = raw.get("created_at")
    updated = raw.get("updated_at")
    if isinstance(created, str):
        created = datetime.fromisoformat(created.replace("Z", "+00:00"))
    if isinstance(updated, str):
        updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))

    return ActorDecayProfile(
        actor_id=raw["actor_id"],
        learned_half_lives=half_lives,
        created_at=created or datetime.now(timezone.utc),
        updated_at=updated or datetime.now(timezone.utc),
    )
