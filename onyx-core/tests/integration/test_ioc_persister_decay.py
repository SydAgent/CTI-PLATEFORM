"""
Integration tests for the decay recalculation batch loop.

These tests use an in-memory MongoDB mock (mongomock-motor) so they run
offline without a live database. They verify that _process_decay_batch
correctly computes and writes back decay_score, decay_state, and
composite_confidence for a realistic set of IoC documents.

Run:  pytest tests/integration/test_ioc_persister_decay.py -v
"""

from __future__ import annotations

import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Feature gate must be on for the recalculation to run
os.environ["ONYX_DECAY_ENGINE_ENABLED"] = "true"

from onyx_core.services.decay_engine import calculate_decay, classify_decay_state
from onyx_core.services.confidence_composite import calculate_composite_confidence


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _make_ioc(
    ioc_type: str,
    hours_old: float,
    source: str = "cisa_advisory",
    doc_id: str | None = None,
) -> dict:
    detected = datetime.now(timezone.utc) - timedelta(hours=hours_old)
    return {
        "id": doc_id or f"{ioc_type}-test-{int(hours_old)}",
        "ioc_type": ioc_type,
        "valeur": f"test-value-{ioc_type}",
        "source": source,
        "date_detection": detected.isoformat(),
        "corroboration_count": 2,
    }


# ── Unit-level tests of _process_decay_batch ─────────────────────────────────

class TestProcessDecayBatch:
    @pytest.mark.asyncio
    async def test_fresh_ipv4_gets_valid_state(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [_make_ioc("ipv4", hours_old=1.0)]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["updated"] == 1
        assert result["errors"] == 0
        call_kwargs = mock_coll.update_one.call_args[0][1]["$set"]
        assert call_kwargs["decay_score"] > 0.8
        assert call_kwargs["decay_state"] == "valid"

    @pytest.mark.asyncio
    async def test_stale_ip_gets_stale_state(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        # 5 days old IP with default host_type (36h half-life) → heavily decayed
        batch = [_make_ioc("ipv4", hours_old=5 * 24)]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["updated"] == 1
        call_kwargs = mock_coll.update_one.call_args[0][1]["$set"]
        # 120h / 36h half-life → exp(-ln2 * 120/36) ≈ 0.099 → OBSOLETE
        assert call_kwargs["decay_score"] < 0.15
        assert call_kwargs["decay_state"] in ("stale", "obsolete")

    @pytest.mark.asyncio
    async def test_doc_without_date_is_skipped(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [{"id": "no-date", "ioc_type": "ipv4"}]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["updated"] == 0
        mock_coll.update_one.assert_not_called()

    @pytest.mark.asyncio
    async def test_unknown_ioc_type_falls_back_to_ipv4(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [_make_ioc("banana_type", hours_old=2.0)]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["updated"] == 1
        assert result["errors"] == 0

    @pytest.mark.asyncio
    async def test_batch_processes_all_docs(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [
            _make_ioc("ipv4", hours_old=1.0, doc_id="ip-1"),
            _make_ioc("domain", hours_old=24.0, doc_id="dom-1"),
            _make_ioc("sha256", hours_old=48.0, doc_id="hash-1"),
            _make_ioc("url", hours_old=6.0, doc_id="url-1"),
        ]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["updated"] == 4
        assert result["errors"] == 0
        assert mock_coll.update_one.call_count == 4

    @pytest.mark.asyncio
    async def test_composite_confidence_written(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [_make_ioc("ipv4", hours_old=2.0, source="mitre_attack")]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

        await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        call_kwargs = mock_coll.update_one.call_args[0][1]["$set"]
        assert "composite_confidence" in call_kwargs
        assert 0.0 <= call_kwargs["composite_confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_db_error_counted_as_error(self):
        from onyx_api.workers.ioc_persister import _process_decay_batch

        batch = [_make_ioc("ipv4", hours_old=1.0)]
        now = datetime.now(timezone.utc)

        mock_coll = AsyncMock()
        mock_coll.update_one = AsyncMock(side_effect=Exception("DB timeout"))

        result = await _process_decay_batch(
            batch, now, mock_coll,
            calculate_decay, classify_decay_state, calculate_composite_confidence,
        )

        assert result["errors"] == 1
        assert result["updated"] == 0
