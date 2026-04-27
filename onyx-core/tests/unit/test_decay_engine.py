"""
Unit tests for onyx_core.services.decay_engine.

Hypothesis property-based tests verify mathematical invariants that must
hold for all valid inputs, independent of specific values.
Deterministic tests cover boundary conditions and known-good values.
"""

from __future__ import annotations

import math

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from onyx_core.services.decay_engine import (
    DecayState,
    _exp_decay,
    calculate_decay,
    classify_decay_state,
    decay_cve,
    decay_domain,
    decay_hash,
    decay_ip,
    decay_url,
)
from onyx_core.services.confidence_composite import corroboration_score

# ── Strategy helpers ───────────────────────────────────────────────────────────

positive_float = st.floats(min_value=0.0, max_value=100_000.0, allow_nan=False, allow_infinity=False)
small_positive = st.floats(min_value=0.01, max_value=8760.0, allow_nan=False, allow_infinity=False)


# ── _exp_decay invariants ──────────────────────────────────────────────────────

class TestExpDecay:
    def test_zero_time_is_one(self):
        assert _exp_decay(0.0, 36.0) == pytest.approx(1.0)

    def test_half_life_is_exactly_half(self):
        for t_half in [1.0, 12.0, 36.0, 180.0, 730.0 * 24]:
            assert _exp_decay(t_half, t_half) == pytest.approx(0.5, rel=1e-9)

    @given(delta=positive_float, half_life=small_positive)
    def test_always_in_unit_interval(self, delta: float, half_life: float):
        # exp(-x) underflows to 0.0 at extreme delta/half_life ratios — that is correct.
        result = _exp_decay(delta, half_life)
        assert 0.0 <= result <= 1.0

    @given(
        delta1=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        delta2=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        half_life=small_positive,
    )
    def test_monotonically_decreasing(self, delta1: float, delta2: float, half_life: float):
        """Older = lower decay score (more decayed)."""
        assume(delta1 < delta2)
        assert _exp_decay(delta1, half_life) >= _exp_decay(delta2, half_life)


# ── classify_decay_state ───────────────────────────────────────────────────────

class TestClassifyDecayState:
    @pytest.mark.parametrize("score,expected", [
        (1.00, DecayState.VALID),
        (0.81, DecayState.VALID),
        # 0.80 is NOT valid — classify uses strict >, so exactly 0.80 → DEGRADING
        (0.80, DecayState.DEGRADING),
        (0.79, DecayState.DEGRADING),
        (0.51, DecayState.DEGRADING),
        # 0.50 is NOT degrading — strict >, so exactly 0.50 → STALE
        (0.50, DecayState.STALE),
        (0.49, DecayState.STALE),
        (0.16, DecayState.STALE),
        # 0.15 is NOT stale — strict >, so exactly 0.15 → OBSOLETE
        (0.15, DecayState.OBSOLETE),
        (0.14, DecayState.OBSOLETE),
        (0.00, DecayState.OBSOLETE),
    ])
    def test_thresholds(self, score: float, expected: DecayState):
        assert classify_decay_state(score) == expected

    @given(score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False))
    def test_always_returns_a_state(self, score: float):
        result = classify_decay_state(score)
        assert isinstance(result, DecayState)
        assert result in (DecayState.VALID, DecayState.DEGRADING, DecayState.STALE, DecayState.OBSOLETE)


# ── Type-specific decay functions ─────────────────────────────────────────────

class TestDecayIP:
    def test_fresh_ip_near_one(self):
        assert decay_ip(0.0) == pytest.approx(1.0)

    def test_bulletproof_decays_slower_than_cloud(self):
        hours = 24.0
        assert decay_ip(hours, "bulletproof") > decay_ip(hours, "cloud_legitimate")

    @given(hours=positive_float)
    def test_result_in_unit_interval(self, hours: float):
        for host_type in ["bulletproof", "cloud_legitimate", "default", "tor_exit"]:
            r = decay_ip(hours, host_type)
            assert 0.0 <= r <= 1.0  # underflows to 0.0 at extreme durations


class TestDecayDomain:
    def test_fresh_domain_near_one(self):
        assert decay_domain(0.0) == pytest.approx(1.0)

    def test_bulletproof_registrar_decays_slower(self):
        days = 14.0
        assert decay_domain(days, ".com", registrar_tier=1) > decay_domain(days, ".com", registrar_tier=4)

    def test_high_abuse_tld_decays_faster_than_stable(self):
        days = 3.0
        assert decay_domain(days, ".tk") < decay_domain(days, ".org")

    @given(days=positive_float)
    def test_result_in_unit_interval(self, days: float):
        for tld in [".tk", ".com", ".ru", "default"]:
            r = decay_domain(days, tld)
            assert 0.0 <= r <= 1.0  # underflows to 0.0 at extreme durations


class TestDecayHash:
    def test_hash_floor_enforced(self):
        # A very old SHA-256 should never go below 0.30
        assert decay_hash(100_000.0, "sha256") == pytest.approx(0.30)

    def test_revoked_returns_near_zero(self):
        assert decay_hash(0.0, "sha256", revoked=True) == pytest.approx(0.05)

    def test_sha256_lives_longer_than_md5(self):
        days = 200.0
        assert decay_hash(days, "sha256") > decay_hash(days, "md5")

    @given(days=positive_float)
    def test_result_above_floor(self, days: float):
        for h in ["sha256", "sha1", "md5"]:
            r = decay_hash(days, h)
            assert r >= 0.30


class TestDecayURL:
    @given(hours=positive_float)
    def test_result_in_unit_interval(self, hours: float):
        r = decay_url(hours)
        assert 0.0 <= r <= 1.0  # underflows to 0.0 at extreme durations

    def test_half_life_at_48h(self):
        assert decay_url(48.0) == pytest.approx(0.5, rel=1e-6)


class TestDecayCVE:
    def test_floor_enforced(self):
        assert decay_cve(10_000.0) >= 0.10

    def test_exploit_available_decays_faster(self):
        days = 90.0
        assert decay_cve(days, exploit_available=True) < decay_cve(days, exploit_available=False)


# ── calculate_decay dispatcher ────────────────────────────────────────────────

class TestCalculateDecay:
    @pytest.mark.parametrize("ioc_type", [
        "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5",
        "email", "ja3", "ja4", "mutex", "registry_key", "named_pipe",
        "user_agent", "yara_rule", "cve",
    ])
    def test_all_supported_types_dispatch(self, ioc_type: str):
        result = calculate_decay(ioc_type, 24.0)
        assert 0.0 < result <= 1.0

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match="Unsupported IoC type"):
            calculate_decay("banana", 1.0)

    @given(hours=positive_float)
    def test_ipv4_result_in_unit_interval(self, hours: float):
        r = calculate_decay("ipv4", hours)
        assert 0.0 <= r <= 1.0  # underflows to 0.0 at extreme durations

    def test_zero_hours_all_types_near_one(self):
        for ioc_type in ["ipv4", "domain", "url", "sha256", "email"]:
            r = calculate_decay(ioc_type, 0.0)
            assert r >= 0.99, f"{ioc_type} at t=0 should be ≈1.0, got {r}"


# ── corroboration_score ────────────────────────────────────────────────────────

class TestCorroborationScore:
    def test_single_source_is_low(self):
        assert corroboration_score(1) == pytest.approx(1 - math.exp(-0.5))

    def test_six_sources_above_0_95(self):
        assert corroboration_score(6) > 0.95

    def test_monotonically_increasing(self):
        scores = [corroboration_score(n) for n in range(1, 10)]
        for i in range(len(scores) - 1):
            assert scores[i] < scores[i + 1]

    @given(n=st.integers(min_value=1, max_value=100))
    def test_always_at_most_one(self, n: int):
        # At n≥75, exp(-0.5n) underflows to 0.0 so the result reaches exactly 1.0
        assert corroboration_score(n) <= 1.0
