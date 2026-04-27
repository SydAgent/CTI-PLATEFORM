"""
Unit tests for onyx_core.services.confidence_composite.

Property-based tests verify the composite score stays within [0, 1]
and that score ordering holds (better source + fresher = higher confidence).
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from onyx_core.services.confidence_composite import (
    ConfidenceBreakdown,
    ConfidenceWeights,
    _CONTEXTUAL_RELEVANCE_PRIOR,
    calculate_composite_confidence,
    contestation_penalty,
    contextual_relevance,
    corroboration_score,
    get_source_reliability,
)


# ── ConfidenceWeights ──────────────────────────────────────────────────────────

class TestConfidenceWeights:
    def test_default_weights_sum_to_one(self):
        w = ConfidenceWeights()
        total = w.source + w.corroboration + w.freshness + w.context + w.analyst
        assert total == pytest.approx(1.0, abs=0.001)

    def test_invalid_weights_raise(self):
        with pytest.raises(ValueError, match="sum to 1.0"):
            ConfidenceWeights(source=0.5, corroboration=0.5, freshness=0.5, context=0.0, analyst=0.0)

    def test_frozen_prevents_mutation(self):
        w = ConfidenceWeights()
        with pytest.raises(Exception):
            w.source = 0.99  # type: ignore[misc]


# ── get_source_reliability ─────────────────────────────────────────────────────

class TestGetSourceReliability:
    def test_known_tier1_source(self):
        assert get_source_reliability("mitre_attack") == pytest.approx(1.0)

    def test_known_tier3_source(self):
        assert get_source_reliability("openphish") == pytest.approx(0.62)

    def test_unknown_source_returns_low(self):
        score = get_source_reliability("totally_unknown_xyz")
        assert score == pytest.approx(0.15)

    def test_prefix_match_works(self):
        # "mandiant_apt_report_2024" → "mandiant_apt" prefix
        score = get_source_reliability("mandiant_apt_report_2024")
        assert score == pytest.approx(0.92)

    def test_case_insensitive(self):
        assert get_source_reliability("MITRE_ATTACK") == pytest.approx(1.0)
        assert get_source_reliability("Mitre_Attack") == pytest.approx(1.0)

    def test_tier1_higher_than_tier4(self):
        assert get_source_reliability("cisa_advisory") > get_source_reliability("dark_web_scrape")


# ── contextual_relevance ───────────────────────────────────────────────────────

class TestContextualRelevance:
    def test_no_campaign_context_returns_prior(self):
        result = contextual_relevance(["Finance"], ["US"], [], [])
        assert result == pytest.approx(_CONTEXTUAL_RELEVANCE_PRIOR)

    def test_perfect_sector_match_above_prior(self):
        result = contextual_relevance(["Finance"], ["US"], ["Finance"], ["US"])
        assert result > _CONTEXTUAL_RELEVANCE_PRIOR

    def test_no_intersection_stays_at_prior(self):
        result = contextual_relevance(["Finance"], ["US"], ["Energy"], ["DE"])
        assert result == pytest.approx(_CONTEXTUAL_RELEVANCE_PRIOR)

    def test_partial_match_between_prior_and_one(self):
        result = contextual_relevance(["Finance", "Energy"], ["US"], ["Finance"], ["DE"])
        assert _CONTEXTUAL_RELEVANCE_PRIOR < result < 1.0

    def test_result_capped_at_one(self):
        sectors = ["Finance", "Energy", "Gov", "Health", "Telco"]
        result = contextual_relevance(sectors, ["US", "DE", "FR"], sectors, ["US", "DE", "FR"])
        assert result <= 1.0


# ── contestation_penalty ──────────────────────────────────────────────────────

class TestContestationPenalty:
    def test_not_contested_is_one(self):
        assert contestation_penalty(contested=False) == pytest.approx(1.0)

    def test_contested_reduces_score(self):
        assert contestation_penalty(contested=True, contestation_certainty=0.5) < 1.0

    def test_contested_floor_at_0_65(self):
        assert contestation_penalty(contested=True, contestation_certainty=0.0) == pytest.approx(0.65)

    def test_contested_certain_is_one(self):
        assert contestation_penalty(contested=True, contestation_certainty=1.0) == pytest.approx(1.0)


# ── calculate_composite_confidence ────────────────────────────────────────────

class TestCalculateCompositeConfidence:
    def test_returns_breakdown_instance(self):
        result = calculate_composite_confidence(source="mitre_attack", decay_score=0.9)
        assert isinstance(result, ConfidenceBreakdown)

    def test_composite_in_unit_interval(self):
        result = calculate_composite_confidence(source="mitre_attack", decay_score=0.9)
        assert 0.0 <= result.composite <= 1.0

    def test_high_quality_inputs_produce_high_score(self):
        result = calculate_composite_confidence(
            source="mitre_attack",
            decay_score=0.95,
            corroboration_count=5,
            analyst_override_score=90,
        )
        assert result.composite > 0.75

    def test_low_quality_inputs_produce_low_score(self):
        result = calculate_composite_confidence(
            source="unknown",
            decay_score=0.05,
            corroboration_count=1,
            analyst_override_score=10,
        )
        assert result.composite < 0.40

    def test_contestation_lowers_composite(self):
        base = calculate_composite_confidence(source="cisa_advisory", decay_score=0.8)
        contested = calculate_composite_confidence(
            source="cisa_advisory",
            decay_score=0.8,
            contested=True,
            contestation_certainty=0.0,
        )
        assert contested.composite < base.composite

    def test_analyst_override_replaces_default_analyst_component(self):
        no_override = calculate_composite_confidence(source="otx_alienvault", decay_score=0.6)
        with_override = calculate_composite_confidence(
            source="otx_alienvault",
            decay_score=0.6,
            analyst_override_score=100,
        )
        assert with_override.analyst_override == pytest.approx(1.0)
        assert no_override.analyst_override is None

    @given(
        decay=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        n=st.integers(min_value=1, max_value=20),
    )
    def test_composite_always_in_unit_interval(self, decay: float, n: int):
        result = calculate_composite_confidence(
            source="unknown",
            decay_score=decay,
            corroboration_count=n,
        )
        assert 0.0 <= result.composite <= 1.0

    @given(decay=st.floats(min_value=0.5, max_value=1.0, allow_nan=False, allow_infinity=False))
    def test_better_source_higher_score(self, decay: float):
        high = calculate_composite_confidence(source="mitre_attack", decay_score=decay)
        low = calculate_composite_confidence(source="unknown", decay_score=decay)
        assert high.composite > low.composite

    @given(
        decay1=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        decay2=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    def test_fresher_ioc_higher_score_same_source(self, decay1: float, decay2: float):
        assume(decay1 < decay2)
        r1 = calculate_composite_confidence(source="cisa_advisory", decay_score=decay1)
        r2 = calculate_composite_confidence(source="cisa_advisory", decay_score=decay2)
        assert r1.composite <= r2.composite
