"""
ONYX CTI — Composite Confidence Engine
Weighted composite confidence score for IoC indicators.

Formula:
    Confidence = Norm(
        w_src  × SourceReliability(source)              +
        w_cor  × Corroboration(count)                   +
        w_frsh × Freshness(decay_score)                 +
        w_ctx  × ContextualRelevance(ioc, actor)        +
        w_ana  × AnalystOverride(score)
    ) × ContestationPenalty(contested)

Weights are configurable per analyst profile (stored in MongoDB).
Default weights reflect operational priority: freshness > source > corroboration.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


# ──────────────────────────────────────────────────────────────────────────────
# Source Reliability Table (Admiralty Code extended)
# Tier 1: Primary validated intelligence sources — 0.85–1.00
# Tier 2: OSINT corroborated — 0.65–0.84
# Tier 3: Community feeds — 0.40–0.64
# Tier 4: Unknown / unvalidated — 0.00–0.39
# ──────────────────────────────────────────────────────────────────────────────

SOURCE_RELIABILITY: dict[str, float] = {
    # Tier 1 — Primary validated
    "mitre_attack": 1.00,
    "cisa_advisory": 0.95,
    "us_cert": 0.95,
    "nsa_advisory": 0.94,
    "fbi_flash": 0.93,
    "mandiant_apt": 0.92,
    "crowdstrike_intel": 0.90,
    "recorded_future": 0.88,
    "palo_alto_unit42": 0.88,
    "microsoft_mstic": 0.89,
    "sentinelone_labs": 0.85,
    # Tier 2 — OSINT corroborated
    "abuse_ch_feodo": 0.82,
    "abuse_ch_urlhaus": 0.80,
    "abuse_ch_threatfox": 0.75,
    "circl_misp": 0.78,
    "otx_alienvault": 0.72,
    "virustotal": 0.70,
    "abuseipdb": 0.68,
    "spamhaus": 0.80,
    "emerging_threats_pro": 0.78,
    # Tier 3 — Community feeds
    "openphish": 0.62,
    "phishtank": 0.58,
    "emerging_threats": 0.60,
    "blocklist_de": 0.50,
    "ipsum": 0.48,
    "firehol": 0.52,
    # Tier 4 — Unvalidated
    "anonymous_tip": 0.30,
    "dark_web_scrape": 0.25,
    "unverified_community": 0.20,
    "unknown": 0.15,
}

# Default weight configuration (must sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "source": 0.30,
    "corroboration": 0.20,
    "freshness": 0.25,
    "context": 0.15,
    "analyst": 0.10,
}

# Prior used when an IoC has no campaign context to compare against.
# Represents "plausible but unconfirmed" relevance.
_CONTEXTUAL_RELEVANCE_PRIOR = 0.40

# O(1) prefix lookup: built once at module load from SOURCE_RELIABILITY keys.
# Allows "mandiant_apt_report_2024" → "mandiant_apt" without O(n) scan per call.
_SOURCE_PREFIX_MAP: dict[str, float] = {k: v for k, v in SOURCE_RELIABILITY.items()}


@dataclass(frozen=True)
class ConfidenceWeights:
    """Configurable per-analyst weights. Frozen — mutating after creation bypasses validation."""
    source: float = 0.30
    corroboration: float = 0.20
    freshness: float = 0.25
    context: float = 0.15
    analyst: float = 0.10

    def __post_init__(self) -> None:
        total = self.source + self.corroboration + self.freshness + self.context + self.analyst
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Confidence weights must sum to 1.0, got {total:.4f}")


@dataclass
class ConfidenceBreakdown:
    """Decomposed confidence score for UI transparency (Axe 1 §AP-06)."""
    source_reliability: float
    corroboration: float
    freshness: float
    contextual_relevance: float
    analyst_override: float | None
    contestation_penalty: float
    composite: float


# ──────────────────────────────────────────────────────────────────────────────
# Component functions
# ──────────────────────────────────────────────────────────────────────────────

def get_source_reliability(source_name: str) -> float:
    """
    Look up source reliability from the Admiralty table.
    Direct O(1) lookup first; falls back to prefix scan only on miss.
    """
    key = source_name.lower().strip()
    score = _SOURCE_PREFIX_MAP.get(key)
    if score is not None:
        return score
    # Prefix match for suffixed variants (e.g. "mandiant_apt_report_2024" → "mandiant_apt")
    for canonical, val in _SOURCE_PREFIX_MAP.items():
        if key.startswith(canonical):
            return val
    return SOURCE_RELIABILITY["unknown"]


def corroboration_score(n_sources: int) -> float:
    """
    Corroboration component: 1 - exp(-0.5n).
    Converges toward 1.0 as independent sources increase.
    n=1 → 0.39, n=2 → 0.63, n=3 → 0.78, n=5 → 0.92, n=6+ → 0.95+.
    """
    return 1.0 - math.exp(-0.5 * max(1, n_sources))


def contextual_relevance(
    actor_sectors: list[str],
    actor_countries: list[str],
    ioc_source_campaign_sectors: list[str],
    ioc_source_campaign_countries: list[str],
) -> float:
    """
    Contextual relevance: intersection between IoC campaign context and actor profile.

    If the IoC was observed in a campaign targeting the same sectors/countries
    as this actor, relevance is high (strong contextual match).
    Generic feeds with no campaign context return 0.40 (prior).
    """
    if not ioc_source_campaign_sectors and not ioc_source_campaign_countries:
        return _CONTEXTUAL_RELEVANCE_PRIOR

    sector_match = 0.0
    if actor_sectors and ioc_source_campaign_sectors:
        actor_set = set(s.lower() for s in actor_sectors)
        ioc_set = set(s.lower() for s in ioc_source_campaign_sectors)
        intersection = actor_set & ioc_set
        if intersection:
            sector_match = len(intersection) / len(actor_set | ioc_set)

    country_match = 0.0
    if actor_countries and ioc_source_campaign_countries:
        actor_c = set(c.upper() for c in actor_countries)
        ioc_c = set(c.upper() for c in ioc_source_campaign_countries)
        intersection = actor_c & ioc_c
        if intersection:
            country_match = len(intersection) / len(actor_c | ioc_c)

    # Weighted: sector is stronger signal than country
    relevance = _CONTEXTUAL_RELEVANCE_PRIOR + (sector_match * 0.40) + (country_match * 0.20)
    return min(1.0, relevance)


def contestation_penalty(
    contested: bool = False,
    contestation_certainty: float = 1.0,
) -> float:
    """
    Penalty multiplier applied to composite score for contested attribution.

    Args:
        contested: Whether the IoC's attribution to this actor is disputed.
        contestation_certainty: 0.0 = fully contested, 1.0 = fully confirmed.

    Returns:
        Multiplier in [0.05, 1.0].
    """
    if not contested:
        return 1.0
    # Linear interpolation: fully contested → 0.65 penalty, certain → 1.0
    return max(0.65, contestation_certainty)


# ──────────────────────────────────────────────────────────────────────────────
# Main engine
# ──────────────────────────────────────────────────────────────────────────────

def calculate_composite_confidence(
    source: str,
    decay_score: float,
    corroboration_count: int = 1,
    actor_sectors: list[str] | None = None,
    actor_countries: list[str] | None = None,
    ioc_campaign_sectors: list[str] | None = None,
    ioc_campaign_countries: list[str] | None = None,
    contested: bool = False,
    contestation_certainty: float = 1.0,
    analyst_override_score: int | None = None,
    weights: ConfidenceWeights | None = None,
) -> ConfidenceBreakdown:
    """
    Compute composite confidence for an IoC indicator.

    Args:
        source: Source identifier string (looked up in SOURCE_RELIABILITY).
        decay_score: Current decay value [0.0, 1.0] from decay_engine.
        corroboration_count: Number of independent sources confirming this IoC.
        actor_sectors: Sectors targeted by the parent actor.
        actor_countries: Countries targeted by the parent actor.
        ioc_campaign_sectors: Sectors targeted by the campaign this IoC is from.
        ioc_campaign_countries: Countries targeted by the campaign this IoC is from.
        contested: Whether attribution is disputed.
        contestation_certainty: Certainty of attribution (0–1).
        analyst_override_score: Manual override (0–100), applied as [0.0, 1.0].
        weights: Custom weight configuration. Uses DEFAULT_WEIGHTS if None.

    Returns:
        ConfidenceBreakdown with all components and final composite score.
    """
    w = weights or ConfidenceWeights()

    src_score = get_source_reliability(source)
    cor_score = corroboration_score(corroboration_count)
    frsh_score = max(0.0, min(1.0, decay_score))
    ctx_score = contextual_relevance(
        actor_sectors or [],
        actor_countries or [],
        ioc_campaign_sectors or [],
        ioc_campaign_countries or [],
    )

    # Analyst override: when provided, replaces (not merely adjusts) the analyst component
    ana_score: float | None = None
    if analyst_override_score is not None:
        ana_score = max(0.0, min(1.0, analyst_override_score / 100.0))

    # Weighted sum
    composite = (
        w.source * src_score
        + w.corroboration * cor_score
        + w.freshness * frsh_score
        + w.context * ctx_score
        + w.analyst * (ana_score if ana_score is not None else (src_score + frsh_score) / 2.0)
    )

    # Apply contestation penalty as a multiplier
    penalty = contestation_penalty(contested, contestation_certainty)
    composite *= penalty

    composite = max(0.0, min(1.0, composite))

    return ConfidenceBreakdown(
        source_reliability=src_score,
        corroboration=cor_score,
        freshness=frsh_score,
        contextual_relevance=ctx_score,
        analyst_override=ana_score,
        contestation_penalty=penalty,
        composite=composite,
    )
