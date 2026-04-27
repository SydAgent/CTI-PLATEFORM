"""
ONYX CTI — IoC Decay Engine
Parameterized exponential decay functions per artifact type.

Formula: decay(t) = exp(-ln(2) × Δt / half_life)
At t = half_life: decay = 0.5 exactly (by construction).
At t = 0:         decay = 1.0 (full freshness).

Each function returns a float in [0.0, 1.0].
No state — pure functions, safe to call from async workers and sync code.

Design references:
  - MISP decaying models (app/Model/MispObject.php) — base concept
  - Extended with: per-actor learned half-lives, host-type modulation,
    TLD/registrar modulation, and artifact-subtype dispatch.
"""

from __future__ import annotations

import math
from enum import Enum

# ln(2) — ensures decay(t=half_life) == 0.5 exactly by construction
_LN2 = 0.6931471805599453


def _exp_decay(delta_time: float, half_life: float) -> float:
    """Single exponential decay step. All type-specific functions delegate here."""
    return math.exp(-_LN2 * delta_time / half_life)


class DecayState(str, Enum):
    """
    Six-state discretization of the continuous decay score.
    Maps to preattentive visual encoding (Axe 3 §3.3).
    UI renders each state with distinct hue + shape pair.
    """
    VALID = "valid"           # decay > 0.80  — act immediately
    DEGRADING = "degrading"   # 0.50–0.80     — validate before acting
    STALE = "stale"           # 0.15–0.50     — check external source
    OBSOLETE = "obsolete"     # 0.05–0.15     — do not block without verification
    CONTESTED = "contested"   # attribution contested regardless of freshness
    RETRACTED = "retracted"   # source has retracted the indicator
    FALSE_POSITIVE = "fp_hist" # confirmed false positive — whitelist immediately


def classify_decay_state(decay_score: float) -> DecayState:
    """
    Map a continuous decay score to a discrete DecayState.
    Thresholds derived from operational impact analysis (Axe 1 §AP-03).
    Contested/Retracted/FP states are set externally, not derived from score.
    """
    if decay_score > 0.80:
        return DecayState.VALID
    if decay_score > 0.50:
        return DecayState.DEGRADING
    if decay_score > 0.15:
        return DecayState.STALE
    return DecayState.OBSOLETE


# ──────────────────────────────────────────────────────────────────────────────
# IP Address
# Half-life modulated by hosting type. Bulletproof hosts rotate slowly
# (actor controls the IP); legitimate cloud hosts recycle in hours.
# ──────────────────────────────────────────────────────────────────────────────

_IP_HALF_LIFE_HOURS: dict[str, float] = {
    "bulletproof": 72.0,       # operator controls infra — slow rotation
    "dedicated_criminal": 96.0, # rented for malicious use — moderate
    "tor_exit": 48.0,          # exit nodes rotate on relay schedule
    "residential_proxy": 24.0, # residential pool recycled daily
    "cloud_legitimate": 6.0,   # AWS/Azure/GCP — IPs recycled within hours
    "shared_hosting": 18.0,
    "vpn": 36.0,
    "default": 36.0,
}


def decay_ip(hours_since_seen: float, host_type: str = "default") -> float:
    """IP address decay. Rapid (6h–96h half-life) — most operationally urgent."""
    t_half = _IP_HALF_LIFE_HOURS.get(host_type, _IP_HALF_LIFE_HOURS["default"])
    return _exp_decay(hours_since_seen, t_half)


def decay_ip_with_learned_profile(
    hours_since_seen: float,
    host_type: str = "default",
    learned_half_life_hours: float | None = None,
) -> float:
    """IP decay with actor-specific learned half-life override."""
    if learned_half_life_hours is not None and learned_half_life_hours > 0:
        return _exp_decay(hours_since_seen, learned_half_life_hours)
    return decay_ip(hours_since_seen, host_type)


# ──────────────────────────────────────────────────────────────────────────────
# Domain
# Half-life modulated by TLD (risk profile) and registrar tier.
# Bulletproof registrars indicate actor controls the domain — slower decay.
# ──────────────────────────────────────────────────────────────────────────────

_TLD_BASE_HALF_LIFE_DAYS: dict[str, float] = {
    # High-abuse TLDs — short half-life (frequently re-registered or expired)
    ".tk": 3.0,
    ".ml": 4.0,
    ".ga": 4.0,
    ".cf": 4.0,
    ".xyz": 5.0,
    ".top": 5.0,
    ".gq": 4.0,
    ".icu": 5.0,
    # Nation-state linked
    ".ru": 21.0,
    ".cn": 14.0,
    ".ir": 14.0,
    ".kp": 30.0,  # NK — rare, long-lived infra
    # Standard TLDs — moderate
    ".com": 30.0,
    ".net": 25.0,
    ".org": 45.0,
    ".io": 20.0,
    ".co": 18.0,
    ".info": 12.0,
    "default": 20.0,
}

# Registrar tier: 1=bulletproof (actor controls), 4=reputable (GoDaddy, Namecheap)
_REGISTRAR_TIER_MODIFIER: dict[int, float] = {
    1: 2.0,   # Bulletproof: domain stays malicious, decay slowed
    2: 1.2,
    3: 0.8,
    4: 0.5,   # Reputable: domain can expire/transfer to innocent party quickly
}


def decay_domain(
    days_since_seen: float,
    tld: str = "default",
    registrar_tier: int = 2,
) -> float:
    """Domain decay. Moderate (3–45 day half-life) with TLD and registrar context."""
    base = _TLD_BASE_HALF_LIFE_DAYS.get(tld, _TLD_BASE_HALF_LIFE_DAYS["default"])
    modifier = _REGISTRAR_TIER_MODIFIER.get(registrar_tier, 1.0)
    return _exp_decay(days_since_seen, base * modifier)


# ──────────────────────────────────────────────────────────────────────────────
# File Hashes (SHA-256, SHA-1, MD5)
# Quasi-immutable: a hash identifies a specific binary artifact.
# Decay encodes *operational relevance* (probability of re-encountering the
# file), not validity. A 2019 SHA-256 is still valid for forensic matching
# but unlikely to be seen on a fresh endpoint — floor at 0.30.
# ──────────────────────────────────────────────────────────────────────────────

_HASH_HALF_LIFE_DAYS: dict[str, float] = {
    "sha256": 730.0,  # 2 years — binary is specific enough to remain relevant
    "sha1": 548.0,    # 1.5 years — weaker but still useful
    "md5": 365.0,     # 1 year — collision risk, lower weight
}
_HASH_FLOOR = 0.30  # A known-malicious hash never fully expires for forensics


def decay_hash(
    days_since_seen: float,
    hash_type: str = "sha256",
    revoked: bool = False,
) -> float:
    """File hash decay. Quasi-immutable — floored at 0.30 for forensic retention."""
    if revoked:
        return 0.05
    t_half = _HASH_HALF_LIFE_DAYS.get(hash_type, 365.0)
    return max(_HASH_FLOOR, _exp_decay(days_since_seen, t_half))


def decay_sha256(days_since_seen: float, revoked: bool = False) -> float:
    """Convenience wrapper — delegates to decay_hash('sha256')."""
    return decay_hash(days_since_seen, "sha256", revoked)


# ──────────────────────────────────────────────────────────────────────────────
# URL
# Short half-life — C2 callback paths and phishing pages change frequently.
# ──────────────────────────────────────────────────────────────────────────────

def decay_url(hours_since_seen: float) -> float:
    """URL decay. Short half-life (48h) — C2 paths and phishing pages rotate fast."""
    return _exp_decay(hours_since_seen, 48.0)


# ──────────────────────────────────────────────────────────────────────────────
# Email Address
# Half-life by email role: phishing senders rotate; C2-registration emails
# are kept longer (actor needs them for infrastructure renewal).
# ──────────────────────────────────────────────────────────────────────────────

_EMAIL_HALF_LIFE_DAYS: dict[str, float] = {
    "phishing_sender": 14.0,
    "c2_registration": 90.0,
    "spearphish_target": 180.0,  # targets don't change
    "default": 30.0,
}


def decay_email(days_since_seen: float, email_type: str = "default") -> float:
    """Email address decay. Role-dependent (14–180 day half-life)."""
    t_half = _EMAIL_HALF_LIFE_DAYS.get(email_type, _EMAIL_HALF_LIFE_DAYS["default"])
    return _exp_decay(days_since_seen, t_half)


# ──────────────────────────────────────────────────────────────────────────────
# JA3 / JA4 TLS Fingerprint
# Tied to the malware implementation — persists until malware update.
# Half-life: ~6 months (one major version cycle for most RATs/backdoors).
# ──────────────────────────────────────────────────────────────────────────────

def decay_ja3(days_since_seen: float) -> float:
    """JA3/JA4 fingerprint decay. Long half-life (180 days) — tied to TLS implementation."""
    return _exp_decay(days_since_seen, 180.0)


# ──────────────────────────────────────────────────────────────────────────────
# YARA Rule Hit
# The rule itself does not decay — its HITS do.
# A binary matching a YARA rule circulates ~2 weeks on average before
# defenders update detection or the actor rotates.
# ──────────────────────────────────────────────────────────────────────────────

def decay_yara_hit(days_since_match: float) -> float:
    """YARA rule HIT decay (not the rule). Half-life 14d — binary circulation window."""
    return _exp_decay(days_since_match, 14.0)


# ──────────────────────────────────────────────────────────────────────────────
# Artifact Artifacts (mutex, registry key, named pipe, user-agent)
# Contextually persistent — tied to malware variant lifecycle.
# ──────────────────────────────────────────────────────────────────────────────

_ARTIFACT_HALF_LIFE_DAYS: dict[str, float] = {
    "mutex": 90.0,
    "registry_key": 60.0,
    "named_pipe": 75.0,
    "user_agent": 45.0,
    "default": 60.0,
}


def decay_artifact(days_since_seen: float, artifact_type: str = "default") -> float:
    """Generic artifact decay (mutex, registry key, named pipe, user-agent). 45–90d half-life."""
    t_half = _ARTIFACT_HALF_LIFE_DAYS.get(artifact_type, _ARTIFACT_HALF_LIFE_DAYS["default"])
    return _exp_decay(days_since_seen, t_half)


# ──────────────────────────────────────────────────────────────────────────────
# CVE
# A CVE doesn't "decay" in validity — it decays in *exploitation probability*
# once patching reaches >80% of vulnerable targets (typically 6-12 months).
# ──────────────────────────────────────────────────────────────────────────────

def decay_cve(days_since_publication: float, exploit_available: bool = False) -> float:
    """CVE decay based on exploitation window. Floored at 0.10 for patch tracking."""
    t_half = 180.0 if exploit_available else 365.0
    return max(0.10, _exp_decay(days_since_publication, t_half))


# ──────────────────────────────────────────────────────────────────────────────
# Dispatcher — route by IoC type string
# ──────────────────────────────────────────────────────────────────────────────

def calculate_decay(
    ioc_type: str,
    hours_since_seen: float,
    *,
    host_type: str = "default",
    tld: str = "default",
    registrar_tier: int = 2,
    email_type: str = "default",
    artifact_type: str = "default",
    revoked: bool = False,
    exploit_available: bool = False,
    learned_half_life_hours: float | None = None,
) -> float:
    """
    Central decay dispatcher. Routes to the correct function by ioc_type.

    All time units are HOURS for consistency — internal functions convert as needed.

    Args:
        ioc_type: One of the 14 supported types.
        hours_since_seen: Hours since last observation.
        **kwargs: Type-specific parameters (see individual functions).

    Returns:
        Decay score in [0.0, 1.0].

    Raises:
        ValueError: If ioc_type is unrecognized.
    """
    days = hours_since_seen / 24.0

    match ioc_type:
        case "ipv4" | "ipv6":
            return decay_ip_with_learned_profile(hours_since_seen, host_type, learned_half_life_hours)
        case "domain":
            return decay_domain(days, tld, registrar_tier)
        case "url":
            return decay_url(hours_since_seen)
        case "sha256":
            return decay_sha256(days, revoked)
        case "sha1":
            return decay_hash(days, "sha1", revoked)
        case "md5":
            return decay_hash(days, "md5", revoked)
        case "email":
            return decay_email(days, email_type)
        case "ja3" | "ja4":
            return decay_ja3(days)
        case "mutex" | "registry_key" | "named_pipe" | "user_agent":
            return decay_artifact(days, artifact_type if artifact_type != "default" else ioc_type)
        case "yara_rule":
            return decay_yara_hit(days)
        case "cve":
            return decay_cve(days, exploit_available)
        case _:
            raise ValueError(f"Unsupported IoC type for decay calculation: {ioc_type!r}")
