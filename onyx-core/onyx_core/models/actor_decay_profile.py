"""
ONYX CTI — Actor Decay Profile Model
Per-actor learned half-life overrides for the decay engine.

Stored in MongoDB collection `actor_decay_profiles`.
Updated daily by decay_learning_worker.py based on observed IoC rotation speed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LearnedHalfLife(BaseModel):
    """Learned half-life for a single IoC type, derived from observed rotation."""
    model_config = ConfigDict(frozen=True)

    ioc_type: Literal[
        "ipv4", "ipv6", "domain", "url",
        "sha256", "sha1", "md5", "email",
        "ja3", "ja4", "mutex", "registry_key",
        "named_pipe", "user_agent", "yara_rule", "cve",
    ]
    half_life_hours: float = Field(
        ...,
        gt=0.0,
        description="Learned half-life in hours for this actor+type combination",
    )
    sample_count: int = Field(
        default=1,
        ge=1,
        description="Number of IoC rotations observed — low count = low confidence",
    )
    last_updated: datetime = Field(
        ...,
        description="UTC timestamp of last learning update",
    )


class ActorDecayProfile(BaseModel):
    """
    Per-actor decay profile storing learned half-life overrides.

    When an actor consistently rotates IPs faster or slower than the global
    default, the learning worker updates this profile. The decay engine
    uses these overrides instead of the global half-life table.

    Feature flag: ONYX_DECAY_ENGINE_ENABLED must be true for overrides to apply.
    """
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_default=True,
    )

    actor_id: str = Field(
        ...,
        min_length=1,
        description="STIX threat-actor ID (e.g. threat-actor--apt29)",
    )
    learned_half_lives: list[LearnedHalfLife] = Field(
        default_factory=list,
        description="Per-type learned half-life overrides",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp of profile creation",
    )
    updated_at: datetime = Field(
        ...,
        description="UTC timestamp of last update",
    )

    def get_half_life_hours(self, ioc_type: str) -> float | None:
        """Return the learned half-life for a given IoC type, or None if not yet learned."""
        for entry in self.learned_half_lives:
            if entry.ioc_type == ioc_type:
                return entry.half_life_hours
        return None

    def update_half_life(
        self,
        ioc_type: str,
        observed_half_life_hours: float,
        now: datetime,
    ) -> "ActorDecayProfile":
        """
        Return a new profile with the half-life for ioc_type updated.
        Uses exponential moving average (α=0.3) to smooth out outliers.
        """
        _ALPHA = 0.3
        updated = []
        found = False
        for entry in self.learned_half_lives:
            if entry.ioc_type == ioc_type:
                smoothed = (1 - _ALPHA) * entry.half_life_hours + _ALPHA * observed_half_life_hours
                updated.append(LearnedHalfLife(
                    ioc_type=entry.ioc_type,
                    half_life_hours=round(smoothed, 2),
                    sample_count=entry.sample_count + 1,
                    last_updated=now,
                ))
                found = True
            else:
                updated.append(entry)
        if not found:
            updated.append(LearnedHalfLife(
                ioc_type=ioc_type,  # type: ignore[arg-type]
                half_life_hours=observed_half_life_hours,
                sample_count=1,
                last_updated=now,
            ))
        return ActorDecayProfile(
            actor_id=self.actor_id,
            learned_half_lives=updated,
            created_at=self.created_at,
            updated_at=now,
        )
