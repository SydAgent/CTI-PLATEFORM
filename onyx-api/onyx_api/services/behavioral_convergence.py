"""
GC-03: Behavioral Convergence Engine

Detects behavioral overlap between threat actors based on shared MITRE ATT&CK
techniques (Jaccard similarity on TTP sets).

Convergence threshold: Jaccard ≥ 0.65  →  badge displayed in UI.

API contract:
  POST /actors/{id}/convergence-check
    body: {"compare_actor_id": "APT29", "techniques_a": [...], "techniques_b": [...]}
    returns: ConvergenceResult

  GET  /actors/{id}/convergence-peers
    returns: list[ConvergenceResult] sorted by jaccard_score desc
"""

from __future__ import annotations

import math
from dataclasses import dataclass

CONVERGENCE_THRESHOLD = 0.65

# ─── Known actor TTP fingerprints (static, sourced from MITRE ATT&CK groups) ─
# Used when the caller doesn't supply techniques_b for comparison

_ACTOR_TTP_DB: dict[str, set[str]] = {
    "APT29": {
        "T1059.001", "T1071.001", "T1078", "T1566", "T1190", "T1027", "T1055",
        "T1568", "T1547", "T1573", "T1105", "T1003", "T1082", "T1083",
    },
    "APT28": {
        "T1059.001", "T1566", "T1190", "T1548", "T1071.001", "T1036", "T1003",
        "T1072", "T1105", "T1027", "T1082", "T1210",
    },
    "Lazarus Group": {
        "T1059.001", "T1566", "T1486", "T1071.001", "T1055", "T1027",
        "T1547", "T1041", "T1105", "T1082", "T1036",
    },
    "Sandworm Team": {
        "T1059.001", "T1486", "T1190", "T1027", "T1036", "T1055",
        "T1547", "T1072", "T1210", "T1041",
    },
    "Volt Typhoon": {
        "T1078", "T1190", "T1059.001", "T1027", "T1083", "T1018",
        "T1048", "T1041", "T1568",
    },
    "Scattered Spider": {
        "T1059.001", "T1078", "T1621", "T1566", "T1027", "T1047",
        "T1547", "T1482", "T1071.001",
    },
    "FIN7": {
        "T1059.001", "T1566", "T1027", "T1055", "T1547", "T1036",
        "T1003", "T1041", "T1082", "T1105",
    },
    "APT41": {
        "T1059.001", "T1190", "T1566", "T1055", "T1027", "T1036",
        "T1078", "T1547", "T1072", "T1003", "T1082", "T1041",
    },
    "Turla": {
        "T1059.001", "T1027", "T1055", "T1547", "T1036", "T1102",
        "T1573", "T1041", "T1003", "T1082",
    },
    "Mustang Panda": {
        "T1059.001", "T1566", "T1027", "T1547", "T1036", "T1055",
        "T1041", "T1082",
    },
    "OilRig": {
        "T1059.001", "T1566", "T1078", "T1047", "T1027", "T1055",
        "T1082", "T1003", "T1041", "T1105",
    },
    "Gorgon Group": {
        "T1059.001", "T1566", "T1027", "T1055", "T1082",
    },
}


@dataclass(frozen=True)
class ConvergenceResult:
    actor_a: str
    actor_b: str
    jaccard_score: float
    shared_techniques: list[str]
    unique_to_a: list[str]
    unique_to_b: list[str]
    convergent: bool       # True when jaccard_score >= CONVERGENCE_THRESHOLD
    interpretation: str    # Human-readable summary


def jaccard(set_a: set[str], set_b: set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def _interpret(score: float, shared: int) -> str:
    if score >= 0.80:
        return (
            f"Convergence comportementale très élevée ({score:.0%}) — {shared} TTPs partagés. "
            "Possible même groupe ou forte inspiration tactique."
        )
    if score >= 0.65:
        return (
            f"Convergence significative ({score:.0%}) — {shared} TTPs partagés. "
            "Infrastructure ou playbook potentiellement partagés."
        )
    if score >= 0.40:
        return (
            f"Convergence modérée ({score:.0%}) — {shared} TTPs partagés. "
            "Quelques techniques communes, probablement indépendants."
        )
    return (
        f"Faible convergence ({score:.0%}) — {shared} TTPs partagés. "
        "Acteurs distincts avec des profils comportementaux différents."
    )


class BehavioralConvergenceEngine:
    """
    Compare TTP fingerprints of two actors using Jaccard similarity.
    """

    def compare(
        self,
        actor_a: str,
        techniques_a: list[str],
        actor_b: str,
        techniques_b: list[str] | None = None,
    ) -> ConvergenceResult:
        """
        Compare actor_a (using techniques_a) against actor_b.

        If techniques_b is None, falls back to the static TTP database.
        """
        set_a = set(techniques_a)
        set_b = set(techniques_b) if techniques_b is not None else _ACTOR_TTP_DB.get(actor_b, set())
        score = jaccard(set_a, set_b)
        shared = sorted(set_a & set_b)
        return ConvergenceResult(
            actor_a=actor_a,
            actor_b=actor_b,
            jaccard_score=round(score, 4),
            shared_techniques=shared,
            unique_to_a=sorted(set_a - set_b),
            unique_to_b=sorted(set_b - set_a),
            convergent=score >= CONVERGENCE_THRESHOLD,
            interpretation=_interpret(score, len(shared)),
        )

    def find_peers(
        self,
        actor_name: str,
        techniques: list[str],
        min_jaccard: float = 0.30,
        top_n: int = 10,
    ) -> list[ConvergenceResult]:
        """
        Compare actor against all known actors in the static DB.
        Returns sorted list (highest jaccard first), excluding self.
        """
        results: list[ConvergenceResult] = []
        for peer_name, peer_ttps in _ACTOR_TTP_DB.items():
            if peer_name.lower() == actor_name.lower():
                continue
            r = self.compare(actor_name, techniques, peer_name, list(peer_ttps))
            if r.jaccard_score >= min_jaccard:
                results.append(r)
        results.sort(key=lambda r: r.jaccard_score, reverse=True)
        return results[:top_n]


# Module-level singleton
convergence_engine = BehavioralConvergenceEngine()
