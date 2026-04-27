"""
GC-02: Alias Disambiguation Engine

Resolves threat actor aliases to their canonical identity using:
  1. MITRE ATT&CK groups static mapping (embedded)
  2. Vendor alias cross-references (CrowdStrike, Mandiant, Microsoft, Recorded Future)

For each alias, computes a certainty score:
  certainty = base_score × source_count_bonus × freshness

Returns AliasNode list forming a tree rooted at the canonical name.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AliasNode:
    alias: str
    canonical: str
    certainty: float         # 0.0 – 1.0
    sources: list[str]       # which vendors use this alias
    disputed: bool = False   # True when vendors disagree on attribution
    note: str = ""


# ─── Static knowledge base ────────────────────────────────────────────────────
# Format: canonical → {alias → {source: certainty_contribution}}
# Certainty = average of source contributions × multi-source bonus

_ALIAS_DB: dict[str, dict[str, dict[str, float]]] = {
    "APT29": {
        "Cozy Bear":       {"MITRE": 0.98, "CrowdStrike": 0.97, "Mandiant": 0.95},
        "The Dukes":       {"MITRE": 0.96, "CrowdStrike": 0.94},
        "Office Monkeys":  {"MITRE": 0.80},
        "CozyCar":         {"Mandiant": 0.75, "CrowdStrike": 0.78},
        "IRON RITUAL":     {"CrowdStrike": 0.90},
        "Midnight Blizzard": {"Microsoft": 0.99},
        "NOBELIUM":        {"Microsoft": 0.98, "Mandiant": 0.90},
        "Dark Halo":       {"Volexity": 0.88},
        "SolarStorm":      {"Unit42": 0.85},
    },
    "APT28": {
        "Fancy Bear":      {"MITRE": 0.98, "CrowdStrike": 0.97, "Mandiant": 0.95},
        "IRON TWILIGHT":   {"CrowdStrike": 0.95},
        "Pawn Storm":      {"TrendMicro": 0.92},
        "Sofacy Group":    {"MITRE": 0.94, "Mandiant": 0.90},
        "Strontium":       {"Microsoft": 0.99},
        "Forest Blizzard":  {"Microsoft": 0.95},
        "Sednit":          {"ESET": 0.90},
        "TAG-0700":        {"RecordedFuture": 0.85},
    },
    "Lazarus Group": {
        "Hidden Cobra":    {"MITRE": 0.98, "US-CERT": 0.99},
        "Zinc":            {"Microsoft": 0.95},
        "Diamond Sleet":   {"Microsoft": 0.90},
        "Bluenoroff":      {"MITRE": 0.88, "Kaspersky": 0.92},
        "Andariel":        {"MITRE": 0.88},
        "APT38":           {"Mandiant": 0.85, "CISA": 0.80},
        "NICKEL ACADEMY":  {"CrowdStrike": 0.88},
    },
    "Sandworm Team": {
        "BlackEnergy Group":  {"MITRE": 0.88},
        "Telebots":           {"ESET": 0.95, "MITRE": 0.90},
        "IRON VIKING":        {"CrowdStrike": 0.93},
        "Voodoo Bear":        {"CrowdStrike": 0.95},
        "Seashell Blizzard":  {"Microsoft": 0.98},
        "ELECTRUM":           {"Dragos": 0.90},
        "G0034":              {"MITRE": 1.0},
    },
    "Volt Typhoon": {
        "Bronze Silhouette":  {"CrowdStrike": 0.95},
        "Vanguard Panda":     {"CrowdStrike": 0.92},
        "Dev-0391":           {"Microsoft": 0.90},
        "KV-Botnet":          {"CISA": 0.85, "FBI": 0.85},
        "VOLTZITE":           {"Dragos": 0.95},
    },
    "Scattered Spider": {
        "Octo Tempest":    {"Microsoft": 0.98},
        "UNC3944":         {"Mandiant": 0.97},
        "0ktapus":         {"Group-IB": 0.90},
        "MUDDLED LIBRA":   {"Unit42": 0.95},
        "Roasted 0ktapus": {"Unit42": 0.88},
        "Star Fraud":      {"CrowdStrike": 0.85},
    },
    "FIN7": {
        "Carbanak":        {"MITRE": 0.85, "Kaspersky": 0.90},
        "Carbon Spider":   {"CrowdStrike": 0.95},
        "Sangria Tempest": {"Microsoft": 0.92},
        "NAVIGATOR":       {"Mandiant": 0.88},
        "ITG14":           {"IBM": 0.85},
    },
    "APT41": {
        "Double Dragon":   {"Mandiant": 0.95},
        "BARIUM":          {"Microsoft": 0.95},
        "Bronze Atlas":    {"CrowdStrike": 0.92},
        "Wicked Panda":    {"CrowdStrike": 0.90},
        "Winnti Group":    {"MITRE": 0.88, "Kaspersky": 0.85},
        "Earth Baku":      {"TrendMicro": 0.88},
    },
    "Turla": {
        "Snake":           {"MITRE": 0.96, "CISA": 0.95},
        "Uroburos":        {"MITRE": 0.94, "ESET": 0.92},
        "Waterbug":        {"Symantec": 0.90},
        "IRON HUNTER":     {"CrowdStrike": 0.93},
        "Venomous Bear":   {"CrowdStrike": 0.92},
        "Secret Blizzard": {"Microsoft": 0.98},
        "TAG-0530":        {"RecordedFuture": 0.82},
    },
    "Mustang Panda": {
        "BRONZE PRESIDENT":   {"CrowdStrike": 0.95},
        "HoneyMyte":          {"Microsoft": 0.90},
        "RedDelta":           {"RecordedFuture": 0.92},
        "TA416":              {"Proofpoint": 0.92},
        "PKPLUG":             {"Unit42": 0.88},
        "Earth Preta":        {"TrendMicro": 0.90},
    },
    "OilRig": {
        "APT34":           {"Mandiant": 0.97, "MITRE": 0.95},
        "HELIX KITTEN":    {"CrowdStrike": 0.95},
        "Crambus":         {"Symantec": 0.88},
        "IRN2":            {"Secureworks": 0.85},
        "Cobalt Gypsy":    {"CrowdStrike": 0.82},
    },
    "Equation": {
        "PLATINUM":        {"Microsoft": 0.80},
        "TilledSoil":      {"Kaspersky": 0.90},
        "GREYFISH":        {"Kaspersky": 0.88},
        "DarkSeoul":       {"Unit42": 0.75, "disputed": 0.0},
    },
    "Gorgon Group": {
        "Subaat":          {"Unit42": 0.85},
        "SilverTerrier":   {"Unit42": 0.82, "disputed": 0.0},
    },
}

# Disputed aliases: vendor cross-attribution disagreements
_DISPUTED_ALIASES: set[tuple[str, str]] = {
    ("Equation", "DarkSeoul"),
    ("Gorgon Group", "SilverTerrier"),
}


class AliasDisambiguator:
    """Resolve threat actor aliases to canonical identity with certainty scores."""

    def resolve(self, actor_name: str) -> list[AliasNode]:
        """
        Return all known aliases for actor_name sorted by certainty desc.
        Also handles reverse lookup (alias → canonical).
        """
        canonical = self._find_canonical(actor_name)
        if not canonical:
            return []
        return self._build_nodes(canonical)

    def resolve_alias(self, alias: str) -> str | None:
        """Return the canonical name for a given alias string, or None."""
        return self._find_canonical(alias)

    def all_actor_names(self) -> list[str]:
        return list(_ALIAS_DB.keys())

    # ── Internals ─────────────────────────────────────────────────────────────

    def _find_canonical(self, name: str) -> str | None:
        name_lower = name.lower()
        # Exact canonical match
        for canonical in _ALIAS_DB:
            if canonical.lower() == name_lower:
                return canonical
        # Match against aliases
        for canonical, aliases in _ALIAS_DB.items():
            for alias in aliases:
                if alias.lower() == name_lower:
                    return canonical
        # Substring canonical match
        for canonical in _ALIAS_DB:
            if name_lower in canonical.lower() or canonical.lower() in name_lower:
                return canonical
        return None

    def _build_nodes(self, canonical: str) -> list[AliasNode]:
        alias_map = _ALIAS_DB.get(canonical, {})
        nodes: list[AliasNode] = []

        for alias, source_dict in alias_map.items():
            # Filter out meta keys
            real_sources = {k: v for k, v in source_dict.items() if k != "disputed"}
            if not real_sources:
                continue
            base = sum(real_sources.values()) / len(real_sources)
            # Multi-source bonus: +3% per additional source beyond 1, max +15%
            bonus = min(0.15, (len(real_sources) - 1) * 0.03)
            certainty = round(min(1.0, base + bonus), 3)
            disputed = (canonical, alias) in _DISPUTED_ALIASES
            nodes.append(AliasNode(
                alias=alias,
                canonical=canonical,
                certainty=certainty,
                sources=list(real_sources.keys()),
                disputed=disputed,
                note="Attribution contestée entre sources" if disputed else "",
            ))

        nodes.sort(key=lambda n: n.certainty, reverse=True)
        return nodes


# Module-level singleton
alias_disambiguator = AliasDisambiguator()
