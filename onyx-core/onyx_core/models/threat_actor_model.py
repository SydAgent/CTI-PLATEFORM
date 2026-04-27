"""
ONYX CTI v5.0 SOVEREIGN — Modèle de Données Strict : Acteur de la Menace
=========================================================================

Implémente le modèle à 7 champs structurels obligatoires pour la fiche
de renseignement d'un acteur de la menace (Threat Actor Intelligence Card).

Chaque champ est strictement typé via Pydantic v2 avec validation exhaustive.
L'instanciation échoue si l'un des 7 champs critiques est manquant ou mal typé.

Architecture :
  1. Identité          — Nom, alias, type, pays d'origine
  2. Profil Opérationnel — Objectifs, secteurs ciblés
  3. Techniques MITRE   — TTPs ATT&CK liés (id, nom, tactique, kill chain)
  4. IOCs Liés          — Indicateurs de compromission associés
  5. Campagnes Récentes — Opérations attribuées
  6. Scoring Dynamique  — Score multidimensionnel normalisé 0-100
  7. Métadonnées        — Dates d'observation, sources, confiance

Référence : STIX 2.1 §4.17, MITRE ATT&CK v14, ISO/IEC 27032
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from onyx_core.services.decay_engine import DecayState


# ═══════════════════════════════════════════════════════════════════════════════
# Énumérations
# ═══════════════════════════════════════════════════════════════════════════════

class TypeActeur(str, Enum):
    """Classification du type d'acteur de la menace."""
    APT = "APT"
    CYBERCRIMINEL = "Cybercriminel"
    HACKTIVISTE = "Hacktiviste"
    ETAT_NATION = "État-Nation"
    INSIDER = "Insider"
    INCONNU = "Inconnu"


class NiveauPriorite(str, Enum):
    """Niveau de priorité de la menace."""
    CRITIQUE = "critique"
    ELEVEE = "élevée"
    MOYENNE = "moyenne"
    FAIBLE = "faible"
    INFO = "information"


class PhaseKillChain(str, Enum):
    """Phases de la kill chain MITRE ATT&CK."""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


# ═══════════════════════════════════════════════════════════════════════════════
# Sous-modèles (composants des 7 champs)
# ═══════════════════════════════════════════════════════════════════════════════

class TechniqueMITRE(BaseModel):
    """
    Technique MITRE ATT&CK associée à l'acteur.
    Référence : https://attack.mitre.org/techniques/
    """
    model_config = ConfigDict(frozen=True)

    id: StrictStr = Field(
        ...,
        description="Identifiant MITRE (ex: T1566, T1059.001)",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    nom: StrictStr = Field(
        ...,
        min_length=1,
        description="Nom de la technique (ex: Phishing)",
    )
    tactique: StrictStr = Field(
        ...,
        min_length=1,
        description="Tactique ATT&CK (ex: Initial Access)",
    )
    phase_kill_chain: PhaseKillChain = Field(
        ...,
        description="Phase correspondante dans la kill chain",
    )


class ReferenceIOC(BaseModel):
    """
    Référence à un indicateur de compromission (IOC) lié à l'acteur.
    Chaque IOC est traçable via sa source et sa date de détection.
    """
    model_config = ConfigDict(frozen=True)

    type_ioc: Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "cve"] = Field(
        ...,
        description="Type de l'indicateur",
    )
    valeur: StrictStr = Field(
        ...,
        min_length=1,
        description="Valeur brute de l'IOC (ex: 185.220.101.45)",
    )
    confiance: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Niveau de confiance de l'IOC (0-100)",
    )
    source: StrictStr = Field(
        ...,
        min_length=1,
        description="Source de renseignement (ex: abuse.ch Feodo Tracker)",
    )
    date_detection: datetime = Field(
        ...,
        description="Date de première détection (UTC)",
    )
    severite: NiveauPriorite = Field(
        default=NiveauPriorite.ELEVEE,
        description="Sévérité de l'IOC",
    )

    # ── Decay engine fields (Phase 1 — all optional, backward-compatible) ──
    decay_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Current decay value [0.0, 1.0] from decay_engine",
    )
    decay_state: DecayState | None = Field(
        default=None,
        description="Discretized decay state for preattentive UI encoding",
    )
    corroboration_count: int = Field(
        default=1,
        ge=1,
        description="Number of independent sources confirming this IoC",
    )
    composite_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Composite confidence score from confidence_composite engine",
    )
    last_decay_calculated: datetime | None = Field(
        default=None,
        description="UTC timestamp of last decay recalculation",
    )


class CampagneInfo(BaseModel):
    """
    Campagne d'attaque attribuée à l'acteur.
    Représente une opération offensive identifiée avec dates et impact.
    """
    nom: StrictStr = Field(
        ...,
        min_length=1,
        description="Nom de la campagne (ex: SolarWinds / SUNBURST 2020)",
    )
    date_debut: datetime = Field(
        ...,
        description="Date de début de la campagne (UTC)",
    )
    date_fin: datetime | None = Field(
        default=None,
        description="Date de fin (None = en cours)",
    )
    description: StrictStr = Field(
        ...,
        min_length=1,
        description="Description de la campagne et de son vecteur d'attaque",
    )
    impact: StrictStr = Field(
        ...,
        min_length=1,
        description="Impact observé (ex: Exfiltration de données gouvernementales)",
    )
    secteurs_cibles: list[StrictStr] = Field(
        default_factory=list,
        description="Secteurs impactés par la campagne",
    )


class ScoreMenace(BaseModel):
    """
    Score de menace multidimensionnel.

    Formule du score global :
        global = (technique × 0.3) + (impact × 0.3) + (activite × 0.4)

    Justification mathématique :
        - L'activité (0.4) est surpondérée : un acteur récemment actif
          représente un danger immédiat supérieur, indépendamment de
          son niveau technique historique.
        - Technique et Impact (0.3 chacun) représentent la capacité
          offensive et le potentiel de dommage structurel.
    """
    model_config = ConfigDict(frozen=True)

    technique: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Score technique : sophistication des TTPs (0-100)",
    )
    impact: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Score impact : criticité des secteurs ciblés (0-100)",
    )
    activite: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Score activité : fraîcheur des IOCs et campagnes (0-100)",
    )
    global_score: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Score global pondéré : tech×0.3 + impact×0.3 + activité×0.4",
    )

    @model_validator(mode="after")
    def valider_score_global(self) -> "ScoreMenace":
        """Vérifie que le score global correspond à la formule de pondération."""
        attendu = round(self.technique * 0.3 + self.impact * 0.3 + self.activite * 0.4)
        if abs(self.global_score - attendu) > 1:
            raise ValueError(
                f"Score global ({self.global_score}) ne correspond pas à la formule "
                f"(technique×0.3 + impact×0.3 + activité×0.4 = {attendu})"
            )
        return self


# ═══════════════════════════════════════════════════════════════════════════════
# Modèle Principal : Fiche de Renseignement Acteur de la Menace
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatActorIntelCard(BaseModel):
    """
    Fiche de renseignement structurée d'un acteur de la menace.

    Modèle strict à 7 champs obligatoires. L'instanciation échoue si
    l'un des champs critiques est manquant ou mal typé.

    Champs structurels :
        1. IDENTITÉ           — nom, alias, type_acteur, pays_origine
        2. PROFIL OPÉRATIONNEL — objectifs, secteurs_cibles
        3. TECHNIQUES MITRE    — techniques_mitre (list[TechniqueMITRE])
        4. IOCs LIÉS           — iocs_lies (list[ReferenceIOC])
        5. CAMPAGNES RÉCENTES  — campagnes (list[CampagneInfo])
        6. SCORING DYNAMIQUE   — score_menace (ScoreMenace)
        7. MÉTADONNÉES         — premiere_observation, derniere_observation, etc.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_default=True,
    )

    # ─── CHAMP 1 : Identité ──────────────────────────────────────────────────
    nom: StrictStr = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Nom principal de l'acteur (ex: APT29)",
    )
    alias: list[StrictStr] = Field(
        ...,
        min_length=0,
        description="Noms alternatifs connus (ex: Cozy Bear, The Dukes)",
    )
    type_acteur: TypeActeur = Field(
        ...,
        description="Classification de l'acteur",
    )
    pays_origine: StrictStr = Field(
        ...,
        min_length=2,
        max_length=2,
        description="Code pays ISO 3166-1 alpha-2 (ex: RU, CN, KP)",
    )

    # ─── CHAMP 2 : Profil Opérationnel ───────────────────────────────────────
    objectifs: list[StrictStr] = Field(
        ...,
        min_length=1,
        description="Objectifs stratégiques (ex: Espionnage, Vol de données)",
    )
    secteurs_cibles: list[StrictStr] = Field(
        ...,
        min_length=1,
        description="Secteurs d'activité ciblés (ex: Gouvernement, Énergie)",
    )

    # ─── CHAMP 3 : Techniques MITRE ATT&CK ──────────────────────────────────
    techniques_mitre: list[TechniqueMITRE] = Field(
        ...,
        min_length=1,
        description="Techniques MITRE ATT&CK observées (au moins 1 requise)",
    )

    # ─── CHAMP 4 : IOCs Liés ─────────────────────────────────────────────────
    iocs_lies: list[ReferenceIOC] = Field(
        ...,
        description="Indicateurs de compromission liés à cet acteur",
    )

    # ─── CHAMP 5 : Campagnes Récentes ────────────────────────────────────────
    campagnes: list[CampagneInfo] = Field(
        ...,
        description="Campagnes d'attaque attribuées",
    )

    # ─── CHAMP 6 : Scoring Dynamique ─────────────────────────────────────────
    score_menace: ScoreMenace = Field(
        ...,
        description="Score de menace multidimensionnel (technique, impact, activité, global)",
    )

    # ─── CHAMP 7 : Métadonnées ───────────────────────────────────────────────
    premiere_observation: datetime = Field(
        ...,
        description="Date de première observation (UTC)",
    )
    derniere_observation: datetime = Field(
        ...,
        description="Date de dernière observation (UTC)",
    )
    sources_renseignement: list[StrictStr] = Field(
        ...,
        min_length=1,
        description="Sources de renseignement (ex: MITRE ATT&CK, AlienVault OTX)",
    )
    niveau_confiance: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Niveau de confiance global dans le renseignement (0-100)",
    )

    # ─── Identifiant interne ONYX ────────────────────────────────────────────
    onyx_id: StrictStr = Field(
        ...,
        min_length=1,
        description="Identifiant ONYX interne unique (ex: threat-actor--apt29)",
    )

    # ─── Validateurs ─────────────────────────────────────────────────────────

    @field_validator("pays_origine")
    @classmethod
    def valider_code_pays(cls, v: str) -> str:
        """Vérifie que le code pays est en majuscules (ISO 3166-1 alpha-2)."""
        if not v.isupper():
            raise ValueError(f"Code pays doit être en majuscules ISO 3166-1 : {v}")
        return v

    @model_validator(mode="after")
    def valider_coherence_dates(self) -> "ThreatActorIntelCard":
        """Vérifie que dernière observation >= première observation."""
        if self.derniere_observation < self.premiere_observation:
            raise ValueError(
                f"derniere_observation ({self.derniere_observation}) ne peut pas "
                f"précéder premiere_observation ({self.premiere_observation})"
            )
        return self


# ═══════════════════════════════════════════════════════════════════════════════
# Modèle de réponse API (résumé léger pour les listes)
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatActorSummary(BaseModel):
    """
    Résumé compact d'un acteur pour les endpoints de listing.
    Évite le transfert de la fiche complète dans les vues agrégées.
    """
    onyx_id: StrictStr
    nom: StrictStr
    type_acteur: TypeActeur
    pays_origine: StrictStr
    score_global: StrictInt = Field(ge=0, le=100)
    derniere_observation: datetime
    nombre_iocs: StrictInt = Field(ge=0)
    nombre_techniques: StrictInt = Field(ge=0)
    nombre_campagnes: StrictInt = Field(ge=0)
    statut: Literal["actif", "surveillé", "inactif"] = "surveillé"

    @classmethod
    def from_intel_card(cls, card: ThreatActorIntelCard) -> "ThreatActorSummary":
        """Construit un résumé depuis une fiche complète."""
        return cls(
            onyx_id=card.onyx_id,
            nom=card.nom,
            type_acteur=card.type_acteur,
            pays_origine=card.pays_origine,
            score_global=card.score_menace.global_score,
            derniere_observation=card.derniere_observation,
            nombre_iocs=len(card.iocs_lies),
            nombre_techniques=len(card.techniques_mitre),
            nombre_campagnes=len(card.campagnes),
        )
