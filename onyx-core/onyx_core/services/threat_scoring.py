"""
ONYX CTI v5.0 SOVEREIGN — Moteur de Scoring Dynamique des Acteurs de Menace
============================================================================

Calcule un score multidimensionnel normalisé 0-100 pour chaque acteur.

Architecture du scoring :
    Score Global = (Score Technique × 0.3) + (Score Impact × 0.3) + (Score Activité × 0.4)

Justification mathématique des pondérations :
    - Activité (0.4) : Facteur temps réel. Un acteur récemment actif représente
      un risque immédiat plus élevé qu'un acteur dormant, même si ce dernier
      possède un arsenal technique supérieur.
    - Technique (0.3) : Capacité offensive. Mesurée par le nombre, la diversité
      et la sophistication des TTPs MITRE déployés.
    - Impact (0.3) : Potentiel de dommage. Évalué par la criticité des secteurs
      ciblés et l'ampleur des campagnes historiques.

Chaque sous-score est calculé via des tables de correspondance déterministes
(aucune composante aléatoire). Le résultat est reproductible pour un même
état d'entrée.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from onyx_core.models.threat_actor_model import (
    CampagneInfo,
    PhaseKillChain,
    ReferenceIOC,
    ScoreMenace,
    TechniqueMITRE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Tables de correspondance déterministes
# ═══════════════════════════════════════════════════════════════════════════════

# Poids de criticité par secteur ciblé (échelle 0-10)
_CRITICITE_SECTEUR: dict[str, int] = {
    # Infrastructures critiques (9-10)
    "Énergie": 10,
    "Energy": 10,
    "Nucléaire": 10,
    "Nuclear": 10,
    "ICS/SCADA": 10,
    "Défense": 9,
    "Defense": 9,
    "Militaire": 9,
    "Military": 9,
    "Gouvernement": 9,
    "Government": 9,
    # Secteurs essentiels (7-8)
    "Santé": 8,
    "Healthcare": 8,
    "Finance": 8,
    "Financial Services": 8,
    "Télécommunications": 8,
    "Telecommunications": 8,
    "Infrastructure critique": 8,
    "Critical Infrastructure": 8,
    "Eau": 8,
    "Water": 8,
    # Secteurs stratégiques (5-6)
    "Technologie": 6,
    "Technology": 6,
    "Recherche": 6,
    "Research": 6,
    "Transport": 6,
    "Transportation": 6,
    "Cryptomonnaies": 6,
    "Cryptocurrency": 6,
    "Cloud": 6,
    "Cloud Services": 6,
    # Secteurs à impact modéré (3-4)
    "Retail": 4,
    "Commerce": 4,
    "Hospitality": 4,
    "Médias": 4,
    "Media": 4,
    "Éducation": 3,
    "Education": 3,
    "Gaming": 3,
    "Non-Profits": 3,
    "Think Tanks": 4,
}

# Nombre de phases kill chain distinctes couvertes → bonus de sophistication
_PHASE_DIVERSITE_BONUS: dict[int, int] = {
    1: 0,
    2: 5,
    3: 10,
    4: 18,
    5: 25,
    6: 35,
    7: 42,
    8: 50,
    9: 58,
    10: 65,
    11: 72,
    12: 80,
    13: 88,
    14: 95,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Moteur de Scoring
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatScoringEngine:
    """
    Moteur de calcul de score multidimensionnel pour les acteurs de menace.

    Invariant : retourne toujours un ScoreMenace avec global_score ∈ [0, 100].
    """

    # Pondérations (constantes de classe — jamais modifiées à l'exécution)
    POIDS_TECHNIQUE: float = 0.3
    POIDS_IMPACT: float = 0.3
    POIDS_ACTIVITE: float = 0.4

    @classmethod
    def calculer_score(
        cls,
        techniques: list[TechniqueMITRE],
        iocs: list[ReferenceIOC],
        campagnes: list[CampagneInfo],
        secteurs_cibles: list[str],
    ) -> ScoreMenace:
        """
        Point d'entrée principal du moteur de scoring.

        Paramètres :
            techniques      — TTPs MITRE observés pour cet acteur
            iocs            — IOCs liés à cet acteur
            campagnes       — Campagnes attribuées à cet acteur
            secteurs_cibles — Secteurs d'activité ciblés

        Retourne :
            ScoreMenace avec les 4 dimensions calculées et validées.
        """
        score_tech = cls._calculer_score_technique(techniques)
        score_impact = cls._calculer_score_impact(secteurs_cibles, campagnes)
        score_activite = cls._calculer_score_activite(iocs, campagnes)

        score_global = round(
            score_tech * cls.POIDS_TECHNIQUE
            + score_impact * cls.POIDS_IMPACT
            + score_activite * cls.POIDS_ACTIVITE
        )

        # Clamp de sécurité — garantit [0, 100]
        score_global = max(0, min(100, score_global))

        return ScoreMenace(
            technique=score_tech,
            impact=score_impact,
            activite=score_activite,
            global_score=score_global,
        )

    # ─── Sous-scores ─────────────────────────────────────────────────────────

    @classmethod
    def _calculer_score_technique(cls, techniques: list[TechniqueMITRE]) -> int:
        """
        Score Technique (0-100).

        Critères :
            1. Nombre de techniques uniques (plafonné à 20 → 50 pts max)
            2. Diversité des phases kill chain couvertes (0-50 pts)

        Un acteur qui couvre plus de phases simultanément démontre une
        sophistication opérationnelle supérieure.
        """
        if not techniques:
            return 0

        # 1. Volume de techniques (courbe logarithmique, plafonné à 50)
        nb_techniques = len(set(t.id for t in techniques))
        score_volume = min(50, int(50 * math.log(1 + nb_techniques, 21)))

        # 2. Diversité des phases kill chain
        phases_couvertes = set(t.phase_kill_chain for t in techniques)
        nb_phases = len(phases_couvertes)
        score_diversite = _PHASE_DIVERSITE_BONUS.get(
            nb_phases,
            min(95, nb_phases * 7),
        )
        # Normaliser la diversité sur 50 points
        score_diversite = min(50, int(score_diversite * 50 / 95))

        return max(0, min(100, score_volume + score_diversite))

    @classmethod
    def _calculer_score_impact(
        cls,
        secteurs_cibles: list[str],
        campagnes: list[CampagneInfo],
    ) -> int:
        """
        Score Impact (0-100).

        Critères :
            1. Criticité maximale des secteurs ciblés (0-60 pts)
            2. Nombre de campagnes historiques (0-20 pts)
            3. Nombre de secteurs distincts ciblés (0-20 pts)

        La criticité d'un seul secteur sensible (ex: Nucléaire) suffit
        à élever fortement le score d'impact.
        """
        if not secteurs_cibles:
            return 0

        # 1. Criticité maximale parmi les secteurs ciblés
        criticites = [_CRITICITE_SECTEUR.get(s, 3) for s in secteurs_cibles]
        max_criticite = max(criticites) if criticites else 0
        score_criticite = min(60, max_criticite * 6)

        # 2. Nombre de campagnes (courbe dégressive)
        nb_campagnes = len(campagnes)
        score_campagnes = min(20, int(20 * math.log(1 + nb_campagnes, 6)))

        # 3. Diversité des cibles
        nb_secteurs = len(set(secteurs_cibles))
        score_diversite = min(20, nb_secteurs * 3)

        return max(0, min(100, score_criticite + score_campagnes + score_diversite))

    @classmethod
    def _calculer_score_activite(
        cls,
        iocs: list[ReferenceIOC],
        campagnes: list[CampagneInfo],
    ) -> int:
        """
        Score Activité (0-100).

        Critères :
            1. Fraîcheur du dernier IOC détecté (0-50 pts)
            2. Volume d'IOCs actifs (0-30 pts)
            3. Campagne en cours (pas de date_fin) (0-20 pts)

        La fraîcheur est le facteur dominant : un IOC de moins de 24h
        donne le score maximum (50 pts), tandis qu'un IOC de plus de
        90 jours donne 0 pts.
        """
        maintenant = datetime.now(timezone.utc)
        score_fraicheur = 0
        score_volume = 0
        score_campagne_active = 0

        # 1. Fraîcheur (basée sur l'IOC le plus récent)
        if iocs:
            dates_detection = [ioc.date_detection for ioc in iocs]
            dernier_ioc = max(dates_detection)
            # Normaliser tzinfo pour la comparaison
            if dernier_ioc.tzinfo is None:
                dernier_ioc = dernier_ioc.replace(tzinfo=timezone.utc)
            delta_heures = (maintenant - dernier_ioc).total_seconds() / 3600

            if delta_heures <= 24:
                score_fraicheur = 50
            elif delta_heures <= 72:
                score_fraicheur = 40
            elif delta_heures <= 168:  # 7 jours
                score_fraicheur = 30
            elif delta_heures <= 720:  # 30 jours
                score_fraicheur = 20
            elif delta_heures <= 2160:  # 90 jours
                score_fraicheur = 10
            else:
                score_fraicheur = 0

        # 2. Volume d'IOCs (courbe logarithmique)
        if iocs:
            nb_iocs = len(iocs)
            score_volume = min(30, int(30 * math.log(1 + nb_iocs, 50)))

        # 3. Campagne en cours (sans date de fin)
        campagnes_actives = [c for c in campagnes if c.date_fin is None]
        if campagnes_actives:
            score_campagne_active = 20

        return max(0, min(100, score_fraicheur + score_volume + score_campagne_active))

    # ─── Utilitaires ─────────────────────────────────────────────────────────

    @classmethod
    def classifier_risque(cls, score_global: int) -> str:
        """
        Classifie le niveau de risque en label lisible.

        Seuils :
            90-100 : CRITIQUE
            70-89  : ÉLEVÉ
            40-69  : MOYEN
            1-39   : FAIBLE
            0      : AUCUN
        """
        if score_global >= 90:
            return "CRITIQUE"
        if score_global >= 70:
            return "ÉLEVÉ"
        if score_global >= 40:
            return "MOYEN"
        if score_global >= 1:
            return "FAIBLE"
        return "AUCUN"
