"""
ONYX CTI v5.0 SOVEREIGN — Moteur de Recommandations Actionnables
==================================================================

Produit des commandes déterministes (iptables, YARA, Sigma) basées sur 
les IOCs et TTPs détectés.
"""

from typing import Any
from structlog import get_logger

logger = get_logger("onyx.services.recommendations")

class RecommendationEngine:
    @classmethod
    def generate_actionable_recommendations(cls, alert_data: dict[str, Any]) -> list[dict[str, str]]:
        """Généère des recommandations atomiques en fonction de l'alerte."""
        recommendations = []
        
        # 1. Traitement des IOCs IP
        iocs = alert_data.get("iocs", [])
        for ioc in iocs:
            if ioc.get("type", "") in ("ipv4", "ipv6"):
                ip = ioc.get("value")
                recommendations.append({
                    "action": "Bloquer IP via iptables",
                    "commande": f"iptables -A INPUT -s {ip} -j DROP",
                    "priorite": "CRITIQUE" if ioc.get("severity") == "critical" else "HAUTE",
                    "justification": f"IP détectée par {ioc.get('source', 'OSINT')}"
                })
        
        # 2. Traitement des TTPs
        ttps = alert_data.get("techniques", [])
        if "T1059" in ttps:
            recommendations.append({
                "action": "Auditer exécution PowerShell",
                "commande": "Set-ExecutionPolicy Restricted -Scope LocalMachine",
                "priorite": "HAUTE",
                "justification": "Technique MITRE T1059 (Command and Scripting Interpreter) détectée."
            })
            
        if "T1566" in ttps:
            recommendations.append({
                "action": "Déployer règle de filtrage email",
                "commande": "New-TransportRule -Name 'Bloquer Phishing' -SubjectOrBodyContainsWords 'URGENT','Facture'",
                "priorite": "HAUTE",
                "justification": "Technique MITRE T1566 (Phishing) active sur le périmètre."
            })

        if not recommendations:
            recommendations.append({
                "action": "Isoler segment réseau",
                "commande": "VLAN isolation req #8082",
                "priorite": "MOYENNE",
                "justification": "Activité anormale détectée, nécessitant une analyse forensique."
            })

        return recommendations
