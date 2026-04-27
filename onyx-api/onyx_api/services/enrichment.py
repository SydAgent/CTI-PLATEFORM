"""
ONYX CTI v5.0 SOVEREIGN — Service d'Enrichissement Dédicacé
============================================================

Service centralisant l'enrichissement des entités (IoCs, Acteurs).
Intègre GeoIP, résolution DNS, et correlation MITRE de manière
synchrone ou asynchrone lors du pipeline d'ingestion.
"""

import os
import asyncio
import httpx
from typing import Any
from structlog import get_logger
from onyx_api.services.geoip import GeoIPResolver
from onyx_api.services.osint_integrations import MitreConnector
from onyx_api.config import settings

logger = get_logger("onyx.services.enrichment")


class EnrichmentService:
    """Service d'enrichissement unifié pour le pipeline de données."""

    @classmethod
    async def fetch_virustotal(cls, client: httpx.AsyncClient, ip: str) -> dict | None:
        if not settings.OSINT_VIRUSTOTAL_API_KEY:
            return None
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.OSINT_VIRUSTOTAL_API_KEY},
                timeout=5.0
            )
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}
        except Exception as e:
            logger.warning("virustotal.enrichment.failed", ip=ip, error=str(e))
        return None

    @classmethod
    async def fetch_abuseipdb(cls, client: httpx.AsyncClient, ip: str) -> dict | None:
        if not settings.OSINT_ABUSEIPDB_API_KEY:
            return None
        try:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.OSINT_ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5.0
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {"abuse_confidence_score": data.get("abuseConfidenceScore", 0), "total_reports": data.get("totalReports", 0)}
        except Exception as e:
            logger.warning("abuseipdb.enrichment.failed", ip=ip, error=str(e))
        return None

    @classmethod
    async def fetch_shodan(cls, client: httpx.AsyncClient, ip: str) -> dict | None:
        if not settings.OSINT_SHODAN_API_KEY:
            return None
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.OSINT_SHODAN_API_KEY},
                timeout=5.0
            )
            if resp.status_code == 200:
                data = resp.json()
                return {"org": data.get("org", "Unknown"), "ports": data.get("ports", []), "os": data.get("os", "Unknown")}
        except Exception as e:
            logger.warning("shodan.enrichment.failed", ip=ip, error=str(e))
        return None

    @classmethod
    async def enrich_ioc(cls, ioc_data: dict[str, Any]) -> dict[str, Any]:
        """
        Enrichit un IOC brut avec les coordonnées géographiques, l'ASN,
        et croise avec la base MITRE pour y associer des acteurs si pertinent.
        """
        # 1. Enrichissement GeoIP (Déterministe via base MaxMind locale/offline)
        ioc_val = ioc_data.get("value", "")
        ioc_type = ioc_data.get("type", "ipv4")

        if ioc_type in ("ipv4", "ipv6") and ioc_val:
            try:
                geo = await GeoIPResolver.resolve(ioc_val)
                ioc_data["geolocation"] = geo
            except Exception as e:
                logger.warning("enrichment.geoip.failed", ip=ioc_val, error=str(e))
                ioc_data["geolocation"] = {
                    "latitude": 0.0, "longitude": 0.0, 
                    "country": "Unresolved", "city": "Unknown Origin"
                }

            # 1.5. Enrichissement API Externe concurrent (VT, AbuseIPDB, Shodan)
            async with httpx.AsyncClient() as client:
                vt_task = cls.fetch_virustotal(client, ioc_val)
                abuse_task = cls.fetch_abuseipdb(client, ioc_val)
                shodan_task = cls.fetch_shodan(client, ioc_val)
                
                vt_res, abuse_res, shodan_res = await asyncio.gather(vt_task, abuse_task, shodan_task)
                
                ioc_data["external_enrichment"] = {
                    "virustotal": vt_res,
                    "abuseipdb": abuse_res,
                    "shodan": shodan_res
                }

        # 2. Corrélation STIX / MITRE rudimentaire basée sur les tags
        if "actor" not in ioc_data and "tags" in ioc_data:
            tags = [t.lower() for t in ioc_data["tags"]]
            # Exemple déterministe: Si tag "apt29" présent, lier l'acteur
            if "apt29" in tags or "cozy bear" in tags:
                ioc_data["actor_attribution"] = "APT29"
            elif "lazarus" in tags:
                ioc_data["actor_attribution"] = "Lazarus Group"



        ioc_data["enriched"] = True
        return ioc_data
