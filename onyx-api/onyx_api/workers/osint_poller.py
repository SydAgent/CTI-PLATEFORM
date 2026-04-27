"""
ONYX CTI — Autonomous OSINT Poller (Production Worker)
Periodically polls real-world OSINT feeds and updates app.state.armed_iocs.
Broadcasts newly discovered IOCs to the SSE/WebSocket pipeline.

Feeds:
  - AbuseCH Feodo Tracker (C2 IPs)
  - AbuseCH URLhaus (malicious URLs)
  - MISP Warninglists (widespread bad IPs)
  - CISA KEV (known exploited vulnerabilities)
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

import httpx
import structlog

from onyx_api.config import settings
from onyx_api.services.enrichment import EnrichmentService

logger = structlog.get_logger("onyx.worker.osint_poller")

# ── Feed Definitions ─────────────────────────────────────────────────────────

OSINT_SOURCES: list[dict[str, Any]] = [
    {
        "label": "AbuseCH Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "parser": "_parse_feodo",
    },
    {
        "label": "ET Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "parser": "_parse_et_compromised",
        "text_mode": True,
    },
    {
        "label": "CISA KEV",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "parser": "_parse_cisa_kev",
    },
    {
        "label": "AbuseCH URLhaus",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "parser": "_parse_urlhaus",
    },
    {
        "label": "Tor Exit Nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "parser": "_parse_tor_exit",
        "text_mode": True,
    },
    {
        "label": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "parser": "_parse_openphish",
        "text_mode": True,
    },
    {
        "label": "ThreatFox",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "parser": "_parse_threatfox",
        "method": "POST",
        "payload": {"query": "get_iocs", "days": 1}
    },
]

# ── Parsers ──────────────────────────────────────────────────────────────────


def _parse_feodo(data: Any) -> list[dict[str, Any]]:
    """Parse AbuseCH Feodo Tracker JSON."""
    results: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return results
    for entry in data:
        ip = entry.get("ip_address", "")
        if not ip:
            continue
        results.append({
            "type": "ipv4",
            "value": ip,
            "source": "abuse.ch Feodo Tracker",
            "confidence": 99,
            "severity": "critical",
            "tags": ["feodo", "c2", "botnet", entry.get("malware", "").lower()],
            "mitre_techniques": ["T1071"],
            "malware_family": entry.get("malware", ""),
            "first_seen": entry.get("first_seen", ""),
            "last_online": entry.get("last_online", ""),
            "port": entry.get("dst_port"),
        })
    return results


def _parse_urlhaus(data: Any) -> list[dict[str, Any]]:
    """Parse AbuseCH URLhaus recent URLs."""
    results: list[dict[str, Any]] = []
    urls = data.get("urls", []) if isinstance(data, dict) else []
    for entry in urls[:100]:
        url = entry.get("url", "")
        if not url or entry.get("url_status") != "online":
            continue
        tags = entry.get("tags") or []
        results.append({
            "type": "url",
            "value": url,
            "source": "abuse.ch URLhaus",
            "confidence": 96,
            "severity": "high",
            "tags": ["urlhaus", "malware-distribution"] + [t for t in tags if t],
            "mitre_techniques": ["T1566", "T1105"],
            "malware_family": tags[0] if tags else "",
            "threat": entry.get("threat", ""),
        })
    return results


def _parse_misp_ips(data: Any) -> list[dict[str, Any]]:
    """Parse MISP warninglist JSON."""
    results: list[dict[str, Any]] = []
    ip_list = data.get("list", []) if isinstance(data, dict) else []
    for ip in ip_list[:500]:
        if not ip or not isinstance(ip, str):
            continue
        results.append({
            "type": "ipv4",
            "value": ip,
            "source": "MISP Warninglist",
            "confidence": 98,
            "severity": "high",
            "tags": ["misp", "c2", "botnet"],
            "related_mitre_techniques": ["T1071", "T1059"],
        })
    return results


def _parse_et_compromised(data: str) -> list[dict[str, Any]]:
    """Parse Emerging Threats compromised IPs text list."""
    results: list[dict[str, Any]] = []
    for line in data.splitlines():
        ip = line.strip()
        if not ip or ip.startswith('#'):
            continue
        results.append({
            "type": "ipv4",
            "value": ip,
            "source": "ET Compromised IPs",
            "confidence": 97,
            "severity": "high",
            "tags": ["et", "compromised"],
            "related_mitre_techniques": ["T1078"],
        })
    return results[:500]


def _parse_cisa_kev(data: Any) -> list[dict[str, Any]]:
    """Parse CISA Known Exploited Vulnerabilities catalog."""
    results: list[dict[str, Any]] = []
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    for entry in vulns[:200]:
        cve_id = entry.get("cveID", "")
        if not cve_id:
            continue
        results.append({
            "type": "cve",
            "value": cve_id,
            "source": "CISA KEV",
            "confidence": 100,
            "severity": "critical",
            "tags": ["cisa-kev", "actively-exploited"],
            "related_mitre_techniques": ["T1190"],
            "vendor": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "description": entry.get("shortDescription", ""),
            "date_added": entry.get("dateAdded", ""),
            "due_date": entry.get("dueDate", ""),
        })
    return results


def _parse_tor_exit(data: str) -> list[dict[str, Any]]:
    """Parse Tor Exit Nodes list."""
    results: list[dict[str, Any]] = []
    for line in data.splitlines():
        ip = line.strip()
        if not ip or ip.startswith('#'):
            continue
        results.append({
            "type": "ipv4",
            "value": ip,
            "source": "Tor Exit Nodes",
            "confidence": 100,
            "severity": "medium",
            "tags": ["tor", "anonymization"],
            "related_mitre_techniques": ["T1090.003"],
        })
    return results[:500]


def _parse_openphish(data: str) -> list[dict[str, Any]]:
    """Parse OpenPhish URLs."""
    results: list[dict[str, Any]] = []
    for line in data.splitlines():
        url = line.strip()
        if not url:
            continue
        results.append({
            "type": "url",
            "value": url,
            "source": "OpenPhish",
            "confidence": 95,
            "severity": "high",
            "tags": ["phishing", "credential-harvesting"],
            "related_mitre_techniques": ["T1566"],
        })
    return results[:100]


def _parse_threatfox(data: Any) -> list[dict[str, Any]]:
    """Parse ThreatFox IOCs."""
    results: list[dict[str, Any]] = []
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return results
    iocs = data.get("data", [])
    for entry in iocs[:100]:
        results.append({
            "type": entry.get("ioc_type", "unknown"),
            "value": entry.get("ioc_value", ""),
            "source": "ThreatFox",
            "confidence": entry.get("confidence_level", 80),
            "severity": "high",
            "tags": ["threatfox", entry.get("threat_type", "")],
            "malware_family": entry.get("malware_printable", ""),
        })
    return results


_PARSERS = {
    "_parse_feodo": _parse_feodo,
    "_parse_et_compromised": _parse_et_compromised,
    "_parse_cisa_kev": _parse_cisa_kev,
    "_parse_urlhaus": _parse_urlhaus,
    "_parse_tor_exit": _parse_tor_exit,
    "_parse_openphish": _parse_openphish,
    "_parse_threatfox": _parse_threatfox,
}


# ── IOC Fingerprint for Deduplication ────────────────────────────────────────


def _ioc_fingerprint(ioc: dict) -> str:
    return hashlib.sha256(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()[:16]


# ── Main Poller Loop ─────────────────────────────────────────────────────────


async def start_osint_poller(
    app_state: Any,
    broadcast_callback: Callable[[dict], Coroutine] | None = None,
    poll_interval: int = 300,   # 5 minutes
) -> None:
    """
    Autonomous background task.
    - Polls all OSINT feeds every `poll_interval` seconds.
    - Deduplicates against existing armed_iocs.
    - Atomically updates app.state.armed_iocs.
    - Broadcasts new IOCs via the callback.
    """
    logger.info("onyx.osint_poller.start", message="OSINT Poller armed — entering polling loop", interval=poll_interval)

    # Build initial fingerprint set from existing armed IOCs
    seen: set[str] = set()
    existing = getattr(app_state, "armed_iocs", [])
    for ioc in existing:
        seen.add(_ioc_fingerprint(ioc))

    cycle = 0
    while True:
        cycle += 1
        all_new: list[dict[str, Any]] = []
        logger.info("onyx.osint_poller.cycle", cycle=cycle)

        for source in OSINT_SOURCES:
            try:
                # ── URLhaus: isolated client with mandatory Auth-Key ──
                if source["label"] == "AbuseCH URLhaus":
                    _urlhaus_headers = {}
                    if settings.URLHAUS_API_KEY:
                        _urlhaus_headers["Auth-Key"] = settings.URLHAUS_API_KEY
                    async with httpx.AsyncClient() as _urlhaus_client:
                        resp = await _urlhaus_client.get(
                            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                            headers=_urlhaus_headers,
                            timeout=15.0,
                        )
                else:
                    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                        if source.get("method") == "POST":
                            resp = await client.post(source["url"], json=source.get("payload", {}))
                        else:
                            resp = await client.get(source["url"])

                resp.raise_for_status()
                parser = _PARSERS[source["parser"]]
                if source.get("text_mode"):
                    parsed = parser(resp.text)
                else:
                    parsed = parser(resp.json())

                new_for_source = 0
                for ioc in parsed:
                    fp = _ioc_fingerprint(ioc)
                    if fp not in seen:
                        seen.add(fp)
                        ioc["_ingested_at"] = datetime.now(timezone.utc).isoformat()
                        
                        # Injection dynamique de l'Infrastructure et Cibles (Hotfix)
                        ioc = await EnrichmentService.enrich_ioc(ioc)
                        
                        all_new.append(ioc)
                        new_for_source += 1

                logger.info(
                    "onyx.osint_poller.source_ok",
                    label=source["label"],
                    total_parsed=len(parsed),
                    new=new_for_source,
                )
            except Exception as e:
                logger.warning(
                    "onyx.osint_poller.source_fail",
                    label=source["label"],
                    error=str(e),
                )

        # ── Fallback Historique Réel (Zéro Empty State) ──
        if not all_new:
            logger.warning("onyx.osint_poller.engage_fallback", message="API Streams empty. Engaging historical real data fallback.")
            try:
                import json
                import os
                fallback_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "osint_cache.json")
                if os.path.exists(fallback_path):
                    with open(fallback_path, "r", encoding="utf-8") as f:
                        raw_cache = json.load(f)

                    # osint_cache.json is a dict: {"iocs": [...], "threat_actors": [...]}
                    if isinstance(raw_cache, dict):
                        fallback_iocs = list(raw_cache.get("iocs", []))
                    elif isinstance(raw_cache, list):
                        fallback_iocs = list(raw_cache)
                    else:
                        fallback_iocs = []

                    logger.info("onyx.osint_poller.fallback_loaded", count=len(fallback_iocs))

                    for fioc in fallback_iocs:
                        fioc["_ingested_at"] = datetime.now(timezone.utc).isoformat()
                        fioc["source"] = fioc.get("source", "Historical Cache") + " (Fallback)"
                        fioc = await EnrichmentService.enrich_ioc(fioc)
                        all_new.append(fioc)

                    if fallback_iocs:
                        logger.info("onyx.osint_poller.fallback_injected", count=len(fallback_iocs))
                    else:
                        logger.error("onyx.osint_poller.fallback_empty", message="osint_cache.json contained zero IOCs")
                else:
                    logger.error("onyx.osint_poller.fallback_missing", path=fallback_path)
            except Exception as e:
                logger.error("onyx.osint_poller.fallback_error", error=str(e))

        # Atomic state update
        if all_new:
            current = list(getattr(app_state, "armed_iocs", []))
            current.extend(all_new)
            app_state.armed_iocs = current

            # Rebuild by_source map
            by_source: dict[str, int] = {}
            for ioc in current:
                src = ioc.get("source", "unknown")
                by_source[src] = by_source.get(src, 0) + 1
            app_state.armed_iocs_by_source = by_source

            logger.info(
                "onyx.osint_poller.state_updated",
                new_iocs=len(all_new),
                total=len(current),
            )

            # Broadcast new IOCs to SSE/WebSocket if callback provided
            if broadcast_callback:
                for ioc in all_new[:25]:  # Pace: max 25 broadcasts per cycle
                    try:
                        await broadcast_callback({
                            "type": ioc.get("type", "unknown"),
                            "value": ioc.get("value", ""),
                            "source": ioc.get("source", ""),
                            "severity": ioc.get("severity", "medium"),
                            "confidence": ioc.get("confidence", 50),
                            "geolocation": ioc.get("geolocation"),
                            "target_geolocation": ioc.get("target_geolocation"),
                            "ts": datetime.now(timezone.utc).isoformat(),
                        })
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)
        else:
            logger.info("onyx.osint_poller.no_new", message="No new IOCs discovered this cycle")

        await asyncio.sleep(poll_interval)
