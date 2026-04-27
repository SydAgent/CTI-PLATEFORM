"""
ONYX CTI — Geopolitical Threat Ingestor (Production Worker)
Ingests cybersecurity news RSS feeds, extracts geopolitical intelligence,
resolves IP geolocation, and provides data for the Threat Map module.

Sources:
  - BleepingComputer RSS
  - The Hacker News RSS
  - CISA Cybersecurity Advisories
"""

from __future__ import annotations

import asyncio
import html
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

import httpx
import structlog

logger = structlog.get_logger("onyx.worker.geopolitical")

# ── RSS Feed Sources ─────────────────────────────────────────────────────────

RSS_FEEDS = [
    {"name": "CERT-FR", "url": "https://www.cert.ssi.gouv.fr/feed/"},
    {"name": "ANSSI Actualités", "url": "https://www.cert.ssi.gouv.fr/feed/"},
    {"name": "ZATAZ Sec", "url": "https://www.zataz.com/feed/"},
]

# ── GeoIP Cache ──────────────────────────────────────────────────────────────

_geoip_cache: dict[str, dict] = {}


async def _resolve_geoip(client: httpx.AsyncClient, ip: str) -> dict | None:
    """Resolve IP to geolocation using ip-api.com with caching."""
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,lat,lon,isp,org"},
            timeout=5.0,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "lat": data["lat"],
                "lon": data["lon"],
                "country": data["country"],
                "country_code": data["countryCode"],
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
            }
            _geoip_cache[ip] = result
            return result
    except Exception:
        pass
    return None


# ── Entity Extraction (Regex NLP) ────────────────────────────────────────────

_PATTERNS = [
    (re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', re.I), "CVE"),
    (re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'), "IP_ADDRESS"),
    (re.compile(r'\b(?:APT\d+|Lazarus|Volt Typhoon|Cozy Bear|FIN\d+|Scattered Spider|LockBit|Cl0p|ALPHV|BlackCat|Sandworm|Kimsuky|Mustang Panda|Turla|Gamaredon|SideWinder|OilRig|Charming Kitten)\b', re.I), "THREAT_ACTOR"),
    (re.compile(r'\b(?:Cobalt Strike|Mimikatz|Qakbot|IcedID|Emotet|Trickbot|Bumblebee|BlackCat|Ransomware|Ryuk|Conti|Hive|REvil|DarkSide|BlackBasta)\b', re.I), "MALWARE"),
    (re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b'), "MITRE_TTP"),
]

# ── Country mapping for known APT groups ─────────────────────────────────────

_APT_ORIGIN: dict[str, dict[str, Any]] = {
    "apt29": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "cozy bear": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "sandworm": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "turla": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "gamaredon": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "apt41": {"lat": 39.9, "lon": 116.4, "country": "China", "code": "CN"},
    "volt typhoon": {"lat": 39.9, "lon": 116.4, "country": "China", "code": "CN"},
    "mustang panda": {"lat": 39.9, "lon": 116.4, "country": "China", "code": "CN"},
    "lazarus": {"lat": 39.02, "lon": 125.75, "country": "North Korea", "code": "KP"},
    "kimsuky": {"lat": 39.02, "lon": 125.75, "country": "North Korea", "code": "KP"},
    "apt33": {"lat": 35.69, "lon": 51.39, "country": "Iran", "code": "IR"},
    "charming kitten": {"lat": 35.69, "lon": 51.39, "country": "Iran", "code": "IR"},
    "oilrig": {"lat": 35.69, "lon": 51.39, "country": "Iran", "code": "IR"},
    "fin7": {"lat": 50.45, "lon": 30.52, "country": "Ukraine/E.Europe", "code": "UA"},
    "scattered spider": {"lat": 38.9, "lon": -77.04, "country": "USA", "code": "US"},
    "lockbit": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "cl0p": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "alphv": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "blackcat": {"lat": 55.75, "lon": 37.62, "country": "Russia", "code": "RU"},
    "sidewinder": {"lat": 28.61, "lon": 77.23, "country": "India", "code": "IN"},
}


def _extract_entities(text: str) -> list[dict[str, str]]:
    """Extract CTI entities from text using regex patterns."""
    entities: list[dict[str, str]] = []
    seen: set[str] = set()
    for regex, label in _PATTERNS:
        for match in regex.finditer(text):
            val = match.group(0)
            key = f"{label}:{val.lower()}"
            if key not in seen:
                seen.add(key)
                entities.append({"label": label, "text": val, "conf": 0.98})
    return entities


def _clean_html(raw_html: str) -> str:
    return html.unescape(re.sub(r'<.*?>', '', raw_html)).strip()


# ── RSS Parsing ──────────────────────────────────────────────────────────────


async def _fetch_rss(client: httpx.AsyncClient, feed: dict) -> list[dict]:
    """Fetch and parse an RSS feed, returns list of articles."""
    articles: list[dict] = []
    try:
        resp = await client.get(feed["url"], timeout=12.0, follow_redirects=True)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        for element in root.iter():
            tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag
            if tag in ("item", "entry"):
                title = ""
                desc = ""
                pub_date = ""
                for child in element:
                    child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child_tag == "title":
                        title = child.text or ""
                    elif child_tag in ("description", "summary"):
                        desc = child.text or ""
                    elif child_tag in ("pubDate", "published", "updated"):
                        pub_date = child.text or ""

                combined = f"{title}. {_clean_html(desc)}"
                if len(combined) > 20:
                    articles.append({
                        "title": title,
                        "text": combined[:800],
                        "source": feed["name"],
                        "date": pub_date,
                    })
    except Exception as e:
        logger.warning("onyx.geopolitical.rss_error", feed=feed["name"], error=str(e))

    return articles


# ── Main Ingestor Loop ───────────────────────────────────────────────────────


async def start_geopolitical_ingestor(
    app_state: Any,
    broadcast_callback: Callable[[dict], Coroutine] | None = None,
    poll_interval: int = 300,
) -> None:
    """
    Background task that:
    1. Polls cybersecurity RSS feeds
    2. Extracts CTI entities (threat actors, IPs, CVEs)
    3. Resolves geolocation for IPs and APT groups
    4. Updates app.state.geopolitical_threats with map markers
    5. Broadcasts to SSE stream
    """
    logger.info("onyx.geopolitical.start", message="Geopolitical Ingestor armed", interval=poll_interval)

    # Initialize state
    if not hasattr(app_state, "geopolitical_threats"):
        app_state.geopolitical_threats = []
    if not hasattr(app_state, "geopolitical_markers"):
        app_state.geopolitical_markers = []
    if not hasattr(app_state, "geopolitical_articles"):
        app_state.geopolitical_articles = []

    seen_titles: set[int] = set()
    cycle = 0

    while True:
        cycle += 1
        logger.info("onyx.geopolitical.cycle", cycle=cycle)

        # 🚀 ZERO DELAY DIRECTIVE: Pipe IOC geolocations immediately on startup (cycle=1)
        if cycle == 1:
            try:
                from onyx_core.services import MongoDBService
                mongo = MongoDBService()
                armed_iocs = await mongo.list_stix("indicator", limit=1000)
            except Exception:
                armed_iocs = getattr(app_state, "armed_iocs", [])

            import geoip2.database

            # ── Multi-path mmdb resolution (no synthetic fallback) ──
            _mmdb_candidates = [
                os.path.join(os.path.dirname(__file__), '../../data/GeoLite2-City.mmdb'),
                os.path.abspath('data/GeoLite2-City.mmdb'),
                r'C:\Users\USER\Downloads\CTI\CTI-Platform\onyx-api\data\GeoLite2-City.mmdb',
            ]
            _resolved_mmdb = None
            for _cand in _mmdb_candidates:
                _norm = os.path.normpath(_cand)
                if os.path.isfile(_norm):
                    _resolved_mmdb = _norm
                    logger.info("onyx.geopolitical.mmdb_resolved", path=_norm)
                    break
            if not _resolved_mmdb:
                logger.error("onyx.geopolitical.mmdb_not_found", candidates=_mmdb_candidates)

            boot_markers: dict[str, dict] = {}
            if _resolved_mmdb:
                try:
                    reader = geoip2.database.Reader(_resolved_mmdb)
                    for ioc in armed_iocs:
                        ip = str(ioc.get("value", ""))
                        if not ip:
                            continue
                        try:
                            response = reader.city(ip)
                            lat = response.location.latitude
                            lon = response.location.longitude
                            country = response.country.name or "Unknown"
                            code = response.country.iso_code or "XX"

                            loc = {"country_code": code, "lat": lat, "lon": lon, "country": country}
                            ioc["geolocation"] = loc

                            if code not in boot_markers:
                                boot_markers[code] = {
                                    "lat": lat,
                                    "lon": lon,
                                    "country": country,
                                    "country_code": code,
                                    "count": 0,
                                    "actors": [],
                                }
                            boot_markers[code]["count"] += 1
                        except Exception:
                            pass
                    reader.close()
                except Exception as e:
                    logger.error("geoip2 error", error=str(e))

            if boot_markers:
                # Assign threat_level per marker
                for m in boot_markers.values():
                    c = m["count"]
                    m["threat_level"] = "high" if c >= 10 else "medium" if c >= 4 else "low"
                app_state.geopolitical_markers = list(boot_markers.values())
                logger.info("onyx.geopolitical.startup", markers=len(boot_markers), message="Pushed immediate armed IOC markers on cycle 1")

        new_articles: list[dict] = []
        new_threats: list[dict] = []
        marker_updates: dict[str, dict] = {}  # country_code -> marker

        async with httpx.AsyncClient() as client:
            # 1. Fetch RSS articles
            for feed in RSS_FEEDS:
                articles = await _fetch_rss(client, feed)
                for art in articles:
                    sig = hash(art["title"])
                    if sig not in seen_titles:
                        seen_titles.add(sig)
                        new_articles.append(art)

            # 2. Extract entities and build geopolitical intel
            for art in new_articles:
                entities = _extract_entities(art["text"])
                if not entities:
                    continue

                threat_entry = {
                    "title": art["title"],
                    "source": art["source"],
                    "date": art.get("date", datetime.now(timezone.utc).isoformat()),
                    "entities": entities,
                    "text_preview": art["text"][:300],
                }
                new_threats.append(threat_entry)

                # 3. Resolve geolocation
                for ent in entities:
                    if ent["label"] == "THREAT_ACTOR":
                        actor_key = ent["text"].lower()
                        if actor_key in _APT_ORIGIN:
                            origin = _APT_ORIGIN[actor_key]
                            code = origin["code"]
                            if code not in marker_updates:
                                marker_updates[code] = {
                                    "lat": origin["lat"],
                                    "lon": origin["lon"],
                                    "country": origin["country"],
                                    "country_code": code,
                                    "count": 0,
                                    "actors": [],
                                }
                            marker_updates[code]["count"] += 1
                            if ent["text"] not in marker_updates[code]["actors"]:
                                marker_updates[code]["actors"].append(ent["text"])

                    elif ent["label"] == "IP_ADDRESS":
                        geo = await _resolve_geoip(client, ent["text"])
                        if geo:
                            code = geo["country_code"]
                            if code not in marker_updates:
                                marker_updates[code] = {
                                    "lat": geo["lat"],
                                    "lon": geo["lon"],
                                    "country": geo["country"],
                                    "country_code": code,
                                    "count": 0,
                                    "actors": [],
                                }
                            marker_updates[code]["count"] += 1

                        # Rate limiting: ip-api.com allows 45/min
                        await asyncio.sleep(1.5)

        # 4. Update state
        # Pipe IOC database geolocated IPs into markers
        armed_iocs = getattr(app_state, "armed_iocs", [])
        for ioc in armed_iocs:
            loc = ioc.get("geolocation")
            if loc and isinstance(loc, dict) and "lat" in loc and "lon" in loc:
                code = loc.get("country_code", "XX")
                if code not in marker_updates:
                    marker_updates[code] = {
                        "lat": loc["lat"],
                        "lon": loc["lon"],
                        "country": loc.get("country", "Unknown"),
                        "country_code": code,
                        "count": 0,
                        "actors": [],
                    }
                marker_updates[code]["count"] += 1

        if new_threats or marker_updates:
            current_threats = list(getattr(app_state, "geopolitical_threats", []))
            if new_threats:
                current_threats = new_threats + current_threats
                app_state.geopolitical_threats = current_threats[:200]  # Cap at 200

            # Merge markers
            existing_markers: dict[str, dict] = {}
            for m in getattr(app_state, "geopolitical_markers", []):
                existing_markers[m.get("country_code", "")] = m

            for code, marker in marker_updates.items():
                if code in existing_markers:
                    existing_markers[code]["count"] += marker["count"]
                    for actor in marker.get("actors", []):
                        if actor not in existing_markers[code].get("actors", []):
                            existing_markers[code].setdefault("actors", []).append(actor)
                else:
                    existing_markers[code] = marker

            app_state.geopolitical_markers = list(existing_markers.values())

            # Store articles for module display
            current_articles = list(getattr(app_state, "geopolitical_articles", []))
            current_articles = new_articles + current_articles
            app_state.geopolitical_articles = current_articles[:100]

            logger.info(
                "onyx.geopolitical.updated",
                new_threats=len(new_threats),
                markers=len(existing_markers),
            )

            # 5. Broadcast
            if broadcast_callback:
                for threat in new_threats[:10]:
                    try:
                        await broadcast_callback({
                            "type": "geopolitical_threat",
                            "title": threat["title"],
                            "source": threat["source"],
                            "entities": threat["entities"][:5],
                            "ts": datetime.now(timezone.utc).isoformat(),
                        })
                    except Exception:
                        pass
                    await asyncio.sleep(0.5)
        else:
            logger.info("onyx.geopolitical.no_new", message="No new geopolitical threats this cycle")

        await asyncio.sleep(poll_interval)
