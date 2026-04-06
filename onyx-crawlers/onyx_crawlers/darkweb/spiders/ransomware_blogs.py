"""
ONYX CTI — Ransomware Blog Spider
Crawls ransomware group leak sites (.onion) to extract victim data,
countdown timers, leaked file listings, and group activity intelligence.

Targeted groups: LockBit, BlackCat/ALPHV, Cl0p, Play, 8Base, Akira,
BianLian, Black Basta, NoEscape, Medusa, Royal, Rhysida, Hunters Intl.

Pattern source: AIL Framework's recursive save_capture_response() + domain
tracking logic adapted for ransomware-specific content extraction.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from onyx_crawlers.darkweb.spider_base import CrawlResult, DarkWebSpider

logger = logging.getLogger("onyx.crawler.ransomware")

# Known ransomware blog .onion addresses (updated periodically)
# These are public research URLs documented by security researchers.
RANSOMWARE_ONION_REGISTRY: dict[str, dict[str, Any]] = {
    "lockbit": {
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "LockBit Black"],
        "onions": [],  # Populated at runtime from threat feeds
        "patterns": {
            "victim_selector": ".post-block, .post-item, .company-block, article",
            "name_selector": ".post-title, .post-block-title, h2, h3",
            "timer_selector": ".timer, .countdown, [data-timer], .post-timer",
            "description_selector": ".post-body, .post-text, .description, p",
            "date_selector": ".post-date, time, .date",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1490", "T1027"],
    },
    "blackcat": {
        "name": "BlackCat/ALPHV",
        "aliases": ["ALPHV", "BlackCat"],
        "onions": [],
        "patterns": {
            "victim_selector": ".post, .victim, article, .card",
            "name_selector": "h2, h3, .title, .victim-name",
            "timer_selector": ".countdown, .timer",
            "description_selector": ".content, .description, p",
            "date_selector": ".date, time",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1490", "T1048"],
    },
    "clop": {
        "name": "Cl0p",
        "aliases": ["Clop", "TA505"],
        "onions": [],
        "patterns": {
            "victim_selector": ".line, article, .item, tr",
            "name_selector": ".title, h3, td:first-child",
            "timer_selector": ".timer",
            "description_selector": ".text, p, td:nth-child(2)",
            "date_selector": ".date, td:last-child",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1567", "T1190"],
    },
    "play": {
        "name": "Play",
        "aliases": ["PlayCrypt"],
        "onions": [],
        "patterns": {
            "victim_selector": ".news-item, article, .post",
            "name_selector": "h2, h3, .name",
            "timer_selector": ".timer, .countdown",
            "description_selector": ".content, p",
            "date_selector": ".date, time",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1490"],
    },
    "akira": {
        "name": "Akira",
        "aliases": [],
        "onions": [],
        "patterns": {
            "victim_selector": ".post, article, .item, .card",
            "name_selector": "h2, h3, .title",
            "timer_selector": ".timer",
            "description_selector": ".description, p, .content",
            "date_selector": ".date, time",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1078"],
    },
    "medusa": {
        "name": "Medusa",
        "aliases": ["MedusaLocker"],
        "onions": [],
        "patterns": {
            "victim_selector": ".card, .post, article",
            "name_selector": ".card-title, h2, h3",
            "timer_selector": ".countdown, .timer",
            "description_selector": ".card-body, .description, p",
            "date_selector": ".date, time",
            "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
        },
        "mitre_techniques": ["T1486", "T1489"],
    },
}


class RansomwareBlogSpider(DarkWebSpider):
    """
    Multi-group ransomware blog crawler.
    
    Extracts:
    - Victim organization names
    - Countdown timers (time until data publication)
    - Data volume threatened/leaked (TB/GB)
    - Sector/industry of the victim (when available)
    - New .onion mirror addresses (self-propagating discovery)
    - Communication channels (Tox, email, etc.)
    
    Each victim entry is converted to a STIX 2.1 Report + Indicator bundle.
    """

    @property
    def name(self) -> str:
        return "ransomware-blog-spider"

    @property
    def description(self) -> str:
        return "Crawls ransomware group leak sites for victim data and threat intelligence"

    @property
    def target_domains(self) -> list[str]:
        domains = []
        for group in RANSOMWARE_ONION_REGISTRY.values():
            domains.extend(group.get("onions", []))
        return domains

    def get_seed_urls(self) -> list[str]:
        """Return all known ransomware blog URLs."""
        urls = []
        for group in RANSOMWARE_ONION_REGISTRY.values():
            for onion in group.get("onions", []):
                urls.append(f"http://{onion}")
        return urls

    async def parse(self, result: CrawlResult) -> list[dict[str, Any]]:
        """
        Parse ransomware blog page and extract victim entries.
        
        Uses adaptive CSS selectors — tries each group's known patterns,
        falls back to generic heuristics for unknown blog layouts.
        """
        if not result.html or result.error:
            return []

        extracted: list[dict[str, Any]] = []
        soup = BeautifulSoup(result.html, "html.parser")

        # Identify which ransomware group this page belongs to
        group_info = self._identify_group(result.domain, result.title, result.text)
        group_name = group_info.get("name", "Unknown")
        patterns = group_info.get("patterns", {})

        # Extract victim entries using the group's CSS selectors
        victim_blocks = self._find_victim_blocks(soup, patterns)

        for block in victim_blocks:
            victim = self._extract_victim_data(block, patterns, group_name)
            if victim and victim.get("victim_name"):
                victim.update({
                    "source_url": result.url,
                    "source_domain": result.domain,
                    "ransomware_group": group_name,
                    "crawled_at": result.crawled_at.isoformat(),
                    "content_hash": result.content_hash,
                    "mitre_techniques": group_info.get("mitre_techniques", []),
                    "data_type": "ransomware_victim",
                })
                extracted.append(victim)
                logger.info(
                    "[%s] Victim detected: %s (group: %s)",
                    self.name,
                    victim["victim_name"],
                    group_name,
                )

        # Extract .onion mirrors for self-propagating discovery (AIL pattern)
        new_onions = self._discover_onion_links(soup, result.domain)
        for onion in new_onions:
            extracted.append({
                "data_type": "onion_discovery",
                "onion_address": onion,
                "found_on": result.url,
                "ransomware_group": group_name,
            })

        # Extract communication channels (Tox, XMPP, email, etc.)
        channels = self._extract_comms(result.text)
        if channels:
            extracted.append({
                "data_type": "threat_comms",
                "ransomware_group": group_name,
                "channels": channels,
                "source_url": result.url,
            })

        return extracted

    def _identify_group(self, domain: str, title: str, text: str) -> dict[str, Any]:
        """Identify which ransomware group operates this blog."""
        combined = f"{domain} {title} {text}".lower()

        for key, group in RANSOMWARE_ONION_REGISTRY.items():
            # Check domain match
            for onion in group.get("onions", []):
                if onion in domain:
                    return group

            # Check name/alias match in content
            names_to_check = [group["name"].lower()] + [a.lower() for a in group.get("aliases", [])]
            for name in names_to_check:
                if name in combined:
                    return group

        # Fallback: generic ransomware blog patterns
        return {
            "name": "Unknown",
            "patterns": {
                "victim_selector": "article, .post, .card, .item, .entry, tr",
                "name_selector": "h2, h3, .title, strong",
                "timer_selector": ".timer, .countdown",
                "description_selector": "p, .content, .description",
                "date_selector": ".date, time",
                "file_size_pattern": r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)",
            },
            "mitre_techniques": ["T1486"],
        }

    def _find_victim_blocks(self, soup: BeautifulSoup, patterns: dict) -> list:
        """Find DOM elements that represent individual victim entries."""
        selector = patterns.get("victim_selector", "article, .post, .card")
        blocks = soup.select(selector)

        # Filter out blocks that are too small to be victim entries
        return [b for b in blocks if len(b.get_text(strip=True)) > 20]

    def _extract_victim_data(
        self,
        block: Any,
        patterns: dict,
        group_name: str,
    ) -> dict[str, Any]:
        """Extract structured victim data from a DOM block."""
        victim: dict[str, Any] = {}

        # Victim name
        name_el = block.select_one(patterns.get("name_selector", "h2, h3"))
        if name_el:
            victim["victim_name"] = name_el.get_text(strip=True)[:200]

        # Description / leaked data info
        desc_el = block.select_one(patterns.get("description_selector", "p"))
        if desc_el:
            victim["description"] = desc_el.get_text(strip=True)[:2000]

        # Timer / countdown
        timer_el = block.select_one(patterns.get("timer_selector", ".timer"))
        if timer_el:
            timer_text = timer_el.get_text(strip=True)
            victim["countdown_text"] = timer_text
            victim["deadline"] = self._parse_countdown(timer_text)

        # Date
        date_el = block.select_one(patterns.get("date_selector", ".date, time"))
        if date_el:
            victim["published_date"] = date_el.get_text(strip=True)
            # Try parsing datetime attribute
            if date_el.get("datetime"):
                victim["published_date"] = date_el["datetime"]

        # File size (regex from block text)
        block_text = block.get_text()
        size_pattern = patterns.get("file_size_pattern", r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)")
        size_match = re.search(size_pattern, block_text, re.IGNORECASE)
        if size_match:
            victim["data_volume"] = f"{size_match.group(1)} {size_match.group(2).upper()}"

        # Try to extract victim website/domain
        for link in block.find_all("a", href=True):
            href = link["href"]
            if not href.endswith(".onion") and "." in href:
                victim["victim_website"] = href
                break

        # Sector detection from keywords
        victim["sector"] = self._detect_sector(block_text)

        return victim

    def _parse_countdown(self, timer_text: str) -> str | None:
        """Parse countdown timer text into an estimated deadline."""
        # Common formats: "23d 04h 12m", "2024-01-15", "3 days left"
        days_match = re.search(r"(\d+)\s*d", timer_text, re.IGNORECASE)
        if days_match:
            from datetime import timedelta
            days = int(days_match.group(1))
            deadline = datetime.now(timezone.utc) + timedelta(days=days)
            return deadline.isoformat()
        return None

    def _detect_sector(self, text: str) -> str:
        """Detect victim industry sector from contextual keywords."""
        text_lower = text.lower()
        sector_keywords = {
            "healthcare": ["hospital", "medical", "health", "pharma", "clinic", "patient"],
            "finance": ["bank", "financial", "insurance", "investment", "capital"],
            "education": ["university", "school", "college", "education", "student"],
            "government": ["government", "federal", "municipality", "city of", "county"],
            "manufacturing": ["manufacturing", "industrial", "factory", "production"],
            "technology": ["software", "technology", "tech", "digital", "cyber", "IT services"],
            "retail": ["retail", "store", "shop", "ecommerce", "consumer"],
            "energy": ["energy", "oil", "gas", "power", "utility"],
            "legal": ["law firm", "legal", "attorney", "lawyer"],
            "construction": ["construction", "building", "engineering", "architect"],
            "transportation": ["transport", "logistics", "shipping", "freight"],
        }

        for sector, keywords in sector_keywords.items():
            if any(kw in text_lower for kw in keywords):
                return sector

        return "unknown"

    def _discover_onion_links(self, soup: BeautifulSoup, current_domain: str) -> list[str]:
        """
        Discover new .onion addresses in the page content.
        Adapted from AIL's onion discovery push pattern.
        """
        onion_pattern = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)
        text = soup.get_text()
        found = set(onion_pattern.findall(text))

        # Exclude the current domain
        found.discard(current_domain)

        # Also check href attributes
        for link in soup.find_all("a", href=True):
            match = onion_pattern.search(link["href"])
            if match:
                found.add(match.group())

        return list(found)[:20]

    def _extract_comms(self, text: str) -> dict[str, list[str]]:
        """Extract communication channels from page text."""
        channels: dict[str, list[str]] = {}

        # Tox IDs (76 hex characters)
        tox = re.findall(r"[A-Fa-f0-9]{76}", text)
        if tox:
            channels["tox"] = list(set(tox))

        # Email addresses
        emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
        if emails:
            channels["email"] = list(set(emails))

        # XMPP/Jabber
        xmpp = re.findall(r"[\w.+-]+@[\w-]+\.(?:im|chat|xmpp|jabber)[\w.]*", text)
        if xmpp:
            channels["xmpp"] = list(set(xmpp))

        # Session IDs
        session = re.findall(r"05[a-f0-9]{64}", text)
        if session:
            channels["session"] = list(set(session))

        return channels
