 """
ONYX CTI — Base Dark Web Spider
Abstract base class for all .onion crawlers. Provides:
- Tor-proxied HTTP requests with retry logic
- Anti-detection: request throttling, header rotation, circuit rotation
- Content extraction pipeline integration
- Screenshot capture via Playwright fallback
- Structured crawl result output to the processing pipeline

Pattern source: AIL Framework Crawler.py — compute(), save_capture_response(),
enqueue_capture() logic adapted to async Python with HTTPX transport.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from onyx_core.config import get_config
from onyx_core.services.redis import RedisService
from onyx_crawlers.darkweb.tor_manager import TorManager

logger = logging.getLogger("onyx.crawler.darkweb")


# Rotating User-Agents (Tor Browser versions — blends with real Tor traffic)
TOR_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
]


@dataclass
class CrawlResult:
    """Structured output from a single page crawl."""
    url: str
    domain: str
    status_code: int = 0
    title: str = ""
    html: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)
    crawled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_ms: float = 0.0
    content_hash: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CrawlJob:
    """Configuration for a crawl task."""
    url: str
    spider_name: str
    depth: int = 1
    max_pages: int = 50
    delay_min: float = 3.0
    delay_max: float = 8.0
    screenshot: bool = True
    extract_links: bool = True
    follow_redirects: bool = True
    custom_headers: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    priority: int = 5


class DarkWebSpider(ABC):
    """
    Abstract base class for dark web crawlers.
    
    Lifecycle adapted from AIL's Crawler.compute() flow:
    1. Initialize Tor circuit → verify connectivity
    2. Crawl target URL(s) with anti-detection delays
    3. Extract content (title, text, links) from HTML
    4. Deduplicate via content hashing (SimHash pattern from AIL)
    5. Push results to the processing pipeline via Redis Streams
    6. Rotate circuit after N requests
    
    Subclasses implement:
    - parse(result: CrawlResult) → Extract structured data from crawled page
    - get_seed_urls() → Return initial URLs to crawl
    """

    def __init__(self, tor_manager: TorManager | None = None) -> None:
        self.tor = tor_manager or TorManager()
        self.config = get_config().crawler
        self._results: list[CrawlResult] = []
        self._visited: set[str] = set()
        self._content_hashes: set[str] = set()
        self._stats = {
            "pages_crawled": 0,
            "pages_skipped": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique spider identifier."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""

    @property
    @abstractmethod
    def target_domains(self) -> list[str]:
        """List of .onion domains this spider targets."""

    @abstractmethod
    async def parse(self, result: CrawlResult) -> list[dict[str, Any]]:
        """
        Parse a crawl result and extract structured threat intelligence.
        
        Returns:
            List of extracted data dicts (IOCs, threat actors, leak data, etc.)
        """

    @abstractmethod
    def get_seed_urls(self) -> list[str]:
        """Return initial URLs to begin crawling."""

    async def crawl(self, job: CrawlJob | None = None) -> list[CrawlResult]:
        """
        Execute the full crawl lifecycle.
        
        Adapted from AIL's Crawler.compute() + save_capture_response() flow:
        - Enqueue capture → process capture → save results
        """
        if self.tor.is_killed:
            logger.error("Crawl aborted: Tor kill-switch is active")
            return []

        self._stats["start_time"] = datetime.now(timezone.utc).isoformat()

        # Step 1: Verify Tor connectivity (AIL's refresh_lacus_status pattern)
        circuit = await self.tor.check_connection()
        if not circuit.is_tor:
            logger.error("Cannot start crawl: Tor is not connected")
            return []

        logger.info(
            "[%s] Starting crawl — exit IP: %s, targets: %d domains",
            self.name,
            circuit.exit_ip,
            len(self.target_domains),
        )

        # Step 2: Get seed URLs
        urls = [job.url] if job else self.get_seed_urls()
        max_pages = job.max_pages if job else 50
        depth = job.depth if job else 1

        # Step 3: BFS crawl with depth control
        current_depth = 0
        queue = [(url, 0) for url in urls]

        while queue and self._stats["pages_crawled"] < max_pages:
            url, url_depth = queue.pop(0)

            if url in self._visited or url_depth > depth:
                continue

            self._visited.add(url)

            # Anti-detection delay (AIL's pending_seconds pattern + randomization)
            delay = random.uniform(
                job.delay_min if job else self.config.request_delay,
                job.delay_max if job else self.config.request_delay * 2,
            )
            await asyncio.sleep(delay)

            # Fetch page
            result = await self._fetch_page(url)
            if result.error:
                self._stats["errors"] += 1
                continue

            # Content dedup (AIL's dom-hash pattern)
            if result.content_hash in self._content_hashes:
                self._stats["pages_skipped"] += 1
                logger.debug("Skipping duplicate content: %s", url)
                continue
            self._content_hashes.add(result.content_hash)

            self._results.append(result)
            self._stats["pages_crawled"] += 1

            # Parse structured data
            extracted = await self.parse(result)
            if extracted:
                await self._emit_results(result, extracted)

            # Extract and enqueue child links (AIL's recursive save_capture_response)
            if result.links and url_depth < depth:
                for link in result.links:
                    if link not in self._visited:
                        queue.append((link, url_depth + 1))

            # Auto-rotate circuit after threshold
            await self.tor.maybe_rotate()

            logger.info(
                "[%s] Crawled %d/%d — %s (%dms)",
                self.name,
                self._stats["pages_crawled"],
                max_pages,
                url[:80],
                result.response_time_ms,
            )

        self._stats["end_time"] = datetime.now(timezone.utc).isoformat()
        logger.info(
            "[%s] Crawl complete — %d pages, %d errors, %d skipped",
            self.name,
            self._stats["pages_crawled"],
            self._stats["errors"],
            self._stats["pages_skipped"],
        )

        return self._results

    async def _fetch_page(self, url: str) -> CrawlResult:
        """
        Fetch a single page through Tor with retry logic.
        Adapted from AIL's enqueue_capture → get_capture flow.
        """
        domain = urlparse(url).netloc
        result = CrawlResult(url=url, domain=domain)

        for attempt in range(3):
            try:
                start = time.monotonic()
                async with self.tor.get_proxy_client(timeout=45.0) as client:
                    # Rotate User-Agent per request (anti-fingerprinting)
                    client.headers["User-Agent"] = random.choice(TOR_USER_AGENTS)

                    response = await client.get(url)
                    elapsed = (time.monotonic() - start) * 1000

                    result.status_code = response.status_code
                    result.html = response.text
                    result.response_time_ms = round(elapsed, 1)

                    # Extract content (AIL's extract_title_from_html + content processing)
                    soup = BeautifulSoup(result.html, "html.parser")

                    # Title extraction
                    title_tag = soup.find("title")
                    result.title = title_tag.get_text(strip=True) if title_tag else ""

                    # Clean text extraction (remove scripts, styles)
                    for tag in soup(["script", "style", "noscript", "nav", "footer", "header"]):
                        tag.decompose()
                    result.text = soup.get_text(separator="\n", strip=True)

                    # Content hash for deduplication (AIL's dom-hash pattern)
                    result.content_hash = hashlib.sha256(
                        result.text.encode("utf-8", errors="ignore")
                    ).hexdigest()

                    # Link extraction
                    if self.config.darkweb_enabled:
                        result.links = self._extract_links(soup, url)

                    return result

            except httpx.TimeoutException:
                logger.warning("Timeout on attempt %d for %s", attempt + 1, url[:80])
                if attempt < 2:
                    await asyncio.sleep(5 * (attempt + 1))
            except (httpx.ConnectError, httpx.ProxyError) as e:
                logger.warning("Connection error on attempt %d for %s: %s", attempt + 1, url[:80], str(e))
                if attempt < 2:
                    await self.tor.rotate_circuit()
                    await asyncio.sleep(10)
            except Exception as e:
                logger.error("Unexpected error fetching %s: %s", url[:80], str(e))
                result.error = str(e)
                return result

        result.error = f"Failed after 3 attempts: {url}"
        return result

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        """
        Extract and normalize links from HTML.
        Filters to same-domain only for .onion sites.
        """
        links = []
        base_domain = urlparse(base_url).netloc

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue

            # Resolve relative URLs
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)

            # Only follow links to same .onion domain (isolation principle)
            if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in links:
                    links.append(clean)

        return links[:100]  # Cap at 100 links per page

    async def _emit_results(self, result: CrawlResult, extracted: list[dict[str, Any]]) -> None:
        """
        Push extracted data to the processing pipeline via Redis Streams.
        Adapted from AIL's add_message_to_queue() pattern.
        """
        try:
            redis = RedisService()
            for item in extracted:
                await redis.publish_event(
                    stream="onyx:events:crawlers",
                    event_type="crawler.data_extracted",
                    data={
                        "spider": self.name,
                        "source_url": result.url,
                        "domain": result.domain,
                        "crawled_at": result.crawled_at.isoformat(),
                        "content_hash": result.content_hash,
                        "extracted": item,
                    },
                )
        except Exception as e:
            logger.error("Failed to emit results: %s", str(e))
