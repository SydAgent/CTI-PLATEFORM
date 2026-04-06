"""
ONYX CTI — GitHub Leak Monitor
Monitors public GitHub repositories and Gists for exposed credentials,
API keys, internal documents, and threat intelligence artifacts.

Pattern source: AIL Framework paste monitoring logic extended to GitHub's
search API, combined with patterns from tools like truffleHog / gitleaks.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from onyx_core.services.redis import RedisService

logger = logging.getLogger("onyx.crawler.github")


# High-value secret patterns (truffleHog/gitleaks inspired)
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "github_oauth": re.compile(r"gho_[A-Za-z0-9_]{36,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,250}"),
    "slack_webhook": re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
    "stripe_key": re.compile(r"[sr]k_live_[0-9a-zA-Z]{24,}"),
    "twilio_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+"),
    "azure_key": re.compile(r"(?i)(?:azure|storage).*?(?:key|token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{44,88})['\"]?"),
    "generic_password": re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,100})['\"]"),
    "database_url": re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
    "telegram_bot": re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    "sendgrid_key": re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    "heroku_key": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
}

# GitHub Code Search dorks for CTI monitoring
GITHUB_SEARCH_DORKS = [
    # Credential leaks
    "password filename:.env",
    "PRIVATE KEY filename:id_rsa",
    "AWS_SECRET_ACCESS_KEY",
    "api_key filename:config",
    # Internal infrastructure
    "filename:wp-config.php password",
    "filename:.htpasswd",
    "filename:shadow path:etc",
    # Threat intelligence artifacts
    "ransomware decrypt tool",
    "cobalt strike beacon config",
    "mimikatz sekurlsa",
    "malware c2 server list",
]


@dataclass
class GitHubLeak:
    """A single detected leak from GitHub."""
    repo: str
    file_path: str
    url: str
    secret_type: str
    secret_preview: str  # Redacted preview (first/last 4 chars)
    author: str
    committed_at: str
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    content_hash: str = ""
    severity: str = "high"
    search_query: str = ""


class GitHubMonitor:
    """
    Monitors GitHub for exposed credentials and threat intelligence data.
    Uses the GitHub Code Search API with rate limiting and pagination.
    """

    def __init__(self, github_token: str | None = None) -> None:
        self.token = github_token or os.getenv("GITHUB_TOKEN", "")
        self._seen_hashes: set[str] = set()
        self._stats = {
            "repos_scanned": 0,
            "leaks_found": 0,
            "last_scan": None,
        }

    async def scan(self) -> list[GitHubLeak]:
        """Execute a full scan cycle across all search dorks."""
        logger.info("Starting GitHub leak scan cycle")
        self._stats["last_scan"] = datetime.now(timezone.utc).isoformat()
        all_leaks: list[GitHubLeak] = []

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ONYX-CTI-Monitor/3.0",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            for dork in GITHUB_SEARCH_DORKS:
                try:
                    leaks = await self._search_github(client, dork)
                    all_leaks.extend(leaks)
                    # GitHub API rate limit: 10 req/min for code search
                    await asyncio.sleep(7)
                except Exception as e:
                    logger.error("GitHub search error for '%s': %s", dork, str(e))

        if all_leaks:
            await self._emit_leaks(all_leaks)

        logger.info("GitHub scan complete — %d leaks found", len(all_leaks))
        return all_leaks

    async def _search_github(self, client: httpx.AsyncClient, query: str) -> list[GitHubLeak]:
        """Execute a single GitHub code search query."""
        leaks: list[GitHubLeak] = []

        resp = await client.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": 30, "sort": "indexed", "order": "desc"},
        )

        if resp.status_code == 403:
            logger.warning("GitHub rate limit hit — waiting 60s")
            await asyncio.sleep(60)
            return leaks

        if resp.status_code != 200:
            logger.warning("GitHub search returned %d", resp.status_code)
            return leaks

        data = resp.json()
        for item in data.get("items", []):
            self._stats["repos_scanned"] += 1
            repo_name = item.get("repository", {}).get("full_name", "unknown")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            # Fetch raw content for deeper analysis
            raw_url = item.get("git_url", "")
            if raw_url:
                content = await self._fetch_file_content(client, raw_url)
                if content:
                    content_hash = hashlib.sha256(content.encode()).hexdigest()
                    if content_hash in self._seen_hashes:
                        continue
                    self._seen_hashes.add(content_hash)

                    # Scan for secrets
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        matches = pattern.findall(content)
                        if matches:
                            for match in matches[:3]:  # Cap at 3 per type per file
                                match_str = match if isinstance(match, str) else match[0] if match else ""
                                preview = self._redact(match_str)
                                leak = GitHubLeak(
                                    repo=repo_name,
                                    file_path=file_path,
                                    url=html_url,
                                    secret_type=secret_type,
                                    secret_preview=preview,
                                    author=item.get("repository", {}).get("owner", {}).get("login", ""),
                                    committed_at="",
                                    content_hash=content_hash,
                                    severity=self._severity_for_type(secret_type),
                                    search_query=query,
                                )
                                leaks.append(leak)
                                self._stats["leaks_found"] += 1

        return leaks

    async def _fetch_file_content(self, client: httpx.AsyncClient, git_url: str) -> str | None:
        """Fetch raw file content from GitHub git blob API."""
        try:
            resp = await client.get(git_url)
            if resp.status_code == 200:
                data = resp.json()
                import base64
                if data.get("encoding") == "base64":
                    return base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")[:200000
                ]
        except Exception:
            pass
        return None

    def _redact(self, secret: str) -> str:
        """Redact a secret for safe display: show first and last 4 chars."""
        if len(secret) <= 10:
            return "****"
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _severity_for_type(self, secret_type: str) -> str:
        """Map secret type to severity."""
        critical = {"aws_access_key", "aws_secret_key", "private_key", "database_url"}
        high = {"github_token", "stripe_key", "slack_token", "azure_key", "generic_password"}
        if secret_type in critical:
            return "critical"
        if secret_type in high:
            return "high"
        return "medium"

    async def _emit_leaks(self, leaks: list[GitHubLeak]) -> None:
        """Publish discovered leaks to the event stream."""
        try:
            redis = RedisService()
            for leak in leaks:
                await redis.publish_event(
                    stream="onyx:events:crawlers",
                    event_type="github.leak_detected",
                    data={
                        "repo": leak.repo,
                        "file_path": leak.file_path,
                        "secret_type": leak.secret_type,
                        "severity": leak.severity,
                        "url": leak.url,
                    },
                )
        except Exception as e:
            logger.error("Failed to emit GitHub leaks: %s", str(e))
