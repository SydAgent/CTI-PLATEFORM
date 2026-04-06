"""
ONYX CTI — IOC Extractor Engine
High-precision regex-based extraction of Indicators of Compromise from raw text.
Achieves near-zero false positives via multi-layer validation.

Pattern source:
- AIL Framework bin/modules/IPAddress.py, Onion.py, CreditCards.py — 
  extraction patterns and validation logic
- IntelOwl api_app/analyzers_manager — observable classification and type system
- iocextract library patterns — defanging/refanging logic
- Custom ONYX patterns — additional IOC types and validation rules

Supported IOC types: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, SHA512,
email, CVE, BTC wallet, ETH wallet, XMR wallet, YARA rule refs, MITRE
technique IDs, CIDR ranges, ASN numbers, JA3/JA3S hashes.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("onyx.nlp.ioc_extractor")


@dataclass
class IOCMatch:
    """A single extracted IOC with metadata."""
    type: str
    value: str
    raw: str  # Original text as found (may be defanged)
    start: int  # Character offset in source text
    end: int
    confidence: float = 1.0  # 0.0-1.0, reduced for potential FPs
    context: str = ""  # Surrounding text (±50 chars)
    defanged: bool = False  # Whether the original was defanged


@dataclass
class ExtractionResult:
    """Complete IOC extraction result from a text document."""
    source: str = ""
    total_iocs: int = 0
    iocs: list[IOCMatch] = field(default_factory=list)
    by_type: dict[str, int] = field(default_factory=dict)
    processing_time_ms: float = 0.0


# ============================================================================
# Precompiled Regex Patterns — Optimized for performance and accuracy
# ============================================================================

# --- Defanging patterns (convert defanged IOCs back to valid form) ---
REFANG_PATTERNS = [
    (re.compile(r"\[(\.|dot)\]", re.IGNORECASE), "."),
    (re.compile(r"\((\.|dot)\)", re.IGNORECASE), "."),
    (re.compile(r"\[:]", re.IGNORECASE), ":"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"hXXp", re.IGNORECASE), "http"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\\\."), "."),
]

# --- IPv4 Address ---
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
IPV4_PATTERN = re.compile(
    rf"\b({_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET})\b"
)
# Defanged IPv4: 192[.]168[.]1[.]1 or 192(.)168(.)1(.)1
IPV4_DEFANGED_PATTERN = re.compile(
    rf"\b({_IPV4_OCTET}(?:\[?\.\]?|\(?\.\)?){_IPV4_OCTET}"
    rf"(?:\[?\.\]?|\(?\.\)?){_IPV4_OCTET}(?:\[?\.\]?|\(?\.\)?){_IPV4_OCTET})\b"
)

# --- IPv6 Address ---
IPV6_PATTERN = re.compile(
    r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})\b"
)

# --- CIDR Range ---
CIDR_PATTERN = re.compile(
    rf"\b({_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}/(?:3[0-2]|[12]?\d))\b"
)

# --- Domain Name ---
# Strict domain validation: must have valid TLD, no numeric-only labels
DOMAIN_PATTERN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,63}))\b"
)

# --- URL ---
URL_PATTERN = re.compile(
    r"((?:https?|ftp|hxxps?):\/\/(?:[\w.-]+(?:\.[\w.-]+)+|localhost)"
    r"(?::\d{1,5})?(?:\/[\w\-.~:/?#\[\]@!$&'()*+,;=%]*)?)",
    re.IGNORECASE,
)
URL_DEFANGED_PATTERN = re.compile(
    r"(hxxps?(?:\[:\]|:)\/\/[\w\[\]().\-]+(?:\.[\w\[\]().\-]+)+[\w\-.~:/?#@!$&'*+,;=%\[\]()]*)",
    re.IGNORECASE,
)

# --- File Hashes ---
MD5_PATTERN = re.compile(r"\b([a-fA-F0-9]{32})\b")
SHA1_PATTERN = re.compile(r"\b([a-fA-F0-9]{40})\b")
SHA256_PATTERN = re.compile(r"\b([a-fA-F0-9]{64})\b")
SHA512_PATTERN = re.compile(r"\b([a-fA-F0-9]{128})\b")

# --- JA3/JA3S Hashes ---
JA3_PATTERN = re.compile(r"\bja3[s]?:\s*([a-fA-F0-9]{32})\b", re.IGNORECASE)

# --- Email Address ---
EMAIL_PATTERN = re.compile(
    r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63})\b"
)

# --- CVE Identifier ---
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

# --- MITRE ATT&CK Technique ID ---
MITRE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# --- Cryptocurrency Wallets ---
BTC_PATTERN = re.compile(
    r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
    r"|"
    r"\b(bc1[a-zA-HJ-NP-Z0-9]{39,59})\b"
)
ETH_PATTERN = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
XMR_PATTERN = re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")

# --- .onion Address ---
ONION_PATTERN = re.compile(r"\b([a-z2-7]{16,56}\.onion)\b", re.IGNORECASE)

# --- ASN Number ---
ASN_PATTERN = re.compile(r"\b(AS\d{1,10})\b", re.IGNORECASE)

# --- YARA Rule References ---
YARA_PATTERN = re.compile(r"\brule\s+(\w+)\s*\{", re.IGNORECASE)

# ============================================================================
# Validation Functions — Reduce false positives
# ============================================================================

# Common words that look like hashes but aren't
HASH_EXCLUSIONS = {
    "0" * 32, "f" * 32, "0" * 40, "f" * 40, "0" * 64, "f" * 64,
    "0" * 128, "f" * 128,
}

# Private/reserved IP ranges (exclude from IOCs)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),   # Multicast
    ipaddress.ip_network("240.0.0.0/4"),   # Reserved
]

# Non-IOC domains to exclude
DOMAIN_WHITELIST = {
    "example.com", "example.org", "example.net",
    "localhost", "localhost.localdomain",
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.net", "azure.com",
    "github.com", "githubusercontent.com",
    "amazonaws.com", "cloudfront.net",
    "w3.org", "schema.org", "xml.org",
    "mozilla.org", "mozilla.com",
    "jquery.com", "cloudflare.com",
    "twitter.com", "facebook.com",
    "linkedin.com", "youtube.com",
}

# Valid TLDs (subset of common ones to reduce false positives)
VALID_TLDS = {
    "com", "net", "org", "info", "io", "co", "us", "uk", "de", "fr",
    "ru", "cn", "jp", "br", "in", "au", "ca", "it", "es", "nl",
    "se", "no", "fi", "dk", "pl", "cz", "hu", "ro", "bg", "hr",
    "sk", "si", "ee", "lv", "lt", "pt", "gr", "ie", "at", "ch",
    "be", "lu", "is", "kr", "tw", "sg", "hk", "th", "ph", "my",
    "id", "vn", "mx", "ar", "cl", "co", "za", "ng", "ke", "eg",
    "il", "ae", "sa", "tr", "ua", "kz", "by", "md", "ge",
    "top", "xyz", "club", "online", "site", "tech", "store",
    "space", "fun", "icu", "buzz", "cc", "me", "tv", "biz",
    "pro", "name", "mobi", "asia", "tel", "cat", "jobs",
    "gov", "mil", "edu", "int", "onion",
}


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_valid_domain(domain: str) -> bool:
    """Validate a domain name for IOC extraction (strict mode)."""
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    if tld not in VALID_TLDS:
        return False

    # Exclude whitelisted domains
    if domain.lower() in DOMAIN_WHITELIST:
        return False

    # Exclude if ALL labels are numeric (likely version numbers like 1.2.3.4)
    if all(p.isdigit() for p in parts):
        return False

    # Minimum length check
    if len(domain) < 4:
        return False

    return True


def _is_valid_hash(hash_str: str, expected_len: int) -> bool:
    """Validate a hash string — exclude known false positives."""
    if len(hash_str) != expected_len:
        return False
    if hash_str in HASH_EXCLUSIONS:
        return False
    # Check entropy — real hashes have high entropy
    unique_chars = len(set(hash_str.lower()))
    if unique_chars < 6:  # Too low entropy, likely not a real hash
        return False
    return True


def _refang(text: str) -> str:
    """Convert defanged IOCs back to their normal form."""
    for pattern, replacement in REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ============================================================================
# Main Extractor Class
# ============================================================================

class IOCExtractor:
    """
    High-precision IOC extraction engine.
    
    Design principles (from AIL + IntelOwl patterns):
    1. Extract first, validate second — cast a wide net with regexes, then filter
    2. Context preservation — keep surrounding text for analyst review
    3. Defanging support — automatically refang defanged IOCs
    4. Deduplication — return unique IOCs only
    5. Confidence scoring — lower confidence for ambiguous matches
    
    Usage:
        extractor = IOCExtractor()
        result = extractor.extract("Check IP 192.168.1.1 and hash abcdef...")
        for ioc in result.iocs:
            print(f"{ioc.type}: {ioc.value} (confidence: {ioc.confidence})")
    """

    def __init__(
        self,
        include_private_ips: bool = False,
        include_defanged: bool = True,
        min_confidence: float = 0.5,
    ) -> None:
        self.include_private_ips = include_private_ips
        self.include_defanged = include_defanged
        self.min_confidence = min_confidence

    def extract(self, text: str, source: str = "") -> ExtractionResult:
        """
        Extract all IOCs from the given text.
        
        Args:
            text: Raw text to analyze.
            source: Source identifier for tracking.
            
        Returns:
            ExtractionResult with all extracted IOCs, deduplicated and validated.
        """
        import time
        start = time.monotonic()

        result = ExtractionResult(source=source)
        seen_values: set[str] = set()

        # Prepare text variants
        original_text = text
        refanged_text = _refang(text) if self.include_defanged else text

        # --- Extract each IOC type ---
        # Order matters: extract more specific patterns first to avoid collisions

        # SHA-512 (128 chars — most specific hash first)
        self._extract_hashes(refanged_text, SHA512_PATTERN, "sha512", 128, result, seen_values)

        # SHA-256 (64 chars)
        self._extract_hashes(refanged_text, SHA256_PATTERN, "sha256", 64, result, seen_values)

        # SHA-1 (40 chars)
        self._extract_hashes(refanged_text, SHA1_PATTERN, "sha1", 40, result, seen_values)

        # MD5 (32 chars)
        self._extract_hashes(refanged_text, MD5_PATTERN, "md5", 32, result, seen_values)

        # JA3/JA3S
        self._extract_pattern(refanged_text, JA3_PATTERN, "ja3", result, seen_values)

        # CVEs
        self._extract_pattern(refanged_text, CVE_PATTERN, "cve", result, seen_values)

        # MITRE ATT&CK
        self._extract_pattern(refanged_text, MITRE_PATTERN, "mitre_technique", result, seen_values)

        # URLs (before domains, as URLs contain domains)
        self._extract_urls(refanged_text, result, seen_values)
        if self.include_defanged:
            self._extract_defanged_urls(original_text, result, seen_values)

        # Email addresses (before domains)
        self._extract_pattern(refanged_text, EMAIL_PATTERN, "email", result, seen_values)

        # CIDR ranges (before IPs)
        self._extract_pattern(refanged_text, CIDR_PATTERN, "cidr", result, seen_values)

        # IPv4
        self._extract_ipv4(refanged_text, result, seen_values)

        # IPv6
        self._extract_ipv6(refanged_text, result, seen_values)

        # Domains
        self._extract_domains(refanged_text, result, seen_values)

        # Cryptocurrency wallets
        self._extract_crypto(refanged_text, result, seen_values)

        # .onion addresses
        self._extract_pattern(refanged_text, ONION_PATTERN, "onion", result, seen_values)

        # ASN
        self._extract_pattern(refanged_text, ASN_PATTERN, "asn", result, seen_values)

        # YARA rule names
        self._extract_pattern(refanged_text, YARA_PATTERN, "yara_rule", result, seen_values)

        # Compute stats
        result.total_iocs = len(result.iocs)
        result.by_type = {}
        for ioc in result.iocs:
            result.by_type[ioc.type] = result.by_type.get(ioc.type, 0) + 1

        elapsed = (time.monotonic() - start) * 1000
        result.processing_time_ms = round(elapsed, 2)

        logger.info(
            "Extracted %d IOCs (%s) from '%s' in %.1fms",
            result.total_iocs,
            ", ".join(f"{t}:{c}" for t, c in result.by_type.items()),
            source[:50] or "unknown",
            result.processing_time_ms,
        )

        return result

    def _get_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Extract surrounding context for an IOC match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].replace("\n", " ").strip()

    def _extract_hashes(
        self,
        text: str,
        pattern: re.Pattern,
        ioc_type: str,
        expected_len: int,
        result: ExtractionResult,
        seen: set[str],
    ) -> None:
        """Extract and validate file hashes."""
        for match in pattern.finditer(text):
            value = match.group(1).lower()
            if value in seen:
                continue
            if not _is_valid_hash(value, expected_len):
                continue

            # Check it wasn't already captured as a longer hash type
            already_captured = any(
                value in s for s in seen if len(s) > len(value)
            )
            if already_captured:
                continue

            seen.add(value)
            result.iocs.append(IOCMatch(
                type=ioc_type,
                value=value,
                raw=match.group(0),
                start=match.start(),
                end=match.end(),
                confidence=0.9,
                context=self._get_context(text, match.start(), match.end()),
            ))

    def _extract_ipv4(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract and validate IPv4 addresses."""
        for match in IPV4_PATTERN.finditer(text):
            value = match.group(1)
            if value in seen:
                continue

            # Validate it's a real IP, not a version number
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue

            if not self.include_private_ips and _is_private_ip(value):
                continue

            seen.add(value)
            confidence = 0.95
            # Reduce confidence if surrounded by version-like context
            ctx = self._get_context(text, match.start(), match.end())
            if re.search(r"version|v\d|release|update", ctx, re.IGNORECASE):
                confidence = 0.4

            if confidence >= self.min_confidence:
                result.iocs.append(IOCMatch(
                    type="ipv4",
                    value=value,
                    raw=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context=ctx,
                ))

    def _extract_ipv6(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract IPv6 addresses."""
        for match in IPV6_PATTERN.finditer(text):
            value = match.group(1)
            if value in seen or value == "::":
                continue
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue

            seen.add(value)
            result.iocs.append(IOCMatch(
                type="ipv6",
                value=value,
                raw=match.group(0),
                start=match.start(),
                end=match.end(),
                confidence=0.9,
                context=self._get_context(text, match.start(), match.end()),
            ))

    def _extract_domains(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract domain names with strict validation."""
        for match in DOMAIN_PATTERN.finditer(text):
            value = match.group(1).lower().rstrip(".")
            if value in seen:
                continue
            if not _is_valid_domain(value):
                continue

            # Skip if this domain was already captured as part of a URL or email
            if any(value in s for s in seen):
                continue

            seen.add(value)
            result.iocs.append(IOCMatch(
                type="domain",
                value=value,
                raw=match.group(0),
                start=match.start(),
                end=match.end(),
                confidence=0.85,
                context=self._get_context(text, match.start(), match.end()),
            ))

    def _extract_urls(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract URLs."""
        for match in URL_PATTERN.finditer(text):
            value = match.group(1)
            if value in seen:
                continue

            seen.add(value)
            result.iocs.append(IOCMatch(
                type="url",
                value=value,
                raw=match.group(0),
                start=match.start(),
                end=match.end(),
                confidence=0.95,
                context=self._get_context(text, match.start(), match.end()),
            ))

    def _extract_defanged_urls(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract defanged URLs (hxxps://, etc.)."""
        for match in URL_DEFANGED_PATTERN.finditer(text):
            raw = match.group(1)
            value = _refang(raw)
            if value in seen:
                continue

            seen.add(value)
            result.iocs.append(IOCMatch(
                type="url",
                value=value,
                raw=raw,
                start=match.start(),
                end=match.end(),
                confidence=0.95,
                context=self._get_context(text, match.start(), match.end()),
                defanged=True,
            ))

    def _extract_crypto(self, text: str, result: ExtractionResult, seen: set[str]) -> None:
        """Extract cryptocurrency wallet addresses."""
        # Bitcoin
        for match in BTC_PATTERN.finditer(text):
            value = match.group(1) or match.group(2)
            if value and value not in seen:
                seen.add(value)
                result.iocs.append(IOCMatch(
                    type="btc_wallet",
                    value=value,
                    raw=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                    context=self._get_context(text, match.start(), match.end()),
                ))

        # Ethereum
        for match in ETH_PATTERN.finditer(text):
            value = match.group(1)
            if value not in seen:
                seen.add(value)
                result.iocs.append(IOCMatch(
                    type="eth_wallet",
                    value=value,
                    raw=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                    context=self._get_context(text, match.start(), match.end()),
                ))

        # Monero
        for match in XMR_PATTERN.finditer(text):
            value = match.group(1)
            if value not in seen:
                seen.add(value)
                result.iocs.append(IOCMatch(
                    type="xmr_wallet",
                    value=value,
                    raw=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.75,
                    context=self._get_context(text, match.start(), match.end()),
                ))

    def _extract_pattern(
        self,
        text: str,
        pattern: re.Pattern,
        ioc_type: str,
        result: ExtractionResult,
        seen: set[str],
        confidence: float = 0.95,
    ) -> None:
        """Generic pattern extraction for simple IOC types."""
        for match in pattern.finditer(text):
            value = match.group(1)
            if value and value not in seen:
                seen.add(value)
                result.iocs.append(IOCMatch(
                    type=ioc_type,
                    value=value,
                    raw=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context=self._get_context(text, match.start(), match.end()),
                ))
