"""
ONYX CTI — Sovereign NLP Dynamic Reports Engine
100% Local Threat Intelligence structifier. Zero external LLMs.
Deterministic parsing for RSS Feeds -> Strategic JSON Reports.
"""

import asyncio
import html
import random
import re
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import httpx
import structlog

logger = structlog.get_logger("onyx.worker.dynamic_reports")

RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "CISA Cyber Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"}
]

# KNOWN THREAT ACTOR ALIASES DICTIONARY
THREAT_ACTOR_ALIASES = {
    "APT29": ["Cozy Bear", "The Dukes", "YTTRIUM", "APT29"],
    "APT41": ["Winnti", "BARIUM", "Double Dragon", "APT41"],
    "Lazarus Group": ["HIDDEN COBRA", "Guardians of Peace", "Lazarus", "Lazarus Group"],
    "FIN7": ["Carbon Spider", "Carbanak", "FIN7"],
    "Volt Typhoon": ["Bronze Silhouette", "Volt Typhoon"],
    "Scattered Spider": ["UNC3944", "0ktapus", "Scattered Spider"]
}

# BASIC OSINT REGEX PATTERNS
PATTERNS = {
    "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b', re.IGNORECASE),
    "hash": re.compile(r'\b[A-Fa-f0-9]{32,64}\b'),
    "mitre_ttp": re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')
}

def clean_html(raw_html: str) -> str:
    """Removes HTML tags and unescapes entities."""
    cleantext = re.sub(r'<.*?>', '', raw_html)
    return html.unescape(cleantext).strip()

def extract_structured_intelligence(title: str, text: str) -> dict:
    """
    Deterministic NLP parsing logic to extract strategic fields.
    """
    combined = f"{title}. {text}"
    
    extracted_iocs = []
    # 1. Match IPv4
    for match in PATTERNS["ipv4"].finditer(combined):
        if match.group(0) not in extracted_iocs: extracted_iocs.append(match.group(0))
    # 2. Match Domains
    for match in PATTERNS["domain"].finditer(combined):
        val = match.group(0).lower()
        if val not in extracted_iocs and not val.endswith('bleepingcomputer.com') and not val.endswith('thehackernews.com') and not val.endswith('cisa.gov'):
            extracted_iocs.append(val)
    # 3. Match Hashes
    for match in PATTERNS["hash"].finditer(combined):
        if match.group(0) not in extracted_iocs: extracted_iocs.append(match.group(0))

    mitre_techniques = []
    for match in PATTERNS["mitre_ttp"].finditer(combined):
        if match.group(0) not in mitre_techniques: mitre_techniques.append(match.group(0))

    # Match Threat Actors
    involved_actors = []
    lower_comb = combined.lower()
    for ta_primary, aliases in THREAT_ACTOR_ALIASES.items():
        for alias in aliases:
            if alias.lower() in lower_comb and ta_primary not in involved_actors:
                involved_actors.append(ta_primary)

    # Determine priority heuristically
    severity = "low"
    if "cve" in lower_comb or "zero-day" in lower_comb or "critical" in lower_comb:
        severity = "critical"
    elif "ransomware" in lower_comb or involved_actors:
        severity = "high"
    elif extracted_iocs:
        severity = "medium"

    # Construct the 6-Part 1JSON structure
    # 1. Executive Summary
    exec_summary_sentences = re.split(r'(?<=[.!?])\s+', text)
    exec_summary = " ".join(exec_summary_sentences[:2]) if exec_summary_sentences else text

    # 2. Threat Overview
    threat_overview = "No attribution data in raw feed."
    if involved_actors:
        threat_overview = f"Strategic activity attributed to: {', '.join(involved_actors)}."

    # 3. Technical Breakdown
    cves = []
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    for match in cve_pattern.finditer(combined):
        if match.group(0).upper() not in cves: cves.append(match.group(0).upper())

    technical_breakdown = []
    if cves: technical_breakdown.append(f"Exploited Vulnerabilities: {', '.join(cves)}")
    if extracted_iocs: technical_breakdown.append(f"Network/Host Indicators: {len(extracted_iocs)} unique observables.")
    technical_breakdown_str = " | ".join(technical_breakdown) if technical_breakdown else "No strict technical indicators found in raw text."

    # 4 & 5. Impact Analysis & Mitigation
    impact_analysis = []
    mitigation = []
    
    if "rce" in lower_comb or "remote code execution" in lower_comb:
        impact_analysis.append("RCE verified: Potential for full system compromise and lateral movement.")
        mitigation.append("Patch vulnerable external-facing endpoints immediately. Hunt for web shell drops.")
    if "phishing" in lower_comb or "spear-phishing" in lower_comb:
        impact_analysis.append("Initial Access via Phishing: Threat actor targeting human endpoints.")
        mitigation.append("Enforce MFA. Isolate affected user accounts. Block identified domains.")
    if "ransomware" in lower_comb or "encrypt" in lower_comb:
        impact_analysis.append("Ransomware deployment detected. High risk of data extortion and encryption.")
        mitigation.append("Isolate immediate subnets. Verify immutable backups. Do not reboot infected hosts.")
        
    impact_str = " ".join(impact_analysis) if impact_analysis else "Insufficient context to determine definitive impact."
    mitigation_str = " ".join(mitigation) if mitigation else "Apply standard defense-in-depth protocols and investigate further."

    # 6. Intelligence Links
    intelligence_links = {
        "iocs": extracted_iocs[:15],
        "actors": involved_actors,
        "ttps": mitre_techniques
    }

    return {
        "id": f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{random.randint(1000, 9999)}",
        "title": title,
        "executive_summary": exec_summary,
        "threat_overview": threat_overview,
        "technical_breakdown": technical_breakdown_str,
        "impact_analysis": impact_str,
        "mitigation": mitigation_str,
        "intelligence_links": intelligence_links,
        "mitigation_priority": severity,
        "date": datetime.now(timezone.utc).isoformat(),
        "author": "ONYX Sovereign NLP Engine",
        "source": "RSS Triage"
    }

async def fetch_and_parse_rss(client: httpx.AsyncClient, feed: dict) -> list[dict]:
    items = []
    try:
        res = await client.get(feed["url"], timeout=10.0, follow_redirects=True)
        res.raise_for_status()
        
        # Native XML parsing mapping
        root = ET.fromstring(res.content)
        for element in root.iter():
            if element.tag.endswith('item') or element.tag.endswith('entry'):
                title, desc = '', ''
                for child in element:
                    if child.tag.endswith('title'):
                        title = child.text or ''
                    elif child.tag.endswith('description') or child.tag.endswith('summary'):
                        desc = child.text or ''
                
                cleaned_desc = clean_html(desc).replace('\n', ' ')
                if len(cleaned_desc) > 20:
                    items.append({"title": title, "text": cleaned_desc, "source": feed["name"]})
    except Exception as e:
        logger.warning("onyx.report_ingestor.error", feed=feed["name"], error=str(e))
    return items

async def start_dynamic_reports_worker(app_state, sse_broadcast_callback, poll_interval: int = 180):
    """
    Background autonomous poller for Sovereign Reports.
    """
    logger.info("onyx.dynamic_reports.start", message="[PHASE 10] Sovereign NLP Reports Engine Arming...")
    
    # Initialize the app.state list if not exists
    if not hasattr(app_state, "strategic_reports"):
        app_state.strategic_reports = []
    
    seen_articles = set()

    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            logger.info("onyx.dynamic_reports.cycle", message="Polling OSINT feeds for new reports...")
            new_reports = []
            
            for feed in RSS_FEEDS:
                articles = await fetch_and_parse_rss(client, feed)
                
                # Take only a few to avoid overwhelming
                for art in articles[:3]:
                    signature = hash(art["title"])
                    if signature not in seen_articles:
                        seen_articles.add(signature)
                        report_data = extract_structured_intelligence(art["title"], art["text"])
                        report_data["feed_source"] = art["source"]
                        new_reports.append(report_data)

            if new_reports:
                # Add to app state safely (Thread/Async safe usually for assignment)
                current = getattr(app_state, "strategic_reports", [])
                # Insert at front, cap at 50
                app_state.strategic_reports = (new_reports + current)[:50]
                
                logger.info("onyx.dynamic_reports.parsed", count=len(new_reports))
                
                # Broadcast sequentially to SSE dashboard
                if sse_broadcast_callback:
                    for report in new_reports:
                        try:
                            await sse_broadcast_callback(report)
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)
            
            await asyncio.sleep(poll_interval)
