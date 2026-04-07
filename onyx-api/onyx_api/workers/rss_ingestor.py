"""
ONYX CTI — Autonomous RSS Threat Ingestor (Module 3)
Fetches live cybersecurity news from public RSS feeds, runs them 
through the NLP pipeline, and broadcasts the STIX/Entity extraction 
in real-time via the REDIS/Standalone SSE stream.
"""

import asyncio
import html
import json
import random
import re
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import httpx
import structlog

logger = structlog.get_logger("onyx.ingestor.rss")

# We will hit these feeds
RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "CISA Cyber Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"}
]

# Simulated SciBERT extraction logic for standalone deployment
# (In production, this would call `onyx_nlp.processors.pipeline.NLPPipeline`)
def _process_text_with_nlp(text: str) -> dict:
    entities = []
    
    # 1. Regex absolute matches
    patterns = [
        (re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', re.I), "CVE", 0.99),
        (re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'), "IP_ADDRESS", 0.99),
        (re.compile(r'\b(?:APT\d+|Lazarus|Volt Typhoon|Cozy Bear|FIN\d+|Scattered Spider|LockBit|Cl0p|ALPHV)\b', re.I), "THREAT_ACTOR", 0.95),
        (re.compile(r'\b(?:Cobalt Strike|Mimikatz|Qakbot|IcedID|Emotet|Trickbot|Bumblebee|BlackCat)\b', re.I), "MALWARE", 0.94),
        (re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b'), "MITRE_TTP", 0.96)
    ]
    
    seen = set()
    for regex, label, base_conf in patterns:
        for match in regex.finditer(text):
            val = match.group(0)
            if val.lower() not in seen:
                seen.add(val.lower())
                entities.append({
                    "label": label,
                    "text": val,
                    "conf": round(base_conf - random.uniform(0.01, 0.05), 3)
                })
                
    # 2. Contextual NLP heuristics simulation (SciBERT-like)
    context_keywords = {
        "ransomware": ("ATTACK_VECTOR", "Ransomware encryption"),
        "phishing": ("ATTACK_VECTOR", "Spearphishing"),
        "zero-day": ("VULNERABILITY", "Zero-day exploit"),
        "C2": ("MITRE_TTP", "T1071 (C2)"),
    }
    
    lower_text = text.lower()
    for kw, (label, val) in context_keywords.items():
        if kw in lower_text and val.lower() not in seen:
            seen.add(val.lower())
            entities.append({
                "label": label,
                "text": val,
                "conf": round(0.85 + random.uniform(0.01, 0.1), 3)
            })

    # Optional STIX output generation logic could go here
    return {
        "raw": text,
        "entities": entities,
        "source": "RSS_Ingestor"
    }

def clean_html(raw_html: str) -> str:
    cleantext = re.sub(r'<.*?>', '', raw_html)
    return html.unescape(cleantext).strip()

async def fetch_and_parse_rss(client: httpx.AsyncClient, feed: dict) -> list[dict]:
    items = []
    try:
        res = await client.get(feed["url"], timeout=10.0, follow_redirects=True)
        res.raise_for_status()
        
        # Native XML parsing (no feedparser dependency needed)
        root = ET.fromstring(res.content)
        
        # Handle both RSS (item) and Atom (entry)
        for element in root.iter():
            if element.tag.endswith('item') or element.tag.endswith('entry'):
                title = ''
                desc = ''
                for child in element:
                    if child.tag.endswith('title'):
                        title = child.text or ''
                    elif child.tag.endswith('description') or child.tag.endswith('summary'):
                        desc = child.text or ''
                        
                combined = f"{title}. {clean_html(desc)}"
                if len(combined) > 20:
                    items.append({
                        "title": title,
                        "text": combined.replace('\n', ' ')[:500],
                        "source": feed["name"]
                    })
    except Exception as e:
        logger.warning("onyx.rss.error", feed=feed["name"], error=str(e))
        
    return items

async def start_autonomous_ingestor(app_state, sse_broadcast_callback):
    """
    Background worker that fetches RSS, extracts entities, and emits to SSE.
    """
    logger.info("onyx.worker.rss", message="[MODULE 3] Autonomous RSS NLP Ingestor Initialized.")
    seen_articles = set()

    async with httpx.AsyncClient() as client:
        while True:
            logger.info("onyx.worker.rss.poll", message="Polling cyber news feeds...")
            
            new_extractions = []
            for feed in RSS_FEEDS:
                articles = await fetch_and_parse_rss(client, feed)
                for art in articles:
                    signature = hash(art["title"])
                    if signature not in seen_articles:
                        seen_articles.add(signature)
                        # Process with our NLP Engine
                        nlp_result = _process_text_with_nlp(art["text"])
                        nlp_result["title"] = art["title"]
                        nlp_result["source_feed"] = art["source"]
                        new_extractions.append(nlp_result)
            
            # Broadcast the findings dynamically to the dashboard stream
            if new_extractions:
                logger.info("onyx.worker.rss.extracted", count=len(new_extractions))
                for ext in new_extractions:
                    await sse_broadcast_callback(ext)
                    # Pace the live stream for visual effect on the dashboard
                    await asyncio.sleep(random.uniform(2.0, 5.0))
            
            # Poll every 5 minutes in production, but here we loop quickly for demo
            # If seen_articles is full, it won't broadcast anyway.
            await asyncio.sleep(60)
