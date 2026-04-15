"""
ONYX CTI — External OSINT Integrations
Connects to real-world feeds (AlienVault OTX, MITRE, AbuseIPDB) with resilience.
"""

from __future__ import annotations
import gc
import json
import asyncio
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Callable
from functools import wraps

import httpx
from structlog import get_logger

from onyx_core.config import get_config
from onyx_core.services import RedisService

logger = get_logger(__name__)
config = get_config()

# Static cache file — absolute last-resort fallback when API + Redis both fail
_CACHE_FILE_PATH = Path(__file__).parent.parent.parent / "assets" / "osint_cache.json"
_static_cache: dict | None = None


def _load_static_cache() -> dict:
    """Load the pre-verified static CTI cache file. Cached in-memory after first read."""
    global _static_cache
    if _static_cache is not None:
        return _static_cache
    try:
        with open(_CACHE_FILE_PATH, "r", encoding="utf-8") as f:
            _static_cache = json.load(f)
        logger.info("Static OSINT cache loaded", path=str(_CACHE_FILE_PATH), iocs=len(_static_cache.get("iocs", [])))
    except Exception as e:
        logger.error("Failed to load static OSINT cache", error=str(e))
        _static_cache = {"iocs": [], "threat_actors": []}
    return _static_cache


def redis_cache_decorator(key_prefix: str, ttl: int = 3600):
    """
    Stale-While-Revalidate caching pattern using Redis.
    If the decorated function fails (e.g. Rate Limit 429 or Timeout),
    it retrieves the last known good response from Redis.
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Try wrapper attribute first, then class attribute (for @classmethod stacking)
            redis: RedisService | None = getattr(wrapper, "redis_svc", None)
            if not redis and args:
                redis = getattr(args[0], "redis_svc", None)
            if not redis:
                # Fallback if redis_svc wasn't injected yet via the class
                return await func(*args, **kwargs)

            cache_key = f"onyx:osint:cache:{key_prefix}"
            
            try:
                # Attempt to get fresh data
                data = await func(*args, **kwargs)
                # Save to cache
                if data:
                     await redis.client.setex(cache_key, ttl, json.dumps(data))
                return data

            except (httpx.RequestError, httpx.HTTPStatusError, Exception) as e:
                logger.warning(f"OSINT API Error for {key_prefix}: {e}. Falling back to Redis cache.")
                
                # Retrieve stale data gracefully
                cached_raw = await redis.client.get(cache_key)
                if cached_raw:
                    return json.loads(cached_raw)
                
                # If absolutely no cache exists, fall back to static file
                logger.error(f"Cache miss for {key_prefix} during an API failure — loading static cache.")
                static = _load_static_cache()
                if "mitre" in key_prefix:
                    return static.get("threat_actors", [])
                return static.get("iocs", [])

        return wrapper
    return decorator


class AlienVaultConnector:
    redis_svc: RedisService | None = None

    @classmethod
    @redis_cache_decorator("otx_live_iocs", ttl=600)  # 10 minute cache
    async def fetch_live_iocs(cls) -> list[dict[str, Any]]:
        """
        Fetch real-world IOCs from AlienVault OTX Subscribed Pulses.
        Maps them to the internal Dashboard Armed IOC schema.
        """
        api_key = config.osint.alienvault_otx_key
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        
        # We query the general pulses if no key is provided, or subscribed if we have one
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed" if api_key else "https://otx.alienvault.com/api/v1/pulses/activity?limit=25"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        results = []
        for pulse in data.get("results", []):
            source_name = "AlienVault OTX"
            tags = pulse.get("tags", [])
            for ind in pulse.get("indicators", [])[:10]: # limit IOCs per pulse
                results.append({
                     "id": f"otx-{ind.get('id')}",
                     "type": ind.get("type", "unknown").lower(),
                     "value": ind.get("indicator", ""),
                     "severity": "high" if "malware" in tags else "medium",
                     "confidence": 85,
                     "source": source_name,
                     "tags": tags,
                     "description": pulse.get("name", ""),
                     "timestamp": pulse.get("created", ""),
                })
        return results


class MitreConnector:
    redis_svc: RedisService | None = None
    _MEMORY_FALLBACK = []

    @classmethod
    async def preload_cache(cls, redis_svc: RedisService):
        """
        Startup task triggered from main.py `lifespan`.
        Downloads the 30MB+ MITRE STIX 2.1 matrix, parses it locally,
        and saves the aggregated threat actors to Redis.
        """
        logger.info("MitreConnector: Initializing MITRE STIX preload...")
        cls.redis_svc = redis_svc
        try:
            cache_key = "onyx:osint:cache:mitre_apt"
            # Fast check if it exists in cache already to avoid 30MB download during rapid dev reloads
            exists = await redis_svc.client.exists(cache_key)
            if exists:
                logger.info("MitreConnector: Cache already populated. Skipping preload.")
                return

            url = config.osint.mitre_taxii_url
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.get(url)
                res.raise_for_status()
                stix_data = res.json()

            # Parse the massive payload into our fast lean format
            actors_dict = {}
            # Step 1: Find all intrusion-sets (APTs)
            for obj in stix_data.get("objects", []):
                if obj.get("type") == "intrusion-set":
                    uid = obj.get("id")
                    actors_dict[uid] = {
                         "id": uid,
                         "name": obj.get("name", "Unknown APT"),
                         "description": obj.get("description", "")[:100] + "...",
                         "aliases": obj.get("aliases", []),
                         "techniques": [],
                         "tools": [],
                         "severity": "critical"
                    }
                    
            # Step 2: Map relationships (techniques, malware, tools)
            # Find all relationships
            for obj in stix_data.get("objects", []):
                if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                    src = obj.get("source_ref", "")
                    tgt = obj.get("target_ref", "")
                    
                    if src in actors_dict:
                        # Find what target represents
                        if "attack-pattern" in tgt:
                            # It's a technique. Example: attack-pattern--<uuid>
                            actors_dict[src]["techniques"].append(tgt)
                        elif "malware" in tgt or "tool" in tgt:
                            actors_dict[src]["tools"].append(tgt)
            
            # Step 3: Resolve Technique Names to T-Codes and map tools
            t_enriched_map = {}
            for o in stix_data.get("objects", []):
                if o.get("type") == "attack-pattern" and o.get("external_references"):
                    t_code = o["external_references"][0]["external_id"]
                    t_name = o.get("name", t_code)
                    phases = [p.get("phase_name", "").replace("-", " ").title() for p in o.get("kill_chain_phases", [])]
                    t_enriched_map[o["id"]] = {"id": t_code, "name": t_name, "tactics": phases}
                     
            tools_map = {o["id"]: o["name"] for o in stix_data.get("objects", []) 
                         if o.get("type") in ["malware", "tool"]}

            final_list = []
            for uid, apt in actors_dict.items():
                # Replace UUIDs with Enriched Dicts
                resolved_ttps = []
                for t in apt["techniques"]:
                    if t in t_enriched_map:
                        resolved_ttps.append(t_enriched_map[t])
                # Ensure unique by id
                seen_ttps = set()
                uniq_ttps = []
                for r_ttp in resolved_ttps:
                    if r_ttp["id"] not in seen_ttps:
                        uniq_ttps.append(r_ttp)
                        seen_ttps.add(r_ttp["id"])
                apt["techniques"] = uniq_ttps
                
                # Strict Tool Filtering: reject unresolved UUIDs
                resolved_tools = []
                for t in apt["tools"]:
                    if t in tools_map:
                        resolved_tools.append(tools_map[t])
                apt["tools"] = list(set(resolved_tools))
                
                final_list.append(apt)

            logger.info("MitreConnector: Processed APT entries from STIX", count=len(final_list))
            await redis_svc.client.setex(cache_key, 86400, json.dumps(final_list)) # 24h cache
            
            del stix_data
            gc.collect()

        except Exception as e:
            logger.error("MitreConnector: Preload failed!", error=str(e))


    @classmethod
    @redis_cache_decorator("mitre_apt", ttl=86400)
    async def get_threat_actors(cls) -> list[dict[str, Any]]:
        """
        Instead of HTTPX fetching here, the Redis decorator will natively 
        intercept and serve the `preload_cache` data.
        If cache is somehow completely empty, we raise an HTTPX exception on a dummy request to trigger fallback.
        """
        raise httpx.RequestError("Force Cache read for pre-calculated MITRE payload.")
