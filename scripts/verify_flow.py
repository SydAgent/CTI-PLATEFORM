"""
ONYX CTI — Zero-Latency Geopolitical Payload Injector (Phase 7)
Injects a known IPv4 with strict GeoIP localization into the live Redis Pub/Sub stream,
which will appear dynamically on the Dashboard GUI in < 100ms.
"""

import sys
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Fix python local path to import Onyx modules
sys.path.append(str(Path(__file__).resolve().parent.parent))

from onyx_api.services.geoip import GeoIPResolver
from onyx_core.services import RedisService
from structlog import get_logger

logger = get_logger(__name__)

async def inject_synthetic_ioc(ip_payload: str):
    logger.info("Starting Synthetic Target Injection", target=ip_payload)

    # 1. Pipeline Step 1 - GeoLocation (Offline)
    await GeoIPResolver.initialize()
    geo_data = GeoIPResolver.resolve(ip_payload)
    
    if not geo_data:
        logger.error(f"GeoIP resolution strictly failed for {ip_payload}")
        return
        
    logger.info("GeoIP Resolved Successfully", geo=geo_data)

    # 2. Pipeline Step 2 - Construct Formal Payload
    ioc_payload = {
        "id": f"synthetic-{uuid.uuid4()}",
        "type": "ipv4",
        "value": ip_payload,
        "source": "Manual Synthetic Verification",
        "severity": "critical",
        "confidence": 99,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "geolocation": geo_data
    }

    # 3. Pipeline Step 3 - Redis Pub/Sub
    try:
        redis_svc = RedisService()
        await redis_svc.connect()
        
        # Dispatch to WebSockets immediately
        await redis_svc.ws_publish("ioc_detected", ioc_payload)
        logger.info("SYNTHETIC INJECTION SUCCESSFUL. Verify 3D Arc targeting Paris SOC on WebGL map.", payload=ioc_payload)
    except Exception as e:
        logger.error("Failed to inject via Redis", error=str(e))


if __name__ == "__main__":
    ip_to_test = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    asyncio.run(inject_synthetic_ioc(ip_to_test))
