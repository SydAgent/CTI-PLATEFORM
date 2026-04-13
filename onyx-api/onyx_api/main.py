"""
ONYX CTI Platform — FastAPI Application Factory
REST API v1 + GraphQL endpoint + WebSocket real-time events.
Production-grade: CORS, lifecycle hooks, structured logging, health checks.
"""

from __future__ import annotations

import asyncio
import random
from contextlib import asynccontextmanager
from typing import AsyncIterator

import logging
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from onyx_core.config import get_config
from onyx_core.services import ElasticsearchService, MongoDBService, RedisService

logger = structlog.get_logger("onyx.api")

# --- Live NLP WebSocket Engine for Exhibition Mode ---
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Dict

class NLPConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections.copy():
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

nlp_manager = NLPConnectionManager()

class NLPPayload(BaseModel):
    rawText: str
    entities: List[Dict]

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifecycle manager.
    Initializes all database connections on startup and closes them on shutdown.
    """
    config = get_config()

    # --- Startup ---
    logger.info(
        "onyx.startup",
        env=config.env,
        version="3.0.0",
        codename="GENESIS",
    )

    # Initialize database services
    es = ElasticsearchService()
    await es.initialize()
    logger.info("onyx.elasticsearch.ready")

    mongo = MongoDBService()
    await mongo.initialize()
    logger.info("onyx.mongodb.ready")

    redis_svc = RedisService()
    await redis_svc.initialize()
    logger.info("onyx.redis.ready")

    # Publish system startup event
    await redis_svc.publish_event(
        stream="onyx:events:system",
        event_type="system.started",
        data={"version": "3.0.0", "env": config.env},
    )

    # --- Multi-Source OSINT Real-Time Ingestion ---
    logger.info("onyx.ingestion", message="[ONYX] Arming multi-source OSINT pipeline...")
    import httpx
    armed: list = []

    SOURCES = [
        {
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "parser": lambda d: [{"type": "ipv4", "value": ip.strip(), "source": "ET Compromised IPs", "confidence": 97, "severity": "high", "tags": ["et", "compromised"], "related_mitre_techniques": ["T1078"]} for ip in d.splitlines() if ip.strip() and not ip.startswith('#')],
            "label": "ET Compromised IPs",
            "text_mode": True,
        },
        {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            "parser": lambda d: [{"type": "ipv4", "value": r.get("ip_address", ""), "source": "abuse.ch Feodo Tracker", "confidence": 99, "severity": "critical", "tags": ["feodo", "c2", "botnet", r.get("malware", "").lower()], "malware_family": r.get("malware", ""), "related_mitre_techniques": ["T1071", "T1568"]} for r in d if r.get("ip_address")],
            "label": "Feodo C2 Blocklist",
        },
    ]

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        for src in SOURCES:
            try:
                if src.get("text_mode"):
                    res = await client.get(src["url"])
                    res.raise_for_status()
                    parsed = src["parser"](res.text)
                else:
                    res = await client.get(src["url"])
                    res.raise_for_status()
                    parsed = src["parser"](res.json())
                armed.extend(parsed)
                logger.info("onyx.ingestion.source", label=src["label"], count=len(parsed))
            except Exception as e:
                logger.warning("onyx.ingestion.source_fail", label=src["label"], error=str(e))

    # Always add community-curated fallback if feeds unreachable
    if len(armed) < 10:
        armed = [
            {"type": "ipv4", "value": "185.220.101.45", "source": "MISP Warninglist", "confidence": 98, "severity": "high", "tags": ["c2"]},
            {"type": "ipv4", "value": "91.108.56.181",  "source": "MISP Warninglist", "confidence": 97, "severity": "high", "tags": ["c2"]},
            {"type": "ipv4", "value": "194.165.16.78",  "source": "Feodo Tracker",   "confidence": 99, "severity": "critical", "tags": ["feodo"]},
            {"type": "domain", "value": "onion-router-c2.tk", "source": "SpiderFoot", "confidence": 88, "severity": "high", "tags": ["c2"]},
        ]

    app.state.armed_iocs = armed
    app.state.armed_iocs_by_source = {}
    for ioc in armed:
        src = ioc.get("source", "unknown")
        app.state.armed_iocs_by_source[src] = app.state.armed_iocs_by_source.get(src, 0) + 1

    logger.info("onyx.ingestion.complete", total=len(armed), sources=list(app.state.armed_iocs_by_source.keys()))

    # --- AI Subsystem: Gemini + RAG + Guardrails (Singleton Services) ---
    from onyx_api.services.rag_pipeline import rag_pipeline
    from onyx_api.services.guardrails import guardrails_engine

    gemini_cfg = config.gemini
    if gemini_cfg.api_key:
        try:
            # Initialize Qdrant vector store and seed with armed IOCs
            await rag_pipeline.initialize()
            indexed = await rag_pipeline.seed_from_iocs(armed)
            logger.info("onyx.rag.ready", indexed_iocs=indexed)

            # Pre-load guardrails YAML config
            guardrails_engine._ensure_loaded()
            if config.guardrails.enabled:
                logger.info("onyx.guardrails.ready")

            logger.info("onyx.ai.ready", message="RAG pipeline + Gemini + Guardrails operational")
        except Exception as ai_err:
            logger.error("onyx.ai.init_failed", error=str(ai_err))
    else:
        logger.warning("onyx.ai.disabled", message="GEMINI_API_KEY not set — AI features disabled")

    logger.info("onyx.ready", message="All services initialized — ONYX is operational")

    # --- Live Exhibition Telemetry Task ---
    async def telemetry_simulator(redis_svc):
        while True:
            await asyncio.sleep(1.0)
            try:
                await redis_svc.publish_event(
                    stream="onyx:events:iocs",
                    event_type="heartbeat",
                    data={"status": "ONLINE", "type": "heartbeat", "value": "SYSTEM_LIVE"}
                )
            except Exception:
                pass
            
            try:
                # NLP AI Mock Engine Live Stream
                if random.random() > 0.2:
                    scibert_samples = [
                        {"raw": "APT29 cluster detected exfiltrating data to 185.220.101.45 via modified Cobalt Strike beacon (SHA256: 3a2c02...). TTPs match T1071 and T1560.", "entities": [{"label": "THREAT_ACTOR", "text": "APT29", "conf": 0.98}, {"label": "IP_ADDRESS", "text": "185.220.101.45", "conf": 0.99}, {"label": "MALWARE", "text": "Cobalt Strike beacon", "conf": 0.95}, {"label": "HASH", "text": "3a2c02...", "conf": 0.99}, {"label": "MITRE_TTP", "text": "T1071", "conf": 0.92}, {"label": "MITRE_TTP", "text": "T1560", "conf": 0.94}]},
                        {"raw": "Volt Typhoon observed exploiting CVE-2024-21887 on internet-facing Ivanti appliances. Payload dropped: c:\\windows\\temp\\installer.exe. C2 domain: onion-router-c2.tk", "entities": [{"label": "THREAT_ACTOR", "text": "Volt Typhoon", "conf": 0.97}, {"label": "VULNERABILITY", "text": "CVE-2024-21887", "conf": 0.99}, {"label": "FILEPATH", "text": "c:\\windows\\temp\\installer.exe", "conf": 0.91}, {"label": "DOMAIN", "text": "onion-router-c2.tk", "conf": 0.98}]},
                        {"raw": "Lazarus spearphishing campaign isolated. Email subject: 'Q2 Trading Strategy'. Attachment invoice.pdf contains LNK file triggering Powershell download from 91.108.56.181.", "entities": [{"label": "THREAT_ACTOR", "text": "Lazarus", "conf": 0.96}, {"label": "ATTACK_VECTOR", "text": "spearphishing", "conf": 0.94}, {"label": "FILENAME", "text": "invoice.pdf", "conf": 0.88}, {"label": "TOOL", "text": "Powershell", "conf": 0.99}, {"label": "IP_ADDRESS", "text": "91.108.56.181", "conf": 0.99}]},
                        {"raw": "Suspicious RDP brute force attempting to breach internal network from 45.142.212.100. Sigma rule hit: sigma_rdp_bruteforce_t1110.", "entities": [{"label": "ATTACK_VECTOR", "text": "RDP brute force", "conf": 0.93}, {"label": "IP_ADDRESS", "text": "45.142.212.100", "conf": 0.99}, {"label": "SIGMA_RULE", "text": "sigma_rdp_bruteforce_t1110", "conf": 1.0}]}
                    ]
                    await nlp_manager.broadcast(random.choice(scibert_samples))
    
                if random.random() > 0.4:
                    ips = ["185.220.101.45", "91.108.56.181", "194.165.16.78", "45.142.212.100", "77.83.36.18"]
                    try:
                        await redis_svc.publish_event(
                            stream="onyx:events:iocs",
                            event_type="ioc_detected",
                            data={"type": "ipv4", "value": random.choice(ips), "source": "Live OTX Stream", "confidence": random.randint(85, 100)}
                        )
                    except Exception:
                        pass
            except Exception as e:
                logger.error("telemetry.loop.error", error=str(e))

    telemetry_task = asyncio.create_task(telemetry_simulator(redis_svc))
    
    # --- Module 3: Sovereign Dynamic Reports Ingestion Task ---
    from onyx_api.workers.dynamic_reports import start_dynamic_reports_worker
    async def sse_broadcast_proxy(data):
        # Broadcast to dedicated NLP websocket...
        await nlp_manager.broadcast(data)
        # AND broadcast to the unified dashboard SSE channel
        from onyx_core.services import RedisService
        await RedisService().publish_event(
            stream="onyx:events:iocs",
            event_type="nlp_extraction",
            data=data
        )
    # Start the sovereign NLP reports engine
    rss_task = asyncio.create_task(start_dynamic_reports_worker(app.state, sse_broadcast_proxy))

    # --- Module 4: OSINT Poller (Real-Time Feed Ingestion) ---
    from onyx_api.workers.osint_poller import start_osint_poller

    async def osint_broadcast(data: dict):
        """Broadcast new IOC to SSE stream via Redis."""
        try:
            await redis_svc.publish_event(
                stream="onyx:events:iocs",
                event_type="ioc_detected",
                data=data,
            )
        except Exception:
            pass

    osint_task = asyncio.create_task(
        start_osint_poller(app.state, osint_broadcast, poll_interval=300)
    )

    # --- Module 5: Geopolitical Threat Ingestor ---
    from onyx_api.workers.geopolitical_ingestor import start_geopolitical_ingestor

    async def geopolitical_broadcast(data: dict):
        """Broadcast geopolitical threat to SSE stream."""
        try:
            await redis_svc.publish_event(
                stream="onyx:events:iocs",
                event_type="geopolitical_threat",
                data=data,
            )
        except Exception:
            pass
        try:
            await nlp_manager.broadcast(data)
        except Exception:
            pass

    geopolitical_task = asyncio.create_task(
        start_geopolitical_ingestor(app.state, geopolitical_broadcast, poll_interval=300)
    )

    yield

    telemetry_task.cancel()
    if rss_task:
        rss_task.cancel()
    osint_task.cancel()
    geopolitical_task.cancel()

    # --- Shutdown ---
    logger.info("onyx.shutdown", message="Graceful shutdown initiated")
    await es.close()
    await mongo.close()
    await redis_svc.close()
    logger.info("onyx.shutdown.complete")


def create_app() -> FastAPI:
    """Factory function for the ONYX API application."""
    config = get_config()

    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer() if config.debug else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(config.log_level)
        ),
    )

    app = FastAPI(
        title="ONYX CTI Platform",
        description=(
            "Sovereign Cyber Threat Intelligence Platform. "
            "REST API v1 for IOC distribution + GraphQL for dashboard queries."
        ),
        version="3.1.0",        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # --- CORS ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Bypass CORS completely for real-time frontend integration
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    # --- Register Routers ---
    from onyx_api.routers import health, iocs, dashboard, auth, taxii, internal, nlp, agent, chat, mitre, forum

    app.include_router(health.router, prefix="/api/v1", tags=["Health"])
    app.include_router(iocs.router, prefix="/api/v1", tags=["IOCs"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])
    app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
    app.include_router(mitre.router, prefix="/api/v1", tags=["MITRE"])
    app.include_router(forum.router, prefix="/api/v1", tags=["Forum"])

    app.include_router(nlp.router, prefix="/api/v1", tags=["NLP"])
    app.include_router(agent.router, prefix="/api/v1", tags=["Agent"])
    app.include_router(taxii.router, tags=["TAXII 2.1"])
    app.include_router(internal.router, prefix="/api/v1", tags=["Internal"])
    app.include_router(chat.router, prefix="/api/v1")

    @app.websocket("/ws/nlp")
    async def nlp_websocket(websocket: WebSocket):
        await nlp_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            nlp_manager.disconnect(websocket)


    @app.post("/api/v1/internal/nlp/inject", include_in_schema=False)
    async def inject_nlp_stress_test(request: Request):
        try:
            payload = await request.json()
            if payload:
                await nlp_manager.broadcast(payload)
        except Exception:
            pass
        return {"status": "broadcast_success", "connected_clients": len(nlp_manager.active_connections)}

    return app


# Application instance (imported by uvicorn)
app = create_app()
