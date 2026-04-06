"""
ONYX CTI Platform — FastAPI Application Factory
REST API v1 + GraphQL endpoint + WebSocket real-time events.
Production-grade: CORS, lifecycle hooks, structured logging, health checks.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from onyx_core.config import get_config
from onyx_core.services import ElasticsearchService, MongoDBService, RedisService

logger = structlog.get_logger("onyx.api")


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

    logger.info("onyx.ready", message="All services initialized — ONYX is operational")

    yield

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
        version="3.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # --- CORS ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api_cors_origins + ["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Total-Count", "X-Request-Id"],
    )

    # --- Register Routers ---
    from onyx_api.routers import health, iocs, dashboard, auth, taxii, internal

    app.include_router(health.router, prefix="/api/v1", tags=["Health"])
    app.include_router(iocs.router, prefix="/api/v1", tags=["IOCs"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])
    # app.include_router(nlp.router, prefix="/api/v1", tags=["NLP"])  # Bypass NLP in Standalone
    app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
    app.include_router(taxii.router, tags=["TAXII 2.1"])
    app.include_router(internal.router, prefix="/api/v1", tags=["Internal"])

    return app


# Application instance (imported by uvicorn)
app = create_app()
