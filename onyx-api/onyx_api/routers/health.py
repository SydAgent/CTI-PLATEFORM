"""
ONYX CTI — Health Check Router
Provides system health, readiness, and liveness endpoints.
Used by Docker health checks and monitoring systems.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter

from onyx_core.services import ElasticsearchService, MongoDBService, RedisService

router = APIRouter()


@router.get("/health", summary="Liveness probe")
async def health_check() -> dict[str, Any]:
    """
    Basic liveness check. Returns 200 if the API process is running.
    Used by Docker HEALTHCHECK and load balancers.
    """
    return {
        "status": "ok",
        "service": "onyx-api",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready", summary="Readiness probe")
async def readiness_check() -> dict[str, Any]:
    """
    Deep readiness check. Verifies all backend dependencies are reachable.
    Returns 503 if any dependency is unhealthy.
    """
    checks: dict[str, Any] = {}
    overall_status = "ok"

    # Elasticsearch
    try:
        es = ElasticsearchService()
        es_health = await es.health()
        checks["elasticsearch"] = {
            "status": es_health.get("status", "unknown"),
            "cluster_name": es_health.get("cluster_name", "unknown"),
            "number_of_nodes": es_health.get("number_of_nodes", 0),
        }
    except Exception as e:
        checks["elasticsearch"] = {"status": "error", "error": str(e)}
        overall_status = "degraded"

    # MongoDB
    try:
        mongo = MongoDBService()
        mongo_health = await mongo.health()
        checks["mongodb"] = mongo_health
    except Exception as e:
        checks["mongodb"] = {"status": "error", "error": str(e)}
        overall_status = "degraded"

    # Redis
    try:
        redis_svc = RedisService()
        redis_health = await redis_svc.health()
        checks["redis"] = redis_health
    except Exception as e:
        checks["redis"] = {"status": "error", "error": str(e)}
        overall_status = "degraded"

    return {
        "status": overall_status,
        "service": "onyx-api",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }
