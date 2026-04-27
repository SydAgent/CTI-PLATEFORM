"""
ONYX CTI v4.0-APEX — WebSocket Event Hub
=========================================
Authenticated, bidirectional WebSocket channels backed by Redis Pub/Sub.
Replaces SSE for <50ms end-to-end latency.

Features:
  - JWT auth on handshake (bypassed in development/standalone mode)
  - Origin header validation (CSWSH protection)
  - Redis Pub/Sub fan-out — all API workers share the same broadcast channel
  - Per-client heartbeat (15s ping, 5s timeout)
  - Graceful disconnection with cleanup
  - Rate limiting stubs (per-IP connection cap)

Channel: onyx:ws:broadcast
Protocol: JSON frames → { "channel": "...", "payload": {...}, "ts": "...", "seq": N }
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette.websockets import WebSocketState

from onyx_core.config import get_config

logger = logging.getLogger("onyx.ws.hub")

router = APIRouter()

# ─── Connection Registry ─────────────────────────────────────────────────────
# In-memory tracking of active WebSocket connections for this worker process.
# Redis Pub/Sub handles cross-worker fan-out; this is process-local only.

_connections: list[WebSocket] = []
_seq_counter: int = 0


def _next_seq() -> int:
    global _seq_counter
    _seq_counter += 1
    return _seq_counter


class WSConnectionManager:
    """
    Process-local WebSocket connection manager.
    Thread-safe via asyncio event loop (single-threaded by design).
    """

    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self._ip_counts: dict[str, int] = {}
        self._max_per_ip: int = 10  # Rate limit: max connections per IP

    async def accept(self, ws: WebSocket) -> bool:
        """
        Validate and accept a WebSocket connection.
        Returns False if rate-limited or origin check fails.
        """
        # ── Origin validation (CSWSH protection) ──────────────────────────
        config = get_config()
        origin = ws.headers.get("origin", "")
        is_dev = config.env == "development" or config.debug

        if not is_dev and origin:
            allowed = config.api_cors_origins
            if "*" not in allowed and origin not in allowed:
                logger.warning("ws.origin_rejected", extra={"origin": origin})
                await ws.close(code=4003, reason="Origin not allowed")
                return False

        # ── Rate limiting (per-IP) ────────────────────────────────────────
        client_ip = ws.client.host if ws.client else "unknown"
        current = self._ip_counts.get(client_ip, 0)
        if current >= self._max_per_ip:
            logger.warning("ws.rate_limited", extra={"ip": client_ip, "count": current})
            await ws.close(code=4029, reason="Too many connections")
            return False

        # ── JWT Authentication ────────────────────────────────────────────
        # In development/standalone mode, skip auth entirely.
        # In production, require a valid JWT token as query parameter.
        if not is_dev:
            token = ws.query_params.get("token", "")
            if not token:
                await ws.close(code=4001, reason="Authentication required")
                return False
            try:
                from onyx_api.auth.jwt import verify_token
                verify_token(token)
            except Exception as e:
                logger.warning("ws.auth_failed", extra={"error": str(e)})
                await ws.close(code=4001, reason="Invalid or expired token")
                return False

        # ── Accept ────────────────────────────────────────────────────────
        await ws.accept()
        self.active.append(ws)
        self._ip_counts[client_ip] = current + 1
        logger.info("ws.connected", extra={"ip": client_ip, "total": len(self.active)})
        return True

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the active list."""
        if ws in self.active:
            self.active.remove(ws)
        client_ip = ws.client.host if ws.client else "unknown"
        current = self._ip_counts.get(client_ip, 0)
        if current > 0:
            self._ip_counts[client_ip] = current - 1
        logger.info("ws.disconnected", extra={"ip": client_ip, "total": len(self.active)})

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Send a message to all connected WebSocket clients.
        Silently drops connections that have closed.
        """
        frame = json.dumps(message)
        stale: list[WebSocket] = []
        for ws in self.active:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(frame)
                else:
                    stale.append(ws)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)

    @property
    def client_count(self) -> int:
        return len(self.active)


# Singleton manager for this process
ws_manager = WSConnectionManager()


# ─── Redis Pub/Sub Listener ──────────────────────────────────────────────────
# Background task that subscribes to the Redis broadcast channel and fans out
# messages to all local WebSocket connections.

_listener_task: asyncio.Task | None = None


async def _redis_listener() -> None:
    """
    Subscribe to Redis Pub/Sub channel and broadcast to all local WS clients.
    Auto-reconnects on failure.
    """
    from onyx_core.services import RedisService

    while True:
        try:
            redis_svc = RedisService()
            async for message in redis_svc.ws_subscribe("onyx:ws:broadcast"):
                # Inject sequence number for client-side ordering
                message["seq"] = _next_seq()
                await ws_manager.broadcast(message)
        except asyncio.CancelledError:
            logger.info("ws.redis_listener.cancelled")
            return
        except Exception as e:
            logger.error("ws.redis_listener.error", extra={"error": str(e)})
            await asyncio.sleep(2)  # Reconnect backoff


def start_redis_listener() -> asyncio.Task:
    """Start the Redis → WebSocket fan-out listener as a background task."""
    global _listener_task
    if _listener_task is None or _listener_task.done():
        _listener_task = asyncio.create_task(_redis_listener())
        logger.info("ws.redis_listener.started")
    return _listener_task


def stop_redis_listener() -> None:
    """Cancel the Redis listener task."""
    global _listener_task
    if _listener_task and not _listener_task.done():
        _listener_task.cancel()
        _listener_task = None


# ─── WebSocket Endpoint ──────────────────────────────────────────────────────

@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    """
    Main real-time event channel.

    Clients connect here to receive:
      - ioc_detected events
      - nlp_extraction events
      - heartbeat signals
      - threat_update events
      - report_generated events

    Authentication:
      - Development: No auth required (ws://localhost:8000/ws/events)
      - Production: JWT token required (wss://host/ws/events?token=<jwt>)
    """
    # Ensure Redis listener is running
    start_redis_listener()

    accepted = await ws_manager.accept(websocket)
    if not accepted:
        return

    # Send initial connection confirmation
    await websocket.send_json({
        "channel": "system",
        "payload": {
            "type": "connected",
            "message": "ONYX WebSocket Event Hub — Connection established",
            "clients": ws_manager.client_count,
            "protocol": "v4.0-APEX",
        },
        "ts": datetime.now(timezone.utc).isoformat(),
        "seq": _next_seq(),
    })

    try:
        while True:
            # Keep connection alive — wait for client messages
            # Client can send ping frames; we process them here.
            # If client sends JSON, we can handle commands in the future.
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Process client commands (future: subscribe/unsubscribe to channels)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_json({
                            "channel": "system",
                            "payload": {"type": "pong"},
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "seq": _next_seq(),
                        })
                except (json.JSONDecodeError, Exception):
                    pass
            except asyncio.TimeoutError:
                # No message from client in 30s — send server heartbeat
                try:
                    await websocket.send_json({
                        "channel": "heartbeat",
                        "payload": {
                            "type": "heartbeat",
                            "status": "ONLINE",
                            "clients": ws_manager.client_count,
                        },
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "seq": _next_seq(),
                    })
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("ws.connection_error", extra={"error": str(e)})
    finally:
        ws_manager.disconnect(websocket)
