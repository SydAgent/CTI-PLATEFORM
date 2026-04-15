"""
ONYX CTI — Redis Service
Async Redis client for caching, event streaming, rate limiting, and
real-time message bus (Redis Streams). Powers the WebSocket layer
and inter-service communication.

Pattern source: OpenCTI's listener/event system + IntelOwl's WebSocket broadcasts.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
from tenacity import retry, stop_after_attempt, wait_exponential

from onyx_core.config import RedisConfig, get_config

logger = logging.getLogger("onyx.redis")

# Event stream names
STREAM_IOC_EVENTS = "onyx:events:iocs"
STREAM_THREAT_EVENTS = "onyx:events:threats"
STREAM_CRAWLER_EVENTS = "onyx:events:crawlers"
STREAM_SYSTEM_EVENTS = "onyx:events:system"

# Cache key prefixes
CACHE_PREFIX = "onyx:cache:"
RATE_LIMIT_PREFIX = "onyx:ratelimit:"
SESSION_PREFIX = "onyx:session:"


class RedisService:
    """
    Async Redis service providing:
    - Key/value caching with TTL
    - Redis Streams for real-time event broadcasting
    - Rate limiting (token bucket via Lua script)
    - Session storage
    - Pub/Sub for WebSocket fan-out

    Thread-safe singleton with connection pooling.
    """

    _instance: RedisService | None = None
    _pool: aioredis.Redis | None = None
    _event_pool: aioredis.Redis | None = None

    def __new__(cls) -> RedisService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._pool is not None:
            return
        cfg: RedisConfig = get_config().redis
        self._cfg = cfg

        # Main cache/queue pool
        self._pool = aioredis.from_url(
            cfg.url(cfg.db_cache),
            decode_responses=True,
            max_connections=20,
        )
        # Dedicated event stream pool (separate DB for isolation)
        self._event_pool = aioredis.from_url(
            cfg.url(cfg.db_events),
            decode_responses=True,
            max_connections=10,
        )

    @property
    def client(self) -> aioredis.Redis:
        assert self._pool is not None, "Redis not initialized"
        return self._pool

    @property
    def events(self) -> aioredis.Redis:
        assert self._event_pool is not None, "Redis events pool not initialized"
        return self._event_pool

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, max=30))
    async def initialize(self) -> None:
        """Verify Redis connectivity and create consumer groups for streams."""
        pong = await self.client.ping()
        if not pong:
            raise ConnectionError("Redis ping failed")
        logger.info("Redis connected (cache pool)")

        pong = await self.events.ping()
        if not pong:
            raise ConnectionError("Redis events ping failed")
        logger.info("Redis connected (events pool)")

        # Create stream consumer groups (idempotent)
        streams = [
            STREAM_IOC_EVENTS,
            STREAM_THREAT_EVENTS,
            STREAM_CRAWLER_EVENTS,
            STREAM_SYSTEM_EVENTS,
        ]
        for stream in streams:
            try:
                await self.events.xgroup_create(
                    name=stream,
                    groupname="onyx-consumers",
                    id="0",
                    mkstream=True,
                )
                logger.debug("Created consumer group for stream: %s", stream)
            except aioredis.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    logger.debug("Consumer group already exists for: %s", stream)
                else:
                    raise

        logger.info("Redis initialization complete — %d event streams ready", len(streams))

    async def close(self) -> None:
        """Close Redis connection pools."""
        if self._pool:
            await self._pool.close()
        if self._event_pool:
            await self._event_pool.close()
        self._pool = None
        self._event_pool = None
        RedisService._instance = None
        logger.info("Redis connections closed")

    async def health(self) -> dict[str, Any]:
        """Check Redis connectivity and memory usage."""
        info = await self.client.info("memory")
        return {
            "status": "ok",
            "used_memory_human": info.get("used_memory_human", "unknown"),
            "connected_clients": (await self.client.info("clients")).get("connected_clients", 0),
        }

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    async def cache_get(self, key: str) -> Any | None:
        """Get a cached value. Returns None on miss."""
        raw = await self.client.get(f"{CACHE_PREFIX}{key}")
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    async def cache_set(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        """Set a cached value with TTL."""
        serialized = json.dumps(value) if not isinstance(value, str) else value
        await self.client.setex(f"{CACHE_PREFIX}{key}", ttl_seconds, serialized)

    async def cache_delete(self, key: str) -> None:
        """Delete a cached key."""
        await self.client.delete(f"{CACHE_PREFIX}{key}")

    async def cache_invalidate_pattern(self, pattern: str) -> int:
        """Delete all keys matching a glob pattern. Returns count deleted."""
        count = 0
        async for key in self.client.scan_iter(f"{CACHE_PREFIX}{pattern}"):
            await self.client.delete(key)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Event Streaming (Redis Streams)
    # ------------------------------------------------------------------

    async def publish_event(
        self,
        stream: str,
        event_type: str,
        data: dict[str, Any],
    ) -> str:
        """
        Publish an event to a Redis Stream.

        Args:
            stream: Stream name (use STREAM_* constants).
            event_type: Event type identifier (e.g., 'ioc.created', 'crawler.started').
            data: Event payload.

        Returns:
            The stream message ID.
        """
        message = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(data),
        }
        msg_id = await self.events.xadd(
            name=stream,
            fields=message,
            maxlen=10000,  # Keep last 10k events per stream
            approximate=True,
        )
        logger.debug("Published event %s to %s (id: %s)", event_type, stream, msg_id)
        return str(msg_id)

    async def consume_events(
        self,
        stream: str,
        consumer_name: str,
        count: int = 10,
        block_ms: int = 5000,
    ) -> list[dict[str, Any]]:
        """
        Consume events from a Redis Stream as part of a consumer group.

        Args:
            stream: Stream name.
            consumer_name: Unique consumer identifier.
            count: Maximum messages to consume.
            block_ms: Maximum time to block waiting for messages.

        Returns:
            List of event dicts with id, event_type, timestamp, and data.
        """
        results = await self.events.xreadgroup(
            groupname="onyx-consumers",
            consumername=consumer_name,
            streams={stream: ">"},
            count=count,
            block=block_ms,
        )

        events = []
        for _stream_name, messages in results:
            for msg_id, fields in messages:
                event = {
                    "id": msg_id,
                    "event_type": fields.get("event_type", ""),
                    "timestamp": fields.get("timestamp", ""),
                    "data": json.loads(fields.get("data", "{}")),
                }
                events.append(event)
                # Acknowledge the message
                await self.events.xack(stream, "onyx-consumers", msg_id)

        return events

    async def stream_events_sse(
        self,
        stream: str,
        last_id: str = "$",
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Async generator for Server-Sent Events (SSE) from a Redis Stream.
        Uses XREAD (non-consumer-group) for broadcast to all connected clients.
        """
        current_id = last_id
        while True:
            results = await self.events.xread(
                streams={stream: current_id},
                count=10,
                block=5000,
            )
            for _stream_name, messages in results:
                for msg_id, fields in messages:
                    current_id = msg_id
                    yield {
                        "id": msg_id,
                        "event_type": fields.get("event_type", ""),
                        "timestamp": fields.get("timestamp", ""),
                        "data": json.loads(fields.get("data", "{}")),
                    }

    # ------------------------------------------------------------------
    # Rate Limiting (Token Bucket via Lua)
    # ------------------------------------------------------------------

    _RATE_LIMIT_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local current = tonumber(redis.call('GET', key) or '0')
    if current >= limit then
        return 0
    end
    redis.call('INCR', key)
    if current == 0 then
        redis.call('EXPIRE', key, window)
    end
    return 1
    """

    async def check_rate_limit(
        self,
        identifier: str,
        limit: int = 100,
        window_seconds: int = 60,
    ) -> bool:
        """
        Check if a request is within rate limits.

        Args:
            identifier: Unique identifier (user_id, IP, API key).
            limit: Maximum requests per window.
            window_seconds: Window duration in seconds.

        Returns:
            True if request is allowed, False if rate limited.
        """
        key = f"{RATE_LIMIT_PREFIX}{identifier}"
        result = await self.client.eval(
            self._RATE_LIMIT_SCRIPT, 1, key, str(limit), str(window_seconds)
        )
        return bool(result)

    # ------------------------------------------------------------------
    # Pub/Sub for WebSocket fan-out
    # ------------------------------------------------------------------

    async def publish_ws(self, channel: str, message: dict[str, Any]) -> None:
        """Publish a message to a Redis Pub/Sub channel (for WebSocket broadcast)."""
        await self.events.publish(channel, json.dumps(message))

    async def subscribe_ws(self, channel: str) -> AsyncIterator[dict[str, Any]]:
        """Subscribe to a Redis Pub/Sub channel for WebSocket events."""
        pubsub = self.events.pubsub()
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield json.loads(message["data"])
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()

    # ------------------------------------------------------------------
    # WebSocket Event Bus (v4.0-APEX)
    # ------------------------------------------------------------------

    async def ws_publish(
        self,
        channel_name: str,
        payload: dict[str, Any],
        broadcast_channel: str = "onyx:ws:broadcast",
    ) -> None:
        """
        Publish a WebSocket event to the Redis broadcast channel.

        This is the primary method for injecting events into the
        WebSocket Event Bus. All connected WS clients (across all
        API worker processes) will receive the message via Pub/Sub.

        Args:
            channel_name: Event channel (e.g., 'ioc_detected', 'nlp_extraction')
            payload: Event data dict.
            broadcast_channel: Redis Pub/Sub channel name.
        """
        frame = {
            "channel": channel_name,
            "payload": payload,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self.events.publish(broadcast_channel, json.dumps(frame))
        except Exception:
            # Standalone Mode fallback: broadcast via local process manager if Redis is offline
            from onyx_api.routers.websocket_hub import ws_manager
            import asyncio
            asyncio.create_task(ws_manager.broadcast(frame))

    async def ws_subscribe(
        self,
        broadcast_channel: str = "onyx:ws:broadcast",
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Subscribe to the WebSocket broadcast channel.

        Yields parsed message dicts as they arrive. Used by the
        WebSocket Hub to fan-out events to connected clients.

        Auto-reconnects on subscription failure (caller should
        wrap in a retry loop).
        """
        pubsub = self.events.pubsub()
        await pubsub.subscribe(broadcast_channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        yield json.loads(message["data"])
                    except json.JSONDecodeError:
                        logger.warning("ws.malformed_message", extra={"raw": str(message["data"])[:200]})
        finally:
            await pubsub.unsubscribe(broadcast_channel)
            await pubsub.close()
