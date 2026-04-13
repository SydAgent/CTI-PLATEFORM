"""
ONYX CTI Platform — Gemini AI Service
Google GenAI SDK integration with exponential backoff, streaming,
and config-driven initialization.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import AsyncIterator

from google import genai
from google.genai import types
from google.genai.errors import APIError, ClientError

class QuotaExhaustedException(Exception):
    """Raised when the strict billing/API quota is exhausted, requiring an immediate abort."""
    pass

from onyx_core.config import get_config

logger = logging.getLogger("onyx.services.gemini")

# ── Constants ────────────────────────────────────────────────────────────────

_MAX_RETRIES: int = 5
_BASE_DELAY: float = 1.0
_MAX_DELAY: float = 60.0


class GeminiService:
    """
    Async Gemini client with:
    - Lazy initialization from ``OnyxConfig.gemini``
    - True exponential backoff + jitter on 429 / 503
    - Streaming and non-streaming generation
    """

    def __init__(self) -> None:
        self._client: genai.Client | None = None
        self._model_id: str = ""
        self._embedding_model_id: str = ""
        self._temperature: float = 0.3
        self._max_output_tokens: int = 8192

    # ── Lazy init ────────────────────────────────────────────────────────

    def _ensure_client(self) -> genai.Client:
        """Initialize the GenAI client exactly once."""
        if self._client is not None:
            return self._client

        cfg = get_config().gemini

        if not cfg.api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. "
                "Provide it via environment variable or .env file."
            )

        self._client = genai.Client(api_key=cfg.api_key)
        self._model_id = cfg.model
        self._embedding_model_id = cfg.embedding_model
        self._temperature = cfg.temperature
        self._max_output_tokens = cfg.max_output_tokens

        logger.info(
            "gemini.initialized",
            extra={"model": self._model_id, "embedding": self._embedding_model_id},
        )
        return self._client

    # ── Backoff helper ───────────────────────────────────────────────────

    @staticmethod
    async def _backoff_delay(attempt: int) -> None:
        """Exponential backoff with full jitter (AWS-style)."""
        delay = min(_BASE_DELAY * (2 ** attempt), _MAX_DELAY)
        jittered = random.uniform(0, delay)
        logger.warning(
            "gemini.rate_limited",
            extra={"attempt": attempt + 1, "backoff_seconds": round(jittered, 2)},
        )
        await asyncio.sleep(jittered)

    # ── Core generation ──────────────────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        *,
        system_instruction: str | None = None,
    ) -> str:
        """
        Non-streaming generation with retry on 429 / 503.
        Returns the full response text.
        """
        client = self._ensure_client()

        config = types.GenerateContentConfig(
            temperature=self._temperature,
            max_output_tokens=self._max_output_tokens,
        )
        if system_instruction:
            config.system_instruction = system_instruction

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=self._model_id,
                    contents=prompt,
                    config=config,
                )
                return response.text or ""
            except ClientError as exc:
                if exc.code == 404:
                    logger.error("gemini.model_not_found", extra={"model": self._model_id, "error": str(exc)})
                    raise RuntimeError(
                        f"Gemini model '{self._model_id}' not found (404). "
                        f"Update GEMINI_MODEL in .env to a valid model ID."
                    ) from exc
                raise
            except APIError as exc:
                last_exc = exc
                if exc.code == 429:
                    # Distinguish hard quota versus soft rate limit
                    err_msg = str(exc).lower()
                    if "quota" in err_msg or "billing" in err_msg or "exhausted" in err_msg:
                        logger.error("gemini.quota_exhausted", extra={"error": str(exc)})
                        raise QuotaExhaustedException("API Quota Exceeded. Please verify your billing account or API limits.") from exc
                    # Otherwise, transient rate limit
                    await self._backoff_delay(attempt)
                elif exc.code == 503:
                    await self._backoff_delay(attempt)
                else:
                    logger.error("gemini.generate.error", extra={"error": str(exc)})
                    raise
            except Exception as exc:
                logger.error("gemini.generate.unhandled_error", extra={"error": str(exc)})
                raise

        raise RuntimeError(
            f"Gemini API exhausted after {_MAX_RETRIES} retries: {last_exc}"
        )

    # ── Streaming generation ─────────────────────────────────────────────

    async def generate_stream(
        self,
        prompt: str,
        *,
        system_instruction: str | None = None,
    ) -> AsyncIterator[str]:
        """
        Streaming generation with retry on 429 / 503.
        Yields text chunks as they arrive.
        """
        client = self._ensure_client()

        config = types.GenerateContentConfig(
            temperature=self._temperature,
            max_output_tokens=self._max_output_tokens,
        )
        if system_instruction:
            config.system_instruction = system_instruction

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                # We do streaming asynchronously, but Google's sync generator
                # can be wrapped in asyncio logic or treated as simple iterator.
                stream = client.models.generate_content_stream(
                    model=self._model_id,
                    contents=prompt,
                    config=config,
                )
                for chunk in stream:
                    if chunk.text:
                        yield chunk.text
                return  # successful — exit retry loop
            except ClientError as exc:
                if exc.code == 404:
                    logger.error("gemini.stream.model_not_found", extra={"model": self._model_id, "error": str(exc)})
                    raise RuntimeError(
                        f"Gemini model '{self._model_id}' not found (404). "
                        f"Update GEMINI_MODEL in .env to a valid model ID."
                    ) from exc
                raise
            except APIError as exc:
                last_exc = exc
                if exc.code == 429:
                    err_msg = str(exc).lower()
                    if "quota" in err_msg or "billing" in err_msg or "exhausted" in err_msg:
                        logger.error("gemini.stream.quota_exhausted", extra={"error": str(exc)})
                        raise QuotaExhaustedException("API Quota Exceeded. Please verify your billing account or API limits.") from exc
                    await self._backoff_delay(attempt)
                elif exc.code == 503:
                    await self._backoff_delay(attempt)
                else:
                    logger.error("gemini.stream.error", extra={"error": str(exc)})
                    raise
            except Exception as exc:
                logger.error("gemini.stream.unhandled_error", extra={"error": str(exc)})
                raise

        raise RuntimeError(
            f"Gemini streaming exhausted after {_MAX_RETRIES} retries: {last_exc}"
        )

    # ── Embedding ────────────────────────────────────────────────────────

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """
        Generate embeddings for a batch of texts using the configured
        embedding model. Returns a list of float vectors.
        """
        if not texts:
            return []
            
        client = self._ensure_client()

        all_embeddings = []
        chunk_size = 90
        
        for i in range(0, len(texts), chunk_size):
            chunk = texts[i:i + chunk_size]
            last_exc: Exception | None = None
            
            for attempt in range(_MAX_RETRIES):
                try:
                    response = await asyncio.to_thread(
                        client.models.embed_content,
                        model=self._embedding_model_id,
                        contents=chunk,
                    )
                    all_embeddings.extend([e.values for e in response.embeddings])
                    break
                except ClientError as exc:
                    if exc.code == 404:
                        logger.error("gemini.embed.model_not_found", extra={"model": self._embedding_model_id, "error": str(exc)})
                        raise RuntimeError(
                            f"Gemini embedding model '{self._embedding_model_id}' not found (404). "
                            f"Update GEMINI_EMBEDDING_MODEL in .env."
                        ) from exc
                    raise
                except APIError as exc:
                    last_exc = exc
                    if exc.code == 429:
                        err_msg = str(exc).lower()
                        if "quota" in err_msg or "billing" in err_msg or "exhausted" in err_msg:
                            logger.error("gemini.embed.quota_exhausted", extra={"error": str(exc)})
                            raise QuotaExhaustedException("API Quota Exceeded. Please verify your billing account or API limits.") from exc
                        await self._backoff_delay(attempt)
                    elif exc.code == 503:
                        await self._backoff_delay(attempt)
                    else:
                        logger.error("gemini.embed.error", extra={"error": str(exc)})
                        raise
                except Exception as exc:
                    logger.error("gemini.embed.unhandled_error", extra={"error": str(exc)})
                    raise
            else:
                raise RuntimeError(
                    f"Gemini embed exhausted after {_MAX_RETRIES} retries: {last_exc}"
                )

        return all_embeddings


# ── Singleton ────────────────────────────────────────────────────────────────

gemini_service = GeminiService()
