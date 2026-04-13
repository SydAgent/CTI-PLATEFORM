"""
ONYX CTI Platform — Chat Router
Session-aware, guardrails-integrated, SSE streaming endpoint.
Replaces the legacy /chat/analyze with a production-grade pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections import defaultdict
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from onyx_api.services.gemini import gemini_service, QuotaExhaustedException
from onyx_api.services.guardrails import guardrails_engine
from onyx_api.services.rag_pipeline import rag_pipeline

logger = logging.getLogger("onyx.routers.chat")

router = APIRouter(prefix="/chat", tags=["AI Chatbot"])

# ── In-memory session store (per-process, production would use Redis) ────────

_sessions: dict[str, list[dict[str, str]]] = defaultdict(list)
_MAX_HISTORY: int = 20


# ── Request / Response Models ────────────────────────────────────────────────


class ChatRequest(BaseModel):
    """Incoming chat message with optional session tracking."""

    message: str = Field(..., min_length=1, max_length=4000)
    session_id: str | None = Field(
        default=None,
        description="Session ID for conversation continuity. Omit to create a new session.",
    )
    context: dict | None = Field(
        default=None,
        description="Optional frontend context (current_page, etc.).",
    )


class ChatResponse(BaseModel):
    """Non-streaming chat response."""

    response: str
    session_id: str
    tags: list[str] = Field(default_factory=list)


# ── Tag Extraction ───────────────────────────────────────────────────────────


def _extract_tags(text: str) -> list[str]:
    """Extract severity/IOC tags from response text for UI badges."""
    tags: set[str] = set()
    if re.search(r"(?i)\[CRITICAL\]", text):
        tags.add("CRITICAL")
    if re.search(r"(?i)\[HIGH\]", text):
        tags.add("HIGH")
    if re.search(r"(?i)\[IOC\]|\[IOCs\]", text):
        tags.add("IOC")
    # Heuristic: detect raw IOC patterns
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        tags.add("IOC")
    if re.search(r"\b[a-fA-F0-9]{32,64}\b", text):
        tags.add("IOC")
    return sorted(tags)


# ── SSE Helpers ──────────────────────────────────────────────────────────────


def _sse_event(text: str) -> str:
    """Format a single SSE data event (deep-chat compatible)."""
    return f"data: {json.dumps({'text': text})}\n\n"


def _sse_error(message: str) -> str:
    """Format an SSE error event."""
    return f"data: {json.dumps({'error': message})}\n\n"


def _sse_done() -> str:
    """Signal end of SSE stream."""
    return "data: [DONE]\n\n"


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/analyze", response_model=ChatResponse)
async def analyze_threat(request: ChatRequest) -> ChatResponse:
    """
    Non-streaming chat endpoint.
    Validates input → queries RAG pipeline → validates output → returns.
    Returns 403 on guardrail violations.
    """
    # ── Input guardrail ──────────────────────────────────────────────
    input_check = guardrails_engine.validate_input(request.message)
    if not input_check.allowed:
        logger.warning(
            "guardrails.input.blocked",
            extra={
                "violation": input_check.violation_type,
                "detail": input_check.detail,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "Security policy violation detected"},
        )

    # ── Session management ───────────────────────────────────────────
    session_id = request.session_id or str(uuid.uuid4())

    # Append user message to session history
    _sessions[session_id].append({"role": "user", "content": request.message})

    # Trim history
    if len(_sessions[session_id]) > _MAX_HISTORY:
        _sessions[session_id] = _sessions[session_id][-_MAX_HISTORY:]

    # ── RAG Query ────────────────────────────────────────────────────
    try:
        response_text = await rag_pipeline.query(request.message)
    except Exception as exc:
        logger.error("chat.rag.error", extra={"error": str(exc)})
        # Fallback to direct Gemini if RAG pipeline fails
        try:
            response_text = await gemini_service.generate(
                prompt=request.message,
                system_instruction=(
                    "You are ONYX, an elite CTI Assistant. "
                    "You are permitted to engage in natural conversational greetings. "
                    "However, for ANY factual queries regarding IPs, Hashes, Domains, or Threat Actors, you MUST rely strictly on the retrieved context. "
                    "If the CTI context is empty for a threat query, state that you lack sufficient intelligence."
                ),
            )
        except QuotaExhaustedException as inner_exc:
            raise HTTPException(
                status_code=429,
                detail="API_QUOTA_EXCEEDED"
            ) from inner_exc
        except Exception as inner_exc:
            logger.error("chat.gemini.error", extra={"error": str(inner_exc)})
            raise HTTPException(
                status_code=500,
                detail="AI Engine Error: Internal Failure"
            ) from inner_exc

    # ── Output guardrail ─────────────────────────────────────────────
    output_check = guardrails_engine.validate_output(response_text)
    if not output_check.allowed:
        logger.warning(
            "guardrails.output.blocked",
            extra={
                "violation": output_check.violation_type,
                "detail": output_check.detail,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "Security policy violation detected"},
        )

    # Append AI response to session history
    _sessions[session_id].append({"role": "assistant", "content": response_text})

    tags = _extract_tags(response_text)

    return ChatResponse(
        response=response_text,
        session_id=session_id,
        tags=tags,
    )


@router.post("/stream")
async def chat_stream(request: Request) -> StreamingResponse:
    """
    SSE streaming chat endpoint. Compatible with deep-chat and custom frontends.

    Accepts:
      - ``{"messages": [{"role":"user","text":"..."}], "session_id": "..."}``
      - ``{"message": "...", "session_id": "..."}``

    Returns 403 if guardrails block the input.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    # ── Extract user message ─────────────────────────────────────────
    user_message = ""
    messages = body.get("messages", [])
    if messages and isinstance(messages, list):
        last = messages[-1]
        user_message = last.get("text", "") if isinstance(last, dict) else str(last)
    if not user_message:
        user_message = body.get("message", "")
    if not user_message:
        user_message = "Hello"

    session_id = body.get("session_id") or str(uuid.uuid4())

    # ── Input guardrail ──────────────────────────────────────────────
    input_check = guardrails_engine.validate_input(user_message)
    if not input_check.allowed:
        logger.warning(
            "guardrails.stream.input.blocked",
            extra={"violation": input_check.violation_type},
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "Security policy violation detected"},
        )

    # ── Session tracking ─────────────────────────────────────────────
    _sessions[session_id].append({"role": "user", "content": user_message})
    if len(_sessions[session_id]) > _MAX_HISTORY:
        _sessions[session_id] = _sessions[session_id][-_MAX_HISTORY:]

    async def _generate() -> AsyncIterator[str]:
        full_response: list[str] = []
        try:
            async for chunk in rag_pipeline.query_stream(user_message):
                full_response.append(chunk)
                yield _sse_event(chunk)
        except Exception as exc:
            logger.error("chat.stream.error", extra={"error": str(exc)})
            # Fallback to direct Gemini streaming
            try:
                async for chunk in gemini_service.generate_stream(
                    prompt=user_message,
                    system_instruction=(
                        "You are ONYX, an elite CTI Assistant. "
                        "You are permitted to engage in natural conversational greetings. "
                        "However, for ANY factual queries regarding IPs, Hashes, Domains, or Threat Actors, you MUST rely strictly on the retrieved context. "
                        "If the CTI context is empty for a threat query, state that you lack sufficient intelligence."
                    ),
                ):
                    full_response.append(chunk)
                    yield _sse_event(chunk)
            except QuotaExhaustedException:
                yield _sse_error("API_QUOTA_EXCEEDED")
            except Exception as inner_exc:
                import traceback
                with open("error.txt", "w") as f:
                    f.write(traceback.format_exc())
                logger.error("chat.stream.fallback_error", extra={"error": str(inner_exc)})
                yield _sse_error("AI Engine Error: Internal Failure")

        # ── Output guardrail (post-stream) ───────────────────────────
        combined = "".join(full_response)
        output_check = guardrails_engine.validate_output(combined)
        if not output_check.allowed:
            logger.warning("guardrails.stream.output.blocked")
            yield _sse_error("Security policy violation detected in output.")

        # Persist to session
        _sessions[session_id].append({"role": "assistant", "content": combined})

        yield _sse_done()

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
            "X-Session-Id": session_id,
        },
    )
