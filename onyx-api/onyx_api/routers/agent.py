"""
ONYX CTI Platform — Agent Copilot Streaming Endpoints
SSE streaming backed by real Gemini + RAG pipeline.

Contract: Each SSE event MUST be  data: {"text": "<chunk>"}\n\n
Compatible with deep-chat-react and the custom OnyxCopilot frontend.
"""

from __future__ import annotations

import json
import logging
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from onyx_api.services.gemini import gemini_service, QuotaExhaustedException
from onyx_api.services.guardrails import guardrails_engine
from onyx_api.services.rag_pipeline import rag_pipeline

logger = logging.getLogger("onyx.routers.agent")

router = APIRouter(prefix="/agent", tags=["agent"])


# ── War Room Report Prompt ───────────────────────────────────────────────────

WAR_ROOM_PROMPT: str = """[ROLE] You are the Chief Strategic Analyst of the War Room.
[MISSION] Transform raw threat intelligence feeds into a state-level "Executive Briefing".
[FORMAT CONSTRAINTS] Your report MUST follow this exact structure:
**BLUF (Bottom Line Up Front)**: Summarize the threat in ONE sentence.
**ATTACK VECTOR**: How the threat operates (e.g., targeted phishing, 0-day exploitation).
**IMPACT**: Financial damage, data exfiltration, sabotage potential.
**IMMEDIATE COUNTERMEASURE (ACTIONABLE INTEL)**: Firewall rule, patch to deploy, IOC to block.
[TONE] Cold, analytical, surgical. No unnecessary jargon. Use bullet points.

Target threat: {target}
Generate the briefing now."""

WAR_ROOM_SYSTEM: str = (
    "You are ONYX Copilot in War Room mode. Generate executive threat briefings. "
    "If you lack intelligence on the target, state so clearly. "
    "Do not hallucinate IOCs or threat data."
)


# ── SSE Helpers ──────────────────────────────────────────────────────────────


def _sse_event(text: str) -> str:
    return f"data: {json.dumps({'text': text})}\n\n"


def _sse_error(message: str) -> str:
    return f"data: {json.dumps({'error': message})}\n\n"


def _sse_done() -> str:
    return "data: [DONE]\n\n"


# ── Streaming SSE Headers ───────────────────────────────────────────────────

_SSE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
    "Access-Control-Allow-Origin": "*",
}


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/chat/stream")
async def agent_chat_stream(request: Request) -> StreamingResponse:
    """
    Streaming chat endpoint for the ONYX Copilot.
    Integrates guardrails + RAG pipeline + real Gemini streaming.

    Accepts:
      - deep-chat format: {"messages": [{"role":"user","text":"..."}]}
      - legacy format:    {"message": "...", "context": {...}}

    Returns 403 on guardrail violations.
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

    logger.info(f"AGENT STREAM RECEIVED user_message={user_message} body={body}")

    # ── Input guardrail ──────────────────────────────────────────────
    input_check = guardrails_engine.validate_input(user_message)
    if not input_check.allowed:
        logger.warning(
            "guardrails.agent.input.blocked",
            extra={"violation": input_check.violation_type},
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "Security policy violation detected"},
        )

    async def _generate() -> AsyncIterator[str]:
        full_response: list[str] = []
        try:
            async for chunk in rag_pipeline.query_stream(user_message):
                full_response.append(chunk)
                yield _sse_event(chunk)
        except Exception as exc:
            logger.error("agent.stream.rag_error", extra={"error": str(exc)})
            # Fallback to direct Gemini streaming
            try:
                async for chunk in gemini_service.generate_stream(
                    prompt=user_message,
                    system_instruction=(
                        "You are ONYX Copilot, an elite Cyber Threat Intelligence assistant. "
                        "If you lack context, state that you do not have sufficient intelligence "
                        "to respond. Do not hallucinate IOCs or threat data."
                    ),
                ):
                    full_response.append(chunk)
                    yield _sse_event(chunk)
            except QuotaExhaustedException:
                yield _sse_error("API_QUOTA_EXCEEDED")
            except Exception as inner_exc:
                logger.error("agent.stream.fallback_error", extra={"error": str(inner_exc)})
                yield _sse_error("AI Engine Error: Internal Failure")

        # ── Output guardrail (post-stream) ───────────────────────────
        combined = "".join(full_response)
        output_check = guardrails_engine.validate_output(combined)
        if not output_check.allowed:
            logger.warning("guardrails.agent.output.blocked")
            yield _sse_error("Security policy violation detected in output.")

        yield _sse_done()

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


@router.get("/report/stream")
async def agent_report_stream(target: str = "Global Threat Landscape") -> StreamingResponse:
    """
    Generates a tactical War Room briefing as an SSE stream.
    Real Gemini generation — no mocks.
    """
    prompt = WAR_ROOM_PROMPT.format(target=target)

    async def _generate() -> AsyncIterator[str]:
        try:
            async for chunk in gemini_service.generate_stream(
                prompt=prompt,
                system_instruction=WAR_ROOM_SYSTEM,
            ):
                yield _sse_event(chunk)
        except QuotaExhaustedException:
            yield _sse_error("API_QUOTA_EXCEEDED")
        except Exception as exc:
            logger.error("agent.report.error", extra={"error": str(exc)})
            yield _sse_error("AI Engine Error: Internal Failure")

        yield _sse_done()

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )
