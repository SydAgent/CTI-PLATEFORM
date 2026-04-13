"""
ONYX CTI — Forum Router
Provides a lightweight analyst collaboration forum backed by in-memory state.
Supports threads (topics) and replies, with real-time broadcasting via SSE.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter()


# ── Pydantic Schemas ─────────────────────────────────────────────────────────

class ForumPostCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=300)
    content: str = Field(..., min_length=5, max_length=5000)
    author: str = Field(default="Analyst")
    tags: list[str] = Field(default_factory=list)


class ForumReplyCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=3000)
    author: str = Field(default="Analyst")


# ── Endpoints ────────────────────────────────────────────────────────────────

def _ensure_forum_state(request: Request):
    """Ensure the forum state exists on app.state."""
    if not hasattr(request.app.state, "forum_threads"):
        request.app.state.forum_threads = _seed_initial_threads()


def _seed_initial_threads() -> list[dict]:
    """Seed some initial forum threads so the module isn't empty."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": str(uuid.uuid4()),
            "title": "🔴 ALERTE : Campagne APT29 active détectée sur les VPN Ivanti",
            "content": "Nos sondes OSINT détectent une recrudescence d'exploitation de CVE-2024-21887 sur les appliances Ivanti. Les IOCs corrélés pointent vers le cluster APT29/Cozy Bear. Recommandation immédiate : patch critique + isolation DMZ des équipements concernés.",
            "author": "SOC Lead",
            "tags": ["apt29", "cve-2024-21887", "critical"],
            "created_at": now,
            "replies": [
                {"id": str(uuid.uuid4()), "content": "Confirmé. Nos logs Suricata montrent des beacons HTTPS sortants vers 185.220.101.45 toutes les 30 secondes. Signature Cobalt Strike identifiée.", "author": "Analyste Réseau", "created_at": now},
                {"id": str(uuid.uuid4()), "content": "Règle Sigma déployée : sigma_apt29_ivanti_exploit_t1190. Le SIEM alerte maintenant en temps réel.", "author": "Ingénieur SIEM", "created_at": now},
            ],
            "pinned": True,
        },
        {
            "id": str(uuid.uuid4()),
            "title": "📊 Partage de rapport : Analyse post-mortem LockBit 3.0",
            "content": "Suite à l'incident du 2 avril, le rapport complet est disponible. Points clés : l'attaquant a utilisé T1486 (chiffrement) après avoir désactivé les shadow copies via vssadmin.exe. La chaîne d'attaque complète est documentée dans le STIX bundle attaché.",
            "author": "DFIR Lead",
            "tags": ["lockbit", "ransomware", "post-mortem"],
            "created_at": now,
            "replies": [
                {"id": str(uuid.uuid4()), "content": "Excellent travail. J'ai corrélé avec les IOCs de notre feed Feodo : 3 IPs C2 supplémentaires identifiées.", "author": "CTI Analyst", "created_at": now},
            ],
            "pinned": False,
        },
        {
            "id": str(uuid.uuid4()),
            "title": "💡 Discussion : Implémentation de Deception Grids (Honeypots)",
            "content": "Je propose de déployer des honeypots T-Pot sur nos segments critiques pour détecter les mouvements latéraux. Qui a de l'expérience avec cette approche ? Quels sont les risques de false-positive en production ?",
            "author": "Security Architect",
            "tags": ["deception", "honeypot", "defense"],
            "created_at": now,
            "replies": [],
            "pinned": False,
        },
    ]


@router.get("/forum/threads", summary="List all forum threads")
async def list_threads(request: Request) -> dict[str, Any]:
    _ensure_forum_state(request)
    threads = request.app.state.forum_threads
    return {
        "total": len(threads),
        "threads": threads,
        "status": "ONLINE",
    }


@router.get("/forum/threads/{thread_id}", summary="Get a single thread with replies")
async def get_thread(request: Request, thread_id: str) -> dict:
    _ensure_forum_state(request)
    for thread in request.app.state.forum_threads:
        if thread["id"] == thread_id:
            return thread
    raise HTTPException(status_code=404, detail=f"Thread not found: {thread_id}")


@router.post("/forum/threads", status_code=201, summary="Create a new forum thread")
async def create_thread(request: Request, body: ForumPostCreate) -> dict:
    _ensure_forum_state(request)
    thread = {
        "id": str(uuid.uuid4()),
        "title": body.title,
        "content": body.content,
        "author": body.author,
        "tags": body.tags,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "replies": [],
        "pinned": False,
    }
    request.app.state.forum_threads.insert(0, thread)
    return {"status": "created", "thread": thread}


@router.post("/forum/threads/{thread_id}/replies", status_code=201, summary="Reply to a thread")
async def create_reply(request: Request, thread_id: str, body: ForumReplyCreate) -> dict:
    _ensure_forum_state(request)
    for thread in request.app.state.forum_threads:
        if thread["id"] == thread_id:
            reply = {
                "id": str(uuid.uuid4()),
                "content": body.content,
                "author": body.author,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            thread["replies"].append(reply)
            return {"status": "created", "reply": reply}
    raise HTTPException(status_code=404, detail=f"Thread not found: {thread_id}")


@router.get("/forum/status", summary="Forum health check")
async def forum_status(request: Request) -> dict:
    _ensure_forum_state(request)
    return {
        "status": "ONLINE",
        "threads": len(request.app.state.forum_threads),
        "total_replies": sum(len(t.get("replies", [])) for t in request.app.state.forum_threads),
    }
