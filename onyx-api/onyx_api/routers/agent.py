"""
ONYX CTI Platform — Agent Copilot Streaming Endpoints
SSE streaming compatible with deep-chat-react's native stream mode.

Contract: Each SSE event MUST be  data: {"text": "<chunk>"}\n\n
deep-chat accumulates all "text" values into a single AI message bubble.
"""

import asyncio
import json
import random
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/agent", tags=["agent"])

# ─── Mock CTI Response Bank (Démo PFE) ────────────────────────────────────────
# Contextual mock responses keyed by intent detection.

_RESPONSES = {
    "status": (
        "**[ONYX COPILOT — Rapport de Situation]**\n\n"
        "La plateforme ONYX est en état de **Vigilance Élevée**.\n\n"
        "• IOCs armés : `{ioc_count}` (flux live MISP + Feodo + URLhaus)\n"
        "• Moteur NLP : SciBERT — **Actif**\n"
        "• Confiance moyenne : 97.4%\n"
        "• Dernière rotation Tor : il y a 4 min\n\n"
        "Les flux récents indiquent une recrudescence d'activités liées "
        "aux **Infostealers** (Lumma, RedLine) dans le secteur EMEA. "
        "Souhaitez-vous une analyse détaillée ?"
    ),
    "remediation": (
        "**[PROTOCOLE DE REMÉDIATION ACTIVÉ]**\n\n"
        "Action : Blocage périmétrique via eBPF Firewall Hook.\n\n"
        "• `[OK]` Commande envoyée au cluster Edge.\n"
        "• `[OK]` IP ajoutée à la Threat Intelligence partagée.\n"
        "• `[OK]` Alerte SOC niveau 1 générée (SIEM forwarding).\n\n"
        "Une analyse forensique de l'hôte source a été initiée. "
        "Temps estimé : 12 minutes."
    ),
    "default": (
        "Je suis **ONYX Copilot**, votre interface d'intelligence "
        "tactique. Je suis connecté en temps réel aux flux CTI de la "
        "plateforme (MISP, Feodo Tracker, URLhaus).\n\n"
        "Je peux :\n"
        "• Analyser le statut des menaces en cours\n"
        "• Lancer un protocole de remédiation\n"
        "• Générer un rapport de crise (8 sections)\n"
        "• Corréler des IOCs avec la matrice MITRE ATT&CK\n\n"
        "Quelle est votre directive ?"
    ),
}

_STATUS_KEYWORDS = ["statut", "status", "combien", "how many", "ioc", "menace", "threat"]
_REMED_KEYWORDS = ["bloque", "block", "isole", "isolate", "remediation", "quarantine"]


def _pick_response(user_message: str, ioc_count: int) -> str:
    """Select a mock response based on keyword matching."""
    msg = user_message.lower()
    if any(k in msg for k in _STATUS_KEYWORDS):
        return _RESPONSES["status"].format(ioc_count=ioc_count)
    if any(k in msg for k in _REMED_KEYWORDS):
        return _RESPONSES["remediation"]
    return _RESPONSES["default"]


async def _deep_chat_sse_generator(user_message: str, request: Request):
    """
    Async generator that yields SSE events in the EXACT format
    required by deep-chat's native stream mode:

        data: {"text": "word "}\n\n

    Each yield appends text to the current AI message bubble.
    """
    # Resolve IOC count from app state (populated at startup)
    armed_iocs = getattr(request.app.state, "armed_iocs", [])
    ioc_count = len(armed_iocs) if armed_iocs else 427

    response_text = _pick_response(user_message, ioc_count)

    # Stream word-by-word with a typing delay
    words = response_text.split(" ")
    for i, word in enumerate(words):
        chunk = word + (" " if i < len(words) - 1 else "")
        # CRITICAL: double-quoted JSON with "text" key only
        payload = json.dumps({"text": chunk})
        yield f"data: {payload}\n\n"
        await asyncio.sleep(0.05)


async def _report_sse_generator(target: str):
    """
    Streams the 8-section tactical report in deep-chat SSE format.
    """
    sections = [
        ("### 1. Informations générales\n",
         f"**Date :** 2026-04-07\n**Titre :** Threat Intelligence Report — "
         f"{target.upper()}\n**Auteur :** ONYX Copilot\n"
         "**Classification :** TLP:RED\n\n"),
        ("### 2. Niveau de criticité\n",
         "**Score CVSS :** 9.8 (CRITIQUE)\n"
         "**Vecteur :** Accès initial via compromission de supply chain.\n"
         "**Blast Radius :** Élevé — mouvement latéral global détecté.\n\n"),
        ("### 3. Indicateurs techniques\n",
         "Détection initiale via eBPF hooks sur processus système non "
         "autorisés. Analyse mémoire corroborant l'exploitation d'une "
         "vulnérabilité zero-day.\n\n"),
        ("### 4. Corrélations\n",
         "Le cluster d'activité correspond à 98% au Mode Opératoire de "
         "*Volt Typhoon*. Corrélation établie avec 14 nœuds C2 connus.\n\n"),
        ("### 5. IOCs associés\n",
         "| Type | Valeur | Confiance |\n|---|---|---|\n"
         "| IP | `185.220.101.45` | 99% |\n"
         "| Hash | `a3e4..f9q2` | 100% |\n"
         "| Domaine | `onion-router-c2.tk` | 95% |\n\n"),
        ("### 6. Comportements observés\n",
         "La menace exécute `certutil.exe` (T1105) pour télécharger le "
         "payload. L'exfiltration (T1048) se produit via DNS tunneling.\n\n"),
        ("### 7. Analyse contextuelle\n",
         "Cette campagne vise les infrastructures critiques occidentales. "
         "L'acteur évite l'écriture sur disque (Living off the Land).\n\n"),
        ("### 8. Recommandations\n",
         "1. **Isoler** les segments de réseau affectés.\n"
         "2. **Déployer** les règles YARA/Sigma sur les EDR.\n"
         "3. **Révoquer** les certificats compromis.\n"),
    ]

    for title, content in sections:
        # Stream title character by character
        for char in title:
            yield f"data: {json.dumps({'text': char})}\n\n"
            await asyncio.sleep(0.01)
        # Stream content word by word
        words = content.split(" ")
        for i, word in enumerate(words):
            chunk = word + (" " if i < len(words) - 1 else "")
            yield f"data: {json.dumps({'text': chunk})}\n\n"
            await asyncio.sleep(0.04)
        await asyncio.sleep(0.2)


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/chat/stream")
async def agent_chat_stream(request: Request):
    """
    Streaming chat endpoint for the ONYX Copilot (deep-chat compatible).

    Accepts either:
      - deep-chat native format: {"messages": [{"role":"user","text":"..."}]}
      - legacy format:           {"message": "...", "context": {...}}
    """
    # Parse body — handle both deep-chat and legacy formats robustly
    try:
        body = await request.json()
    except Exception:
        body = {}

    user_message = ""

    # deep-chat sends {"messages": [{"role":"user","text":"hello"}]}
    messages = body.get("messages", [])
    if messages and isinstance(messages, list):
        last = messages[-1]
        user_message = last.get("text", "") if isinstance(last, dict) else str(last)

    # Fallback to legacy {"message": "..."} format
    if not user_message:
        user_message = body.get("message", "")

    if not user_message:
        user_message = "Bonjour"

    return StreamingResponse(
        _deep_chat_sse_generator(user_message, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/report/stream")
async def agent_report_stream(target: str = "Menace Globale"):
    """Generates the 8-section tactical report as an SSE stream."""
    return StreamingResponse(
        _report_sse_generator(target),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )
