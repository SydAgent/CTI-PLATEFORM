import asyncio
import json
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/agent", tags=["agent"])

class ChatRequest(BaseModel):
    message: str
    context: Optional[dict] = {}

class ReportRequest(BaseModel):
    target: str

async def _chat_stream_generator(msg: str, request: Request):
    msg_low = msg.lower()
    
    # Simulate thinking
    yield f"data: {json.dumps({'text': '...', 'status': 'thinking'})}\n\n"
    await asyncio.sleep(0.5)

    armed_iocs = getattr(request.app.state, "armed_iocs", [])
    ioc_count = len(armed_iocs) if armed_iocs else 427

    response_text = ""

    if any(k in msg_low for k in ["statut", "status", "combien", "how many", "ioc", "menace"]):
        response_text = f"### Rapport de Situation OMNI-AGENT\n\nLa plateforme ONYX est actuellement dans un état de **Vigilance Élevée**.\n* **IOCs Armés :** `{ioc_count}` (Flux live)\n* **Moteur NLP :** SciBERT (Actif)\n* **Confiance Moyenne :** 97.4%\n\nLes flux récents indiquent une recrudescence d'activités liées aux **Infostealers** dans le secteur EMEA. Souhaitez-vous une analyse détaillée des derniers échantillons ?"
    elif any(k in msg_low for k in ["bloque", "block", "isole", "isolate", "remediation"]):
        response_text = "### 🛡️ PROTOCOLE DE REMÉDIATION ACTIVÉ\n\n**Action :** Blocage périmétrique (eBPF Firewall Hook)\n\n* `[SUCCESS]` Commande envoyée au cluster Edge.\n* `[SUCCESS]` IP ajoutée à la Threat Intelligence partagée.\n* `[SUCCESS]` Alerte SOC niveau 1 générée.\n\nUne analyse forensique de l'hôte source a été initiée."
    else:
        response_text = "Je suis l'Agent Copilot ONYX (Moteur Expert Mock). Je suis connecté en temps réel aux flux d'intelligence de la plateforme. Je peux générer des rapports de crise, analyser des menaces ou lancer des protocoles de remédiation. Quelle est votre directive ?"

    # Stream the response word by word for the WOW effect
    words = response_text.split(" ")
    for i, word in enumerate(words):
        chunk = word + (" " if i < len(words) - 1 else "")
        yield f"data: {json.dumps({'text': chunk, 'status': 'streaming'})}\n\n"
        await asyncio.sleep(0.02)
        
    yield f"data: {json.dumps({'text': '', 'status': 'done'})}\n\n"


async def _report_stream_generator(target: str):
    yield f"data: {json.dumps({'text': 'Initialisation de la génération du rapport...', 'status': 'thinking'})}\n\n"
    await asyncio.sleep(0.5)

    sections = [
        ("### 1. Informations générales\n", "**Date :** 2026-04-07\n**Titre :** Threat Intelligence Report - " + target.upper() + "\n**Auteur :** ONYX Omni-Agent\n**Classification :** TLP:RED\n\n"),
        ("### 2. Données de sécurité et niveau de criticité\n", "**Score CVSS :** 9.8 (CRITIQUE)\n**Vecteur :** Accès initial via compromission de supply chain.\n**Blast Radius :** Élevé (Potentiel mouvement latéral global détecté).\n\n"),
        ("### 3. Indicateurs techniques et méthodologie d'analyse\n", "Détection initiale via eBPF hooks sur processus système non autorisés. Analyse mémoire en direct corroborant l'exploitation de la vulnérabilité zero-day.\n\n"),
        ("### 4. Relations, corrélations et interactions entre les éléments\n", "Le cluster d'activité correspond fortement (98%) au Mode Opératoire de *Volt Typhoon*. Corrélation établie avec 14 noeuds C2 connus.\n\n"),
        ("### 5. Détails associés (IOC, entités liées, artefacts)\n", "| Type | Valeur | Confiance |\n|---|---|---|\n| IP | `185.220.101.45` | 99% |\n| Hash | `a3e4..f9q2` | 100% |\n| Domaine | `onion-router-c2.tk` | 95% |\n\n"),
        ("### 6. Comportements observés et analyse des menaces\n", "La menace exécute `certutil.exe` (T1105) pour télécharger le payload de second stade. L'exfiltration (T1048) se produit via DNS tunneling.\n\n"),
        ("### 7. Analyse contextuelle approfondie et interprétation intelligente\n", "Cette campagne vise explicitement les infrastructures critiques occidentales. L'acteur de menace démontre une sophistication notable en évitant l'écriture sur disque (Living off the Land).\n\n"),
        ("### 8. Synthèse claire et recommandations actionnables\n", "1. **Isoler** immédiatement les segments de réseau affectés.\n2. **Déployer** les règles YARA/Sigma fournies sur l'ensemble des EDR.\n3. **Révoquer** les certificats compromis identifiés dans l'infrastructure PKI.\n")
    ]

    for title, content in sections:
        # Stream title
        for t_char in title:
            yield f"data: {json.dumps({'text': t_char, 'status': 'streaming'})}\n\n"
            await asyncio.sleep(0.01)
        # Stream content word by word
        words = content.split(" ")
        for i, word in enumerate(words):
            chunk = word + (" " if i < len(words) - 1 else "")
            yield f"data: {json.dumps({'text': chunk, 'status': 'streaming'})}\n\n"
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.3)

    yield f"data: {json.dumps({'text': '', 'status': 'done'})}\n\n"

@router.post("/chat/stream")
async def agent_chat_stream(req: ChatRequest, request: Request):
    """Streaming chat endpoint for the Copilot"""
    return StreamingResponse(
        _chat_stream_generator(req.message, request), 
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "Access-Control-Allow-Origin": "*"}
    )

@router.get("/report/stream")
async def agent_report_stream(target: str = "Menace Globale"):
    """Generates the 8-section report dynamically in a stream"""
    return StreamingResponse(
        _report_stream_generator(target), 
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "Access-Control-Allow-Origin": "*"}
    )
