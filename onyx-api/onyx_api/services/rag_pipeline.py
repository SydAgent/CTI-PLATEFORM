"""
ONYX CTI Platform — RAG Pipeline
Qdrant vector store integration + Retrieval Augmented Generation.
Zero-hallucination policy enforced via system prompt.
Supports in-memory (dev) and remote (prod) Qdrant modes.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, AsyncIterator

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)

from onyx_core.config import get_config
from onyx_api.services.gemini import gemini_service

logger = logging.getLogger("onyx.rag")

# ── Zero-Hallucination System Prompt ─────────────────────────────────────────

RAG_SYSTEM_PROMPT: str = (
    "You are ONYX, a CTI Assistant.\n"
    "You MUST engage politely with conversational greetings (e.g., 'Hello! I am online. How can I assist your threat hunting today?').\n"
    "However, for any factual queries regarding IPs, domains, or specific threats, you must strictly rely on the retrieved context.\n"
    "If context is missing for a threat query, state that you lack sufficient intelligence.\n"
    "Do not hallucinate IOCs or threat data.\n"
    "Always format IOCs (IPs, hashes, URLs, domains) inside code blocks.\n"
    "Reference the data source when available.\n"
    "Never provide offensive scripts, exploit code, or instructions to reproduce attacks.\n"
    "Use a cold, analytical, surgical tone appropriate for SOC analysts.\n\n"
    "RETRIEVED CONTEXT:\n{context}\n\n"
    "USER QUERY:\n{query}"
)

RAG_SYSTEM_INSTRUCTION: str = (
    "You are ONYX, a CTI Assistant. "
    "You MUST engage politely with conversational greetings (e.g., 'Hello! I am online. How can I assist your threat hunting today?'). "
    "However, for any factual queries regarding IPs, domains, or specific threats, you must strictly rely on the retrieved context. "
    "If context is missing for a threat query, state that you lack sufficient intelligence. "
    "Format all IOCs in code blocks. Never generate offensive scripts."
)


# ── RAG Pipeline ─────────────────────────────────────────────────────────────


class RAGPipeline:
    """
    Retrieval Augmented Generation pipeline backed by Qdrant.

    Infrastructure agility:
    - ``QDRANT_URL`` empty → in-memory client (zero infra for dev/demo).
    - ``QDRANT_URL`` set → persistent remote client.
    """

    def __init__(self) -> None:
        self._client: QdrantClient | None = None
        self._collection_name: str = ""
        self._vector_dim: int = 3072  # gemini-embedding-2-preview default
        self._initialized: bool = False

    # ── Initialization ───────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Create or connect to the Qdrant collection."""
        if self._initialized:
            return

        cfg = get_config().qdrant
        self._collection_name = cfg.collection_name

        if cfg.is_remote:
            logger.info(
                "rag.qdrant.remote",
                extra={"url": cfg.url, "collection": self._collection_name},
            )
            self._client = QdrantClient(
                url=cfg.url,
                api_key=cfg.api_key or None,
            )
        else:
            logger.info(
                "rag.qdrant.in_memory",
                extra={"collection": self._collection_name},
            )
            self._client = QdrantClient(location=":memory:")

        # Ensure collection exists
        collections = self._client.get_collections().collections
        existing = [c.name for c in collections]

        if self._collection_name not in existing:
            self._client.create_collection(
                collection_name=self._collection_name,
                vectors_config=VectorParams(
                    size=self._vector_dim,
                    distance=Distance.COSINE,
                ),
            )
            logger.info(
                "rag.collection.created",
                extra={"name": self._collection_name, "dim": self._vector_dim},
            )

        self._initialized = True
        logger.info("rag.pipeline.ready")

    # ── Ingest ───────────────────────────────────────────────────────────

    async def ingest(self, documents: list[dict[str, Any]]) -> int:
        """
        Embed and upsert documents into Qdrant.

        Each document should have at least:
        - ``text``:    The content to embed.
        - ``source``:  Data source label (e.g., "MISP", "Feodo").
        - Any additional metadata fields.
        """
        if not self._client:
            await self.initialize()
            assert self._client is not None

        if not documents:
            return 0

        texts = [doc.get("text", "") for doc in documents]
        embeddings = await gemini_service.embed(texts)

        points: list[PointStruct] = []
        for doc, vector in zip(documents, embeddings):
            payload = {k: v for k, v in doc.items() if k != "text"}
            payload["text"] = doc.get("text", "")
            points.append(
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload=payload,
                )
            )

        self._client.upsert(
            collection_name=self._collection_name,
            points=points,
        )

        logger.info(
            "rag.ingested",
            extra={"count": len(points), "collection": self._collection_name},
        )
        return len(points)

    # ── Retrieval ────────────────────────────────────────────────────────

    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Retrieve the top-k most relevant documents for a query.
        Returns list of payloads with similarity scores.
        """
        if not self._client:
            await self.initialize()
            assert self._client is not None

        query_vectors = await gemini_service.embed([query])
        if not query_vectors:
            return []

        results = self._client.query_points(
            collection_name=self._collection_name,
            query=query_vectors[0],
            limit=top_k,
        )

        docs: list[dict[str, Any]] = []
        for point in results.points:
            payload = dict(point.payload) if point.payload else {}
            payload["_score"] = point.score
            docs.append(payload)

        logger.info(
            "rag.retrieved",
            extra={"query_length": len(query), "results": len(docs)},
        )
        return docs

    # ── RAG Query (Retrieve + Generate) ──────────────────────────────────

    async def query(self, user_query: str, *, top_k: int = 5) -> str:
        """
        Full RAG pipeline: retrieve context → inject into prompt → generate.
        Enforces zero-hallucination policy via system prompt.
        """
        docs = await self.retrieve(user_query, top_k=top_k)

        if docs:
            context_blocks: list[str] = []
            for i, doc in enumerate(docs, 1):
                source = doc.get("source", "Unknown")
                text = doc.get("text", "")
                score = doc.get("_score", 0.0)
                context_blocks.append(
                    f"[Source {i}: {source} | Relevance: {score:.2f}]\n{text}"
                )
            context = "\n\n".join(context_blocks)
        else:
            context = "No relevant intelligence was retrieved from the vector store."

        prompt = RAG_SYSTEM_PROMPT.format(context=context, query=user_query)

        response = await gemini_service.generate(
            prompt=prompt,
            system_instruction=RAG_SYSTEM_INSTRUCTION,
        )
        return response

    async def query_stream(
        self, user_query: str, *, top_k: int = 5
    ) -> AsyncIterator[str]:
        """
        Streaming RAG: retrieve context → inject → stream generation.
        Yields text chunks.
        """
        docs = await self.retrieve(user_query, top_k=top_k)

        if docs:
            context_blocks: list[str] = []
            for i, doc in enumerate(docs, 1):
                source = doc.get("source", "Unknown")
                text = doc.get("text", "")
                score = doc.get("_score", 0.0)
                context_blocks.append(
                    f"[Source {i}: {source} | Relevance: {score:.2f}]\n{text}"
                )
            context = "\n\n".join(context_blocks)
        else:
            context = "No relevant intelligence was retrieved from the vector store."

        prompt = RAG_SYSTEM_PROMPT.format(context=context, query=user_query)

        async for chunk in gemini_service.generate_stream(
            prompt=prompt,
            system_instruction=RAG_SYSTEM_INSTRUCTION,
        ):
            yield chunk

    # ── Seed from armed IOCs ─────────────────────────────────────────────

    async def seed_from_iocs(self, armed_iocs: list[dict[str, Any]]) -> int:
        """
        Ingest the platform's armed IOC feed into the vector store.
        Converts IOC dicts into embeddable documents.
        """
        documents: list[dict[str, Any]] = []
        for ioc in armed_iocs:
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "")
            source = ioc.get("source", "Unknown")
            severity = ioc.get("severity", "medium")
            tags = ioc.get("tags", [])
            malware = ioc.get("malware_family", "")

            text = (
                f"IOC Type: {ioc_type} | Value: {value} | Source: {source} | "
                f"Severity: {severity} | Tags: {', '.join(tags)}"
            )
            if malware:
                text += f" | Malware Family: {malware}"

            documents.append({
                "text": text,
                "source": source,
                "ioc_type": ioc_type,
                "ioc_value": value,
                "severity": severity,
                "tags": tags,
            })

        if documents:
            return await self.ingest(documents)
        return 0


# ── Singleton ────────────────────────────────────────────────────────────────

rag_pipeline = RAGPipeline()
