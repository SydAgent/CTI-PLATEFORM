"""
ONYX CTI — MongoDB Service
Async MongoDB client for STIX 2.1 object persistence, graph queries,
and relationship traversal. Uses Motor (async PyMongo) with connection pooling.

Design: Adapted from OpenCTI's domain layer + Yeti's ArangoDB graph patterns,
re-implemented on MongoDB with $graphLookup for relationship traversal.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from tenacity import retry, stop_after_attempt, wait_exponential

from onyx_core.config import MongoDBConfig, get_config
from onyx_core.models.stix import STIXBase, create_stix_object

logger = logging.getLogger("onyx.mongodb")


class MongoDBService:
    """
    Async MongoDB service for STIX 2.1 object lifecycle management.
    Provides CRUD, graph traversal, and aggregation pipelines.
    Singleton pattern for connection pool reuse.
    """

    _instance: MongoDBService | None = None
    _client: AsyncIOMotorClient | None = None  # type: ignore[type-arg]
    _db: AsyncIOMotorDatabase | None = None  # type: ignore[type-arg]

    def __new__(cls) -> MongoDBService:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._client is not None:
            return
        cfg: MongoDBConfig = get_config().mongodb
        self._client = AsyncIOMotorClient(
            cfg.uri,
            maxPoolSize=50,
            minPoolSize=5,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=30000,
        )
        self._db = self._client[cfg.database]
        self._cfg = cfg

    @property
    def db(self) -> AsyncIOMotorDatabase:  # type: ignore[type-arg]
        assert self._db is not None, "MongoDB not initialized"
        return self._db

    def collection(self, name: str) -> AsyncIOMotorCollection:  # type: ignore[type-arg]
        """Get a collection by name."""
        return self.db[name]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, max=30))
    async def initialize(self) -> None:
        """Verify connectivity and collection existence."""
        info = await self._client.server_info()  # type: ignore[union-attr]
        logger.info(
            "MongoDB connected: version=%s, host=%s",
            info.get("version"),
            self._cfg.host,
        )
        # Verify expected collections exist
        collections = await self.db.list_collection_names()
        expected = [
            "stix_objects", "stix_relationships", "stix_sightings",
            "marking_definitions", "crawler_state", "feed_configs",
            "playbooks", "users", "audit_log",
        ]
        missing = [c for c in expected if c not in collections]
        if missing:
            logger.warning("Missing collections (will be auto-created on first write): %s", missing)
        else:
            logger.info("All %d expected collections are present", len(expected))

    async def close(self) -> None:
        """Close the MongoDB connection pool."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None
            MongoDBService._instance = None
            logger.info("MongoDB connection closed")

    async def health(self) -> dict[str, Any]:
        """Check MongoDB connectivity."""
        result = await self.db.command("ping")
        return {"status": "ok" if result.get("ok") == 1.0 else "error"}

    # ------------------------------------------------------------------
    # STIX Object CRUD
    # ------------------------------------------------------------------

    async def create_stix(self, stix_obj: STIXBase) -> str:
        """
        Create or update a STIX object. Uses upsert on id for idempotency.

        Args:
            stix_obj: Validated STIX Pydantic model instance.

        Returns:
            The STIX id of the created/updated object.
        """
        data = stix_obj.model_dump(mode="json")
        data["modified"] = datetime.now(timezone.utc).isoformat()

        # Route to correct collection based on type
        coll_name = self._get_collection_for_type(stix_obj.type)
        collection = self.collection(coll_name)

        await collection.update_one(
            {"id": stix_obj.id},
            {"$set": data},
            upsert=True,
        )
        logger.debug("Upserted STIX %s: %s", stix_obj.type, stix_obj.id)
        return stix_obj.id

    async def get_stix(self, stix_id: str) -> STIXBase | None:
        """
        Retrieve a STIX object by its ID.
        Automatically detects the collection from the id prefix.
        """
        stix_type = stix_id.split("--")[0]
        coll_name = self._get_collection_for_type(stix_type)
        doc = await self.collection(coll_name).find_one(
            {"id": stix_id}, {"_id": 0}
        )
        if doc is None:
            return None
        return create_stix_object(doc)

    async def delete_stix(self, stix_id: str) -> bool:
        """Soft-delete a STIX object by setting revoked=True."""
        stix_type = stix_id.split("--")[0]
        coll_name = self._get_collection_for_type(stix_type)
        result = await self.collection(coll_name).update_one(
            {"id": stix_id},
            {"$set": {"revoked": True, "modified": datetime.now(timezone.utc).isoformat()}},
        )
        return result.modified_count > 0

    async def list_stix(
        self,
        stix_type: str,
        limit: int = 50,
        offset: int = 0,
        sort_field: str = "modified",
        sort_order: int = -1,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        List STIX objects of a given type with pagination and filtering.
        """
        coll_name = self._get_collection_for_type(stix_type)
        query: dict[str, Any] = {"type": stix_type, "revoked": {"$ne": True}}
        if filters:
            query.update(filters)

        cursor = (
            self.collection(coll_name)
            .find(query, {"_id": 0})
            .sort(sort_field, sort_order)
            .skip(offset)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def count_stix(self, stix_type: str) -> int:
        """Count non-revoked STIX objects of a given type."""
        coll_name = self._get_collection_for_type(stix_type)
        return await self.collection(coll_name).count_documents(
            {"type": stix_type, "revoked": {"$ne": True}}
        )

    # ------------------------------------------------------------------
    # Bulk Operations
    # ------------------------------------------------------------------

    async def bulk_create_stix(self, objects: list[STIXBase]) -> int:
        """
        Bulk upsert STIX objects. Groups by collection for efficiency.

        Returns:
            Number of successfully upserted documents.
        """
        from collections import defaultdict
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for obj in objects:
            coll_name = self._get_collection_for_type(obj.type)
            data = obj.model_dump(mode="json")
            data["modified"] = datetime.now(timezone.utc).isoformat()
            grouped[coll_name].append(data)

        total = 0
        for coll_name, docs in grouped.items():
            collection = self.collection(coll_name)
            from pymongo import UpdateOne
            operations = [
                UpdateOne({"id": doc["id"]}, {"$set": doc}, upsert=True)
                for doc in docs
            ]
            if operations:
                result = await collection.bulk_write(operations, ordered=False)
                total += result.upserted_count + result.modified_count
                logger.info(
                    "Bulk upserted %d docs into %s",
                    result.upserted_count + result.modified_count,
                    coll_name,
                )
        return total

    # ------------------------------------------------------------------
    # Graph Traversal (adapted from Yeti's ArangoDB patterns)
    # ------------------------------------------------------------------

    async def get_relationships(
        self,
        stix_id: str,
        relationship_type: str | None = None,
        direction: str = "both",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get relationships for a STIX object.

        Args:
            stix_id: STIX ID of the source/target object.
            relationship_type: Optional filter by relationship type.
            direction: 'outgoing' (source), 'incoming' (target), or 'both'.
            limit: Maximum number of relationships to return.
        """
        query: dict[str, Any] = {}

        if direction == "outgoing":
            query["source_ref"] = stix_id
        elif direction == "incoming":
            query["target_ref"] = stix_id
        else:
            query["$or"] = [{"source_ref": stix_id}, {"target_ref": stix_id}]

        if relationship_type:
            query["relationship_type"] = relationship_type

        cursor = (
            self.collection("stix_relationships")
            .find(query, {"_id": 0})
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def get_neighbors(
        self,
        stix_id: str,
        max_depth: int = 2,
        relationship_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Traverse the STIX relationship graph using $graphLookup.
        Returns all reachable nodes up to max_depth.

        This replaces Yeti's ArangoDB graph traversal with MongoDB's
        built-in $graphLookup aggregation pipeline.
        """
        match_stage: dict[str, Any] = {}
        if relationship_types:
            match_stage["relationship_type"] = {"$in": relationship_types}

        pipeline = [
            {"$match": {"$or": [{"source_ref": stix_id}, {"target_ref": stix_id}]}},
            {
                "$graphLookup": {
                    "from": "stix_relationships",
                    "startWith": "$target_ref",
                    "connectFromField": "target_ref",
                    "connectToField": "source_ref",
                    "as": "graph_path",
                    "maxDepth": max_depth - 1,
                    "depthField": "depth",
                    "restrictSearchWithMatch": match_stage if match_stage else {},
                }
            },
            {"$limit": 500},
        ]

        cursor = self.collection("stix_relationships").aggregate(pipeline)
        results = await cursor.to_list(length=500)

        # Collect all unique STIX IDs from the graph
        node_ids: set[str] = {stix_id}
        edges: list[dict[str, Any]] = []

        for rel in results:
            node_ids.add(rel.get("source_ref", ""))
            node_ids.add(rel.get("target_ref", ""))
            edges.append({
                "source": rel.get("source_ref"),
                "target": rel.get("target_ref"),
                "type": rel.get("relationship_type"),
            })
            for path_item in rel.get("graph_path", []):
                node_ids.add(path_item.get("source_ref", ""))
                node_ids.add(path_item.get("target_ref", ""))
                edges.append({
                    "source": path_item.get("source_ref"),
                    "target": path_item.get("target_ref"),
                    "type": path_item.get("relationship_type"),
                    "depth": path_item.get("depth"),
                })

        node_ids.discard("")

        # Fetch node metadata
        nodes = []
        for nid in node_ids:
            obj = await self.get_stix(nid)
            if obj:
                nodes.append({
                    "id": obj.id,
                    "type": obj.type,
                    "name": getattr(obj, "name", obj.id),
                    "confidence": obj.confidence,
                })

        return {"nodes": nodes, "edges": edges, "root": stix_id}

    # ------------------------------------------------------------------
    # Dashboard Aggregations
    # ------------------------------------------------------------------

    async def get_stix_stats(self) -> dict[str, Any]:
        """Get counts of all STIX object types for the dashboard."""
        pipeline = [
            {"$match": {"revoked": {"$ne": True}}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        cursor = self.collection("stix_objects").aggregate(pipeline)
        results = await cursor.to_list(length=50)
        return {
            "types": {r["_id"]: r["count"] for r in results},
            "total": sum(r["count"] for r in results),
        }

    async def get_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get the most recently modified STIX objects."""
        cursor = (
            self.collection("stix_objects")
            .find({"revoked": {"$ne": True}}, {"_id": 0, "id": 1, "type": 1, "name": 1, "modified": 1})
            .sort("modified", -1)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    # ------------------------------------------------------------------
    # Crawler State Management
    # ------------------------------------------------------------------

    async def update_crawler_state(
        self,
        crawler_id: str,
        status: str,
        **kwargs: Any,
    ) -> None:
        """Update crawler execution state."""
        update_data = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        await self.collection("crawler_state").update_one(
            {"crawler_id": crawler_id},
            {"$set": update_data},
            upsert=True,
        )

    async def get_crawler_states(self) -> list[dict[str, Any]]:
        """Get all crawler states for monitoring."""
        cursor = self.collection("crawler_state").find({}, {"_id": 0})
        return await cursor.to_list(length=100)

    # ------------------------------------------------------------------
    # User Management
    # ------------------------------------------------------------------

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Fetch a user document by username."""
        return await self.collection("users").find_one(
            {"username": username}, {"_id": 0}
        )

    async def get_user_by_api_key(self, api_key_hash: str) -> dict[str, Any] | None:
        """Fetch a user document by hashed API key."""
        return await self.collection("users").find_one(
            {"api_key_hash": api_key_hash}, {"_id": 0}
        )

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_collection_for_type(stix_type: str) -> str:
        """Route STIX types to their MongoDB collections."""
        if stix_type in ("relationship",):
            return "stix_relationships"
        if stix_type in ("sighting",):
            return "stix_sightings"
        if stix_type in ("marking-definition",):
            return "marking_definitions"
        return "stix_objects"
