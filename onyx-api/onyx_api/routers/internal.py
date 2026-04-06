from typing import Any, List
from fastapi import APIRouter
from pydantic import BaseModel
import os

from onyx_core.services import MongoDBService

router = APIRouter()

class SeedPayload(BaseModel):
    objects: List[Any]

@router.post("/_internal/seed", summary="Exhibition Mode Topology Seeder")
async def seed_topology(payload: SeedPayload) -> dict[str, Any]:
    """
    Direct memory injection for standalone exhibition mode.
    Bypasses Elasticsearch/Redis and populates STIX states directly.
    """
    if os.environ.get("STANDALONE_MODE") != "true":
        return {"status": "ignored", "message": "Endpoint only available in Standalone mode."}
        
    mongo = MongoDBService()
    
    # Store objects in Mock DB
    for obj in payload.objects:
        await mongo.create_stix(obj)
        
    return {"status": "success", "injected": len(payload.objects)}
