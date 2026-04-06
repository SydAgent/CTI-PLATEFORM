"""
ONYX CTI — NLP Processing API Router
Exposes the NLP pipeline as REST endpoints for text analysis,
IOC extraction, and TTP mapping.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from onyx_nlp.extractors.ioc_extractor import IOCExtractor
from onyx_nlp.extractors.ttp_mapper import TTPMapper
from onyx_nlp.processors.pipeline import NLPPipeline

router = APIRouter()

# Singleton instances
_extractor = IOCExtractor(include_private_ips=False, include_defanged=True)
_mapper = TTPMapper(confidence_threshold=0.25)
_pipeline = NLPPipeline()


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500000)
    source: str = Field(default="manual")
    source_url: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    tlp: str = Field(default="TLP:GREEN")


class ExtractIOCsRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500000)
    source: str = Field(default="manual")
    include_private_ips: bool = Field(default=False)
    include_defanged: bool = Field(default=True)


class MapTTPsRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500000)


@router.post("/nlp/analyze", summary="Full NLP analysis pipeline")
async def analyze_text(request: AnalyzeRequest) -> dict[str, Any]:
    """
    Run the full NLP pipeline: IOC extraction + TTP mapping + STIX generation.
    Results are automatically indexed into Elasticsearch.
    """
    result = await _pipeline.process_text(
        text=request.text,
        source=request.source,
        source_url=request.source_url,
        tags=request.tags,
        tlp=request.tlp,
    )
    return result


@router.post("/nlp/extract-iocs", summary="Extract IOCs from text")
async def extract_iocs(request: ExtractIOCsRequest) -> dict[str, Any]:
    """
    Extract IOCs from text without indexing or TTP mapping.
    Useful for quick analysis and validation.
    """
    extractor = IOCExtractor(
        include_private_ips=request.include_private_ips,
        include_defanged=request.include_defanged,
    )
    result = extractor.extract(request.text, source=request.source)
    return {
        "total": result.total_iocs,
        "by_type": result.by_type,
        "iocs": [
            {"type": i.type, "value": i.value, "confidence": i.confidence,
             "context": i.context, "defanged": i.defanged}
            for i in result.iocs
        ],
        "processing_time_ms": result.processing_time_ms,
    }


@router.post("/nlp/map-ttps", summary="Map text to ATT&CK techniques")
async def map_ttps(request: MapTTPsRequest) -> dict[str, Any]:
    """
    Map text to MITRE ATT&CK techniques using keyword matching.
    SciBERT enhancement available when model is loaded.
    """
    result = _mapper.map_text(request.text)
    return {
        "total": len(result.techniques),
        "top_tactics": result.top_tactics,
        "techniques": [
            {"id": t.technique_id, "name": t.technique_name, "tactic": t.tactic,
             "confidence": t.confidence, "method": t.method}
            for t in result.techniques
        ],
        "model_used": result.model_used,
        "processing_time_ms": result.processing_time_ms,
    }
