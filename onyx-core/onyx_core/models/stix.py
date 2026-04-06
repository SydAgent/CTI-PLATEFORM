"""
ONYX CTI — STIX 2.1 Base Models
Implements the STIX 2.1 specification as Pydantic v2 models with full validation.
Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

Design decisions:
- All models inherit from STIXBase which enforces the id format (type--uuid4).
- Timestamps are always UTC-aware datetime objects.
- Confidence is normalized to 0-100 scale (STIX 2.1 §4.14).
- orjson is used for high-performance serialization.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import orjson
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _utcnow() -> datetime:
    """Return timezone-aware UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def _generate_stix_id(stix_type: str) -> str:
    """Generate a STIX 2.1 compliant identifier: type--uuid4."""
    return f"{stix_type}--{uuid.uuid4()}"


def _orjson_dumps(v: Any, *, default: Any) -> str:
    """High-performance JSON serialization via orjson."""
    return orjson.dumps(v, default=default).decode()


# ============================================================================
# Enumerations
# ============================================================================

class TLPMarking(str, Enum):
    """Traffic Light Protocol v2.0 markings."""
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


class STIXObjectType(str, Enum):
    """All STIX 2.1 Domain Object types."""
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    COURSE_OF_ACTION = "course-of-action"
    GROUPING = "grouping"
    IDENTITY = "identity"
    INDICATOR = "indicator"
    INFRASTRUCTURE = "infrastructure"
    INTRUSION_SET = "intrusion-set"
    LOCATION = "location"
    MALWARE = "malware"
    MALWARE_ANALYSIS = "malware-analysis"
    NOTE = "note"
    OBSERVED_DATA = "observed-data"
    OPINION = "opinion"
    REPORT = "report"
    THREAT_ACTOR = "threat-actor"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class RelationshipType(str, Enum):
    """Common STIX 2.1 Relationship types."""
    USES = "uses"
    TARGETS = "targets"
    INDICATES = "indicates"
    MITIGATES = "mitigates"
    ATTRIBUTED_TO = "attributed-to"
    DELIVERS = "delivers"
    DROPS = "drops"
    EXPLOITS = "exploits"
    VARIANT_OF = "variant-of"
    COMPROMISES = "compromises"
    ORIGINATES_FROM = "originates-from"
    INVESTIGATES = "investigates"
    BASED_ON = "based-on"
    COMMUNICATES_WITH = "communicates-with"
    CONSISTS_OF = "consists-of"
    CONTROLS = "controls"
    HAS = "has"
    HOSTS = "hosts"
    OWNS = "owns"
    AUTHORED_BY = "authored-by"
    BEACONS_TO = "beacons-to"
    EXFILTRATES_TO = "exfiltrates-to"


class PatternType(str, Enum):
    """Indicator pattern languages supported."""
    STIX = "stix"
    SNORT = "snort"
    SIGMA = "sigma"
    YARA = "yara"
    PCRE = "pcre"


class ThreatActorSophistication(str, Enum):
    """STIX 2.1 Threat Actor sophistication levels (§4.17)."""
    NONE = "none"
    MINIMAL = "minimal"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    INNOVATOR = "innovator"
    STRATEGIC = "strategic"


class MalwareType(str, Enum):
    """Common malware type vocabulary."""
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    WORM = "worm"
    ROOTKIT = "rootkit"
    SPYWARE = "spyware"
    ADWARE = "adware"
    KEYLOGGER = "keylogger"
    RAT = "remote-access-trojan"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    BOTNET = "botnet"
    EXPLOIT_KIT = "exploit-kit"
    WEBSHELL = "webshell"
    WIPER = "wiper"
    INFOSTEALER = "infostealer"
    CRYPTOMINER = "cryptominer"
    LOADER = "loader"
    UNKNOWN = "unknown"


# ============================================================================
# External Reference Model
# ============================================================================

class ExternalReference(BaseModel):
    """STIX 2.1 External Reference (§2.10)."""

    model_config = ConfigDict(populate_by_name=True)

    source_name: str = Field(..., min_length=1, description="Name of the external source")
    description: str | None = Field(default=None)
    url: str | None = Field(default=None)
    external_id: str | None = Field(default=None, description="External identifier (e.g., CVE-2024-XXXX)")
    hashes: dict[str, str] | None = Field(default=None, description="File hashes if applicable")


class KillChainPhase(BaseModel):
    """STIX 2.1 Kill Chain Phase (§2.11)."""

    kill_chain_name: str = Field(..., description="Name of the kill chain (e.g., 'mitre-attack')")
    phase_name: str = Field(..., description="Phase within the kill chain (e.g., 'initial-access')")


class GranularMarking(BaseModel):
    """STIX 2.1 Granular Marking (§2.14)."""

    marking_ref: str = Field(..., description="Reference to marking-definition object")
    selectors: list[str] = Field(..., description="STIX property selectors this marking applies to")


# ============================================================================
# STIX Base Model — All SDOs/SROs inherit from this
# ============================================================================

class STIXBase(BaseModel):
    """
    Base model for all STIX 2.1 objects.
    Enforces id format, timestamps, versioning, and marking controls.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={datetime: lambda v: v.isoformat()},
        ser_json_bytes="base64",
        str_strip_whitespace=True,
    )

    id: str = Field(
        ...,
        description="STIX 2.1 identifier in format: type--uuid4",
        pattern=r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    type: str = Field(..., description="STIX object type")
    spec_version: str = Field(default="2.1", description="STIX specification version")
    created: datetime = Field(default_factory=_utcnow, description="Creation timestamp (UTC)")
    modified: datetime = Field(default_factory=_utcnow, description="Last modification timestamp (UTC)")
    created_by_ref: str | None = Field(
        default=None,
        description="STIX ID of the identity that created this object",
    )
    revoked: bool = Field(default=False, description="Whether this object has been revoked")
    confidence: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Confidence level (0-100, STIX §4.14)",
    )
    lang: str | None = Field(default=None, description="Language of the object content (RFC 5646)")
    labels: list[str] = Field(default_factory=list, description="Open vocabulary labels")
    external_references: list[ExternalReference] = Field(
        default_factory=list,
        description="External references (CVEs, URLs, etc.)",
    )
    object_marking_refs: list[str] = Field(
        default_factory=list,
        description="TLP and other marking definition references",
    )
    granular_markings: list[GranularMarking] = Field(
        default_factory=list,
        description="Property-level markings",
    )

    # ONYX-specific extensions (not part of STIX spec)
    onyx_source: str | None = Field(
        default=None,
        description="ONYX data source identifier (crawler, feed, manual)",
    )
    onyx_tags: list[str] = Field(
        default_factory=list,
        description="ONYX platform tags for internal categorization",
    )

    @field_validator("created", "modified", mode="before")
    @classmethod
    def ensure_utc_datetime(cls, v: Any) -> datetime:
        """Ensure all timestamps are UTC-aware."""
        if isinstance(v, str):
            from dateutil.parser import isoparse
            v = isoparse(v)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        raise ValueError(f"Cannot parse datetime from: {v}")

    @model_validator(mode="after")
    def validate_id_matches_type(self) -> "STIXBase":
        """Ensure the id prefix matches the object type."""
        if not self.id.startswith(f"{self.type}--"):
            raise ValueError(
                f"STIX id prefix '{self.id.split('--')[0]}' does not match type '{self.type}'"
            )
        return self


# ============================================================================
# STIX Domain Objects (SDOs)
# ============================================================================

class ThreatActor(STIXBase):
    """STIX 2.1 Threat Actor SDO (§4.17)."""

    type: str = Field(default="threat-actor", frozen=True)
    name: str = Field(..., min_length=1, description="Primary name of the threat actor")
    description: str | None = Field(default=None, description="Detailed description")
    aliases: list[str] = Field(default_factory=list, description="Alternative names")
    first_seen: datetime | None = Field(default=None, description="First observed activity")
    last_seen: datetime | None = Field(default=None, description="Most recent observed activity")
    roles: list[str] = Field(default_factory=list, description="Roles (e.g., 'agent', 'director')")
    goals: list[str] = Field(default_factory=list, description="High-level goals")
    sophistication: ThreatActorSophistication | None = Field(
        default=None, description="Sophistication level"
    )
    resource_level: str | None = Field(default=None, description="Resource level")
    primary_motivation: str | None = Field(default=None, description="Primary motivation")
    secondary_motivations: list[str] = Field(default_factory=list)
    personal_motivations: list[str] = Field(default_factory=list)

    # ONYX extensions
    country_of_origin: str | None = Field(default=None, description="ISO 3166-1 alpha-2 country code")
    targeted_sectors: list[str] = Field(default_factory=list, description="Targeted industry sectors")
    targeted_countries: list[str] = Field(default_factory=list, description="Targeted country codes")
    ttps: list[str] = Field(default_factory=list, description="Associated ATT&CK technique IDs")


class Malware(STIXBase):
    """STIX 2.1 Malware SDO (§4.9)."""

    type: str = Field(default="malware", frozen=True)
    name: str = Field(..., min_length=1, description="Malware family name")
    description: str | None = Field(default=None)
    malware_types: list[MalwareType] = Field(
        default_factory=list, description="Categorization of the malware"
    )
    is_family: bool = Field(
        default=True, description="True if this represents a malware family, False for a specific instance"
    )
    aliases: list[str] = Field(default_factory=list)
    first_seen: datetime | None = Field(default=None)
    last_seen: datetime | None = Field(default=None)
    operating_system_refs: list[str] = Field(default_factory=list)
    architecture_execution_envs: list[str] = Field(default_factory=list)
    implementation_languages: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)
    sample_refs: list[str] = Field(default_factory=list, description="References to observed file samples")


class Indicator(STIXBase):
    """STIX 2.1 Indicator SDO (§4.7)."""

    type: str = Field(default="indicator", frozen=True)
    name: str | None = Field(default=None, description="Human-readable indicator name")
    description: str | None = Field(default=None)
    indicator_types: list[str] = Field(
        default_factory=list,
        description="Indicator type vocabulary (e.g., 'malicious-activity', 'compromised')",
    )
    pattern: str = Field(..., description="Detection pattern in specified pattern_type language")
    pattern_type: PatternType = Field(
        default=PatternType.STIX, description="Pattern language used"
    )
    pattern_version: str | None = Field(default=None, description="Pattern language version")
    valid_from: datetime = Field(
        default_factory=_utcnow, description="Start of indicator validity window"
    )
    valid_until: datetime | None = Field(
        default=None, description="End of indicator validity window"
    )
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)

    # ONYX extensions for IOC enrichment
    ioc_type: str | None = Field(
        default=None,
        description="Simplified IOC type (ipv4, ipv6, domain, url, md5, sha1, sha256, email, cve)",
    )
    ioc_value: str | None = Field(default=None, description="Raw IOC value for fast lookup")
    severity: str | None = Field(default=None, description="Severity: critical/high/medium/low/info")
    mitre_techniques: list[str] = Field(
        default_factory=list, description="ATT&CK technique IDs (e.g., T1566.001)"
    )


class Campaign(STIXBase):
    """STIX 2.1 Campaign SDO (§4.2)."""

    type: str = Field(default="campaign", frozen=True)
    name: str = Field(..., min_length=1)
    description: str | None = Field(default=None)
    aliases: list[str] = Field(default_factory=list)
    first_seen: datetime | None = Field(default=None)
    last_seen: datetime | None = Field(default=None)
    objective: str | None = Field(default=None, description="Campaign objective")


class AttackPattern(STIXBase):
    """STIX 2.1 Attack Pattern SDO (§4.1) — Maps to ATT&CK Techniques."""

    type: str = Field(default="attack-pattern", frozen=True)
    name: str = Field(..., min_length=1)
    description: str | None = Field(default=None)
    aliases: list[str] = Field(default_factory=list)
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)

    # ONYX extensions for ATT&CK integration
    mitre_id: str | None = Field(
        default=None,
        description="ATT&CK technique ID (e.g., T1566)",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    tactic: str | None = Field(default=None, description="ATT&CK tactic name")
    platforms: list[str] = Field(default_factory=list, description="Targeted platforms")
    detection: str | None = Field(default=None, description="Detection guidance")


class IntrusionSet(STIXBase):
    """STIX 2.1 Intrusion Set SDO (§4.8) — APT groups."""

    type: str = Field(default="intrusion-set", frozen=True)
    name: str = Field(..., min_length=1)
    description: str | None = Field(default=None)
    aliases: list[str] = Field(default_factory=list)
    first_seen: datetime | None = Field(default=None)
    last_seen: datetime | None = Field(default=None)
    goals: list[str] = Field(default_factory=list)
    resource_level: str | None = Field(default=None)
    primary_motivation: str | None = Field(default=None)
    secondary_motivations: list[str] = Field(default_factory=list)


class Vulnerability(STIXBase):
    """STIX 2.1 Vulnerability SDO (§4.18)."""

    type: str = Field(default="vulnerability", frozen=True)
    name: str = Field(..., min_length=1, description="CVE identifier or vulnerability name")
    description: str | None = Field(default=None)

    # ONYX extensions
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0, description="CVSS v3.1 score")
    cvss_vector: str | None = Field(default=None, description="CVSS vector string")
    cwe_id: str | None = Field(default=None, description="CWE identifier")
    affected_products: list[str] = Field(default_factory=list, description="CPE strings of affected products")
    exploit_available: bool = Field(default=False, description="Whether a public exploit exists")
    patch_available: bool = Field(default=False, description="Whether a patch is available")


class Report(STIXBase):
    """STIX 2.1 Report SDO (§4.15) — Intelligence reports."""

    type: str = Field(default="report", frozen=True)
    name: str = Field(..., min_length=1, description="Report title")
    description: str | None = Field(default=None)
    report_types: list[str] = Field(
        default_factory=list,
        description="Type vocabulary (threat-report, attack-pattern, campaign, etc.)",
    )
    published: datetime = Field(default_factory=_utcnow, description="Publication date")
    object_refs: list[str] = Field(
        default_factory=list,
        description="References to STIX objects described in this report",
    )

    # ONYX extensions
    source_url: str | None = Field(default=None, description="Original source URL")
    raw_content: str | None = Field(default=None, description="Raw crawled text content")
    processed: bool = Field(default=False, description="Whether NLP processing is complete")


class Identity(STIXBase):
    """STIX 2.1 Identity SDO (§4.6) — Represents organizations, individuals."""

    type: str = Field(default="identity", frozen=True)
    name: str = Field(..., min_length=1)
    description: str | None = Field(default=None)
    identity_class: str | None = Field(
        default=None,
        description="Identity class: individual, group, system, organization, class, unknown",
    )
    sectors: list[str] = Field(default_factory=list, description="Industry sectors")
    contact_information: str | None = Field(default=None)
    roles: list[str] = Field(default_factory=list)


class Location(STIXBase):
    """STIX 2.1 Location SDO (§4.8.1)."""

    type: str = Field(default="location", frozen=True)
    name: str | None = Field(default=None)
    description: str | None = Field(default=None)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    precision: float | None = Field(default=None, description="Precision in meters")
    region: str | None = Field(default=None, description="UN M.49 region code")
    country: str | None = Field(default=None, description="ISO 3166-1 alpha-2 code")
    administrative_area: str | None = Field(default=None)
    city: str | None = Field(default=None)
    postal_code: str | None = Field(default=None)


# ============================================================================
# STIX Relationship Objects (SROs)
# ============================================================================

class Relationship(STIXBase):
    """STIX 2.1 Relationship SRO (§5.1) — Links two SDOs."""

    type: str = Field(default="relationship", frozen=True)
    relationship_type: str = Field(
        ..., description="Relationship type (uses, targets, indicates, etc.)"
    )
    description: str | None = Field(default=None)
    source_ref: str = Field(
        ...,
        description="STIX ID of the source object",
        pattern=r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    target_ref: str = Field(
        ...,
        description="STIX ID of the target object",
        pattern=r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    start_time: datetime | None = Field(default=None, description="Relationship start time")
    stop_time: datetime | None = Field(default=None, description="Relationship end time")


class Sighting(STIXBase):
    """STIX 2.1 Sighting SRO (§5.2) — Evidence of observation."""

    type: str = Field(default="sighting", frozen=True)
    description: str | None = Field(default=None)
    first_seen: datetime | None = Field(default=None)
    last_seen: datetime | None = Field(default=None)
    count: int | None = Field(default=None, ge=0, description="Number of times sighted")
    sighting_of_ref: str = Field(
        ...,
        description="STIX ID of the observed object (typically an Indicator)",
        pattern=r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    observed_data_refs: list[str] = Field(
        default_factory=list, description="References to observed-data objects"
    )
    where_sighted_refs: list[str] = Field(
        default_factory=list, description="Identities where the sighting occurred"
    )
    summary: bool = Field(
        default=False, description="Whether this is a summary sighting (count-only)"
    )


# ============================================================================
# STIX Bundle — Container for multiple STIX objects
# ============================================================================

class STIXBundle(BaseModel):
    """STIX 2.1 Bundle (§6.1) — Collection of STIX objects for transport."""

    model_config = ConfigDict(populate_by_name=True)

    type: str = Field(default="bundle", frozen=True)
    id: str = Field(
        default_factory=lambda: f"bundle--{uuid.uuid4()}",
        description="Bundle identifier",
    )
    objects: list[STIXBase] = Field(
        default_factory=list, description="STIX objects contained in this bundle"
    )


# ============================================================================
# Factory Functions
# ============================================================================

# Maps STIX type strings to their Pydantic model classes
STIX_TYPE_MAP: dict[str, type[STIXBase]] = {
    "threat-actor": ThreatActor,
    "malware": Malware,
    "indicator": Indicator,
    "campaign": Campaign,
    "attack-pattern": AttackPattern,
    "intrusion-set": IntrusionSet,
    "vulnerability": Vulnerability,
    "report": Report,
    "identity": Identity,
    "location": Location,
    "relationship": Relationship,
    "sighting": Sighting,
}


def create_stix_object(data: dict[str, Any]) -> STIXBase:
    """
    Factory function to create the correct STIX model from a dictionary.
    Dispatches based on the 'type' field in the input data.

    Args:
        data: Dictionary containing STIX object data with required 'type' field.

    Returns:
        Validated STIX model instance.

    Raises:
        ValueError: If the 'type' field is missing or unrecognized.
    """
    stix_type = data.get("type")
    if not stix_type:
        raise ValueError("STIX data must contain a 'type' field")

    model_class = STIX_TYPE_MAP.get(stix_type)
    if not model_class:
        raise ValueError(f"Unsupported STIX type: {stix_type}")

    return model_class.model_validate(data)


def new_threat_actor(name: str, **kwargs: Any) -> ThreatActor:
    """Create a new ThreatActor with auto-generated STIX ID."""
    return ThreatActor(
        id=_generate_stix_id("threat-actor"),
        name=name,
        **kwargs,
    )


def new_malware(name: str, **kwargs: Any) -> Malware:
    """Create a new Malware with auto-generated STIX ID."""
    return Malware(id=_generate_stix_id("malware"), name=name, **kwargs)


def new_indicator(pattern: str, **kwargs: Any) -> Indicator:
    """Create a new Indicator with auto-generated STIX ID."""
    return Indicator(id=_generate_stix_id("indicator"), pattern=pattern, **kwargs)


def new_relationship(
    source_ref: str,
    relationship_type: str,
    target_ref: str,
    **kwargs: Any,
) -> Relationship:
    """Create a new Relationship with auto-generated STIX ID."""
    return Relationship(
        id=_generate_stix_id("relationship"),
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        **kwargs,
    )
