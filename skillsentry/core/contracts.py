"""Frozen SkillSentry contracts (I1) and pipeline interface (I3).

This module is the **single source of truth** for:

* pipeline stage identifiers and their exact JSON spellings;
* verdict tiers, severities, WS event names, exfil channels, canary contexts;
* the Verdict JSON Contract v1 (FROZEN at M0 — additive changes only);
* the request/response models used by the REST/WS API;
* the ``StageResult`` returned by every analysis stage;
* the tab payloads consumed by the Triage Dashboard.

Python field names are snake_case; API responses are serialised in camelCase
by ``APIModel``.  ``POST /scan`` request bodies intentionally stay snake_case
because that is what docs/05-api-reference.md §5.2 specifies.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
)
from pydantic.alias_generators import to_camel


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    """Timezone-aware UTC now (never the deprecated ``utcnow``)."""
    return datetime.now(UTC)


def format_utc(value: datetime) -> str:
    """ISO-8601 UTC with milliseconds and a literal ``Z`` suffix (§5.1)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


UtcDatetime = Annotated[datetime, PlainSerializer(format_utc, return_type=str)]


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class VerdictTier(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NOTE = "note"

    @property
    def rank(self) -> int:
        return {
            Severity.NOTE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Stage(str, Enum):
    """Canonical pipeline stage identifiers (docs/05 §5.4)."""

    CACHE = "cache"
    SPEC = "spec"
    TYPOSQUAT = "typosquat"
    DETERMINISTIC_ANCHOR = "deterministicAnchor"
    SEMANTIC = "semantic"
    VISION = "vision"
    SANDBOX = "sandbox"
    POISONED_WELL = "poisonedWell"
    EVASION = "evasion"
    VERDICT = "verdict"


class WSEventType(str, Enum):
    STARTED = "started"
    PROGRESS = "progress"
    FINDING = "finding"
    OVERRIDE = "override"
    COMPLETED = "completed"
    ERROR = "error"
    CACHED = "cached"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CACHED_HIT = "cached-hit"


class ExfilChannel(str, Enum):
    DNS_TUNNELING = "DNS_TUNNELING"
    HTTP_POST = "HTTP_POST"
    RAW_SOCKET = "RAW_SOCKET"


class ContextCanary(str, Enum):
    AWS = "AWS"
    GITHUB = "GITHUB"
    SLACK = "SLACK"
    SSH = "SSH"
    GENERIC = "GENERIC"


class Backend(str, Enum):
    AUTO = "auto"
    LOCAL = "local"
    CLOUD = "cloud"
    DEMO = "demo"


class ExportFormat(str, Enum):
    SARIF = "sarif"
    MARKDOWN = "markdown"
    STIX = "stix"


HealthStatus = Literal["ok", "down"]


# ---------------------------------------------------------------------------
# Base models
# ---------------------------------------------------------------------------
class APIModel(BaseModel):
    """Response model: camelCase on the wire, snake_case in Python."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        use_enum_values=False,
    )


class RequestModel(BaseModel):
    """Request model: field names exactly as documented (snake_case)."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


# ---------------------------------------------------------------------------
# Findings + active defense (Verdict Contract v1)
# ---------------------------------------------------------------------------
class FindingEvidence(APIModel):
    """Free-form evidence.  Common keys are typed; extras are preserved."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
    )

    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    code: str | None = None
    c2: str | None = None
    marker: str | None = None
    bbox: list[float] | None = None
    ocr: str | None = None
    process: str | None = None
    path: str | None = None
    channel: str | None = None
    url: str | None = None
    domain: str | None = None
    ip: str | None = None


class Finding(APIModel):
    stage: Stage
    severity: Severity
    message: str
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    # Additive field required by SARIF ruleId = skillsentry/<stage>/<type> (§5.6).
    finding_type: str | None = Field(default=None, alias="type")


class ActiveDefense(APIModel):
    triggered: bool = False
    targeted_assets: list[str] = Field(default_factory=list)
    exfil_channel: ExfilChannel | None = None
    canary_marker: str | None = None
    secondary_canary: str | None = None
    c2_indicators: list[str] = Field(default_factory=list)
    encoding: str | None = None
    sandbox_evasion_detected: bool = False
    declared_intent: str | None = None
    context_aware_canary: ContextCanary | None = None
    # Present in the SARIF extension (§5.6) — additive to the verdict block.
    actual_behavior: str | None = None
    ioc_export: str | None = None


class Verdict(APIModel):
    """Verdict JSON Contract v1 (FROZEN).

    ``skillId`` / ``scanId`` are additive fields agreed before the M0 freeze so
    ``GET /skills/{skill_id}`` is addressable for folder-of-skills scans.
    """

    skill: str
    skill_id: UUID
    scan_id: UUID
    verdict: VerdictTier
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    cached: bool
    scan_duration_ms: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list)
    active_defense: ActiveDefense | None = None

    @property
    def key_finding(self) -> Finding | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank)


# ---------------------------------------------------------------------------
# Pipeline interface I3
# ---------------------------------------------------------------------------
class OverrideSignal(APIModel):
    """Hard evidence that overrides weighted fusion."""

    verdict: VerdictTier = VerdictTier.MALICIOUS
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str
    source: Stage
    evidence: dict[str, Any] = Field(default_factory=dict)


class StageResult(APIModel):
    """Result returned by every stage (interface I3).

    ``signals`` keys consumed by fusion: ``anchors``, ``semantic``, ``vision``,
    ``sandbox`` and ``typosquat``.  Values are normalised 0-100.
    """

    stage: Stage
    findings: list[Finding] = Field(default_factory=list)
    signals: dict[str, float] = Field(default_factory=dict)
    telemetry: dict[str, Any] | None = None
    override: OverrideSignal | None = None
    degraded: bool = False
    error: str | None = None

    @field_validator("signals")
    @classmethod
    def _normalise_signals(cls, value: dict[str, float]) -> dict[str, float]:
        normalised: dict[str, float] = {}
        for key, raw in value.items():
            score = float(raw)
            if score != score:  # NaN
                score = 0.0
            normalised[key] = max(0.0, min(100.0, score))
        return normalised


# ---------------------------------------------------------------------------
# REST request / response models
# ---------------------------------------------------------------------------
class ScanOptions(RequestModel):
    no_cache: bool = False
    backend: Backend = Backend.AUTO
    sandbox: bool = True
    poisoned_well: bool = True
    timeout_s: int = Field(default=60, ge=5, le=600)


class ScanRequest(RequestModel):
    # Optional in demo mode ("Scan All" on the canned store); required live.
    path: str | None = None
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanStartResponse(APIModel):
    scan_id: UUID
    status: ScanStatus = ScanStatus.QUEUED
    stream: str


class ScanStatusResponse(APIModel):
    scan_id: UUID
    status: ScanStatus
    stage: Stage | None = None
    skill: str | None = None
    started_at: UtcDatetime
    elapsed_ms: int | None = None
    error: str | None = None


class VerdictsResponse(APIModel):
    scan_id: UUID
    verdicts: list[Verdict] = Field(default_factory=list)


class ScanSummary(APIModel):
    scan_id: UUID
    skill_id: UUID
    skill: str
    verdict: VerdictTier | None = None
    risk_score: int | None = None
    cached: bool = False
    status: ScanStatus
    started_at: UtcDatetime
    duration_ms: int | None = None
    key_finding: str | None = None


class ScanListResponse(APIModel):
    scans: list[ScanSummary] = Field(default_factory=list)


class CacheStatsResponse(APIModel):
    entries: int
    hit_rate: float
    db_size_bytes: int
    engine_version: str
    model_version: str


class DeleteCacheResponse(APIModel):
    deleted: int
    retained: int = 0


class HealthResponse(APIModel):
    ollama: HealthStatus
    docker: HealthStatus
    db: HealthStatus
    demo_mode: bool = False


class MetaResponse(APIModel):
    version: str
    backend_active: str
    gemma_badge: str
    demo_mode: bool
    contract_version: str


class ErrorDetail(APIModel):
    code: str
    message: str
    stage: Stage | None = None
    degraded: bool = False
    scan_id: UUID | None = None


class ErrorResponse(APIModel):
    error: ErrorDetail


# ---------------------------------------------------------------------------
# WebSocket message
# ---------------------------------------------------------------------------
class WSMessage(APIModel):
    stage: Stage
    skill: str
    event: WSEventType
    ts: UtcDatetime
    detail: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Skill-detail tab payloads (I5)
# ---------------------------------------------------------------------------
class StaticFinding(APIModel):
    file: str
    line: int = Field(ge=1)
    code: str | None = None
    stage: Stage
    severity: Severity
    message: str
    anchor: bool = False
    highlight: bool = True


class VisionEvidence(APIModel):
    image: str
    image_name: str | None = None
    ocr: str
    bboxes: list[list[float]] = Field(default_factory=list)
    view_modes: list[str] = Field(default_factory=lambda: ["normal", "contrast", "gemma-eye"])
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    position_note: str | None = None
    findings: list[Finding] = Field(default_factory=list)


class SandboxEvent(APIModel):
    ts: UtcDatetime
    event_type: str
    path_or_channel: str | None = None
    marker: str | None = None
    process: str | None = None
    detail: dict[str, Any] | None = None


class NetLog(APIModel):
    ts: UtcDatetime
    protocol: Literal["dns", "http"]
    query_or_url: str
    body_b64: str | None = None
    responder_action: str | None = None


class SandboxTrace(APIModel):
    events: list[SandboxEvent] = Field(default_factory=list)
    net_logs: list[NetLog] = Field(default_factory=list)
    resource_usage: dict[str, Any] | None = None


class TimelineRow(APIModel):
    ts: UtcDatetime
    label: str
    kind: str
    marker: str | None = None
    detail: dict[str, Any] | None = None


class IOCGraphNode(APIModel):
    id: str
    label: str
    kind: str
    evidence: dict[str, Any] | None = None


class IOCGraphEdge(APIModel):
    source: str
    target: str
    label: str


class IOCGraph(APIModel):
    nodes: list[IOCGraphNode] = Field(default_factory=list)
    edges: list[IOCGraphEdge] = Field(default_factory=list)


class PoisonedWellView(APIModel):
    active_defense: ActiveDefense | None = None
    timeline: list[TimelineRow] = Field(default_factory=list)
    graph: IOCGraph = Field(default_factory=IOCGraph)
    confirmed: bool = False


class ReportLinks(APIModel):
    sarif: str | None = None
    markdown: str | None = None
    stix: str | None = None


class SkillDetail(APIModel):
    verdict: Verdict
    static_findings: list[StaticFinding] = Field(default_factory=list)
    vision_evidence: list[VisionEvidence] = Field(default_factory=list)
    sandbox_trace: SandboxTrace = Field(default_factory=SandboxTrace)
    poisoned_well: PoisonedWellView = Field(default_factory=PoisonedWellView)
    report_links: ReportLinks = Field(default_factory=ReportLinks)


# ---------------------------------------------------------------------------
# Model-client helper models (interface I2)
# ---------------------------------------------------------------------------
class ImageAnalysis(APIModel):
    ocr: str = ""
    bboxes: list[list[float]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)


class ModelInfo(APIModel):
    backend: str
    model_version: str
    available: bool = True
    detail: str | None = None


# ---------------------------------------------------------------------------
# Schema export + JSON helpers
# ---------------------------------------------------------------------------
SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "Verdict": Verdict,
    "SkillDetail": SkillDetail,
    "ScanRequest": ScanRequest,
    "ScanStartResponse": ScanStartResponse,
    "ScanStatusResponse": ScanStatusResponse,
    "VerdictsResponse": VerdictsResponse,
    "ScanSummary": ScanSummary,
    "ScanListResponse": ScanListResponse,
    "CacheStatsResponse": CacheStatsResponse,
    "HealthResponse": HealthResponse,
    "MetaResponse": MetaResponse,
    "ErrorResponse": ErrorResponse,
    "WSMessage": WSMessage,
    "StageResult": StageResult,
}


def export_json_schemas(directory: str | Path) -> dict[str, Path]:
    """Write the frozen Verdict schema plus the API model bundle.

    Dev 3 generates TypeScript types from these files; contract tests assert
    they are reproducible from ``contracts.py``.
    """
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    verdict_path = target / "verdict.v1.json"
    verdict_path.write_text(
        json.dumps(Verdict.model_json_schema(by_alias=True), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    written["verdict"] = verdict_path

    api_bundle = {
        name: model.model_json_schema(by_alias=True) for name, model in SCHEMA_MODELS.items()
    }
    api_path = target / "api.v1.json"
    api_path.write_text(json.dumps(api_bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written["api"] = api_path
    return written


def model_json(model: BaseModel) -> str:
    """Serialise a contract model with camelCase aliases."""
    return model.model_dump_json(by_alias=True, indent=2)
