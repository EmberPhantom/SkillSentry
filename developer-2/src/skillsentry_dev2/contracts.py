"""
Shared contracts, constants, and data structures for the SkillSentry
Skill Analysis subsystem (Developer 2).

These definitions mirror the project-wide contracts frozen at Milestone M0.
Source of truth: docs/02-architecture.md, docs/03-database.md, docs/05-api-reference.md,
                 docs/11-team-and-workload.md §11.6.

Developer 2 does NOT own the shared contract module in the parent repository.
These are local copies for isolated development; the real integration will
import from skillsentry.core.contracts once Dev 1 delivers CL-D1-1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


# ── Canonical Enums (frozen at M0) ──────────────────────────────────────

STAGES: tuple[str, ...] = (
    "cache",
    "spec",
    "typosquat",
    "deterministicAnchor",
    "semantic",
    "vision",
    "sandbox",
    "poisonedWell",
    "evasion",
    "verdict",
)

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical", "note")

VERDICTS: tuple[str, ...] = ("SAFE", "SUSPICIOUS", "MALICIOUS")

# Declared-intent normalization vocabulary (INT-1)
LEGAL_INTENT_KEYWORDS: frozenset[str] = frozenset({
    "aws", "cloud", "github", "slack", "ssh", "devops", "generic",
})

# Model backend identifiers
MODEL_BACKENDS: tuple[str, ...] = ("ollama", "gemini-api", "demo")


# ── Data Contracts ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Finding:
    """A single analysis finding emitted by a pipeline stage.

    Matches the findings table schema in docs/03-database.md and the
    Verdict JSON Contract v1 in docs/05-api-reference.md §5.5.
    """
    stage: str
    severity: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence_json: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ValueError(f"Invalid stage: {self.stage!r}; must be one of {STAGES}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity!r}; must be one of {SEVERITIES}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the Verdict JSON finding shape."""
        d: dict[str, Any] = {
            "stage": self.stage,
            "severity": self.severity,
            "message": self.message,
        }
        evidence: dict[str, Any] = {}
        if self.file is not None:
            evidence["file"] = self.file
        if self.line is not None:
            evidence["line"] = self.line
        if self.evidence_json:
            evidence.update(self.evidence_json)
        if evidence:
            d["evidence"] = evidence
        return d


@dataclass
class StageResult:
    """Result emitted by each Dev 2 analysis stage.

    Consumed by Dev 1's pipeline orchestrator and verdict fusion engine.
    Interface I3 per docs/11-team-and-workload.md §11.6.
    """
    stage: str
    findings: list[Finding] = field(default_factory=list)
    signals: dict[str, float] = field(default_factory=dict)
    sandbox_instructions: list[Any] = field(default_factory=list)
    telemetry: Optional[dict[str, Any]] = None
    degraded: bool = False

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ValueError(f"Invalid stage: {self.stage!r}")


# ── Package Manifest ────────────────────────────────────────────────────

@dataclass
class ScriptFile:
    """A code file within a skill package."""
    relative_path: str          # POSIX-normalized relative path
    lines: list[str]            # Raw lines (preserving originals)
    size_bytes: int
    content_hash: str           # SHA-256 hex of the file content
    truncated: bool = False     # True if file exceeded size cap


@dataclass
class AssetFile:
    """A non-code asset (image, data file) within a skill package."""
    relative_path: str
    mime_type: str
    size_bytes: int
    content_hash: str


@dataclass
class PackageManifest:
    """Complete parsed inventory of a skill package.

    Constructed once in Stage 1 and shared in-memory across all
    downstream stages (AST scan, semantic prompt, vision extraction,
    sandbox mount specification).
    """
    name: str
    description: str
    trigger_keywords: list[str]
    canonical_root_posix: str
    scripts: dict[str, ScriptFile] = field(default_factory=dict)
    assets: dict[str, AssetFile] = field(default_factory=dict)
    total_size_bytes: int = 0
    raw_frontmatter: Optional[dict[str, Any]] = None


# ── Model Client Protocol (Interface I2) ────────────────────────────────

@runtime_checkable
class ModelClient(Protocol):
    """Typed protocol for Dev 1's model client.

    Dev 2 consumes this interface; Dev 1 produces it.
    Source: docs/11-team-and-workload.md §11.6.
    """

    @property
    def model_version(self) -> str:
        """Canonical model version string (e.g. 'gemma4:e4b-q4').
        Required for Stage 0 cache invalidation."""
        ...

    @property
    def backend_name(self) -> str:
        """Returns 'ollama' | 'gemini-api' | 'demo'."""
        ...

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
        retries: int = 1,
    ) -> dict[str, Any]:
        """Submit structured prompt and return validated JSON output.
        Raises ModelUnavailableError on connection failure."""
        ...

    def analyze_image(
        self,
        image_path: str,
        prompt: str,
    ) -> dict[str, Any]:
        """Perform multimodal vision OCR and instruction detection.
        Returns dict with keys: 'ocr', 'bboxes', 'findings'."""
        ...


class ModelUnavailableError(Exception):
    """Raised when the model backend is unreachable."""
    pass


# ── Sandbox Action Instruction (Interface INT-4) ────────────────────────

@dataclass(frozen=True)
class SandboxActionInstruction:
    """Structured instruction for Dev 1's Stage 4 Docker sandbox.

    Produced by Dev 2's sandbox_instructions.py; consumed by Dev 1's
    sandbox/runner.py and context_honeypot.py.
    Interface INT-4 per developer-2/04-interfaces-and-contracts.md.
    """
    instruction_id: str
    finding_id: Optional[str]
    target_package: str
    entrypoint_script: str
    reason: str
    check_category: str     # TRIGGER_EXECUTION | CREDENTIAL_CANARY_MONITOR |
                            # DNS_SINKHOLE_WATCH | HTTP_EXFIL_MONITOR | EVASION_PROBE_WATCH
    contextual_intent: list[str] = field(default_factory=list)
    execution_parameters: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)
    check_status: str = "required"  # required | optional | blocked | unsupported
    status_notes: Optional[str] = None

    VALID_CATEGORIES: frozenset[str] = frozenset({
        "TRIGGER_EXECUTION",
        "CREDENTIAL_CANARY_MONITOR",
        "DNS_SINKHOLE_WATCH",
        "HTTP_EXFIL_MONITOR",
        "EVASION_PROBE_WATCH",
    })

    VALID_STATUSES: frozenset[str] = frozenset({
        "required", "optional", "blocked", "unsupported",
    })

    def __post_init__(self) -> None:
        if self.check_category not in self.VALID_CATEGORIES:
            raise ValueError(f"Invalid check_category: {self.check_category!r}")
        if self.check_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid check_status: {self.check_status!r}")

