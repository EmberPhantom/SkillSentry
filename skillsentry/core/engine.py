"""Live scan orchestrator.

This module is the single place where the stages are ordered.  It is
synchronous by design: the API runs it in a worker thread and streams the
``WSMessage`` callback into an asyncio queue, while the CLI calls it directly.
No demo/canned verdict path exists here; every field comes from the package,
the model, the sandbox, or an explicit degradation note.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4, uuid5

from skillsentry.core.cache import HashError, SQLiteStore
from skillsentry.core.cache.sqlite_store import StoreError
from skillsentry.core.config import SkillsEntryConfig, load_config
from skillsentry.core.contracts import (
    ActiveDefense,
    Finding,
    FindingEvidence,
    IOCGraph,
    IOCGraphEdge,
    IOCGraphNode,
    PoisonedWellView,
    SandboxTrace,
    ScanOptions,
    ScanStatus,
    Severity,
    SkillDetail,
    Stage,
    StageResult,
    StaticFinding,
    TimelineRow,
    Verdict,
    VisionEvidence,
    WSEventType,
    WSMessage,
    utc_now,
)
from skillsentry.core.decisions import (
    DecisionClient,
    DecisionSelection,
    DecisionUnavailable,
    select_decision_model,
)
from skillsentry.core.decisions.calibration import CalibrationError, load_calibration
from skillsentry.core.decisions.mapping import CAPABILITY_THRESHOLD
from skillsentry.core.evasion.detector import EvasionResult, detect_probes
from skillsentry.core.models.base import ModelClient, ModelError
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.models.selector import select_model
from skillsentry.core.parser import SkillPackage, SkillParseError, parse_skill
from skillsentry.core.parser.typosquat import TyposquatMatch, check_typosquat
from skillsentry.core.poisoned_well.attacker_profile import build_attacker_profile
from skillsentry.core.poisoned_well.canary_gen import (
    CanarySet,
    normalize_intent,
)
from skillsentry.core.poisoned_well.exfil_tracker import Correlation, ExfilTracker
from skillsentry.core.reports import render_report
from skillsentry.core.sandbox.masquerade import MasqueradeConfig
from skillsentry.core.sandbox.runner import (
    SandboxError,
    SandboxRequest,
    SandboxResult,
    SandboxRunner,
    SandboxUnavailable,
)
from skillsentry.core.sandbox.sidecar import SinkholeConfig, SinkholeSidecar
from skillsentry.core.semantic import analyze_semantics, scan_anchors
from skillsentry.core.semantic.laya_analyzer import (
    analyze_semantics_laya,
    degraded_semantic_stage,
    deterministic_only_stage,
)
from skillsentry.core.verdict.fusion import FusionError, FusionResult, fuse
from skillsentry.core.version import engine_version
from skillsentry.core.vision import scan_vision

SCAN_NAMESPACE = UUID("1b0f6d9e-3f7c-4a62-a2d8-2b9a0c6e5f41")
MAX_DISCOVERED_SKILLS = 500
_SKILL_STAGE_ORDER: tuple[Stage, ...] = (
    Stage.CACHE,
    Stage.SPEC,
    Stage.TYPOSQUAT,
    Stage.DETERMINISTIC_ANCHOR,
    Stage.SEMANTIC,
    Stage.VISION,
    Stage.SANDBOX,
    Stage.POISONED_WELL,
    Stage.EVASION,
    Stage.VERDICT,
)


class ScanError(RuntimeError):
    """A scan cannot continue; the caller must surface an error, not a verdict."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "scan_failed",
        stage: Stage | None = None,
        degraded: bool = True,
        status_code: int = 500,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.degraded = degraded
        self.status_code = status_code


class ScanCancelled(ScanError):
    def __init__(self, message: str = "cancelled by client") -> None:
        super().__init__(message, code="cancelled", stage=None, degraded=True, status_code=409)


@dataclass
class ScanOutcome:
    scan_id: UUID
    skill_id: UUID
    skill_name: str
    verdict: Verdict
    detail: SkillDetail
    stage_results: list[StageResult]
    cached: bool
    started_at: datetime
    duration_ms: int
    status: ScanStatus = ScanStatus.COMPLETED
    error: str | None = None


@dataclass
class _ScanContext:
    scan_id: UUID
    started_at: datetime
    started_monotonic: float
    package: SkillPackage
    options: ScanOptions
    skill_name: str
    skill_id: UUID
    cache_hit: bool = False
    stage_results: list[StageResult] = field(default_factory=list)
    sandbox_result: SandboxResult | None = None
    sandbox_skipped: bool = False
    canaries: CanarySet | None = None
    correlation: Correlation | None = None
    evasion: EvasionResult | None = None
    active: ActiveDefense | None = None
    trace: SandboxTrace = field(default_factory=SandboxTrace)
    vision_evidence: list[VisionEvidence] = field(default_factory=list)
    pw_view: PoisonedWellView = field(default_factory=PoisonedWellView)


ProgressCallback = Callable[[WSMessage], None]


class ScanEngine:
    """Content-addressed, fail-closed scan pipeline."""

    def __init__(
        self,
        config: SkillsEntryConfig | None = None,
        *,
        store: SQLiteStore | None = None,
        model: ModelClient | None = None,
        sandbox_runner: SandboxRunner | None = None,
        sandbox_runner_factory: Callable[[], SandboxRunner] | None = None,
        progress: ProgressCallback | None = None,
        decision_client: DecisionClient | None = None,
    ) -> None:
        self.config = config or load_config()
        self._owns_store = store is None
        self.store = store or SQLiteStore(self.config.db_path)
        self._model = model
        self._model_selected = model is not None
        self._model_error: str | None = None
        self._decision_client = decision_client
        self._decision: DecisionSelection | None = None
        self._sandbox_runner = sandbox_runner
        self._sandbox_runner_factory = sandbox_runner_factory
        self._progress = progress

    def close(self) -> None:
        if self._decision is not None and self._decision.client is not None:
            # Releases resident checkpoints; a no-op for clients without close().
            close = getattr(self._decision.client, "close", None)
            if callable(close):
                close()
            self._decision = None
        if self._owns_store:
            self.store.close()

    # -- discovery ---------------------------------------------------------
    def discover(self, path: str | Path) -> list[Path]:
        """Return every skill package beneath ``path``, in deterministic order.

        The root itself wins: if it contains ``SKILL.md`` it is the only result,
        even when it also contains nested packages.  Symlinked directories are
        never followed, and the result count is bounded so a hostile corpus
        cannot make the CLI walk forever.
        """

        root = Path(path).expanduser()
        if not root.exists() or not root.is_dir():
            raise ScanError(
                f"skill path does not exist or is not a directory: {path}",
                code="no_skill_manifest",
                stage=Stage.SPEC,
                status_code=404,
            )
        manifest = root / "SKILL.md"
        if manifest.is_file() and not manifest.is_symlink():
            return [root]
        found: list[Path] = []
        ignored = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirnames[:] = sorted(
                name
                for name in dirnames
                if name not in ignored and not (current_path / name).is_symlink()
            )
            current_manifest = current_path / "SKILL.md"
            if (
                "SKILL.md" in filenames
                and current_manifest.is_file()
                and not current_manifest.is_symlink()
            ):
                found.append(current_path)
                if len(found) > MAX_DISCOVERED_SKILLS:
                    raise ScanError(
                        f"more than {MAX_DISCOVERED_SKILLS} skills found under {root}; "
                        "scan a smaller directory",
                        code="too_many_skills",
                        stage=Stage.SPEC,
                        status_code=422,
                    )
        found.sort(key=lambda item: item.as_posix())
        if not found:
            raise ScanError(
                f"no SKILL.md found under {root}",
                code="no_skill_manifest",
                stage=Stage.SPEC,
                status_code=404,
            )
        return found

    # -- public scan -------------------------------------------------------
    def scan(
        self,
        path: str | Path,
        *,
        options: ScanOptions | None = None,
        scan_id: UUID | None = None,
        callback: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanOutcome:
        opts = options or ScanOptions()
        sid = scan_id or uuid4()
        started_at = utc_now()
        started_monotonic = time.monotonic()
        emit = callback or self._progress

        try:
            package = parse_skill(path)
        except SkillParseError as exc:
            code = "no_skill_manifest" if "no SKILL.md" in str(exc) else "invalid_skill"
            raise ScanError(
                str(exc), code=code, stage=Stage.SPEC, degraded=True, status_code=404
            ) from exc
        except (OSError, HashError) as exc:
            raise ScanError(
                f"could not read skill package: {exc}",
                code="invalid_skill",
                stage=Stage.SPEC,
                degraded=True,
                status_code=422,
            ) from exc

        skill_id = uuid5(SCAN_NAMESPACE, f"{package.name}:{package.content_hash}")
        self._emit(
            emit,
            Stage.CACHE,
            package.name,
            WSEventType.STARTED,
            {"message": "hashing package", "hash": package.content_hash[:12]},
        )
        backend, model_version = self._model_identity()
        try:
            self.store.create_scan(
                sid,
                skill_name=package.name,
                skill_path=str(package.root),
                content_hash=package.content_hash,
                backend=backend,
                skill_id=skill_id,
                status=ScanStatus.RUNNING,
                started_at=started_at,
            )
        except StoreError as exc:
            raise ScanError(f"could not create scan history: {exc}") from exc

        cache_eligible = self._cache_eligible(opts)
        try:
            cache_hit = None
            if cache_eligible and not opts.no_cache:
                cache_hit = self.store.lookup_cache(
                    package.content_hash,
                    engine_version=engine_version(self.config.scoring.weights),
                    model_version=model_version,
                    model_backend=backend,
                    backend_strict=self.config.cache.backend_strict,
                )
            if cache_hit is not None:
                return self._cached_outcome(
                    cache_hit,
                    sid=sid,
                    started_at=started_at,
                    started_monotonic=started_monotonic,
                    emit=emit,
                )
            if cache_eligible:
                cache_message = "cache miss"
            elif opts.no_cache:
                cache_message = "cache bypassed by --no-cache"
            else:
                cache_message = "cache bypassed for static-only or non-default analysis mode"
            self._emit(
                emit,
                Stage.CACHE,
                package.name,
                WSEventType.PROGRESS,
                {"message": cache_message, "hash": package.content_hash[:12]},
            )
            ctx = _ScanContext(
                scan_id=sid,
                started_at=started_at,
                started_monotonic=started_monotonic,
                package=package,
                options=opts,
                skill_name=package.name,
                skill_id=skill_id,
            )
            return self._run_pipeline(ctx, emit=emit, cancel=cancel)
        except ScanCancelled:
            self.store.fail_scan(sid, "cancelled by client")
            raise
        except ScanError as exc:
            # A storage/verdict failure must not leave a RUNNING row behind;
            # the scan history is the audit trail for an operational error.
            with contextlib.suppress(Exception):
                self.store.fail_scan(sid, str(exc)[:2000])
            raise
        except Exception as exc:
            message = f"scan failed: {exc}"
            self.store.fail_scan(sid, message[:2000])
            self._emit(
                emit,
                Stage.VERDICT,
                package.name,
                WSEventType.ERROR,
                {"code": "scan_failed", "message": message, "degraded": True},
            )
            raise ScanError(message) from exc

    # -- pipeline ----------------------------------------------------------
    def _run_pipeline(
        self,
        ctx: _ScanContext,
        *,
        emit: ProgressCallback | None,
        cancel: threading.Event | None,
    ) -> ScanOutcome:
        self._check_cancel(cancel)

        spec = self._spec_stage(ctx.package)
        self._record(ctx, spec, emit)
        self._check_cancel(cancel)

        typosquat = self._typosquat_stage(ctx.package.name)
        self._record(ctx, typosquat, emit)
        self._check_cancel(cancel)

        anchors = scan_anchors(ctx.package)
        self._record(ctx, anchors, emit)
        self._check_cancel(cancel)

        model = self._get_model()
        semantic = self._semantic_stage(ctx.package, anchors, model)
        self._record(ctx, semantic, emit)
        self._check_cancel(cancel)

        vision = scan_vision(ctx.package, model, max_px=self.config.model.image_max_px)
        self._record(ctx, vision, emit)
        ctx.vision_evidence = self._vision_evidence(vision)
        self._check_cancel(cancel)

        sandbox = self._sandbox_stage(ctx, emit)
        self._record(ctx, sandbox, emit)
        if ctx.sandbox_result is not None:
            ctx.trace = ctx.sandbox_result.to_trace()
        self._check_cancel(cancel)

        pw_stage, evasion_stage = self._active_defense_stages(ctx, emit)
        self._record(ctx, pw_stage, emit)
        self._record(ctx, evasion_stage, emit)
        self._check_cancel(cancel)

        try:
            fused = fuse(
                ctx.stage_results,
                weights=self.config.scoring.weights,
                typosquat_bonus=self.config.scoring.typosquat_bonus,
                safe_max=self.config.scoring.tiers.safe_max,
                malicious_min=self.config.scoring.tiers.malicious_min,
                typosquat_detected=bool(typosquat.findings),
            )
        except FusionError as exc:
            raise ScanError(
                f"could not fuse stage results: {exc}",
                code="fusion_failed",
                stage=Stage.VERDICT,
                degraded=True,
            ) from exc

        duration_ms = max(0, int((time.monotonic() - ctx.started_monotonic) * 1000))
        active = ctx.active
        findings = list(fused.findings)
        # Ensure a confirmed profile's finding is present even if a caller
        # injected a custom stage list.
        if (
            active is not None
            and active.triggered
            and not any(finding.severity.rank >= Severity.CRITICAL.rank for finding in findings)
        ):
            profile_finding = self._profile_finding(ctx)
            if profile_finding is not None:
                findings.append(profile_finding)
        verdict = Verdict(
            skill=ctx.skill_name,
            skill_id=ctx.skill_id,
            scan_id=ctx.scan_id,
            verdict=fused.verdict,
            risk_score=fused.risk_score,
            confidence=fused.confidence,
            cached=False,
            scan_duration_ms=duration_ms,
            findings=findings,
            active_defense=active,
        )
        detail = self._detail(ctx, verdict, duration_ms)
        self._finalize(
            ctx,
            verdict,
            detail,
            fused,
            cache=self._cache_eligible(ctx.options)
            and not any(result.degraded or result.error for result in ctx.stage_results),
        )
        self._emit(
            emit,
            Stage.VERDICT,
            ctx.skill_name,
            WSEventType.COMPLETED,
            {
                "verdict": verdict.model_dump(by_alias=True, mode="json"),
                "durationMs": duration_ms,
                "degraded": [stage.value for stage in fused.degraded_stages],
            },
        )
        return ScanOutcome(
            scan_id=ctx.scan_id,
            skill_id=ctx.skill_id,
            skill_name=ctx.skill_name,
            verdict=verdict,
            detail=detail,
            stage_results=list(ctx.stage_results),
            cached=False,
            started_at=ctx.started_at,
            duration_ms=duration_ms,
            status=ScanStatus.COMPLETED,
        )

    # -- stages ------------------------------------------------------------
    def _spec_stage(self, package: SkillPackage) -> StageResult:
        findings: list[Finding] = []
        high = False
        for issue in package.issues:
            severity = Severity(issue.severity)
            high = high or severity.rank >= Severity.HIGH.rank
            findings.append(
                Finding(
                    stage=Stage.SPEC,
                    severity=severity,
                    message=issue.message,
                    type="manifest-issue",
                    evidence=FindingEvidence(
                        file=issue.file,
                        line=max(1, issue.line),
                        code=issue.code,
                    ),
                )
            )
        if not findings:
            findings.append(
                Finding(
                    stage=Stage.SPEC,
                    severity=Severity.NOTE,
                    message="Frontmatter valid - typosquat check clean",
                    type="spec-valid",
                    evidence=FindingEvidence(file="SKILL.md", line=1),
                )
            )
        return StageResult(
            stage=Stage.SPEC,
            findings=findings,
            telemetry={
                "name": package.name,
                "description": package.description,
                "files": len(package.files),
                "text_files": len(package.text_files),
                "entrypoint": package.entrypoint,
                "entrypoint_declared": package.entrypoint_declared,
                "content_hash": package.content_hash,
            },
            degraded=high,
            error="manifest validation failed" if high else None,
        )

    def _typosquat_stage(self, name: str) -> StageResult:
        match: TyposquatMatch | None = check_typosquat(name)
        if match is None:
            return StageResult(
                stage=Stage.TYPOSQUAT,
                findings=[],
                telemetry={"name": name, "matched": False},
            )
        finding = Finding(
            stage=Stage.TYPOSQUAT,
            severity=Severity.MEDIUM,
            message=match.message,
            type="typosquat",
            evidence=FindingEvidence(
                file="SKILL.md",
                line=1,
                code=f"{name} -> {match.candidate}",
                **{"candidate": match.candidate, "distance": match.distance},
            ),
        )
        return StageResult(
            stage=Stage.TYPOSQUAT,
            findings=[finding],
            signals={"typosquat": 100.0},
            telemetry={
                "name": name,
                "matched": True,
                "candidate": match.candidate,
                "distance": match.distance,
            },
        )

    def _sandbox_stage(self, ctx: _ScanContext, emit: ProgressCallback | None) -> StageResult:
        if not ctx.options.sandbox or not self.config.sandbox.enabled:
            ctx.sandbox_skipped = True
            self._emit(
                emit,
                Stage.SANDBOX,
                ctx.skill_name,
                WSEventType.PROGRESS,
                {"message": "sandbox disabled; static-only evidence collected"},
            )
            return StageResult(
                stage=Stage.SANDBOX,
                findings=[
                    Finding(
                        stage=Stage.SANDBOX,
                        severity=Severity.NOTE,
                        message="Sandbox execution disabled for this scan (static-only mode).",
                        type="sandbox-disabled",
                    )
                ],
                telemetry={"skipped": True, "reason": "disabled by request or config"},
            )
        if ctx.package.entrypoint_declared and ctx.package.entrypoint is None:
            return StageResult(
                stage=Stage.SANDBOX,
                degraded=True,
                error="declared entrypoint is invalid or missing; refusing to execute a fallback",
            )
        runner = self._get_sandbox_runner()
        request = SandboxRequest(
            scan_id=ctx.scan_id,
            skill_dir=ctx.package.root,
            declared_intent=ctx.package.declared_intent,
            command=tuple(ctx.package.entrypoint) if ctx.package.entrypoint else None,
            timeout_s=float(min(self.config.sandbox.timeout_s, ctx.options.timeout_s)),
        )
        self._emit(
            emit,
            Stage.SANDBOX,
            ctx.skill_name,
            WSEventType.STARTED,
            {
                "message": "container starting",
                "memoryMb": self.config.sandbox.memory_mb,
                "cpus": self.config.sandbox.cpus,
                "timeoutS": request.timeout_s,
            },
        )
        try:
            result = runner.run(request)
        except SandboxUnavailable as exc:
            return StageResult(
                stage=Stage.SANDBOX,
                degraded=True,
                error=f"Docker unavailable: {exc}",
                findings=[
                    Finding(
                        stage=Stage.SANDBOX,
                        severity=Severity.NOTE,
                        message="Sandbox unavailable; no execution evidence was collected.",
                        type="sandbox-unavailable",
                    )
                ],
            )
        except (SandboxError, Exception) as exc:
            return StageResult(
                stage=Stage.SANDBOX,
                degraded=True,
                error=f"sandbox failed: {exc}",
                findings=[
                    Finding(
                        stage=Stage.SANDBOX,
                        severity=Severity.NOTE,
                        message=f"Sandbox failed; scan is degraded: {exc}",
                        type="sandbox-unavailable",
                    )
                ],
            )
        ctx.sandbox_result = result
        ctx.canaries = result.canaries
        stage = result.to_stage_result()
        if result.error:
            stage.degraded = True
            stage.error = result.error
        for event in result.events:
            self._emit(
                emit,
                Stage.SANDBOX,
                ctx.skill_name,
                WSEventType.PROGRESS,
                {
                    "message": event.event_type,
                    "path": event.path_or_channel,
                    "marker": event.marker,
                },
            )
        return stage

    def _active_defense_stages(
        self, ctx: _ScanContext, emit: ProgressCallback | None
    ) -> tuple[StageResult, StageResult]:
        if ctx.sandbox_result is None:
            ctx.active = ActiveDefense(
                triggered=False,
                declared_intent=ctx.package.declared_intent or None,
                context_aware_canary=normalize_intent(ctx.package.declared_intent),
            )
            return (
                StageResult(
                    stage=Stage.POISONED_WELL,
                    telemetry={"skipped": True, "reason": "sandbox not run"},
                ),
                StageResult(
                    stage=Stage.EVASION,
                    telemetry={"skipped": True, "reason": "sandbox not run"},
                ),
            )

        result = ctx.sandbox_result
        canaries = result.canaries
        tracker = ExfilTracker(
            canaries,
            window_s=self.config.poisoned_well.correlation_window_s,
        )
        for event in result.events:
            if event.event_type == "canary_read":
                tracker.record_canary_read(event)
        # Shell expansion cannot be observed by shim getenv(); the environment
        # itself is exposure.  The within-window + marker rule still applies.
        if self.config.poisoned_well.enabled:
            tracker.record_implicit_env_reads(ts=result.started_at)
            for observation in result.sinkhole_observations:
                if observation.protocol == "dns":
                    tracker.observe_dns(
                        observation.query_or_url,
                        ts=observation.ts,
                        client=observation.client,
                        responder_action=observation.responder_action,
                    )
                else:
                    method, _, url = observation.query_or_url.partition(" ")
                    if not url:
                        method, url = "POST", observation.query_or_url
                    tracker.observe_http(
                        method,
                        url,
                        body=observation.body,
                        headers=observation.headers,
                        ts=observation.ts,
                        client=observation.client,
                        responder_action=observation.responder_action,
                    )
        correlations = [item for item in tracker.results if item.matched]
        ctx.correlation = correlations[-1] if correlations else None
        # Do not let an unverified, writable shim log alone produce an
        # evasion override.  The current shim has no signed channel; probes are
        # still surfaced as findings, but only a sandbox result the engine
        # actually produced is eligible for the hard override.
        ctx.evasion = detect_probes(result.events)
        secondary_served = any(
            event.event_type == "secondary_served" for event in result.events
        ) or any(
            observation.responder_action == "200+secondary"
            for observation in result.sinkhole_observations
        )
        profile = build_attacker_profile(
            canaries,
            correlation=ctx.correlation,
            evasion=ctx.evasion if result.events else EvasionResult(detected=False),
            secondary_served=secondary_served,
            ioc_export="stix-bundle.json" if correlations else None,
        )
        ctx.active = profile.to_active_defense()
        ctx.pw_view = self._poisoned_well_view(ctx, tracker, profile)
        ctx.trace = result.to_trace()

        pw_findings: list[Finding] = []
        if ctx.correlation is not None:
            profile_finding = profile.to_finding()
            if profile_finding is not None:
                pw_findings.append(profile_finding)
            self._emit(
                emit,
                Stage.POISONED_WELL,
                ctx.skill_name,
                WSEventType.OVERRIDE,
                {
                    "kind": "poisoned_well",
                    "message": "CANARY MARKER CONFIRMED",
                    "marker": ctx.correlation.marker,
                    "c2": list(ctx.correlation.c2_indicators),
                    "channel": ctx.correlation.channel.value,
                },
            )
        pw_stage = StageResult(
            stage=Stage.POISONED_WELL,
            findings=pw_findings,
            telemetry={
                "confirmed": ctx.correlation is not None,
                "reads": len(tracker.reads),
                "observations": len(tracker.observations),
                "summary": tracker.summary(),
            },
            override=ctx.correlation.to_override() if ctx.correlation else None,
        )

        evasion_findings: list[Finding] = []
        if ctx.evasion is not None and ctx.evasion.detected:
            evasion_findings.append(
                Finding(
                    stage=Stage.EVASION,
                    severity=Severity.CRITICAL,
                    message="Sandbox evasion probe(s) detected: " + ", ".join(ctx.evasion.targets),
                    type="evasion-probe",
                    evidence=FindingEvidence(
                        path=ctx.evasion.targets[0] if ctx.evasion.targets else None,
                        **{"probes": list(ctx.evasion.targets)},
                    ),
                )
            )
            self._emit(
                emit,
                Stage.EVASION,
                ctx.skill_name,
                WSEventType.OVERRIDE,
                {"kind": "evasion", "probes": list(ctx.evasion.targets)},
            )
        evasion_stage = StageResult(
            stage=Stage.EVASION,
            findings=evasion_findings,
            telemetry=ctx.evasion.summary() if ctx.evasion else {},
            override=ctx.evasion.to_override() if ctx.evasion and ctx.evasion.detected else None,
        )
        return pw_stage, evasion_stage

    # -- persistence / details --------------------------------------------
    def _finalize(
        self,
        ctx: _ScanContext,
        verdict: Verdict,
        detail: SkillDetail,
        fused: FusionResult,
        *,
        cache: bool,
    ) -> None:
        backend, model_version = self._model_identity()
        self.store.set_cache_identity(
            engine_version=engine_version(self.config.scoring.weights),
            model_backend=backend,
            model_version=model_version,
        )
        sarif = ""
        try:
            sarif = render_report(
                verdict,
                _sarif_format(),
                stage_results=ctx.stage_results,
            ).content.decode("utf-8")
        except Exception:
            # SARIF is a report view; its failure must not fabricate a clean
            # verdict or block the evidence trail.
            sarif = ""
        try:
            self.store.finish_scan(
                verdict,
                detail,
                stage_results=ctx.stage_results,
                sarif_json=sarif,
                cache=cache,
            )
        except StoreError as exc:
            raise ScanError(
                f"could not persist scan evidence: {exc}",
                code="storage_error",
                stage=Stage.VERDICT,
                degraded=True,
            ) from exc
        del fused

    def _cached_outcome(
        self,
        cached: Any,
        *,
        sid: UUID,
        started_at: datetime,
        started_monotonic: float,
        emit: ProgressCallback | None,
    ) -> ScanOutcome:
        duration_ms = max(0, int((time.monotonic() - started_monotonic) * 1000))
        old_verdict: Verdict = cached.verdict
        verdict = old_verdict.model_copy(
            update={
                "scan_id": sid,
                "cached": True,
                "scan_duration_ms": duration_ms,
            }
        )
        detail = cached.detail.model_copy(update={"verdict": verdict})
        detail = detail.model_copy(
            update={
                "report_links": detail.report_links.model_copy(
                    update={
                        "sarif": f"/skills/{verdict.skill_id}/export?format=sarif",
                        "markdown": f"/skills/{verdict.skill_id}/export?format=markdown",
                        "stix": (
                            f"/skills/{verdict.skill_id}/export?format=stix"
                            if verdict.active_defense and verdict.active_defense.triggered
                            else None
                        ),
                    }
                )
            }
        )
        self._emit(
            emit,
            Stage.CACHE,
            verdict.skill,
            WSEventType.CACHED,
            {
                "message": "cached verdict",
                "durationMs": duration_ms,
                "hash": cached.content_hash[:12],
            },
        )
        backend, model_version = self._model_identity()
        self.store.set_cache_identity(
            engine_version=engine_version(self.config.scoring.weights),
            model_backend=backend,
            model_version=model_version,
        )
        self.store.finish_scan(
            verdict,
            detail,
            sarif_json=cached.sarif_json,
            cache=False,
        )
        self._emit(
            emit,
            Stage.VERDICT,
            verdict.skill,
            WSEventType.COMPLETED,
            {"verdict": verdict.model_dump(by_alias=True, mode="json"), "durationMs": duration_ms},
        )
        return ScanOutcome(
            scan_id=sid,
            skill_id=verdict.skill_id,
            skill_name=verdict.skill,
            verdict=verdict,
            detail=detail,
            stage_results=[],
            cached=True,
            started_at=started_at,
            duration_ms=duration_ms,
            status=ScanStatus.CACHED_HIT,
        )

    def _detail(self, ctx: _ScanContext, verdict: Verdict, duration_ms: int) -> SkillDetail:
        del duration_ms
        active = verdict.active_defense
        links = {
            "sarif": f"/skills/{ctx.skill_id}/export?format=sarif",
            "markdown": f"/skills/{ctx.skill_id}/export?format=markdown",
            "stix": (
                f"/skills/{ctx.skill_id}/export?format=stix"
                if active is not None and active.triggered
                else None
            ),
        }
        return SkillDetail(
            verdict=verdict,
            static_findings=self._static_findings(verdict),
            vision_evidence=ctx.vision_evidence,
            sandbox_trace=ctx.trace,
            poisoned_well=ctx.pw_view.model_copy(update={"active_defense": active}),
            report_links=_report_links(links),
        )

    def _static_findings(self, verdict: Verdict) -> list[StaticFinding]:
        results: list[StaticFinding] = []
        for finding in verdict.findings:
            if finding.stage is Stage.VISION:
                continue
            if finding.severity is Severity.NOTE and finding.stage not in {
                Stage.SPEC,
                Stage.SEMANTIC,
            }:
                continue
            results.append(
                StaticFinding(
                    file=finding.evidence.file or "SKILL.md",
                    line=max(1, finding.evidence.line or 1),
                    code=finding.evidence.code,
                    stage=finding.stage,
                    severity=finding.severity,
                    message=finding.message,
                    anchor=finding.stage is Stage.DETERMINISTIC_ANCHOR,
                )
            )
        return results

    def _vision_evidence(self, stage: StageResult) -> list[VisionEvidence]:
        items: list[VisionEvidence] = []
        raw = (stage.telemetry or {}).get("evidence")
        if isinstance(raw, list):
            for item in raw:
                try:
                    items.append(VisionEvidence.model_validate(item))
                except Exception:
                    continue
        return items

    def _poisoned_well_view(
        self,
        ctx: _ScanContext,
        tracker: ExfilTracker,
        profile: Any,
    ) -> PoisonedWellView:
        timeline: list[TimelineRow] = []
        if ctx.sandbox_result is not None:
            for event in ctx.sandbox_result.events:
                kind = {
                    "canary_read": "canary_read",
                    "probe_detected": "probe",
                    "fake_served": "fake_served",
                    "marker_matched": "confirmed",
                }.get(event.event_type, event.event_type)
                timeline.append(
                    TimelineRow(
                        ts=event.ts,
                        label=(
                            f"{event.event_type}: {event.path_or_channel or event.process or ''}".strip()
                        ),
                        kind=kind,
                        marker=event.marker,
                    )
                )
            for observation in ctx.sandbox_result.sinkhole_observations:
                timeline.append(
                    TimelineRow(
                        ts=observation.ts,
                        label=observation.query_or_url,
                        kind="dns" if observation.protocol == "dns" else "http",
                    )
                )
        timeline.sort(key=lambda row: row.ts)
        graph = IOCGraph()
        if ctx.correlation is not None:
            correlation = ctx.correlation
            c2 = correlation.c2_indicators[0] if correlation.c2_indicators else "unknown"
            graph = IOCGraph(
                nodes=[
                    IOCGraphNode(id="script", label=ctx.skill_name, kind="script"),
                    IOCGraphNode(
                        id="canary",
                        label=", ".join(correlation.targeted_assets) or "canary",
                        kind="canary_file",
                    ),
                    IOCGraphNode(
                        id="marker",
                        label=correlation.marker or "marker",
                        kind="marker",
                    ),
                    IOCGraphNode(
                        id="channel",
                        label=correlation.channel.value,
                        kind="channel",
                    ),
                    IOCGraphNode(id="c2", label=c2, kind="c2"),
                ],
                edges=[
                    IOCGraphEdge(source="script", target="canary", label="reads"),
                    IOCGraphEdge(source="canary", target="marker", label="fake"),
                    IOCGraphEdge(source="marker", target="channel", label="exfil"),
                    IOCGraphEdge(source="channel", target="c2", label="resolves"),
                ],
            )
        return PoisonedWellView(
            active_defense=profile.to_active_defense() if profile else None,
            timeline=timeline,
            graph=graph,
            confirmed=ctx.correlation is not None,
        )

    def _profile_finding(self, ctx: _ScanContext) -> Finding | None:
        if ctx.correlation is not None:
            return Finding(
                stage=Stage.POISONED_WELL,
                severity=Severity.CRITICAL,
                message=(
                    f"Canary marker exfiltrated via {ctx.correlation.channel.value} "
                    f"to {', '.join(ctx.correlation.c2_indicators) or 'unknown'}"
                ),
                type="exfil-confirmed",
                evidence=FindingEvidence(
                    marker=ctx.correlation.marker,
                    channel=ctx.correlation.channel.value,
                    c2=ctx.correlation.c2_indicators[0] if ctx.correlation.c2_indicators else None,
                    path=ctx.correlation.targeted_assets[0]
                    if ctx.correlation.targeted_assets
                    else None,
                    code=ctx.correlation.observation.query_or_url[:500],
                ),
            )
        if ctx.evasion is not None and ctx.evasion.detected:
            return Finding(
                stage=Stage.EVASION,
                severity=Severity.CRITICAL,
                message="Sandbox evasion probe detected",
                type="evasion-probe",
                evidence=FindingEvidence(
                    path=ctx.evasion.targets[0] if ctx.evasion.targets else None,
                    **{"probes": list(ctx.evasion.targets)},
                ),
            )
        return None

    # -- helpers -----------------------------------------------------------
    def _record(
        self,
        ctx: _ScanContext,
        result: StageResult,
        emit: ProgressCallback | None,
    ) -> None:
        ctx.stage_results.append(result)
        self._emit(
            emit,
            result.stage,
            ctx.skill_name,
            WSEventType.STARTED,
            {"message": f"{result.stage.value} started"},
        )
        for finding in result.findings:
            if finding.severity is Severity.NOTE and finding.finding_type in {
                "semantic-clean",
                "spec-valid",
            }:
                continue
            self._emit(
                emit,
                result.stage,
                ctx.skill_name,
                WSEventType.FINDING,
                {"finding": finding.model_dump(by_alias=True, mode="json")},
            )
        if result.degraded:
            self._emit(
                emit,
                result.stage,
                ctx.skill_name,
                WSEventType.PROGRESS,
                {"message": f"degraded: {result.error or 'stage unavailable'}"},
            )
        self._emit(
            emit,
            result.stage,
            ctx.skill_name,
            WSEventType.PROGRESS,
            {"message": f"{result.stage.value} complete"},
        )

    def _cache_eligible(self, opts: ScanOptions) -> bool:
        """Whether this analysis mode can safely reuse a cached verdict.

        A static-only scan lacks sandbox evidence and must never poison the
        cache for a later full scan.  A non-default timeout is also treated as
        a different analysis mode because execution/evidence can differ.
        """

        if not opts.sandbox or not self.config.sandbox.enabled:
            return False
        if opts.timeout_s != self.config.sandbox.timeout_s:
            return False
        return opts.poisoned_well == self.config.poisoned_well.enabled

    def _check_cancel(self, cancel: threading.Event | None) -> None:
        if cancel is not None and cancel.is_set():
            raise ScanCancelled()

    def _semantic_stage(
        self,
        package: SkillPackage,
        anchors: StageResult,
        model: ModelClient | None,
    ) -> StageResult:
        """Route the semantic stage: typed decision backend, then legacy model."""

        try:
            selection = self._decision_selection(model)
        except DecisionUnavailable as exc:
            return degraded_semantic_stage(anchors, str(exc))
        if selection.client is not None:
            try:
                calibration = load_calibration(self.config.decision.calibration_path)
            except CalibrationError as exc:
                # An unreadable calibration must not silently fall back to the provisional threshold.
                return degraded_semantic_stage(anchors, f"calibration unavailable: {exc}")
            threshold = calibration.capability_threshold if calibration else CAPABILITY_THRESHOLD
            temperature = calibration.temperature if calibration else 1.0
            label = (
                calibration.label
                if calibration
                else (self.config.decision.calibration_version.strip() or "uncalibrated")
            )
            stage = analyze_semantics_laya(
                package,
                anchors,
                selection.client,
                threshold=threshold,
                temperature=temperature,
            )
            return stage.model_copy(
                update={
                    "telemetry": {
                        **(stage.telemetry or {}),
                        "calibration_version": label,
                        "capability_threshold": threshold,
                        "temperature": temperature,
                    }
                }
            )
        if selection.backend == "legacy":
            return analyze_semantics(package, anchors, model)
        if selection.backend == "none":
            off_values = {"none", "off", "disabled"}
            explicitly_off = self.config.decision.backend.strip().lower() in off_values
            if explicitly_off and not selection.required:
                return deterministic_only_stage(anchors)
            return degraded_semantic_stage(
                anchors, selection.reason or "semantic decision backend unavailable"
            )
        return analyze_semantics(package, anchors, model)

    def _decision_selection(self, model: ModelClient | None) -> DecisionSelection:
        """Select the typed decision backend once per engine, not once per scan.

        Selection is memoised because a Laya client loads checkpoint weights on
        first use.  A failed selection raises and is retried on the next scan.
        """

        if self._decision is None:
            self._decision = select_decision_model(
                self.config,
                laya_client=self._decision_client,
                legacy_available=model is not None,
            )
        return self._decision

    def _semantic_identity(self, model: ModelClient | None) -> str:
        """Cache-identity fragment for the typed decision layer; empty when unused.

        Empty for the legacy and deterministic-only paths so their cache keys do
        not change.  Laya's identity includes the calibration version, so
        changing the checkpoint or calibration invalidates cached verdicts.
        """

        try:
            selection = self._decision_selection(model)
        except DecisionUnavailable:
            return "laya:unavailable"
        if selection.client is None:
            return ""
        try:
            calibration = load_calibration(self.config.decision.calibration_path)
        except CalibrationError:
            return "laya:calibration-invalid"
        version = str(getattr(selection.client, "model_version", "unknown"))
        fitted = (
            f"{calibration.version}:{calibration.capability_threshold}" if calibration else "none"
        )
        return f"laya:{version}:{self.config.decision.cache_identity}:{fitted}"

    def _get_model(self) -> ModelClient | None:
        if self._model_selected:
            return self._model
        self._model_selected = True
        if self.config.model.backend == "demo":
            self._model = MockGemma()
            return self._model
        try:
            self._model = select_model(self.config)
        except (ModelError, ValueError, OSError) as exc:
            self._model = None
            self._model_error = str(exc)
        except Exception as exc:  # network clients can raise provider exceptions
            self._model = None
            self._model_error = f"model selection failed: {exc}"
        return self._model

    def model_identity(self) -> tuple[str, str]:
        """Return ``(backend, model_version)`` for the selected model.

        Public because health/meta endpoints must report the identity the
        engine will actually use (including an injected deterministic model),
        rather than re-running backend selection and guessing.
        """

        return self._model_identity()

    def _model_identity(self) -> tuple[str, str]:
        model = self._get_model()
        if model is None:
            backend, version = "unavailable", "unavailable"
        else:
            backend = str(getattr(model, "backend", "unknown"))
            version = str(getattr(model, "model_version", "unknown"))
        semantic = self._semantic_identity(model)
        if semantic:
            version = f"{version}|{semantic}"
        return backend, version

    def _get_sandbox_runner(self) -> SandboxRunner:
        if self._sandbox_runner is not None:
            return self._sandbox_runner
        if self._sandbox_runner_factory is not None:
            self._sandbox_runner = self._sandbox_runner_factory()
            return self._sandbox_runner
        from skillsentry.core.sandbox.runner import SandboxConfig

        config = SandboxConfig(
            image=self.config.sandbox.base_image,
            memory_mb=self.config.sandbox.memory_mb,
            cpus=self.config.sandbox.cpus,
            timeout_s=float(self.config.sandbox.timeout_s),
            # ``SandboxSettings.masquerade`` is a boolean feature flag; the
            # runner expects a MasqueradeConfig, not the raw flag.  Passing the
            # bool here made dataclasses.replace() fail on every full scan.
            masquerade=MasqueradeConfig(require_shim=self.config.sandbox.masquerade),
            verify_masquerade=self.config.sandbox.masquerade,
        )
        self._sandbox_runner = SandboxRunner(
            config=config,
            sidecar_factory=lambda client: SinkholeSidecar(
                client,
                SinkholeConfig(
                    image="python:3.11-slim",
                    ip=config.sidecar_ip,
                    subnet=config.sidecar_subnet,
                ),
            ),
        )
        return self._sandbox_runner

    def _emit(
        self,
        callback: ProgressCallback | None,
        stage: Stage,
        skill: str,
        event: WSEventType,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if callback is None:
            return
        # A broken UI subscriber must not break evidence collection.
        with contextlib.suppress(Exception):
            callback(
                WSMessage(
                    stage=stage,
                    skill=skill,
                    event=event,
                    ts=utc_now(),
                    detail=detail,
                )
            )


def _sarif_format():
    from skillsentry.core.contracts import ExportFormat

    return ExportFormat.SARIF


def _report_links(values: dict[str, str | None]):
    from skillsentry.core.contracts import ReportLinks

    return ReportLinks(**values)


__all__ = [
    "SCAN_NAMESPACE",
    "ScanCancelled",
    "ScanEngine",
    "ScanError",
    "ScanOutcome",
]
