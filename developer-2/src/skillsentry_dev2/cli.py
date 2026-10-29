"""
SkillSentry Command-Line Interface (Windows PowerShell CLI).

Provides user-facing scan initiation directly from Windows PowerShell (5.1 & 7.x)
and other command-line environments. Implements input validation, path normalization,
caching, static analysis, semantic model execution, dynamic sandbox action instruction
generation (INT-4), verdict fusion, and multi-format report export.

CL-D2-7 · REQ-D2-PS-01/02 · REQ-D2-SBX-01/02/03 · REQ-D2-PERF-01/02/03/04
Source: developer-2/03-functional-specifications.md Cap J, K, L.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

from skillsentry_dev2.contracts import (
    Finding,
    ModelUnavailableError,
    SandboxActionInstruction,
)
from skillsentry_dev2.core.cache.hash_utils import compute_directory_hash
from skillsentry_dev2.core.cache.sqlite_store import CacheStore
from skillsentry_dev2.core.parser.skill_parser import parse_package
from skillsentry_dev2.core.parser.typosquat import check_typosquat
from skillsentry_dev2.core.semantic.analyzer import analyze_semantics
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors
from skillsentry_dev2.core.semantic.sandbox_instructions import generate_sandbox_instructions
from skillsentry_dev2.core.vision.vision_scanner import scan_visual_assets
from skillsentry_dev2.mock_gemma import MockGemma, MockMode
from skillsentry_dev2.sarif import generate_sarif_report, sarif_to_json

logger = logging.getLogger("skillsentry_dev2.cli")


# ── Windows Device Names & Path Sanitization ───────────────────────────

RESERVED_DEVICE_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})

ENGINE_VERSION = "2.1.0"
MODEL_VERSION = "gemma4:e4b-q4"

_OLLAMA_PROBE_RESULT: Optional[bool] = None


def _is_ollama_online(timeout_s: float = 0.5) -> bool:
    """Check if local Ollama daemon is reachable, caching the probe result."""
    global _OLLAMA_PROBE_RESULT
    if _OLLAMA_PROBE_RESULT is not None:
        return _OLLAMA_PROBE_RESULT
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=timeout_s)
        _OLLAMA_PROBE_RESULT = True
    except Exception:
        _OLLAMA_PROBE_RESULT = False
    return _OLLAMA_PROBE_RESULT


def reset_ollama_probe() -> None:
    """Reset the cached Ollama daemon probe result (useful for test fixtures)."""
    global _OLLAMA_PROBE_RESULT
    _OLLAMA_PROBE_RESULT = None


# ── ANSI Terminal Styling ──────────────────────────────────────────────

class TerminalColors:
    """ANSI color codes for terminal formatting."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def strip(cls, text: str) -> str:
        """Strip ANSI escape sequences from text."""
        return re.sub(r"\033\[[0-9;]*m", "", text)


def _init_windows_console() -> None:
    """Configure Windows console for clean UTF-8 and ANSI output."""
    if sys.platform == "win32":
        os.environ["PYTHONUTF8"] = "1"
        try:
            # Enable ANSI virtual terminal processing on Windows conhost
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


# ── Path Normalization & Validation ────────────────────────────────────

def sanitize_and_validate_path(path_str: str) -> Path:
    """Sanitize and validate a target scan path from Windows PowerShell.

    Handles drive letters, quotes, backslashes, reserved DOS names,
    and NTFS alternate data streams.

    Raises:
        ValueError: If the path contains illegal device names or streams.
        FileNotFoundError: If the path does not exist.
    """
    clean_str = path_str.strip().strip("'\"")
    if not clean_str:
        raise ValueError("Target path cannot be empty")

    if clean_str.startswith("\\\\?\\"):
        clean_str = clean_str[4:]

    # Check for reserved DOS device names in any path component
    parts = Path(clean_str).parts
    for part in parts:
        stem = part.split(".")[0].upper()
        if stem in RESERVED_DEVICE_NAMES:
            raise ValueError(
                f"Path contains reserved Windows MS-DOS device name: '{stem}'"
            )

    # Check for NTFS Alternate Data Stream notation (colon after drive letter)
    # A colon is allowed only at index 1 for Windows drive letters (e.g. C:\)
    rest_of_path = clean_str[2:] if (len(clean_str) >= 2 and clean_str[1] == ":") else clean_str
    if ":" in rest_of_path:
        raise ValueError(
            f"Path contains invalid NTFS Alternate Data Stream notation: '{clean_str}'"
        )

    target_path = Path(clean_str).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: '{clean_str}'")

    return target_path


def discover_scan_targets(target_path: Path) -> list[Path]:
    """Find skill packages to scan from a single path or parent directory."""
    # Case 0: Target is a file pointing to or inside a skill package
    if target_path.is_file():
        if target_path.name.lower() in ("skill.md", "skill.yaml", "skill.json"):
            return [target_path.parent]
        # Check parent and ancestor directories for SKILL.md
        curr = target_path.parent
        while curr != curr.parent:
            if (curr / "SKILL.md").exists() or (curr / "skill.md").exists():
                return [curr]
            curr = curr.parent

        raise ValueError(
            f"Target file '{target_path}' is not within a valid skill package (missing SKILL.md)"
        )

    # Case 1: Single skill directory (contains SKILL.md)
    if (target_path / "SKILL.md").exists() or (target_path / "skill.md").exists():
        return [target_path]

    # Case 2: Parent directory containing multiple skills
    subdirs: list[Path] = []
    if target_path.is_dir():
        for child in sorted(target_path.iterdir()):
            if child.is_dir() and ((child / "SKILL.md").exists() or (child / "skill.md").exists()):
                subdirs.append(child)

    if subdirs:
        return subdirs

    # If it is a directory but no SKILL.md found anywhere
    raise ValueError(
        f"Target directory '{target_path}' is not a valid skill package (missing SKILL.md)"
    )


# ── Core Single Package Scanner ────────────────────────────────────────

def scan_single_package(
    skill_dir: Path,
    use_cache: bool = True,
    no_sandbox: bool = False,
    backend: str = "auto",
    demo_mode: bool = False,
    timeout_s: int = 60,
    db_path: Optional[str | Path] = None,
) -> dict[str, Any]:
    """Execute the full Developer 2 scanning and analysis pipeline on a skill package.

    Returns structured scan assessment dictionary.
    """
    start_time = time.monotonic()
    skill_name = skill_dir.name
    all_findings: list[Finding] = []
    stage_statuses: dict[str, str] = {}
    c2_indicators: list[str] = []
    degraded = False

    # Stage 0: Cache Check
    content_hash = compute_directory_hash(skill_dir)
    cache_store: Optional[CacheStore] = None
    if use_cache:
        try:
            cache_store = CacheStore(db_path=db_path)
            cached_entry = cache_store.get_cached(
                content_hash=content_hash,
                engine_version=ENGINE_VERSION,
                model_version=MODEL_VERSION,
                backend_strict=True,
                model_backend=backend,
            )
            if cached_entry:
                verdict_json_str, sarif_json_str = cached_entry
                cached_data = json.loads(verdict_json_str)
                # Never serve degraded results from cache (DEF-09)
                if not cached_data.get("degraded", False):
                    cached_data["cached"] = True
                    cached_data["content_hash"] = content_hash
                    cached_data["scan_duration_ms"] = int((time.monotonic() - start_time) * 1000)
                    return cached_data
            stage_statuses["cache"] = f"miss (hash {content_hash[:8]}...)"
        except Exception as e:
            stage_statuses["cache"] = f"bypass (cache error: {e})"
            degraded = True
    else:
        stage_statuses["cache"] = "bypassed (--no-cache)"

    # Stage 1: Spec Validation & Inventory
    manifest, spec_result = parse_package(skill_dir)
    all_findings.extend(spec_result.findings)
    if spec_result.degraded:
        degraded = True
    if manifest:
        skill_name = manifest.name
        stage_statuses["spec"] = f"frontmatter valid ({len(manifest.scripts)} scripts, {len(manifest.assets)} assets)"
    else:
        stage_statuses["spec"] = "invalid frontmatter"

    # Stage 1: Typosquatting Analysis
    typosquat_result = check_typosquat(skill_name)
    all_findings.extend(typosquat_result.findings)
    typosquat_detected = typosquat_result.signals.get("typosquat_detected", 0.0) > 0.0
    if typosquat_detected:
        stage_statuses["typosquat"] = "FLAGGED (+15 risk bonus)"
    else:
        stage_statuses["typosquat"] = "clean"

    # Stage 2: AST & Regex Anchor Scanning (<100ms)
    scripts = manifest.scripts if manifest else {}
    anchor_result, raw_anchors, anchor_block = scan_anchors(scripts)
    all_findings.extend(anchor_result.findings)
    s_anchors = anchor_result.signals.get("anchor_risk", 0.0)
    stage_statuses["anchors"] = f"{len(raw_anchors)} code findings"

    # Stage 2: Model Client Selection & Semantic Analysis (DEF-01: zero path cheating)
    model_client: Optional[MockGemma] = None
    if timeout_s <= 0 or (time.monotonic() - start_time) >= timeout_s:
        degraded = True
        all_findings.append(Finding(
            stage="semantic",
            severity="high",
            message=f"Semantic analysis skipped: execution exceeded timeout threshold ({timeout_s}s)",
            evidence_json={"pattern": "stage_timeout"},
        ))
        s_semantic = 0.0
        intent_keywords = ["generic"]
        stage_statuses["semantic"] = f"timed out (> {timeout_s}s)"
        model_used = "timeout (skipped)"
    else:
        if demo_mode or backend == "demo":
            model_client = MockGemma(mode=MockMode.AUTO)
            model_used = "demo (MockGemma)"
        else:
            if _is_ollama_online():
                try:
                    from skillsentry.core.models.ollama_client import OllamaClient
                    model_client = OllamaClient()
                    model_used = "local (ollama gemma4:e4b)"
                except Exception:
                    model_client = MockGemma(mode=MockMode.AUTO)
                    model_used = "local (mock fallback)"
# model_used resolved
            else:
                if backend == "local":
                    raise ModelUnavailableError("Local Ollama backend is not accessible on localhost:11434")
                # Auto fallback
                try:
                    from skillsentry.core.models.ollama_client import OllamaClient
                    model_client = OllamaClient()
                    model_used = "local (ollama gemma4:e4b)"
                except Exception:
                    model_client = MockGemma(mode=MockMode.AUTO)
                    model_used = "local (mock fallback)"
# model_used resolved

        if manifest:
            sem_result = analyze_semantics(manifest, anchor_block, raw_anchors, model_client)
            all_findings.extend(sem_result.findings)
            if sem_result.degraded:
                degraded = True
            s_semantic = sem_result.signals.get("semantic_risk", sem_result.signals.get("semantic", 0.0))
            intent_keywords = sem_result.telemetry.get("intent_keywords", ["generic"]) if sem_result.telemetry else ["generic"]
            is_deceptive = sem_result.signals.get("is_deceptive", 0.0) > 0.0
            stage_statuses["semantic"] = "deceptive intent" if is_deceptive else "intent consistent"
        else:
            s_semantic = 0.0
            intent_keywords = ["generic"]
            stage_statuses["semantic"] = "skipped (no manifest)"
            degraded = True

    # Stage 3: Multimodal Vision Scanning
    if timeout_s <= 0 or (time.monotonic() - start_time) >= timeout_s:
        degraded = True
        all_findings.append(Finding(
            stage="vision",
            severity="high",
            message=f"Vision scanning skipped: execution exceeded timeout threshold ({timeout_s}s)",
            evidence_json={"pattern": "stage_timeout"},
        ))
        s_vision = 0.0
        stage_statuses["vision"] = f"timed out (> {timeout_s}s)"
    elif manifest and manifest.assets:
        if model_client is None:
            model_client = MockGemma(mode=MockMode.AUTO)
        vision_result = scan_visual_assets(manifest, model_client, skill_dir)
        all_findings.extend(vision_result.findings)
        if vision_result.degraded:
            degraded = True
        s_vision = vision_result.signals.get("vision_risk", vision_result.signals.get("vision", 0.0))
        v_count = len(vision_result.findings)
        stage_statuses["vision"] = f"{v_count} visual findings"
    else:
        s_vision = 0.0
        stage_statuses["vision"] = "0 visual assets"

    # Stage 4: Dynamic Sandbox Instructions (INT-4)
    if timeout_s <= 0 or (time.monotonic() - start_time) >= timeout_s:
        degraded = True
        all_findings.append(Finding(
            stage="sandbox",
            severity="high",
            message=f"Sandbox instruction generation skipped: execution exceeded timeout threshold ({timeout_s}s)",
            evidence_json={"pattern": "stage_timeout"},
        ))
        instructions: list[SandboxActionInstruction] = []
        stage_statuses["sandbox"] = f"timed out (> {timeout_s}s)"
    else:
        has_traversal = any(
            f.stage == "spec" and (f.evidence_json or {}).get("type") in ("path_traversal", "symlink_escape")
            for f in all_findings
        )
        instructions = generate_sandbox_instructions(
            anchor_findings=raw_anchors,
            stage_findings=all_findings,
            intent_keywords=intent_keywords,
            package_name=skill_name,
            has_path_traversal=has_traversal,
            declared_scripts=list(scripts.keys()) if scripts else None,
        )

        if no_sandbox:
            all_findings.append(Finding(
                stage="sandbox",
                severity="note",
                message="Sandbox execution skipped (--no-sandbox specified); behavioral checks unverified",
            ))
            stage_statuses["sandbox"] = f"{len(instructions)} checks generated (execution skipped)"
            degraded = True
        else:
            stage_statuses["sandbox"] = f"{len(instructions)} checks prepared for Stage 4 execution"

    # Extract C2 Indicators from findings
    for f in all_findings:
        msg = f.message
        ev = f.evidence_json or {}
        code = ev.get("code", "")
        # Match domains or C2 patterns
        for text_source in (msg, code):
            matches = re.findall(r"([a-zA-Z0-9_\-\.]+\.(?:net|com|org|io|xyz|ru|cn|cc))", text_source)
            for m in matches:
                if m not in c2_indicators and not m.endswith(".py"):
                    dec = set()
                    fm = getattr(manifest, "raw_frontmatter", None) or getattr(manifest, "frontmatter", None)
                    if isinstance(fm, dict):
                        dec = set(fm.get("permissions", {}).get("network", []))
                    if not any(m in d or d in m for d in dec):
                        c2_indicators.append(m)

    # Stage 6: Verdict Fusion with Authoritative Floors (DEF-03, N3, N6)
    w_anchors, w_semantic, w_vision = 0.15, 0.20, 0.20
    sum_w = w_anchors + w_semantic + w_vision
    weighted_sum = (w_anchors * s_anchors) + (w_semantic * s_semantic) + (w_vision * s_vision)
    base_risk = round(weighted_sum / sum_w) if sum_w > 0 else 0

    typosquat_bonus = 15 if typosquat_detected else 0
    total_risk = min(100, base_risk + typosquat_bonus)

    # Typed evidence checks (N6: eliminate brittle message substring checking)
    has_evasion = any(a.pattern == "sandbox_evasion" for a in raw_anchors) or any(
        (f.evidence_json or {}).get("pattern") == "sandbox_evasion" for f in all_findings
    )
    has_critical_spec = any(
        f.stage == "spec" and (
            f.severity == "critical" or
            (f.evidence_json or {}).get("type") in ("path_traversal", "symlink_escape") or
            (f.evidence_json or {}).get("pattern") in ("reserved_device", "ntfs_ads")
        )
        for f in all_findings
    )
    anchor_patterns = {a.pattern for a in raw_anchors}
    has_cred_read = "credential_read" in anchor_patterns or any(
        (f.evidence_json or {}).get("pattern") == "credential_read" for f in all_findings
    )
    has_exfil = bool(anchor_patterns & {"requests_post", "nslookup", "urllib_post", "socket_connect"})
    has_cred_exfil = has_cred_read and has_exfil

    has_critical_vision = any(f.stage == "vision" and f.severity == "critical" for f in all_findings)
    has_critical_anchor = any(a.severity == "critical" for a in raw_anchors)
    has_high_anchor = any(a.severity == "high" for a in raw_anchors)

    # Authoritative Floors (DEF-03, N3)
    if has_evasion:
        total_risk = max(total_risk, 85)
    if has_critical_spec:
        total_risk = max(total_risk, 75)
    if has_cred_exfil:
        total_risk = max(total_risk, 75)
    if has_critical_vision:
        total_risk = max(total_risk, 71)
    if has_critical_anchor:
        total_risk = max(total_risk, 60)
    if has_high_anchor:
        total_risk = max(total_risk, 55)
    if degraded:
        total_risk = max(total_risk, 30)

    # Tier mapping: SAFE < 30 <= SUSPICIOUS <= 70 < MALICIOUS
    # Note: Typosquatting or degraded scans must never produce SAFE
    if total_risk < 30:
        verdict = "SUSPICIOUS" if (typosquat_detected or degraded) else "SAFE"
    elif total_risk <= 70:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    confidence = 1.0 if (s_anchors >= 50.0 or typosquat_detected or s_vision >= 70.0) else 0.85
    duration_ms = int((time.monotonic() - start_time) * 1000)

    result_dict: dict[str, Any] = {
        "skill_name": skill_name,
        "skill_path": str(skill_dir).replace("\\", "/"),
        "verdict": verdict,
        "risk_score": total_risk,
        "confidence": confidence,
        "content_hash": content_hash,
        "cached": False,
        "model_used": model_used,
        "stage_statuses": stage_statuses,
        "findings": [f.to_dict() for f in all_findings],
        "sandbox_instructions": [
            {
                "instruction_id": inst.instruction_id,
                "finding_id": inst.finding_id,
                "target_package": inst.target_package,
                "entrypoint_script": inst.entrypoint_script,
                "reason": inst.reason,
                "check_category": inst.check_category,
                "contextual_intent": inst.contextual_intent,
                "execution_parameters": inst.execution_parameters,
                "constraints": inst.constraints,
                "check_status": inst.check_status,
                "status_notes": inst.status_notes,
            }
            for inst in instructions
        ],
        "c2_indicators": c2_indicators,
        "degraded": degraded,
        "scan_duration_ms": duration_ms,
    }

    # Store into SQLite cache if enabled (DEF-09: never cache degraded scans)
    if use_cache and cache_store and not degraded:
        try:
            sarif_doc = generate_sarif_report([result_dict])
            cache_store.put(
                content_hash=content_hash,
                skill_name=skill_name,
                verdict=verdict,
                risk_score=total_risk,
                confidence=confidence,
                verdict_json=json.dumps(result_dict),
                sarif_json=sarif_to_json(sarif_doc),
                engine_version=ENGINE_VERSION,
                model_backend=backend,
                model_version=MODEL_VERSION,
                scan_duration_ms=duration_ms,
            )
        except Exception as e:
            logger.warning(f"Failed to write to cache: {e}")
            degraded = True
            result_dict["degraded"] = True
            all_findings.append(Finding(
                stage="cache",
                severity="medium",
                message=f"Cache write error: {e}; scan integrity marked degraded",
                evidence_json={"pattern": "cache_write_error"},
            ))
            result_dict["findings"] = [f.to_dict() for f in all_findings]
            if result_dict["risk_score"] < 30:
                result_dict["risk_score"] = 30
                result_dict["verdict"] = "SUSPICIOUS"

    return result_dict


# ── Renderers ──────────────────────────────────────────────────────────

def render_terminal_output(results: list[dict[str, Any]], quiet: bool = False) -> str:
    """Render color-coded ANSI terminal report for Windows PowerShell."""
    c = TerminalColors
    lines: list[str] = []

    for res in results:
        skill = res.get("skill_name", "skill")
        verdict = res.get("verdict", "UNKNOWN")
        risk = res.get("risk_score", 0)
        confidence = res.get("confidence", 1.0)
        cached = res.get("cached", False)
        hash_val = res.get("content_hash", "")[:8]
        duration = res.get("scan_duration_ms", 0)
        stages = res.get("stage_statuses", {})
        findings = res.get("findings", [])
        sbx_insts = res.get("sandbox_instructions", [])
        c2s = res.get("c2_indicators", [])

        if verdict == "SAFE":
            verdict_badge = f"{c.GREEN}{c.BOLD}[PASS] SAFE{c.RESET}"
        elif verdict == "SUSPICIOUS":
            verdict_badge = f"{c.YELLOW}{c.BOLD}[WARN] SUSPICIOUS{c.RESET}"
        else:
            verdict_badge = f"{c.RED}{c.BOLD}[FAIL] MALICIOUS{c.RESET}"

        if quiet:
            lines.append(f"{skill}: {verdict} (Risk: {risk}/100)")
            continue

        lines.append(f"\n{c.CYAN}{c.BOLD}[SkillSentry v{ENGINE_VERSION}]{c.RESET} Scanning: {c.WHITE}{c.BOLD}{skill}{c.RESET} (Windows x64)")
        lines.append(f"{c.DIM}------------------------------------------------------------{c.RESET}")

        if cached:
            lines.append(f"  {c.CYAN}[0/7] cache{c.RESET}     {c.GREEN}* HIT{c.RESET} (hash {hash_val}...) -> instant lookup ({duration}ms)")
        else:
            lines.append(f"  {c.CYAN}[0/7] cache{c.RESET}     {stages.get('cache', 'miss')}")
            lines.append(f"  {c.CYAN}[1/7] spec{c.RESET}      {stages.get('spec', 'valid')}")
            lines.append(f"  {c.CYAN}[2/7] typosquat{c.RESET} {stages.get('typosquat', 'clean')}")
            lines.append(f"  {c.CYAN}[3/7] anchors{c.RESET}   {stages.get('anchors', 'clean')}")
            lines.append(f"  {c.CYAN}[4/7] semantic{c.RESET}  {stages.get('semantic', 'analyzed')}")
            lines.append(f"  {c.CYAN}[5/7] vision{c.RESET}    {stages.get('vision', 'clean')}")
            lines.append(f"  {c.CYAN}[6/7] sandbox{c.RESET}   {stages.get('sandbox', 'ready')}")

        lines.append(f"{c.DIM}------------------------------------------------------------{c.RESET}")
        lines.append(f"  {c.BOLD}Verdict:{c.RESET}        {verdict_badge}")
        lines.append(f"  {c.BOLD}Risk Score:{c.RESET}     {risk}/100 (Confidence: {confidence})")
        lines.append(f"  {c.BOLD}Duration:{c.RESET}       {duration}ms")

        if findings:
            lines.append(f"\n  {c.BOLD}Findings ({len(findings)}):{c.RESET}")
            for f in findings:
                sev = f.get("severity", "medium").upper()
                msg = f.get("message", "")
                ev = f.get("evidence", {}) or {}
                f_path = f.get("file") or ev.get("file")
                f_line = f.get("line") or ev.get("line")
                loc = f" ({f_path}:{f_line})" if f_path and f_line else ""

                if sev in ("CRITICAL", "HIGH"):
                    sev_col = c.RED
                elif sev == "MEDIUM":
                    sev_col = c.YELLOW
                else:
                    sev_col = c.DIM

                lines.append(f"    - {sev_col}[{sev}]{c.RESET} {msg}{c.DIM}{loc}{c.RESET}")

        if sbx_insts:
            lines.append(f"\n  {c.BOLD}Dynamic Sandbox Instructions (INT-4):{c.RESET}")
            for inst in sbx_insts:
                cat = inst.get("check_category", "TRIGGER_EXECUTION")
                status = inst.get("check_status", "required")
                reason = inst.get("reason", "")
                script = inst.get("entrypoint_script", "")
                lines.append(f"    - {c.MAGENTA}{cat}{c.RESET} [{status}]: {reason} ({script})")

        if c2s:
            lines.append(f"\n  {c.RED}{c.BOLD}C2 Indicators Detected:{c.RESET} {', '.join(c2s)}")

        lines.append("")

    return "\n".join(lines)


def render_markdown_output(results: list[dict[str, Any]]) -> str:
    """Render markdown table summary."""
    lines: list[str] = [
        f"# SkillSentry v{ENGINE_VERSION} Security Audit Report",
        "",
        "| Skill Name | Verdict | Risk Score | Confidence | Cached | Findings | Duration |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for res in results:
        lines.append(
            f"| `{res['skill_name']}` | **{res['verdict']}** | {res['risk_score']}/100 "
            f"| {res['confidence']} | {res['cached']} | {len(res['findings'])} | {res['scan_duration_ms']}ms |"
        )

    lines.append("")
    return "\n".join(lines)


# ── CLI Entrypoint ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="skillsentry",
        description="SkillSentry: Pre-Installation Security Firewall for AI Agent Skills",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 'scan' subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a skill package or directory of skills")
    scan_parser.add_argument(
        "path",
        type=str,
        help="Path to skill directory or parent directory containing skills",
    )
    scan_parser.add_argument(
        "--sarif-out",
        type=str,
        default=None,
        help="Write full SARIF 2.1.0 JSON report to specified file path",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Bypass Stage 0 cache lookup and do not write to cache",
    )
    scan_parser.add_argument(
        "--no-sandbox",
        action="store_true",
        default=False,
        help="Skip Stage 4 dynamic sandbox execution; record checks as degraded/unverified",
    )
    scan_parser.add_argument(
        "--backend",
        choices=["auto", "local", "cloud", "demo"],
        default="auto",
        help="Model backend (default: auto)",
    )
    scan_parser.add_argument(
        "--demo-mode",
        action="store_true",
        default=False,
        help="Run in offline canned demo mode with zero model/Docker requirements",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Stage execution timeout in seconds (default: 60)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["safe", "suspicious", "malicious"],
        default="suspicious",
        help="Exit code failure threshold (default: suspicious)",
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Quiet mode: suppress progress banners and output final verdict only",
    )
    scan_parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Custom SQLite cache database path (for testing and isolation)",
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI main entry point.

    Returns exit code per the SkillSentry specification:
        0: PASS (All skills pass --fail-on threshold)
        1: GATE FAIL (Verdict exceeded failure threshold)
        2: USAGE ERROR (Invalid arguments, reserved DOS device names, non-existent path)
        3: OPERATIONAL ERROR (Internal database, I/O, or system failure)
        4: MODEL UNAVAILABLE (Local/cloud model offline without fallback)
    """
    _init_windows_console()
    parser = build_parser()

    # Pre-process argv: if 'scan' is not explicitly passed and user is not requesting
    # root-level help, prepend 'scan' as default command for user convenience in PowerShell
    raw_args = list(argv if argv is not None else sys.argv[1:])
    if raw_args and "scan" not in raw_args:
        if raw_args not in (["-h"], ["--help"]):
            raw_args.insert(0, "scan")

    try:
        args = parser.parse_args(raw_args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    if not args.subcommand:
        parser.print_help()
        return 2

    if args.subcommand == "scan":
        # 1. Validate target path
        try:
            target_path = sanitize_and_validate_path(args.path)
            targets = discover_scan_targets(target_path)
        except (ValueError, FileNotFoundError) as e:
            sys.stderr.write(f"Usage Error: {e}\n")
            return 2

        # 2. Execute scans across all discovered skill packages
        results: list[dict[str, Any]] = []
        try:
            for skill_dir in targets:
                res = scan_single_package(
                    skill_dir=skill_dir,
                    use_cache=not args.no_cache,
                    no_sandbox=args.no_sandbox,
                    backend=args.backend,
                    demo_mode=args.demo_mode,
                    timeout_s=args.timeout,
                    db_path=args.db_path,
                )
                results.append(res)
        except ModelUnavailableError as e:
            sys.stderr.write(f"Model Unavailable Error: {e}\n")
            return 4
        except KeyboardInterrupt:
            sys.stderr.write("\nScan cancelled by user (Ctrl+C).\n")
            return 130
        except Exception as e:
            sys.stderr.write(f"Operational Error: {e}\n")
            return 3

        # 3. Export SARIF if requested
        if args.sarif_out:
            try:
                sarif_doc = generate_sarif_report(results)
                sarif_path = Path(args.sarif_out).resolve()
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(sarif_to_json(sarif_doc), encoding="utf-8")
                if not args.quiet and args.format == "text":
                    print(f"Artifact exported: {sarif_path}")
            except Exception as e:
                sys.stderr.write(f"Failed to export SARIF file: {e}\n")
                return 3

        # 4. Render output
        if args.format == "text":
            print(render_terminal_output(results, quiet=args.quiet))
        elif args.format == "json":
            print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        elif args.format == "sarif":
            sarif_doc = generate_sarif_report(results)
            print(sarif_to_json(sarif_doc))
        elif args.format == "markdown":
            print(render_markdown_output(results))

        # 5. Evaluate CI exit code threshold
        fail_threshold = args.fail_on.lower()
        for res in results:
            verdict = res.get("verdict", "SAFE")
            risk = res.get("risk_score", 0)

            if fail_threshold == "safe" and (verdict != "SAFE" or risk >= 30):
                return 1
            if fail_threshold == "suspicious" and (verdict in ("SUSPICIOUS", "MALICIOUS") or risk >= 30):
                return 1
            if fail_threshold == "malicious" and (verdict == "MALICIOUS" or risk > 70):
                return 1

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
