"""Vision budget: raster images beyond the per-scan model budget are reported, not skipped silently."""

from __future__ import annotations

from pathlib import Path

from PIL import Image
from skill_sentry_cli.core.contracts import ImageAnalysis
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.vision import vision_scanner as scanner


class _CountingVision:
    backend = "fake"
    model_version = "fake@1"

    def __init__(self) -> None:
        self.calls = 0

    def analyze_image(self, path, prompt):  # type: ignore[no-untyped-def]
        self.calls += 1
        return ImageAnalysis()

    def generate_json(self, system, user, schema, retries=1):  # type: ignore[no-untyped-def]
        raise AssertionError("text path not used in this test")

    def health(self) -> bool:
        return True


def _skill_with_images(root: Path, count: int) -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: pics\ndescription: Images\n---\nBody\n", encoding="utf-8"
    )
    (root / "assets").mkdir()
    for index in range(count):
        Image.new("RGB", (32, 32), (index * 10, 40, 200)).save(root / "assets" / f"img{index}.png")
    return root


def test_model_calls_are_capped_and_the_rest_are_partial(tmp_path: Path) -> None:
    package = parse_skill(_skill_with_images(tmp_path / "skill", 5))
    model = _CountingVision()

    stage = scanner.scan_vision(package, model)

    assert model.calls == scanner.MAX_MODEL_IMAGES
    assert stage.degraded is True
    assert stage.telemetry["vision_status"] == "partial"


def test_within_budget_is_fully_evaluated(tmp_path: Path) -> None:
    package = parse_skill(_skill_with_images(tmp_path / "skill", 2))
    model = _CountingVision()

    stage = scanner.scan_vision(package, model)

    assert model.calls == 2
    assert stage.degraded is False
    assert stage.telemetry["vision_status"] == "evaluated"
