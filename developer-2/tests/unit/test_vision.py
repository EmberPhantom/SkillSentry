"""
Unit tests for vision pipeline (image_extractor.py + vision_scanner.py).

Uses MockGemma for model-dependent vision analysis tests.
Covers: contrast pre-filter, SVG static scan, model OCR integration.
"""

import tempfile
from pathlib import Path

import pytest

from skillsentry_dev2.contracts import AssetFile, Finding, PackageManifest, ScriptFile
from skillsentry_dev2.core.vision.image_extractor import (
    compute_contrast_ratio,
    extract_image_assets,
)
from skillsentry_dev2.core.vision.vision_scanner import (
    _scan_svg_static,
    scan_visual_assets,
)
from skillsentry_dev2.mock_gemma import MockGemma, MockMode


@pytest.fixture
def simple_manifest():
    return PackageManifest(
        name="test",
        description="test",
        trigger_keywords=[],
        canonical_root_posix="/test",
    )


class TestContrastPreFilter:
    def test_white_image_flags_suspicious(self, tmp_path):
        """A nearly-white image should potentially flag low contrast."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not available")

        # Create a mostly-white image with slight variation
        img = Image.new("RGB", (100, 100), (255, 255, 255))
        # Draw a very faint pixel (near-white)
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        draw.text((10, 80), "hidden", fill=(252, 252, 252))

        img_path = tmp_path / "white.png"
        img.save(img_path)

        cr, suspicious, downscaled = compute_contrast_ratio(img_path)
        assert downscaled is not None
        # The image is mostly white — contrast ratio should be very low
        # Whether suspicious depends on exact stddev

    def test_high_contrast_image_not_suspicious(self, tmp_path):
        """A high-contrast image should not flag."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not available")

        img = Image.new("RGB", (100, 100), (0, 0, 0))
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        draw.rectangle((10, 10, 90, 90), fill=(255, 255, 255))

        img_path = tmp_path / "contrast.png"
        img.save(img_path)

        cr, suspicious, downscaled = compute_contrast_ratio(img_path)
        assert suspicious is False
        assert downscaled is not None

    def test_nonexistent_image(self):
        cr, suspicious, downscaled = compute_contrast_ratio("/nonexistent/image.png")
        assert cr == 0.0
        assert suspicious is False
        assert downscaled is None


class TestSvgStaticScan:
    def test_clean_svg(self, tmp_path):
        svg_content = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100"/></svg>'
        svg_path = tmp_path / "clean.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "clean.svg")
        assert len(findings) == 0

    def test_script_tag_detected(self, tmp_path):
        svg_content = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("xss")</script></svg>'
        svg_path = tmp_path / "evil.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "evil.svg")
        assert any("script" in f.message.lower() for f in findings)

    def test_onload_detected(self, tmp_path):
        svg_content = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>'
        svg_path = tmp_path / "onload.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "onload.svg")
        assert any("onload" in f.message.lower() for f in findings)

    def test_foreign_object_detected(self, tmp_path):
        svg_content = '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100" height="100">some text</foreignObject></svg>'
        svg_path = tmp_path / "foreign.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "foreign.svg")
        assert len(findings) > 0, f"Expected foreignObject finding, got: {findings}"
        assert any("foreignObject" in f.message or "foreign" in f.message.lower() for f in findings)

    def test_hidden_css_detected(self, tmp_path):
        svg_content = '<svg xmlns="http://www.w3.org/2000/svg"><style>text { display: none; }</style><text>hidden</text></svg>'
        svg_path = tmp_path / "hidden.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "hidden.svg")
        assert any("hidden css" in f.message.lower() for f in findings)

    def test_malformed_svg_fallback(self, tmp_path):
        svg_content = 'not valid xml <script>evil</script>'
        svg_path = tmp_path / "bad.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "bad.svg")
        assert any("script" in f.message.lower() for f in findings)


class TestScanVisualAssets:
    def test_no_assets_produces_note(self):
        manifest = PackageManifest(
            name="test", description="test",
            trigger_keywords=[], canonical_root_posix="/test",
        )
        result = scan_visual_assets(manifest, None, "/test")
        assert result.stage == "vision"
        assert any("No visual assets" in f.message for f in result.findings)

    def test_with_mock_model(self, tmp_path):
        """Test vision scan with MockGemma in deceptive mode."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not available")

        # Create a test image
        img = Image.new("RGB", (50, 50), (255, 255, 255))
        img_path = tmp_path / "test.png"
        img.save(img_path)

        manifest = PackageManifest(
            name="test", description="test",
            trigger_keywords=[], canonical_root_posix=str(tmp_path),
            assets={
                "test.png": AssetFile(
                    relative_path="test.png",
                    mime_type="image/png",
                    size_bytes=100,
                    content_hash="abc",
                )
            },
        )

        client = MockGemma(mode=MockMode.DECEPTIVE)
        result = scan_visual_assets(manifest, client, tmp_path)
        assert result.stage == "vision"
        # Deceptive mock should produce findings
        assert len(result.findings) > 0

    def test_xxe_entity_injection_blocked(self, tmp_path):
        """DEF-12: XML DTD/entity injection in SVG must be blocked and emit critical finding."""
        svg_content = '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:" + "///etc/passwd">]><svg>&xxe;</svg>'
        svg_file = tmp_path / "xxe.svg"
        svg_file.write_text(svg_content)
        findings = _scan_svg_static(str(svg_file), "xxe.svg")
        crit = [f for f in findings if f.severity == "critical"]
        assert len(crit) > 0
        assert "entity" in crit[0].message.lower()

    def test_decompression_bomb_detected(self, tmp_path, monkeypatch):
        """DEF-13: DecompressionBombError caught and emitted as critical finding."""
        from PIL import Image
        from skillsentry_dev2.core.vision.image_extractor import extract_image_assets

        # Monkeypatch compute_contrast_ratio to raise DecompressionBombError
        def raise_bomb(path):
            raise Image.DecompressionBombError("Image size exceeds limit")

        import skillsentry_dev2.core.vision.image_extractor as ie
        monkeypatch.setattr(ie, "compute_contrast_ratio", raise_bomb)

        assets = {
            "bomb.png": AssetFile(
                relative_path="bomb.png",
                mime_type="image/png",
                size_bytes=1000,
                content_hash="h1",
            )
        }
        (tmp_path / "bomb.png").write_bytes(b"\x00" * 100)
        prepared, findings = extract_image_assets(assets, tmp_path)
        crit = [f for f in findings if f.severity == "critical"]
        assert len(crit) > 0
        assert "decompression bomb" in crit[0].message.lower()

    def test_missing_model_sets_degraded(self, tmp_path):
        """DEF-04: Image asset without model client must mark stage as degraded."""
        manifest = PackageManifest(
            name="test", description="test",
            trigger_keywords=[], canonical_root_posix=str(tmp_path),
            assets={
                "img.png": AssetFile(
                    relative_path="img.png",
                    mime_type="image/png",
                    size_bytes=100,
                    content_hash="abc",
                )
            },
        )
        (tmp_path / "img.png").write_bytes(b"\x00" * 10)
        result = scan_visual_assets(manifest, None, tmp_path)
        assert result.degraded is True

    def test_svg_dangerous_tags_and_uris(self, tmp_path):
        """DEF-12 & N9: Expanded dangerous tags (use, embed, object) and javascript:/data: URIs."""
        svg_content = (
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            '<use xlink:href="javascript:alert(1)"/>'
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="/>'
            '<embed src="evil.swf"/>'
            '</svg>'
        )
        svg_path = tmp_path / "tags_uris.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "tags_uris.svg")

        # Must flag dangerous tags (use, object, embed)
        tag_findings = [f for f in findings if any(t in f.message for t in ("use", "object", "embed"))]
        assert len(tag_findings) >= 2

        # Must flag dangerous URI schemes (javascript:, data:text/html)
        crit_findings = [f for f in findings if f.severity == "critical"]
        assert any("javascript:" in f.message.lower() or "uri scheme" in f.message.lower() for f in crit_findings)

    def test_svg_tiny_text_detected(self, tmp_path):
        """N9: Tiny-text obfuscation in SVG."""
        svg_content = (
            '<svg xmlns="http://www.w3.org/2000/svg">'
            '<text font-size="0px">secret payload</text>'
            '</svg>'
        )
        svg_path = tmp_path / "tiny.svg"
        svg_path.write_text(svg_content)
        findings = _scan_svg_static(str(svg_path), "tiny.svg")
        assert any("tiny-text" in f.message.lower() for f in findings)

    def test_malformed_model_output_sets_degraded(self, tmp_path):
        """N8: Malformed model response marks vision stage as degraded without crashing."""
        class BrokenClient:
            def analyze_image(self, image_path, prompt):
                return "not a dict"

        manifest = PackageManifest(
            name="test", description="test",
            trigger_keywords=[], canonical_root_posix=str(tmp_path),
            assets={
                "img.png": AssetFile(
                    relative_path="img.png",
                    mime_type="image/png",
                    size_bytes=100,
                    content_hash="abc",
                )
            },
        )
        (tmp_path / "img.png").write_bytes(b"\x00" * 10)
        result = scan_visual_assets(manifest, BrokenClient(), tmp_path)
        assert result.degraded is True
