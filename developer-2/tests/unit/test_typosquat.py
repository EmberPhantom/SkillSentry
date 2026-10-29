"""
Unit tests for typosquat.py (Stage 1 — Typosquatting Detection).

Covers: homoglyph folding, Damerau-Levenshtein distance, known skill detection,
legitimate pair exclusion, edge cases.
"""

import pytest

from skillsentry_dev2.core.parser.typosquat import (
    KNOWN_SKILLS,
    LEGITIMATE_PAIRS,
    _damerau_levenshtein,
    _fold_homoglyphs,
    check_typosquat,
)


class TestHomoglyphFolding:
    def test_digit_one_to_l(self):
        assert _fold_homoglyphs("g1t") == "glt"

    def test_zero_to_o(self):
        assert _fold_homoglyphs("g0ogle") == "google"

    def test_at_sign_to_a(self):
        assert _fold_homoglyphs("sl@ck") == "slack"

    def test_multi_vv_to_w(self):
        assert _fold_homoglyphs("vveather") == "weather"

    def test_multi_rn_to_m(self):
        assert _fold_homoglyphs("rnain") == "main"

    def test_case_insensitive(self):
        assert _fold_homoglyphs("G1T") == "glt"

    def test_clean_name_unchanged(self):
        assert _fold_homoglyphs("git-helper") == "git-helper"


class TestDamerauLevenshtein:
    def test_identical_strings(self):
        assert _damerau_levenshtein("hello", "hello") == 0

    def test_single_insertion(self):
        assert _damerau_levenshtein("hell", "hello") == 1

    def test_single_deletion(self):
        assert _damerau_levenshtein("hello", "hell") == 1

    def test_single_substitution(self):
        assert _damerau_levenshtein("hello", "hallo") == 1

    def test_transposition(self):
        assert _damerau_levenshtein("ab", "ba") == 1

    def test_distance_two(self):
        # Two substitutions
        assert _damerau_levenshtein("abc", "xyz") == 3

    def test_empty_strings(self):
        assert _damerau_levenshtein("", "") == 0

    def test_one_empty(self):
        assert _damerau_levenshtein("abc", "") == 3
        assert _damerau_levenshtein("", "abc") == 3


class TestCheckTyposquat:
    def test_g1t_translate_detected(self):
        """g1t-translate should be detected as a typosquat of git-translate."""
        result = check_typosquat("g1t-translate")
        assert result.signals.get("typosquat_detected", 0) == 100.0
        assert len(result.findings) > 0
        assert any("git-translate" in f.message for f in result.findings)

    def test_exact_name_not_flagged(self):
        """An exact match with a known skill should NOT be flagged."""
        result = check_typosquat("git-translate")
        assert result.signals.get("typosquat_detected", 0) == 0.0
        assert len(result.findings) == 0

    def test_git_helper_no_false_positive(self):
        """git-helper is a legitimate name — should NOT be flagged as typosquat
        of git-translate (legitimate pair exclusion)."""
        result = check_typosquat("git-helper")
        assert result.signals.get("typosquat_detected", 0) == 0.0

    def test_completely_different_name(self):
        """A completely unique name should not trigger."""
        result = check_typosquat("my-unique-custom-tool-xyz")
        assert result.signals.get("typosquat_detected", 0) == 0.0
        assert len(result.findings) == 0

    def test_empty_name(self):
        result = check_typosquat("")
        assert result.stage == "typosquat"
        assert result.signals.get("typosquat_detected", 0) == 0.0

    def test_sl4ck_notify(self):
        """sl4ck-notify (leet-speak 'a') should match slack-notify."""
        result = check_typosquat("sl4ck-notify")
        assert result.signals.get("typosquat_detected", 0) == 100.0

    def test_distance_one_substitution(self):
        """'git-translat' (missing 'e') is distance 1 from git-translate."""
        result = check_typosquat("git-translat")
        assert result.signals.get("typosquat_detected", 0) == 100.0

    def test_distance_three_not_detected(self):
        """Names with distance > 2 should not match."""
        result = check_typosquat("gxt-trnslat")
        # Distance would be > 2 from any known skill
        assert len(result.findings) == 0

    def test_custom_dictionary(self):
        """Test with a custom known_skills list."""
        result = check_typosquat("my-t00l", known_skills=["my-tool"])
        assert result.signals.get("typosquat_detected", 0) == 100.0

    def test_stage_is_typosquat(self):
        result = check_typosquat("anything")
        assert result.stage == "typosquat"

    def test_case_variant_impersonation(self):
        """DEF-15: Case variant impersonation e.g. Git-Helper vs git-helper must be flagged."""
        result = check_typosquat("Git-Helper")
        assert result.signals.get("typosquat_detected", 0) == 100.0
        assert any("case-variant" in f.message for f in result.findings)

    def test_unicode_nfkc_and_cyrillic_homoglyphs(self):
        """DEF-15: Unicode NFKC and Cyrillic homoglyphs must be detected."""
        # Using Cyrillic 'а' (U+0430) instead of ASCII 'a'
        cyrillic_name = "git-tr\u0430nslate"
        result = check_typosquat(cyrillic_name)
        assert result.signals.get("typosquat_detected", 0) == 100.0


class TestDictionaryLoading:
    def test_dictionary_path_exists(self):
        from skillsentry_dev2.core.parser.typosquat import _DICTIONARY_PATH
        assert _DICTIONARY_PATH.exists(), f"Dictionary file not found at: {_DICTIONARY_PATH}"

    def test_load_known_skills_from_file_nonempty(self):
        from skillsentry_dev2.core.parser.typosquat import _load_known_skills_from_file
        skills = _load_known_skills_from_file()
        assert len(skills) >= 50
        assert "git-translate" in skills
        assert "slack-bot" in skills

    def test_load_legitimate_pairs_nonempty(self):
        from skillsentry_dev2.core.parser.typosquat import _load_legitimate_pairs_from_file
        pairs = _load_legitimate_pairs_from_file()
        assert len(pairs) >= 4
        assert ("git-helper", "git-translate") in pairs

    def test_curator_stats_output(self, capsys):
        from skillsentry_dev2.core.parser.typosquat_curator import cmd_stats, _load
        data = _load()
        cmd_stats(data)
        captured = capsys.readouterr()
        assert "Total skills:" in captured.out
        assert "55" in captured.out


