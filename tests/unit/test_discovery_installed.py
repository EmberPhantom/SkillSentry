"""Installed-skill discovery against a fake home (``tmp_path``); never the real home."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from skill_sentry_cli.core.config import (
    ConfigError,
    DiscoverySettings,
    SkillsEntryConfig,
    load_config,
)
from skill_sentry_cli.core.discovery import finder
from skill_sentry_cli.core.discovery.claude_plugins import enabled_plugin_skill_roots
from skill_sentry_cli.core.discovery.finder import discover_installed
from skill_sentry_cli.core.discovery.sources import known_sources

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")


def _skill(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {folder.name}\ndescription: test skill\n---\nBody.\n", encoding="utf-8"
    )
    return folder


def _names(result, scope: str | None = None) -> set[str]:
    return {s.name for s in result.skills if scope is None or s.scope == scope}


def _write_settings(home: Path, text: str) -> None:
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    (home / ".claude" / "settings.json").write_text(text, encoding="utf-8")


@needs_symlinks
def test_symlinked_skill_is_deduped_across_three_agent_dirs(tmp_path: Path):
    home = tmp_path / "home"
    target = _skill(tmp_path / "system" / "omarchy")
    for base in (".claude/skills", ".agents/skills", ".codex/skills"):
        folder = home / base
        folder.mkdir(parents=True)
        os.symlink(target, folder / "omarchy")

    result = discover_installed(home=home, project_dir=None)

    assert len(result.skills) == 1
    skill = result.skills[0]
    assert skill.name == "omarchy"
    assert skill.agent == "claude"  # claude is first in precedence
    assert skill.scope == "user"
    assert skill.is_symlink is True
    assert skill.real_path == target.resolve()
    assert skill.declared_path == home / ".claude" / "skills" / "omarchy"
    assert set(skill.aliases) == {
        home / ".agents" / "skills" / "omarchy",
        home / ".codex" / "skills" / "omarchy",
    }
    assert result.duplicates_merged == 2


@needs_symlinks
def test_broken_symlink_is_skipped_with_reason(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    os.symlink(tmp_path / "nowhere", home / ".claude" / "skills" / "gone")

    result = discover_installed(home=home, project_dir=None)

    assert result.skills == []
    assert any("gone" in note and "broken symlink" in note for note in result.skipped)


def test_non_skill_children_are_skipped_not_listed(tmp_path: Path):
    home = tmp_path / "home"
    base = home / ".codex" / "skills"
    _skill(base / "real-one")
    (base / "empty-dir").mkdir()
    (base / "notes.txt").write_text("hi", encoding="utf-8")

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == {"real-one"}
    assert any("empty-dir" in note and "no SKILL.md" in note for note in result.skipped)
    assert any("notes.txt" in note for note in result.skipped)


def test_enabled_plugin_is_included_and_disabled_and_uninstalled_are_not(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(
        home,
        json.dumps({"enabledPlugins": {"on@market": True, "off@market": False}}),
    )
    checkout = home / ".claude" / "plugins" / "marketplaces" / "market"
    _skill(checkout / "plugins" / "on" / "skills" / "on-skill")
    _skill(checkout / "plugins" / "off" / "skills" / "off-skill")
    # Present in the marketplace checkout but never enabled: must never be listed.
    _skill(checkout / "plugins" / "uninstalled" / "skills" / "uninstalled-skill")

    result = discover_installed(home=home, project_dir=None)

    assert _names(result, "plugin") == {"on-skill"}
    assert all(s.agent == "claude" for s in result.skills if s.scope == "plugin")
    assert "off-skill" not in _names(result)
    assert "uninstalled-skill" not in _names(result)


def test_plugin_install_path_from_installed_plugins_json(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(home, json.dumps({"enabledPlugins": {"tool@market": True}}))
    install = tmp_path / "cache" / "tool" / "1.2.3"
    _skill(install / "skills" / "tool-skill")
    installed = {
        "version": 2,
        "plugins": {
            "tool@market": [
                {"scope": "user", "installPath": str(install), "version": "1.2.3"},
            ]
        },
    }
    (home / ".claude" / "plugins").mkdir(parents=True)
    (home / ".claude" / "plugins" / "installed_plugins.json").write_text(
        json.dumps(installed), encoding="utf-8"
    )

    roots, notes = enabled_plugin_skill_roots(home)

    assert [root.base for root in roots] == [install / "skills"]
    assert notes == []
    assert _names(discover_installed(home=home, project_dir=None), "plugin") == {"tool-skill"}


def test_malformed_settings_gives_a_note_and_does_not_raise(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(home, "{ this is not json")
    _skill(home / ".codex" / "skills" / "still-found")

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == {"still-found"}
    assert any("could not parse" in note for note in result.skipped)


def test_settings_with_unexpected_shape_gives_a_note(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(home, json.dumps({"enabledPlugins": ["not", "a", "dict"]}))

    roots, notes = enabled_plugin_skill_roots(home)

    assert roots == []
    assert any("enabledPlugins" in note for note in notes)


def test_project_sources_are_found_only_with_project_dir(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _skill(project / ".claude" / "skills" / "proj-claude")
    _skill(project / ".agents" / "skills" / "proj-agents")

    without = discover_installed(home=home, project_dir=None)
    with_project = discover_installed(home=home, project_dir=project)

    assert _names(without) == set()
    assert _names(with_project, "project") == {"proj-claude", "proj-agents"}
    agents = {s.name: s.agent for s in with_project.skills}
    assert agents == {"proj-claude": "claude", "proj-agents": "agents"}


def test_extra_path_as_skill_folder_and_as_folder_of_skills(tmp_path: Path):
    home = tmp_path / "home"
    single = _skill(tmp_path / "solo" / "lone-skill")
    bundle = tmp_path / "bundle"
    _skill(bundle / "bundled-a")
    _skill(bundle / "bundled-b")

    result = discover_installed(home=home, project_dir=None, extra_paths=[single, bundle])

    assert _names(result, "custom") == {"lone-skill", "bundled-a", "bundled-b"}
    assert {s.agent for s in result.skills} == {"custom"}


def test_missing_extra_path_is_noted(tmp_path: Path):
    result = discover_installed(
        home=tmp_path / "home", project_dir=None, extra_paths=[tmp_path / "absent"]
    )
    assert result.skills == []
    assert result.missing_paths == [tmp_path / "absent"]
    assert any("absent" in note and "not found" in note for note in result.skipped)
    assert result.set_aside == 0


@needs_symlinks
def test_set_aside_counts_broken_links_and_folders_without_manifest(tmp_path: Path):
    home = tmp_path / "home"
    base = home / ".claude" / "skills"
    _skill(base / "real-one")
    (base / "empty-dir").mkdir()
    (base / "notes.txt").write_text("hi", encoding="utf-8")
    os.symlink(tmp_path / "nowhere", base / "gone", target_is_directory=True)

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == {"real-one"}
    assert result.set_aside == 3
    assert len(result.skipped) == 3
    assert result.missing_paths == []


@pytest.mark.skipif(sys.platform == "win32", reason="permissions are not enforced on Windows")
def test_set_aside_counts_unreadable_entries(tmp_path: Path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("permissions are not enforced for root")
    home = tmp_path / "home"
    locked = _skill(home / ".codex" / "skills" / "locked")
    locked.chmod(0o000)
    try:
        result = discover_installed(home=home, project_dir=None)
    finally:
        locked.chmod(0o755)

    assert result.set_aside == 1
    assert any("locked" in note for note in result.skipped)


def test_set_aside_ignores_plugin_notes_and_the_cap_note(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(finder, "MAX_DISCOVERED_SKILLS", 2)
    home = tmp_path / "home"
    _write_settings(home, json.dumps({"enabledPlugins": {"ghost@market": True}}))
    for index in range(4):
        _skill(home / ".codex" / "skills" / f"skill-{index}")

    result = discover_installed(home=home, project_dir=None)

    assert any("ghost@market" in note for note in result.skipped)
    assert any("stopped after 2 skills" in note for note in result.skipped)
    assert result.set_aside == 0


def test_agents_filter_limits_sources(tmp_path: Path):
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "c-skill")
    _skill(home / ".codex" / "skills" / "x-skill")
    _skill(home / ".agents" / "skills" / "a-skill")

    only_codex = discover_installed(home=home, project_dir=None, agents=["codex"])
    assert _names(only_codex) == {"x-skill"}
    assert all(".claude" not in path.parts for path in only_codex.checked)

    everything = discover_installed(home=home, project_dir=None)
    assert _names(everything) == {"c-skill", "x-skill", "a-skill"}


def test_experimental_sources_are_gated(tmp_path: Path):
    home = tmp_path / "home"
    _skill(home / ".cursor" / "skills" / "cursor-skill")
    _skill(home / ".gemini" / "extensions" / "ext1" / "skills" / "gem-skill")

    off = discover_installed(home=home, project_dir=None)
    on = discover_installed(home=home, project_dir=None, include_experimental=True)

    assert _names(off) == set()
    assert _names(on) == {"cursor-skill", "gem-skill"}


def test_cap_stops_discovery_and_notes_truncation(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(finder, "MAX_DISCOVERED_SKILLS", 3)
    home = tmp_path / "home"
    for index in range(5):
        _skill(home / ".codex" / "skills" / f"skill-{index}")

    result = discover_installed(home=home, project_dir=None)

    assert len(result.skills) == 3
    assert result.not_scanned == 2
    assert any(
        "stopped after 3 skills; 2 more not scanned; narrow the search (for example with --agent)"
        in note
        for note in result.skipped
    )


def test_cap_count_is_capped_and_reported_as_at_least(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(finder, "MAX_DISCOVERED_SKILLS", 2)
    monkeypatch.setattr(finder, "_COUNT_BOUND", 3)
    home = tmp_path / "home"
    for index in range(10):
        _skill(home / ".codex" / "skills" / f"skill-{index:02d}")

    result = discover_installed(home=home, project_dir=None)

    assert len(result.skills) == 2
    assert result.not_scanned == 3
    assert any("stopped after 2 skills; at least 3 more not scanned" in n for n in result.skipped)


def test_cap_counts_unique_skills_beyond_the_cap_once(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(finder, "MAX_DISCOVERED_SKILLS", 1)
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "kept")
    _skill(home / ".codex" / "skills" / "extra")
    _skill(home / ".agents" / "skills" / "extra-dupe-path")
    target = home / ".agents" / "skills" / "extra-dupe-path"
    # The same folder under a second base must count once, not twice.
    (home / ".codex" / "skills" / "extra-link").symlink_to(target)

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == {"kept"}
    assert result.not_scanned == 2
    assert any("stopped after 1 skills; 2 more not scanned" in n for n in result.skipped)


def test_no_cap_note_when_everything_fits(tmp_path: Path):
    home = _home_with_three_skills(tmp_path)

    result = discover_installed(home=home, project_dir=None)

    assert result.not_scanned == 0
    assert not any("stopped after" in note for note in result.skipped)


def test_unreadable_skill_folder_is_skipped_not_raised(tmp_path: Path):
    if sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("permissions are not enforced here")
    home = tmp_path / "home"
    locked = _skill(home / ".codex" / "skills" / "locked")
    _skill(home / ".codex" / "skills" / "open")
    locked.chmod(0o000)
    try:
        result = discover_installed(home=home, project_dir=None)
    finally:
        locked.chmod(0o755)

    assert _names(result) == {"open"}
    assert any("locked" in note for note in result.skipped)


def test_unlistable_base_is_skipped_not_raised(tmp_path: Path):
    if sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("permissions are not enforced here")
    home = tmp_path / "home"
    base = home / ".codex" / "skills"
    _skill(base / "hidden")
    base.chmod(0o000)
    try:
        result = discover_installed(home=home, project_dir=None)
    finally:
        base.chmod(0o755)

    assert result.skills == []
    assert any("cannot list folder" in note for note in result.skipped)


def test_checked_lists_missing_bases(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    result = discover_installed(home=home, project_dir=project)

    assert home / ".claude" / "skills" in result.checked
    assert home / ".codex" / "skills" in result.checked
    assert project / ".claude" / "skills" in result.checked
    assert not (home / ".codex" / "skills").exists()


def test_known_sources_uses_only_the_given_home(tmp_path: Path):
    sources = known_sources(tmp_path / "home", None)
    assert all(str(s.base).startswith(str(tmp_path / "home")) for s in sources)
    verified = {
        (s.agent, str(s.base.relative_to(tmp_path / "home"))) for s in sources if not s.experimental
    }
    assert ("claude", os.path.join(".claude", "skills")) in verified
    assert ("codex", os.path.join(".codex", "skills")) in verified
    assert ("agents", os.path.join(".agents", "skills")) in verified


def test_discovery_settings_defaults_and_validation():
    settings = SkillsEntryConfig().discovery
    assert settings == DiscoverySettings()
    assert settings.extra_paths == []
    assert settings.agents == []
    assert settings.include_experimental is False

    with pytest.raises(ValueError):
        DiscoverySettings(extra_paths=["relative/skills"])
    with pytest.raises(ValueError):
        DiscoverySettings(extra_paths=["   "])
    with pytest.raises(ValueError):
        DiscoverySettings(agents=["vim"])
    assert DiscoverySettings(extra_paths=["  ~/skills  "], agents=[" Codex "]).extra_paths == [
        "~/skills"
    ]


def test_discovery_section_loads_from_file_and_rejects_bad_keys(tmp_path: Path):
    file = tmp_path / "skillsentry.toml"
    # TOML literal (single-quoted) strings keep Windows backslashes intact.
    extra = str(tmp_path / "opt-skills")
    file.write_text(
        f"[discovery]\nextra_paths = ['{extra}']\nagents = [\"claude\"]\n"
        "include_experimental = true\n",
        encoding="utf-8",
    )
    config = load_config(file)
    assert config.discovery.extra_paths == [extra]
    assert config.discovery.agents == ["claude"]
    assert config.discovery.include_experimental is True

    file.write_text('[discovery]\nextra = ["x"]\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(file)


def test_extra_skill_paths_env_override(tmp_path: Path, monkeypatch):
    first = str(tmp_path / "one")
    second = str(tmp_path / "two")
    monkeypatch.setenv("SKILLSENTRY_EXTRA_SKILL_PATHS", os.pathsep.join([first, "", second]))
    monkeypatch.setenv("SKILLSENTRY_CONFIG", str(tmp_path / "missing-is-ok.toml"))
    (tmp_path / "missing-is-ok.toml").write_text("", encoding="utf-8")

    assert load_config().discovery.extra_paths == [first, second]


def test_env_override_beats_file(tmp_path: Path, monkeypatch):
    from_env = str(tmp_path / "env")
    file = tmp_path / "skillsentry.toml"
    file.write_text(f"[discovery]\nextra_paths = ['{tmp_path / 'file'}']\n", encoding="utf-8")
    monkeypatch.setenv("SKILLSENTRY_EXTRA_SKILL_PATHS", from_env)

    assert load_config(file).discovery.extra_paths == [from_env]


def test_synced_group_folders_are_searched_but_hidden_buckets_are_not(tmp_path: Path):
    home = tmp_path / "home"
    synced = home / ".claude" / "skills" / "synced" / "acct_1"
    _skill(synced / "pdf")
    _skill(synced / "xlsx")
    _skill(home / ".claude" / "skills" / "synced" / ".bucket-acct_1" / "hidden-skill")

    result = discover_installed(home=home, project_dir=None)
    assert _names(result) == {"pdf", "xlsx"}


def test_group_search_is_depth_bounded(tmp_path: Path):
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "a" / "b" / "c" / "too-deep")

    assert _names(discover_installed(home=home, project_dir=None)) == set()


def test_agents_filter_keeps_custom_paths(tmp_path: Path):
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "c-skill")
    mine = _skill(tmp_path / "mine" / "my-skill")

    result = discover_installed(home=home, project_dir=None, extra_paths=[mine], agents=["codex"])
    assert _names(result) == {"my-skill"}


def test_missing_claude_settings_is_silent(tmp_path: Path):
    roots, notes = enabled_plugin_skill_roots(tmp_path / "home")
    assert roots == [] and notes == []


def _home_with_three_skills(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "one")
    _skill(home / ".claude" / "skills" / "two")
    _skill(home / ".codex" / "skills" / "three")
    return home


def test_project_dir_equal_to_home_keeps_user_scope_and_counts_no_duplicates(tmp_path: Path):
    home = _home_with_three_skills(tmp_path)

    result = discover_installed(home=home, project_dir=home)

    assert len(result.skills) == 3
    assert {s.scope for s in result.skills} == {"user"}
    assert result.duplicates_merged == 0
    assert all(skill.aliases == () for skill in result.skills)


@needs_symlinks
def test_project_dir_equal_to_home_with_agents_symlink_counts_one_duplicate(tmp_path: Path):
    home = _home_with_three_skills(tmp_path)
    (home / ".agents" / "skills").mkdir(parents=True)
    os.symlink(home / ".claude" / "skills" / "one", home / ".agents" / "skills" / "one")

    result = discover_installed(home=home, project_dir=home)

    assert len(result.skills) == 3
    assert {s.scope for s in result.skills} == {"user"}
    assert result.duplicates_merged == 1
    one = next(s for s in result.skills if s.name == "one")
    assert one.aliases == (home / ".agents" / "skills" / "one",)


def test_project_inside_home_keeps_project_scope(tmp_path: Path):
    home = _home_with_three_skills(tmp_path)
    project = home / "work" / "app"
    _skill(project / ".claude" / "skills" / "local-only")

    result = discover_installed(home=home, project_dir=project)

    by_name = {s.name: s.scope for s in result.skills}
    assert by_name["local-only"] == "project"
    assert by_name["one"] == by_name["two"] == by_name["three"] == "user"
    assert result.duplicates_merged == 0


@needs_symlinks
def test_same_skill_linked_from_two_agents_is_one_skill_one_duplicate(tmp_path: Path):
    home = tmp_path / "home"
    target = _skill(tmp_path / "store" / "shared")
    for base in (".claude/skills", ".codex/skills"):
        (home / base).mkdir(parents=True)
        os.symlink(target, home / base / "shared")

    result = discover_installed(home=home, project_dir=None)

    assert [s.name for s in result.skills] == ["shared"]
    assert result.skills[0].scope == "user"
    assert result.duplicates_merged == 1
    assert len(result.skills[0].aliases) == 1


# B1: project-level enabledPlugins ----------------------------------------------------------


def _write_project_settings(project: Path, name: str, text: str) -> None:
    (project / ".claude").mkdir(parents=True, exist_ok=True)
    (project / ".claude" / name).write_text(text, encoding="utf-8")


def _plugin_checkout(home: Path, plugin: str, skill: str) -> None:
    checkout = home / ".claude" / "plugins" / "marketplaces" / "market"
    _skill(checkout / "plugins" / plugin / "skills" / skill)


def test_project_settings_enable_a_plugin_the_user_file_does_not_mention(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _write_settings(home, json.dumps({"enabledPlugins": {}}))
    _write_project_settings(
        project, "settings.json", json.dumps({"enabledPlugins": {"p@market": True}})
    )
    _plugin_checkout(home, "p", "proj-plugin-skill")

    roots, notes = enabled_plugin_skill_roots(home, project)

    assert len(roots) == 1 and notes == []
    result = discover_installed(home=home, project_dir=project)
    assert _names(result, "plugin") == {"proj-plugin-skill"}


def test_project_local_settings_disable_what_project_settings_enable(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _write_project_settings(
        project, "settings.json", json.dumps({"enabledPlugins": {"p@market": True}})
    )
    _write_project_settings(
        project, "settings.local.json", json.dumps({"enabledPlugins": {"p@market": False}})
    )
    _plugin_checkout(home, "p", "local-off-skill")

    roots, _ = enabled_plugin_skill_roots(home, project)

    assert roots == []
    assert _names(discover_installed(home=home, project_dir=project), "plugin") == set()


def test_project_false_disables_a_plugin_the_user_enabled(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _write_settings(home, json.dumps({"enabledPlugins": {"p@market": True}}))
    _write_project_settings(
        project, "settings.json", json.dumps({"enabledPlugins": {"p@market": False}})
    )
    _plugin_checkout(home, "p", "user-on-skill")

    roots, notes = enabled_plugin_skill_roots(home, project)

    assert roots == [] and notes == []
    assert _names(discover_installed(home=home, project_dir=project), "plugin") == set()


def test_local_settings_enable_overrides_user_false(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _write_settings(home, json.dumps({"enabledPlugins": {"p@market": False}}))
    _write_project_settings(
        project, "settings.local.json", json.dumps({"enabledPlugins": {"p@market": True}})
    )
    _plugin_checkout(home, "p", "local-on-skill")

    assert _names(discover_installed(home=home, project_dir=project), "plugin") == {
        "local-on-skill"
    }


def test_malformed_project_settings_gives_a_note_and_others_still_work(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    _write_settings(home, json.dumps({"enabledPlugins": {"p@market": True}}))
    _write_project_settings(project, "settings.json", "{ broken")
    _write_project_settings(project, "settings.local.json", json.dumps({"enabledPlugins": {}}))
    _plugin_checkout(home, "p", "still-on-skill")
    _skill(home / ".codex" / "skills" / "codex-skill")

    roots, notes = enabled_plugin_skill_roots(home, project)
    assert len(roots) == 1
    assert len(notes) == 1 and "could not parse" in notes[0]

    result = discover_installed(home=home, project_dir=project)
    assert _names(result, "plugin") == {"still-on-skill"}
    assert "codex-skill" in _names(result)
    assert any("could not parse" in note for note in result.skipped)


def test_missing_project_settings_are_silent(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(home, json.dumps({"enabledPlugins": {}}))

    roots, notes = enabled_plugin_skill_roots(home, tmp_path / "project-without-claude")

    assert roots == [] and notes == []


def test_project_dir_equal_to_home_reads_settings_once(tmp_path: Path):
    home = tmp_path / "home"
    _write_settings(home, "{ broken")

    roots, notes = enabled_plugin_skill_roots(home, home)

    assert roots == []
    assert len(notes) == 1  # One malformed file, one note: not one per read.


# B2: hidden folders -------------------------------------------------------------------------


def test_hidden_system_bundle_under_codex_is_not_listed(tmp_path: Path):
    home = tmp_path / "home"
    _skill(home / ".codex" / "skills" / ".system" / "bundled-by-codex")
    _skill(home / ".codex" / "skills" / "user-installed")

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == {"user-installed"}
    assert not any(".system" in note for note in result.skipped)


def test_hidden_files_and_folders_at_depth_zero_are_skipped_silently(tmp_path: Path):
    home = tmp_path / "home"
    base = home / ".codex" / "skills"
    _skill(base / ".hidden-skill")
    (base / ".DS_Store").write_text("x", encoding="utf-8")
    (base / ".empty-hidden").mkdir()

    result = discover_installed(home=home, project_dir=None)

    assert _names(result) == set()
    assert not any(".hidden" in note or ".DS_Store" in note for note in result.skipped)


def test_extra_path_pointing_at_hidden_skill_folder_is_listed(tmp_path: Path):
    home = tmp_path / "home"
    hidden = _skill(tmp_path / "stash" / ".hidden-skill")

    result = discover_installed(home=home, project_dir=None, extra_paths=[hidden])

    assert _names(result, "custom") == {".hidden-skill"}


def test_extra_path_inside_a_hidden_folder_is_scanned(tmp_path: Path):
    home = tmp_path / "home"
    bundle = tmp_path / "stash" / ".vendor" / "skills"
    _skill(bundle / "vendored")
    _skill(bundle / ".private")

    result = discover_installed(home=home, project_dir=None, extra_paths=[bundle])

    assert _names(result, "custom") == {"vendored"}
