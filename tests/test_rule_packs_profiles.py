"""Focused coverage for local rule-pack metadata and repository profiles."""

from pathlib import Path

import pytest

from worksonmymachine.config import Policy, WorkspaceConfig, load_workspace_config
from worksonmymachine.profiles import get_profile
from worksonmymachine.rules import FixMode, available_rule_packs, get_rule_pack
from worksonmymachine.scanner import scan_repository


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_builtin_rule_packs_are_named_versioned_and_offline() -> None:
    assert {
        "python",
        "docker",
        "javascript-typescript",
        "rust-cargo",
        "shell",
        "ci",
    } <= set(available_rule_packs())
    for name in available_rule_packs():
        pack = get_rule_pack(name)
        assert pack.name == name
        assert pack.version.count(".") == 2
        assert pack.rules


def test_findings_expose_additive_rule_metadata() -> None:
    issues = scan_repository(PROJECT_ROOT / "demo_targets" / "nightmare_ml_service")

    assert issues
    assert all(issue.rule_id == issue.issue_id for issue in issues)
    assert all(issue.rule_version == "1.0.0" for issue in issues)
    assert all(issue.rule_pack for issue in issues)
    assert all(issue.confidence is not None and 0 <= issue.confidence <= 1 for issue in issues)
    assert all(issue.fix_mode in set(FixMode) for issue in issues)
    assert all(issue.evidence is not None for issue in issues)


@pytest.mark.parametrize(
    "name",
    [
        "python-service",
        "rust-native-extension",
        "node-app",
        "monorepo",
        "docker-only",
        "ci-validation",
    ],
)
def test_repository_profiles_are_validated_and_have_policy_defaults(name: str) -> None:
    profile = get_profile(name)

    assert profile.name == name
    assert profile.expectations
    assert profile.enabled_rule_packs
    assert isinstance(profile.policy, Policy)


def test_workspace_profile_selection_reuses_policy_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / ".worksonmymachine.toml"
    config_path.write_text(
        'profile = "docker-only"\n'
        "[policy]\n"
        "min_readiness = 88\n",
        encoding="utf-8",
    )

    configured = load_workspace_config(config_path)

    assert configured.profile == "docker-only"
    assert configured.repository_profile.name == "docker-only"
    assert configured.policy.min_readiness == 88.0
    assert configured.policy.require_lockfiles is False


def test_profile_scan_filters_to_enabled_rule_packs(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 'C:\\\\work\\\\data'\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY run.sh /run.sh\nCMD /run.sh\n", encoding="utf-8"
    )

    issues = scan_repository(tmp_path, profile="docker-only")

    assert issues
    assert {issue.rule_pack for issue in issues} <= {"docker", "ci"}


@pytest.mark.parametrize("value", ["unknown", "", "python-service!", 42])
def test_unknown_profile_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        WorkspaceConfig(profile=value)  # type: ignore[arg-type]
