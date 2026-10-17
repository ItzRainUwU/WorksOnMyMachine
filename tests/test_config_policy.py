"""Focused tests for the shared workspace policy configuration."""

from pathlib import Path

import pytest
from click.testing import CliRunner

import worksonmymachine.cli as cli_module
from worksonmymachine.config import (
    Policy,
    WorkspaceConfig,
    load_policy,
    load_workspace_config,
    load_workspace_policy,
    policy_from_mapping,
)
from worksonmymachine.exports import ci_exit_code
from worksonmymachine.models import (
    AuditReport,
    FileHashNode,
    LandmineIssue,
    ReproducibilityCertificate,
)


def test_policy_defaults_are_safe_and_available_on_workspace_config() -> None:
    configured = WorkspaceConfig()

    assert configured.policy == Policy()
    assert configured.policy_configured is False
    assert configured.policy.fail_on == "high"
    assert configured.policy.min_readiness == 95.0
    assert configured.policy.require_reproducible is True
    assert configured.policy.allow_floating_docker_tags is False
    assert configured.policy.require_lockfiles is True


def test_workspace_config_loads_all_policy_fields_without_changing_suppressions(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / ".worksonmymachine.toml"
    config_path.write_text(
        'target_paths = ["workspace"]\n'
        'ignore_paths = ["vendor"]\n'
        "[policy]\n"
        'fail_on = "critical"\n'
        "min_readiness = 87.5\n"
        "require_reproducible = false\n"
        "allow_floating_docker_tags = true\n"
        "require_lockfiles = false\n"
        "[[suppressions]]\n"
        'issue_id = "REQ-UNPINNED"\n'
        'reason = "Tracked upstream"\n',
        encoding="utf-8",
    )

    configured = load_workspace_config(config_path)

    assert configured.target_paths == ("workspace",)
    assert configured.ignore_paths == ("vendor",)
    assert configured.policy_configured is True
    assert configured.suppressions[0].issue_id == "REQ-UNPINNED"
    assert configured.policy == Policy(
        fail_on="critical",
        min_readiness=87.5,
        require_reproducible=False,
        allow_floating_docker_tags=True,
        require_lockfiles=False,
    )


def test_workspace_policy_helpers_return_the_same_validated_policy(tmp_path: Path) -> None:
    config_path = tmp_path / ".worksonmymachine.toml"
    config_path.write_text('[policy]\nfail_on = "medium"\n', encoding="utf-8")

    expected = Policy(fail_on="medium")
    assert load_workspace_policy(config_path) == expected
    assert load_policy(config_path) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fail_on", '"blocker"'),
        ("min_readiness", "-1"),
        ("min_readiness", "100.1"),
        ("require_reproducible", '"true"'),
        ("allow_floating_docker_tags", "1"),
        ("require_lockfiles", '"false"'),
    ],
)
def test_workspace_policy_rejects_invalid_values(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    config_path = tmp_path / ".worksonmymachine.toml"
    config_path.write_text(f"[policy]\n{field} = {value}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid workspace policy"):
        load_workspace_config(config_path)


def test_workspace_policy_rejects_unknown_fields_and_non_tables(tmp_path: Path) -> None:
    unknown_path = tmp_path / "unknown.toml"
    unknown_path.write_text(
        "[policy]\nfail_threshold = \"high\"\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="unsupported field"):
        load_workspace_config(unknown_path)

    non_table_path = tmp_path / "non-table.toml"
    non_table_path.write_text('policy = "high"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="policy must be a TOML table"):
        load_workspace_config(non_table_path)


def test_policy_mapping_helper_has_the_same_validation_contract() -> None:
    assert policy_from_mapping({"fail_on": "LOW", "min_readiness": 0}) == Policy(
        fail_on="low", min_readiness=0
    )
    with pytest.raises(ValueError, match="unsupported field"):
        policy_from_mapping({"threshold": "high"})


def test_policy_only_workspace_config_controls_cli_exit_code_and_cli_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".worksonmymachine.toml").write_text(
        "[policy]\n"
        'fail_on = "critical"\n'
        "min_readiness = 0\n"
        "require_reproducible = true\n"
        "allow_floating_docker_tags = true\n"
        "require_lockfiles = false\n",
        encoding="utf-8",
    )
    issue = LandmineIssue(
        issue_id="TEST-HIGH",
        category="fixture",
        message="high finding",
        severity="high",
    )
    certificate = ReproducibilityCertificate(
        certificate_id="fixture-certificate",
        root_hash="root",
        runtime="python-3.11",
        verified=False,
        linux_readiness_score=100.0,
        dependency_lock_score=100.0,
        dockerfile_hardened=True,
        is_cleanroom_certified=False,
    )
    report = AuditReport(
        target="workspace",
        issues=[issue],
        certificate=certificate,
        before_certificate=certificate,
    )
    monkeypatch.setattr(cli_module, "run_full_audit", lambda *args, **kwargs: report)

    runner = CliRunner()
    policy_result = runner.invoke(
        cli_module.main,
        ["check", "workspace", "--workspace-root", str(tmp_path), "--format", "json"],
    )
    override_result = runner.invoke(
        cli_module.main,
        [
            "check",
            "workspace",
            "--workspace-root",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "high",
            "--no-require-reproducible",
        ],
    )

    assert policy_result.exit_code == 2, policy_result.output
    assert override_result.exit_code == 1, override_result.output


def test_certificate_policy_gates_use_lockfile_and_docker_evidence() -> None:
    docker_certificate = ReproducibilityCertificate(
        certificate_id="docker-certificate",
        root_hash="root",
        runtime="python-3.11",
        linux_readiness_score=100.0,
        dependency_lock_score=100.0,
        dockerfile_hardened=False,
        is_cleanroom_certified=True,
        file_nodes=[
            FileHashNode(path="Dockerfile", digest="docker", size_bytes=1),
            FileHashNode(path="requirements.lock", digest="lock", size_bytes=1),
        ],
    )
    docker_report = AuditReport(target="fixture", certificate=docker_certificate)

    assert (
        ci_exit_code(
            docker_report,
            [],
            allow_floating_docker_tags=False,
            require_lockfiles=True,
        )
        == 1
    )
    assert (
        ci_exit_code(
            docker_report,
            [],
            allow_floating_docker_tags=True,
            require_lockfiles=True,
        )
        == 0
    )

    missing_lock_certificate = docker_certificate.model_copy(
        update={
            "file_nodes": [
                FileHashNode(path="Dockerfile", digest="docker", size_bytes=1)
            ],
            "dockerfile_hardened": True,
        }
    )
    assert (
        ci_exit_code(
            AuditReport(target="fixture", certificate=missing_lock_certificate),
            [],
            allow_floating_docker_tags=True,
            require_lockfiles=True,
        )
        == 1
    )
