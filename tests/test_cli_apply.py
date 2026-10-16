"""Focused CLI workspace-root and explicit apply safety checks."""

from pathlib import Path
import subprocess

from click.testing import CliRunner
import pytest

from worksonmymachine.cli import _resolve_target, main
from worksonmymachine.scanner import (
    HealingConflictError,
    apply_healing,
)


def test_explicit_workspace_root_resolves_caller_repository(tmp_path: Path) -> None:
    target = tmp_path / "service"
    target.mkdir()
    (target / "app.py").write_text("value = r'C:\\Users\\caller\\data'\n", encoding="utf-8")

    assert _resolve_target("service", tmp_path) == target.resolve()

    result = CliRunner().invoke(
        main,
        ["audit", "service", "--workspace-root", str(tmp_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    assert "PATH-WINDOWS-DRIVE" in result.output
    assert "app.py" in result.output


def test_audit_apply_requires_explicit_confirmation_and_preserves_source(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            "audit",
            "--workspace-root",
            str(tmp_path),
            "--auto-heal",
            "--apply",
        ],
    )

    assert result.exit_code != 0
    assert "--apply requires" in result.output
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "requests\n"
    assert not (tmp_path / "requirements.lock").exists()


def test_audit_apply_yes_updates_workspace_and_reports_application(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests\n", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--workspace-root",
            str(tmp_path),
            "--auto-heal",
            "--apply",
            "--yes",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "\"event\": \"applied\"" in result.output
    assert requirements.read_text(encoding="utf-8") == "requests==2.32.3\n"
    assert (tmp_path / "requirements.lock").is_file()


def test_audit_apply_rejects_invalid_flag_combinations(tmp_path: Path) -> None:
    runner = CliRunner()

    missing_auto_heal = runner.invoke(
        main,
        ["audit", "--workspace-root", str(tmp_path), "--apply", "--yes"],
    )
    yes_without_apply = runner.invoke(
        main,
        ["audit", "--workspace-root", str(tmp_path), "--yes"],
    )

    assert missing_auto_heal.exit_code != 0
    assert "--auto-heal is required" in missing_auto_heal.output
    assert yes_without_apply.exit_code != 0
    assert "--yes is only valid" in yes_without_apply.output


def test_apply_refuses_a_dirty_git_file_without_overwriting_it(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests\n", encoding="utf-8")
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "requirements.txt"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    requirements.write_text("requests\n# local edit\n", encoding="utf-8")

    with pytest.raises(HealingConflictError):
        apply_healing(tmp_path)
    assert requirements.read_text(encoding="utf-8") == "requests\n# local edit\n"
