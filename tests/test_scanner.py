"""Phase 2 scanner, healer, and API integration tests."""

import os
from pathlib import Path
import subprocess

import pytest
from fastapi.testclient import TestClient

from worksonmymachine.app import app
from worksonmymachine import scanner as scanner_module
from worksonmymachine.scanner import (
    HealingConflictError,
    apply_heal_result,
    heal_repository,
    scan_repository,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = PROJECT_ROOT / "demo_targets"


def _issue_categories(target: Path) -> set[str]:
    return {issue.category for issue in scan_repository(target)}


def test_nightmare_scanner_detects_paths_environment_and_shell_landmines() -> None:
    target = DEMO_ROOT / "nightmare_ml_service"
    issues = scan_repository(target)

    windows_path = (
        "C" + chr(58) + chr(92) + "Users" + chr(92) + "Dev" + chr(92)
        + "models" + chr(92) + "weights.bin"
    )
    backslash_path = "data" + chr(92) + "cache" + chr(92) + "items.json"

    assert any(
        issue.category == "HARDCODED_PATH" and windows_path in issue.evidence
        for issue in issues
    )
    assert any(
        issue.category == "BACKSLASH_PATH" and backslash_path in issue.evidence
        for issue in issues
    )
    assert any(
        issue.category == "ENV_DRIFT"
        and "SECRET_MODEL_BUCKET" in issue.evidence
        for issue in issues
    )
    assert "CRLF_LINE_ENDINGS" in _issue_categories(target)
    assert "MISSING_SHEBANG" in _issue_categories(target)
    assert "EXEC_PERMISSIONS" in _issue_categories(target)


def test_case_sensitive_scanner_does_not_use_host_exists_for_import_casing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = DEMO_ROOT / "case_sensitive_webapp"

    def fail_if_exists_is_used(_self: Path) -> bool:
        raise AssertionError("case-sensitive import detection used Path.exists()")

    monkeypatch.setattr(Path, "exists", fail_if_exists_is_used)
    issues = scan_repository(target)

    casing_issues = [issue for issue in issues if issue.category == "CASE_MISMATCH"]
    evidence = {item for issue in casing_issues for item in issue.evidence}
    assert any("webapp.Config" in item and "webapp.config" in item for item in evidence)
    assert any(
        "components/navbar.js" in item and "components/NavBar.js" in item
        for item in evidence
    )


def test_case_sensitive_scanner_detects_all_unpinned_requirements() -> None:
    target = DEMO_ROOT / "case_sensitive_webapp"
    dependency_issues = [
        issue
        for issue in scan_repository(target)
        if issue.category == "UNPINNED_DEPENDENCY"
    ]

    assert len(dependency_issues) == 3
    evidence = {item for issue in dependency_issues for item in issue.evidence}
    assert {"flask>=2.0", "requests*", "numpy"} <= evidence


def test_requirements_https_url_is_not_reported_as_a_package(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text(
        "https://example.invalid/packages/example-1.0.0-py3-none-any.whl\n"
        "requests\n",
        encoding="utf-8",
    )

    issues = scan_repository(target)

    assert [
        issue.evidence for issue in issues if issue.category == "UNPINNED_DEPENDENCY"
    ] == [["requests"]]


def test_tracked_shell_mode_comes_from_git_index_on_any_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    script = target / "run.sh"
    script.write_text("#!/bin/sh\necho ready\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_git(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "100644 deadbeef 0\trun.sh\n",
            "",
        )

    monkeypatch.setattr(scanner_module.subprocess, "run", fake_git)

    issues = scan_repository(target)

    mode_issues = [issue for issue in issues if issue.issue_id == "SHELL-NOT-EXECUTABLE"]
    assert len(mode_issues) == 1
    assert mode_issues[0].file_path == "run.sh"
    assert mode_issues[0].remediation == "Run git update-index --chmod=+x run.sh"
    assert "100644" in mode_issues[0].evidence[0]
    assert any("ls-files" in command for command in calls)


def test_non_git_target_skips_index_mode_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "run.sh").write_text("#!/bin/sh\necho ready\n", encoding="utf-8")

    def unavailable_git(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 128, "", "not a git repository")

    monkeypatch.setattr(scanner_module.subprocess, "run", unavailable_git)

    assert not any(
        issue.issue_id == "SHELL-NOT-EXECUTABLE" for issue in scan_repository(target)
    )


def test_pep621_pyproject_reports_unpinned_dependencies_and_missing_lock(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'fixture'\n"
        "dependencies = ['requests>=2.0', 'flask[async]==3.0.3']\n"
        "[project.optional-dependencies]\n"
        "dev = ['pytest']\n",
        encoding="utf-8",
    )

    issues = scan_repository(target)

    unpinned = [issue for issue in issues if issue.category == "UNPINNED_DEPENDENCY"]
    assert {item for issue in unpinned for item in issue.evidence} == {
        "requests>=2.0",
        "pytest",
    }
    lock_issues = [issue for issue in issues if issue.category == "DEPENDENCY_LOCK"]
    assert len(lock_issues) == 1
    assert lock_issues[0].issue_id == "PYPROJECT-LOCK-MISSING"


def test_poetry_groups_and_uv_lock_are_checked_locally(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        "[tool.poetry]\nname = 'fixture'\nversion = '0.1.0'\n"
        "[tool.poetry.dependencies]\npython = '>=3.11'\nrequests = '^2.0'\n"
        "flask = '3.0.3'\n"
        "[tool.poetry.group.dev.dependencies]\npytest = { version = '>=8.0' }\n",
        encoding="utf-8",
    )
    (target / "uv.lock").write_text(
        "version = 1\n\n[[package]]\nname = 'requests'\nversion = '2.32.3'\n",
        encoding="utf-8",
    )

    issues = scan_repository(target)

    assert {item for issue in issues if issue.category == "UNPINNED_DEPENDENCY" for item in issue.evidence} == {
        "^2.0",
        "version=>=8.0",
    }
    assert not any(issue.category == "DEPENDENCY_LOCK" for issue in issues)


def test_invalid_python_lockfile_is_reported_without_network_access(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        "[project]\nname = 'fixture'\ndependencies = ['requests==2.32.3']\n",
        encoding="utf-8",
    )
    (target / "poetry.lock").write_text("not = 'a package lock'\n", encoding="utf-8")

    issues = scan_repository(target)

    lock_issues = [issue for issue in issues if issue.category == "DEPENDENCY_LOCK"]
    assert len(lock_issues) == 1
    assert lock_issues[0].issue_id == "PYPROJECT-LOCK-INVALID"


@pytest.mark.parametrize(
    ("lock_name", "lock_content"),
    [
        (
            "poetry.lock",
            '[[package]]\nname = "requests"\nversion = "2.32.3"\n',
        ),
        (
            "Pipfile.lock",
            '{"_meta": {}, "default": {"requests": {"version": "==2.32.3"}}}',
        ),
    ],
)
def test_recognized_python_lock_variants_are_validated_locally(
    tmp_path: Path, lock_name: str, lock_content: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        "[project]\nname = 'fixture'\ndependencies = ['requests==2.32.3']\n",
        encoding="utf-8",
    )
    (target / lock_name).write_text(lock_content, encoding="utf-8")

    issues = scan_repository(target)

    assert not any(issue.category == "DEPENDENCY_LOCK" for issue in issues)


def test_tool_only_pyproject_does_not_create_python_dependency_findings(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        "[tool.ruff]\nline-length = 88\n", encoding="utf-8"
    )

    assert not any(
        issue.category in {"UNPINNED_DEPENDENCY", "DEPENDENCY_LOCK"}
        for issue in scan_repository(target)
    )


def test_python_from_import_checks_imported_module_casing(tmp_path: Path) -> None:
    target = tmp_path / "target"
    package = target / "package"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    source = target / "main.py"
    source.write_text("from package import Module\n", encoding="utf-8")

    issues = scan_repository(target)

    assert any(
        issue.category == "CASE_MISMATCH" and "Module -> module" in issue.evidence
        for issue in issues
    )
    output = tmp_path / "healed"
    result = heal_repository(target, output)
    assert result.remaining_issues == []
    assert "from package import module" in (
        output / "main.py"
    ).read_text(encoding="utf-8")


def test_javascript_directory_import_resolves_typescript_index_case(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source_dir = target / "src"
    component_dir = source_dir / "Components"
    component_dir.mkdir(parents=True)
    (component_dir / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    (source_dir / "main.js").write_text(
        'import { value } from "./components";\n', encoding="utf-8"
    )

    issues = scan_repository(target)

    assert any(
        issue.category == "CASE_MISMATCH"
        and "./components" in issue.evidence[0]
        and "./Components/index.ts" in issue.evidence[0]
        for issue in issues
    )


def test_healer_does_not_send_nested_dockerfile_to_root_only_healer(tmp_path: Path) -> None:
    target = tmp_path / "target"
    service = target / "service"
    service.mkdir(parents=True)
    (service / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")

    result = heal_repository(target, tmp_path / "healed")

    assert result.remaining_issues == []
    assert (tmp_path / "healed" / "service" / "Dockerfile").is_file()


@pytest.mark.parametrize(
    "target_name",
    ["nightmare_ml_service", "case_sensitive_webapp", "rust_crypto_worker"],
)
def test_healer_is_copy_on_write_and_reaches_full_readiness(
    tmp_path: Path, target_name: str
) -> None:
    target = DEMO_ROOT / target_name
    before_snapshot = {
        path.relative_to(target).as_posix(): path.read_bytes()
        for path in target.rglob("*")
        if path.is_file()
    }
    output = tmp_path / f"{target_name}-healed"

    result = heal_repository(target, output)

    assert result.issues_found > 0
    assert result.issues_fixed == result.issues_found
    assert result.remaining_issues == []
    assert result.readiness_score_after == 100.0
    assert result.readiness_score_after > result.readiness_score_before
    assert result.unified_diffs
    assert all(diff.startswith("--- a/") for diff in result.unified_diffs)
    assert output.is_dir()

    after_snapshot = {
        path.relative_to(target).as_posix(): path.read_bytes()
        for path in target.rglob("*")
        if path.is_file()
    }
    assert after_snapshot == before_snapshot


def test_healer_repairs_the_expected_fixture_contents(tmp_path: Path) -> None:
    target = DEMO_ROOT / "nightmare_ml_service"
    output = tmp_path / "nightmare-healed"

    result = heal_repository(target, output)
    entrypoint = (output / "entrypoint.sh").read_bytes()
    app_source = (output / "app.py").read_text(encoding="utf-8")
    env_example = (output / ".env.example").read_text(encoding="utf-8")

    assert result.remaining_issues == []
    assert b"\r\n" not in entrypoint
    assert entrypoint.startswith(b"#!/usr/bin/env bash\n")
    assert "C:" not in app_source
    assert "data\\\\cache" not in app_source
    assert "SECRET_MODEL_BUCKET=" in env_example
    assert "chmod +x ./entrypoint.sh" in (
        output / "Dockerfile.broken"
    ).read_text(encoding="utf-8")


def test_scan_endpoint_returns_issues_breakdown_and_readiness() -> None:
    response = TestClient(app).post(
        "/api/v1/scan", json={"target": "nightmare_ml_service"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "nightmare_ml_service"
    assert body["issues"]
    assert body["category_breakdown"]["HARDCODED_PATH"] == 1
    assert body["category_breakdown"]["ENV_DRIFT"] == 1
    assert body["readiness_score"] < 100


def test_heal_endpoint_returns_clean_result_and_diffs() -> None:
    response = TestClient(app).post(
        "/api/v1/heal", json={"target": "case_sensitive_webapp"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["issues_found"] == body["issues_fixed"]
    assert body["remaining_issues"] == []
    assert body["readiness_score_after"] == 100.0
    assert body["unified_diffs"]

    output_path = Path(body["output_path"])
    assert not output_path.exists()


def test_healer_preserves_external_symlinks_without_scanning_through_them(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    external_file = outside / "entrypoint.sh"
    external_file.write_bytes(b"#!/bin/sh\r\necho outside\r\n")
    link = target / "entrypoint.sh"
    try:
        link.symlink_to(external_file)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    output = tmp_path / "output"
    before = external_file.read_bytes()
    result = heal_repository(target, output)

    assert (output / "entrypoint.sh").is_symlink()
    assert external_file.read_bytes() == before
    assert result.remaining_issues == []


def test_api_rejects_workspace_escape() -> None:
    response = TestClient(app).post(
        "/api/v1/scan", json={"target": "../outside"}
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "relative",
    [
        "../outside.txt",
        "nested/../../outside.txt",
        "/absolute.txt",
        "C:/outside.txt",
        r"nested\\outside.txt",
        "nested/file.txt:stream",
        "nested//file.txt",
        "nested/./file.txt",
        "nested/CON.txt",
        "nested/file.txt.",
    ],
)
def test_apply_rejects_unsafe_relative_names(tmp_path: Path, relative: str) -> None:
    target = tmp_path / "target"
    target.mkdir()

    with pytest.raises(HealingConflictError):
        scanner_module._safe_target_path(target, relative)


def test_healer_accepts_nested_output_path_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "requirements.txt"
    source.write_text("requests\n", encoding="utf-8")
    output = tmp_path / "staging" / "nested" / "healed"

    result = heal_repository(target, output)

    assert output.is_dir()
    assert (output / "requirements.txt").read_text(encoding="utf-8") == (
        "requests==2.32.3\n"
    )
    assert source.read_text(encoding="utf-8") == "requests\n"
    assert result.remaining_issues == []


def test_healer_rejects_output_parent_symlink_escape(tmp_path: Path) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    output_parent = tmp_path / "output-link"
    try:
        output_parent.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="link or reparse"):
        heal_repository(target, output_parent / "nested" / "healed")
    assert not (outside / "nested").exists()


def test_apply_rejects_symlink_parent_even_when_it_points_inside_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    staged = tmp_path / "staged"
    target.mkdir()
    staged.mkdir()
    (target / "real").mkdir()
    (staged / "nested").mkdir()
    (staged / "nested" / "file.txt").write_bytes(b"changed\n")
    try:
        (target / "nested").symlink_to(target / "real", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(HealingConflictError):
        scanner_module._safe_target_path(target, "nested/file.txt")
    expected = scanner_module._snapshot_tree(target)
    result = scanner_module.HealResult(
        output_path=str(staged),
        readiness_score_before=100.0,
        readiness_score_after=100.0,
    )
    with pytest.raises(HealingConflictError):
        scanner_module._apply_staged_output(target, staged, result, expected)
    assert not (target / "real" / "file.txt").exists()


def test_apply_rejects_symlink_leaf_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside.txt"
    target.mkdir()
    outside.write_bytes(b"outside\n")
    try:
        (target / "file.txt").symlink_to(outside)
    except OSError:
        pytest.skip("file symlinks are unavailable on this platform")

    with pytest.raises(HealingConflictError):
        scanner_module._safe_target_path(target, "file.txt")
    assert outside.read_bytes() == b"outside\n"


def test_apply_heal_result_uses_staging_baseline_to_detect_late_source_change(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "requirements.txt"
    source.write_text("requests\n", encoding="utf-8")
    result = heal_repository(target, tmp_path / "staged")

    source.write_text("requests\n# local change\n", encoding="utf-8")
    with pytest.raises(HealingConflictError):
        apply_heal_result(target, result)
    assert source.read_text(encoding="utf-8") == "requests\n# local change\n"


def test_healer_refuses_source_change_during_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_text("value = r'C:\\Users\\dev\\data'\n", encoding="utf-8")
    original = scanner_module._scan_python
    changed = False

    def scan_and_race(target_path: Path, path: Path, issues: list[object]) -> None:
        nonlocal changed
        original(target_path, path, issues)
        if not changed:
            changed = True
            source.write_text("value = 'user edit'\n", encoding="utf-8")

    monkeypatch.setattr(scanner_module, "_scan_python", scan_and_race)
    with pytest.raises(HealingConflictError, match="while it was being scanned"):
        heal_repository(target, tmp_path / "staged")
    assert not (tmp_path / "staged").exists()


def test_healer_refuses_source_change_during_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_text("value = r'C:\\Users\\dev\\data'\n", encoding="utf-8")
    original = scanner_module._repair_source_file
    changed = False

    def repair_and_race(target_path: Path, path: Path) -> tuple[str, str]:
        nonlocal changed
        result = original(target_path, path)
        if not changed:
            changed = True
            source.write_text("value = 'user edit during stage'\n", encoding="utf-8")
        return result

    monkeypatch.setattr(scanner_module, "_repair_source_file", repair_and_race)
    with pytest.raises(HealingConflictError, match="while healing was being staged"):
        heal_repository(target, tmp_path / "staged")
    assert source.read_text(encoding="utf-8") == "value = 'user edit during stage'\n"


def test_healer_does_not_follow_windows_junction_or_reparse_point(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction primitives are unavailable on this platform")
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (outside / "outside.py").write_text(
        "value = r'C:\\Users\\outside\\data'\n", encoding="utf-8"
    )
    junction = target / "linked"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0 or not scanner_module._is_reparse_point(junction):
        pytest.skip("Windows junction creation is unavailable on this host")
    before = (outside / "outside.py").read_bytes()
    try:
        output = tmp_path / "output"
        try:
            result = heal_repository(target, output)
        except HealingConflictError:
            # A host without permission to recreate a junction as a symlink
            # must refuse the stage rather than dereference it.
            assert not (output / "linked").exists() or scanner_module._is_link_like(
                output / "linked"
            )
        else:
            assert result.remaining_issues == []
            assert scanner_module._is_link_like(output / "linked")
            assert "PATH-WINDOWS-DRIVE" not in {
                issue.issue_id for issue in scan_repository(target)
            }
        assert (outside / "outside.py").read_bytes() == before
    finally:
        subprocess.run(
            ["cmd", "/c", "rmdir", str(junction)],
            capture_output=True,
            text=True,
            check=False,
        )
