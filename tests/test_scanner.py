"""Phase 2 scanner, healer, and API integration tests."""

from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient

from worksonmymachine.app import app
from worksonmymachine.scanner import heal_repository, scan_repository


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
    if output_path.is_dir():
        shutil.rmtree(output_path)


def test_api_rejects_workspace_escape() -> None:
    response = TestClient(app).post(
        "/api/v1/scan", json={"target": "../outside"}
    )

    assert response.status_code == 400
