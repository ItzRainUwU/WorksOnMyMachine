"""Phase 1 foundation tests; all checks are local and network-free."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from worksonmymachine import (
    AuditReport,
    CompilerDiagnostic,
    DockerfilePatchResult,
    FileHashNode,
    LandmineIssue,
    ReproducibilityCertificate,
    SeverityLevel,
)
from worksonmymachine.app import app
from worksonmymachine.config import DEFAULT_SANDBOX_DIR, load_settings


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_all_public_pydantic_schemas_accept_phase_one_data() -> None:
    issue = LandmineIssue(
        issue_id="WIN-PATH-001",
        category="portability",
        message="Absolute Windows path detected.",
        severity=SeverityLevel.HIGH,
        file_path="demo_targets/nightmare_ml_service/app.py",
        line_number=13,
        remediation="Use a project-relative pathlib path.",
        evidence=[
            "C" + chr(58) + chr(92) + "Users" + chr(92) + "Dev" + chr(92)
            + "models" + chr(92) + "weights.bin"
        ],
    )
    diagnostic = CompilerDiagnostic(
        tool="pip",
        message="Python.h was not found",
        severity=SeverityLevel.CRITICAL,
        file_path="build_error.log",
        line_number=4,
        code="missing-header",
    )
    patch = DockerfilePatchResult(
        source_path="Dockerfile.broken",
        patched_content="FROM python:3.11.9-slim",
        changes=["pin base image"],
        confidence=0.95,
    )
    node = FileHashNode(path="src/app.py", digest="abc123", size_bytes=42)
    certificate = ReproducibilityCertificate(
        certificate_id="cert-001",
        root_hash="merkle-root",
        runtime="python-3.11.9",
        issues=[issue],
    )
    report = AuditReport(
        target="nightmare_ml_service",
        issues=[issue],
        diagnostics=[diagnostic],
        dockerfile_patches=[patch],
        merkle_root="merkle-root",
        certificate=certificate,
    )

    assert issue.severity is SeverityLevel.HIGH
    assert diagnostic.tool == "pip"
    assert patch.applied is False
    assert node.size_bytes == 42
    assert certificate.verified is False
    assert report.target == "nightmare_ml_service"


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "C" + chr(58) + chr(92) + "Users" + chr(92) + "Dev" + chr(92) + "secret.txt",
        "../secret",
    ],
)
def test_schema_rejects_host_absolute_or_parent_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        FileHashNode(path=path, digest="deadbeef", size_bytes=1)


def test_configuration_uses_project_relative_sandbox_and_env_overrides(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "APP_HOST=127.0.0.1\nAPP_PORT=8123\nSANDBOX_DIR=./fixtures\n",
        encoding="utf-8",
    )

    configured = load_settings(dotenv_path=env_file, environ={})

    assert configured.app_host == "127.0.0.1"
    assert configured.app_port == 8123
    assert configured.sandbox_dir == Path("fixtures")
    assert configured.sandbox_path == PROJECT_ROOT / "fixtures"
    assert DEFAULT_SANDBOX_DIR == Path("demo_targets")


def test_env_example_is_present_and_contains_safe_defaults() -> None:
    env_example = PROJECT_ROOT / ".env.example"
    content = env_example.read_text(encoding="utf-8")

    assert env_example.is_file()
    assert "APP_HOST=0.0.0.0" in content
    assert "APP_PORT=8000" in content
    assert "STRICT_REPRO_MODE=true" in content
    assert "SANDBOX_DIR=./demo_targets" in content
    assert "SECRET" not in content


def test_health_endpoint() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "worksonmymachine"


def test_targets_endpoint_lists_demo_directories() -> None:
    response = TestClient(app).get("/api/v1/targets")

    assert response.status_code == 200
    assert response.json()["targets"] == [
        "case_sensitive_webapp",
        "nightmare_ml_service",
        "rust_crypto_worker",
    ]
