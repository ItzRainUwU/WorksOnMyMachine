"""Phase 1 foundation tests; all checks are local and network-free."""

from pathlib import Path
import importlib
from dataclasses import replace

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
from worksonmymachine.config import (
    DEFAULT_SANDBOX_DIR,
    DEFAULT_WORKSPACE_CONFIG,
    load_settings,
    load_workspace_config,
)


APP_MODULE = importlib.import_module("worksonmymachine.app")


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


def test_workspace_targets_expose_current_workspace_and_fixture_paths() -> None:
    response = TestClient(app).get("/api/v1/targets?scope=workspace")

    assert response.status_code == 200
    targets = response.json()["targets"]
    assert "workspace" in targets
    assert "demo_targets/nightmare_ml_service" in targets


def test_workspace_alias_resolves_to_the_project_root() -> None:
    response = TestClient(app).post("/api/v1/scan", json={"target": "workspace"})

    assert response.status_code == 200
    assert response.json()["target"] == "workspace"


def test_issue_context_returns_bounded_source_lines() -> None:
    response = TestClient(app).post(
        "/api/v1/issue-context",
        json={
            "target": "demo_targets/nightmare_ml_service",
            "file_path": "app.py",
            "line_number": 13,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["file_path"] == "app.py"
    assert body["lines"]
    assert any(line["number"] == 13 for line in body["lines"])


def test_staged_build_reports_blocked_without_docker(monkeypatch) -> None:
    monkeypatch.setattr(APP_MODULE.shutil, "which", lambda name: None)

    response = TestClient(app).post(
        "/api/v1/verify-build",
        json={"target": "demo_targets/nightmare_ml_service", "auto_heal": True},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "blocked"
    assert "Docker" in body["detail"]


def test_staged_build_blocks_configured_commands_without_explicit_opt_in(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        APP_MODULE,
        "workspace_config",
        replace(APP_MODULE.workspace_config, build_command="echo unsafe"),
    )
    monkeypatch.setattr(
        APP_MODULE,
        "settings",
        replace(APP_MODULE.settings, allow_configured_build_commands=False),
    )

    response = TestClient(app).post(
        "/api/v1/verify-build",
        json={"target": "demo_targets/nightmare_ml_service", "auto_heal": True},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "blocked"
    assert "disabled" in body["detail"]


def test_staged_build_output_redacts_common_secret_formats() -> None:
    from worksonmymachine.app import _redact_build_output

    assignment = "assignment-secret-123"
    bearer = "bearer-secret-456"
    provider = "sk-proj-provider-secret-abcdefghijklmnopqrstuvwxyz"
    aws = "AKIAIOSFODNN7EXAMPLE"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature-secret"
    pem = "-----BEGIN PRIVATE KEY-----\\nprivate-key-material\\n-----END PRIVATE KEY-----"
    output = (
        f"API_KEY={assignment} Authorization: Bearer {bearer} "
        f"OPENAI_API_KEY={provider} AWS_ACCESS_KEY_ID={aws} JWT={jwt} {pem}"
    )

    redacted = _redact_build_output(output)

    for secret in (assignment, bearer, provider, aws, jwt, "private-key-material"):
        assert secret not in redacted
    assert "API_KEY=[REDACTED]" in redacted
    assert "[REDACTED PRIVATE KEY]" in redacted
    assert _redact_build_output(output, limit=0) == ""


def test_workspace_config_loads_safe_defaults() -> None:
    configured = load_workspace_config(DEFAULT_WORKSPACE_CONFIG)

    assert configured.target_paths == ("workspace",)
    assert configured.ignore_paths == ("vendor", "generated")
    assert configured.build_command is None


def test_workspace_config_loads_baselines_and_suppressions(tmp_path: Path) -> None:
    config_path = tmp_path / ".worksonmymachine.toml"
    config_path.write_text(
        'target_paths = ["workspace"]\n'
        'baseline_file = ".ci/baseline.json"\n'
        '[[suppressions]]\n'
        'issue_id = "REQ-UNPINNED"\n'
        'path = "legacy/requirements.txt"\n'
        'reason = "Managed upstream"\n'
        'expires = "2027-01-01"\n',
        encoding="utf-8",
    )

    configured = load_workspace_config(config_path)

    assert configured.baseline_file == ".ci/baseline.json"
    assert len(configured.suppressions) == 1
    assert configured.suppressions[0].reason == "Managed upstream"


def test_audit_includes_dependency_telemetry() -> None:
    response = TestClient(app).post(
        "/api/v1/audit",
        json={"target": "demo_targets/nightmare_ml_service", "auto_heal": False},
    )

    assert response.status_code == 200
    telemetry = response.json()["dependency_telemetry"]
    assert telemetry["total"] >= telemetry["direct"]
    assert telemetry["manifests"]
