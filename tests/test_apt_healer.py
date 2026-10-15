"""Phase 3 compiler parser, apt healer, and API tests."""

from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient

from worksonmymachine.apt_healer import (
    analyze_log_hybrid,
    heal_dockerfile,
    parse_compiler_log,
)
from worksonmymachine.app import app
from worksonmymachine.scanner import heal_repository


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = PROJECT_ROOT / "demo_targets"


def _read_log(target_name: str) -> str:
    return (DEMO_ROOT / target_name / "build_error.log").read_text(encoding="utf-8")


def _diagnostic_for(diagnostics: list, artifact: str):
    return next(item for item in diagnostics if artifact in (item.missing_artifact or ""))


def test_nightmare_log_parser_recommends_complete_native_packages() -> None:
    diagnostics = parse_compiler_log(_read_log("nightmare_ml_service"))

    python_header = _diagnostic_for(diagnostics, "Python.h")
    postgres = _diagnostic_for(diagnostics, "pg_config")
    libgl = _diagnostic_for(diagnostics, "libGL.so.1")

    assert "Python.h" in python_header.error_signature
    assert {"python3-dev", "build-essential"} <= set(
        python_header.recommended_apt_packages
    )
    assert {"libpq-dev", "gcc"} <= set(postgres.recommended_apt_packages)
    assert {"libgl1", "libglib2.0-0"} <= set(libgl.recommended_apt_packages)
    assert all(0.0 <= item.confidence <= 1.0 for item in diagnostics)


def test_rust_log_parser_recommends_native_and_rust_toolchain_packages() -> None:
    diagnostics = parse_compiler_log(_read_log("rust_crypto_worker"))

    ffi = _diagnostic_for(diagnostics, "ffi.h")
    openssl = _diagnostic_for(diagnostics, "openssl/ssl.h")
    rust = _diagnostic_for(diagnostics, "Cargo/Rust")

    assert {"libffi-dev", "pkg-config"} <= set(ffi.recommended_apt_packages)
    assert {"libssl-dev", "pkg-config"} <= set(openssl.recommended_apt_packages)
    assert {"cargo", "rustc"} <= set(rust.recommended_apt_packages)


@pytest.mark.parametrize(
    ("log_text", "artifact", "packages"),
    [
        ("mysql_config not found", "mysql_config", {"default-libmysqlclient-dev", "pkg-config"}),
        ("cmake: command not found", "cmake", {"cmake"}),
        ("fatal error: portaudio.h: No such file", "portaudio.h", {"portaudio19-dev"}),
        ("fatal error: sndfile.h: No such file", "sndfile.h", {"libsndfile1-dev"}),
    ],
)
def test_parser_knowledge_base_covers_additional_native_failures(
    log_text: str, artifact: str, packages: set[str]
) -> None:
    diagnostic = _diagnostic_for(parse_compiler_log(log_text), artifact)

    assert packages <= set(diagnostic.recommended_apt_packages)


def test_hybrid_analysis_is_offline_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    result = analyze_log_hybrid("fatal error: Python.h: No such file or directory")

    assert result.llm_used is False
    assert result.recommended_apt_packages == ["build-essential", "python3-dev"]
    assert "CPython development header" in result.root_cause_summary


@pytest.mark.parametrize("target_name", ["nightmare_ml_service", "rust_crypto_worker"])
def test_heal_dockerfile_is_copy_on_write_and_hardens_image(
    tmp_path: Path, target_name: str
) -> None:
    target = DEMO_ROOT / target_name
    snapshot = {
        path.relative_to(target).as_posix(): path.read_bytes()
        for path in target.rglob("*")
        if path.is_file()
    }
    output = tmp_path / f"{target_name}-docker-healed"

    result = heal_dockerfile(target, output)

    assert result.applied is True
    assert result.source_path == "Dockerfile.broken"
    assert result.before_content
    assert result.after_content == result.patched_content
    assert result.unified_diff.startswith("--- a/Dockerfile.broken")
    assert "FROM python:3.11.9-slim" in result.after_content
    assert "RUN apt-get update && apt-get install -y --no-install-recommends" in (
        result.after_content
    )
    assert result.apt_packages == sorted(set(result.apt_packages))
    assert "USER appuser" in result.after_content
    assert "useradd -m -u 10001 appuser" in result.after_content
    assert output.is_dir()

    after_snapshot = {
        path.relative_to(target).as_posix(): path.read_bytes()
        for path in target.rglob("*")
        if path.is_file()
    }
    assert after_snapshot == snapshot


def test_parse_log_endpoint_supports_target_and_raw_log() -> None:
    client = TestClient(app)
    target_response = client.post(
        "/api/v1/parse-log", json={"target": "nightmare_ml_service"}
    )
    raw_response = client.post(
        "/api/v1/parse-log",
        json={"log_text": "fatal error: Python.h: No such file or directory"},
    )

    assert target_response.status_code == 200
    target_body = target_response.json()
    assert target_body["target"] == "nightmare_ml_service"
    assert "python3-dev" in target_body["apt_packages"]
    assert "apt-get install -y --no-install-recommends" in target_body[
        "apt_install_command"
    ]
    assert raw_response.status_code == 200
    assert raw_response.json()["target"] is None
    assert raw_response.json()["diagnostics"][0]["missing_artifact"] == "Python.h"


def test_heal_dockerfile_endpoint_supports_target_and_custom_content() -> None:
    client = TestClient(app)
    target_response = client.post(
        "/api/v1/heal-dockerfile", json={"target": "nightmare_ml_service"}
    )
    custom_response = client.post(
        "/api/v1/heal-dockerfile",
        json={
            "dockerfile_content": "FROM python:latest\nCMD [\"./entrypoint.sh\"]\n",
            "log_text": "fatal error: Python.h: No such file or directory",
        },
    )

    assert target_response.status_code == 200
    target_body = target_response.json()
    assert target_body["apt_packages"]
    assert target_body["security_fixes"]
    assert target_body["unified_diff"].startswith("--- a/Dockerfile.broken")
    assert "USER appuser" in target_body["after_content"]
    assert custom_response.status_code == 200
    custom_body = custom_response.json()
    assert "FROM python:3.11.9-slim" in custom_body["after_content"]
    assert "python3-dev" in custom_body["apt_packages"]

    for body in (target_body, custom_body):
        if body["staged_output_path"]:
            staged_path = Path(body["staged_output_path"])
            if staged_path.is_dir():
                shutil.rmtree(staged_path)


def test_full_repository_heal_includes_dockerfile_apt_hardening(tmp_path: Path) -> None:
    target = DEMO_ROOT / "nightmare_ml_service"
    output = tmp_path / "full-healed"

    result = heal_repository(target, output)
    dockerfile = (output / "Dockerfile.broken").read_text(encoding="utf-8")

    assert result.remaining_issues == []
    assert "FROM python:3.11.9-slim" in dockerfile
    assert "apt-get update && apt-get install -y --no-install-recommends" in dockerfile
    assert "USER appuser" in dockerfile


def test_parse_log_endpoint_rejects_ambiguous_input() -> None:
    response = TestClient(app).post(
        "/api/v1/parse-log",
        json={"target": "nightmare_ml_service", "log_text": "error"},
    )

    assert response.status_code == 400
