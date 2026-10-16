"""Phase 3 compiler parser, apt healer, and API tests."""

from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient

from worksonmymachine.apt_healer import (
    analyze_log_hybrid,
    detect_dockerfile_distro,
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


@pytest.mark.parametrize(
    ("log_text", "code", "packages"),
    [
        (
            "npm ERR! sharp: failed to build from source because libvips was not found",
            "missing-sharp-libvips-development-files",
            {"libvips-dev"},
        ),
        (
            "npm ERR! canvas native build failed: cairo headers are missing",
            "missing-canvas-development-files",
            {"libcairo2-dev", "libpango1.0-dev", "libgif-dev"},
        ),
        (
            "gyp ERR! find Python: could not find any Python installation; make and g++ "
            "are not found",
            "missing-node-gyp-build-tools",
            {"python3", "make", "g++"},
        ),
    ],
)
def test_node_native_addon_rules_require_build_failure_evidence(
    log_text: str, code: str, packages: set[str]
) -> None:
    diagnostic = next(
        item for item in parse_compiler_log(log_text) if item.code == code
    )

    assert packages <= set(diagnostic.recommended_apt_packages)


@pytest.mark.parametrize(
    "log_text",
    [
        "The sharp package uses libvips-dev for image processing.",
        "canvas depends on libcairo2-dev, libpango1.0-dev, and libgif-dev.",
        "node-gyp uses python3, make, and g++ for native addons.",
    ],
)
def test_node_native_addon_rules_ignore_ordinary_package_mentions(log_text: str) -> None:
    assert parse_compiler_log(log_text) == []


def test_hybrid_analysis_is_offline_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    result = analyze_log_hybrid("fatal error: Python.h: No such file or directory")

    assert result.llm_used is False
    assert result.recommended_apt_packages == ["build-essential", "python3-dev"]
    assert "CPython development header" in result.root_cause_summary


@pytest.mark.parametrize(
    ("dockerfile", "distro"),
    [
        ("FROM debian:bookworm-slim\n", "debian"),
        ("FROM ubuntu:24.04\n", "debian"),
        ("FROM python:3.11-slim\n", "debian"),
        ("FROM python:3.11-alpine3.20\n", "alpine"),
        ("FROM alpine:3.20\n", "alpine"),
        ("FROM fedora:40\n", "fedora"),
        ("FROM registry.access.redhat.com/ubi9\n", "fedora"),
        ("FROM scratch\n", None),
    ],
)
def test_dockerfile_base_image_detection_is_conservative(
    dockerfile: str, distro: str | None
) -> None:
    assert detect_dockerfile_distro(dockerfile) == distro


def test_alpine_healing_uses_apk_and_explicit_package_mapping(tmp_path: Path) -> None:
    target = tmp_path / "alpine-target"
    target.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM python:3.11-alpine3.20\nWORKDIR /app\nRUN pip install -r requirements.txt\n",
        encoding="utf-8",
    )
    (target / "build_error.log").write_text(
        "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
    )

    result = heal_dockerfile(target, tmp_path / "alpine-output")

    assert result.package_manager == "apk"
    assert result.packages == ["build-base", "python3-dev"]
    assert result.install_command == "apk add --no-cache build-base python3-dev"
    assert "RUN apk add --no-cache" in result.after_content
    assert "apt-get" not in result.after_content
    assert "dnf install" not in result.after_content
    assert "adduser -D -u 10001 appuser" in result.after_content


def test_fedora_healing_uses_dnf_and_rhel_package_names(tmp_path: Path) -> None:
    target = tmp_path / "fedora-target"
    target.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM fedora:40\nWORKDIR /app\nRUN pip install -r requirements.txt\n",
        encoding="utf-8",
    )
    (target / "build_error.log").write_text(
        "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
    )

    result = heal_dockerfile(target, tmp_path / "fedora-output")

    assert result.package_manager == "dnf"
    assert result.packages == ["gcc", "gcc-c++", "make", "python3-devel"]
    assert result.install_command == (
        "dnf install -y gcc gcc-c++ make python3-devel && dnf clean all"
    )
    assert "RUN dnf install -y" in result.after_content
    assert "python3-devel" in result.after_content
    assert "apt-get" not in result.after_content
    assert "apk add" not in result.after_content


def test_alpine_canvas_healing_translates_all_native_addon_packages(tmp_path: Path) -> None:
    target = tmp_path / "canvas-alpine-target"
    target.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM node:22-alpine3.20\nWORKDIR /app\nRUN npm install\n",
        encoding="utf-8",
    )
    (target / "build_error.log").write_text(
        "npm ERR! canvas native build failed: cairo headers are missing\n",
        encoding="utf-8",
    )

    result = heal_dockerfile(target, tmp_path / "canvas-alpine-output")

    assert result.package_manager == "apk"
    assert {"cairo-dev", "pango-dev", "giflib-dev"} <= set(result.packages)
    assert "RUN apk add --no-cache" in result.after_content
    assert "cairo-dev" in result.after_content
    assert "pango-dev" in result.after_content
    assert "giflib-dev" in result.after_content
    assert "apt-get" not in result.after_content
    assert "dnf install" not in result.after_content


def test_unknown_base_does_not_guess_a_package_manager(tmp_path: Path) -> None:
    target = tmp_path / "unknown-target"
    target.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]\n", encoding="utf-8"
    )
    (target / "build_error.log").write_text(
        "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
    )

    result = heal_dockerfile(target, tmp_path / "unknown-output")

    assert result.package_manager is None
    assert result.packages == []
    assert result.install_command == ""
    assert all(
        manager not in result.after_content
        for manager in ("apt-get", "apk add", "dnf install")
    )


def test_multi_stage_healing_targets_supported_build_stage(tmp_path: Path) -> None:
    target = tmp_path / "multi-stage-target"
    target.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM python:3.11-alpine3.20 AS build\n"
        "WORKDIR /app\n"
        "RUN pip install -r requirements.txt\n"
        "FROM scratch\n"
        "COPY --from=build /app /app\n"
        "ENTRYPOINT [\"/app/run\"]\n",
        encoding="utf-8",
    )
    (target / "build_error.log").write_text(
        "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
    )

    result = heal_dockerfile(target, tmp_path / "multi-stage-output")

    assert result.package_manager == "apk"
    assert "RUN apk add --no-cache" in result.after_content
    assert "FROM scratch" in result.after_content
    assert "apt-get" not in result.after_content


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


def test_dockerfile_healer_preserves_external_symlinks_in_staging(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (target / "Dockerfile.broken").write_text(
        "FROM python:latest\nCOPY entrypoint.sh /entrypoint.sh\nCMD [\"./entrypoint.sh\"]\n",
        encoding="utf-8",
    )
    external_file = outside / "entrypoint.sh"
    external_file.write_text("#!/bin/sh\necho outside\n", encoding="utf-8")
    link = target / "entrypoint.sh"
    try:
        link.symlink_to(external_file)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    result = heal_dockerfile(target, tmp_path / "output")

    assert result.applied is True
    assert (tmp_path / "output" / "entrypoint.sh").is_symlink()


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
