"""Phase 4 reproducibility, CLI, and API integration tests."""

from pathlib import Path
import os
import subprocess
import sys

from click.testing import CliRunner
from fastapi.testclient import TestClient

from worksonmymachine.app import app
from worksonmymachine.cli import main
from worksonmymachine.models import FileHashNode
from worksonmymachine.repro_hash import (
    calculate_dependency_lock_score,
    compare_certificates,
    compute_file_hash,
    compute_merkle_root,
    generate_certificate,
    run_full_audit,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = PROJECT_ROOT / "demo_targets"


def test_empty_requirements_lock_cannot_certify_a_target(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11.9-slim\nUSER appuser\n", encoding="utf-8"
    )

    certificate = generate_certificate(tmp_path)

    assert certificate.dependency_lock_score < 100.0
    assert certificate.is_cleanroom_certified is False


def test_floating_cargo_dependency_counts_against_lock_score(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "fixture"\nversion = "0.1.0"\n\n'
        '[dependencies]\nopenssl = "0.10"\n',
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\nname = "fixture"\nversion = "0.1.0"\n'
        'dependencies = ["openssl"]\n\n'
        '[[package]]\nname = "openssl"\nversion = "0.10.68"\n',
        encoding="utf-8",
    )

    assert calculate_dependency_lock_score(tmp_path) < 100.0


def test_merkle_root_is_independent_of_creation_order_and_mtime(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for directory in (first, second):
        (directory / "nested").mkdir(parents=True)

    (first / "a.txt").write_text("alpha\n", encoding="utf-8", newline="")
    (first / "nested" / "b.py").write_text("print('beta')\n", encoding="utf-8")
    (second / "nested" / "b.py").write_text("print('beta')\n", encoding="utf-8")
    (second / "a.txt").write_text("alpha\n", encoding="utf-8", newline="")
    os.utime(first / "a.txt", (1, 1))
    os.utime(second / "a.txt", (2_000_000_000, 2_000_000_000))

    first_nodes = [
        FileHashNode(
            path=path.relative_to(first).as_posix(),
            digest=compute_file_hash(path).digest,
            size_bytes=path.stat().st_size,
            raw_sha256=compute_file_hash(path).raw_sha256,
            has_crlf=compute_file_hash(path).has_crlf,
        )
        for path in sorted(first.rglob("*"))
        if path.is_file()
    ]
    second_nodes = [
        FileHashNode(
            path=path.relative_to(second).as_posix(),
            digest=compute_file_hash(path).digest,
            size_bytes=path.stat().st_size,
            raw_sha256=compute_file_hash(path).raw_sha256,
            has_crlf=compute_file_hash(path).has_crlf,
        )
        for path in reversed(sorted(second.rglob("*")))
        if path.is_file()
    ]

    assert compute_merkle_root(first_nodes) == compute_merkle_root(second_nodes)


def test_normalized_and_raw_hashes_expose_crlf_drift(tmp_path: Path) -> None:
    path = tmp_path / "entrypoint.sh"
    path.write_bytes(b"#!/bin/sh\r\necho ready\r\n")

    normalized = compute_file_hash(path, normalize_newlines=True)
    raw = compute_file_hash(path, normalize_newlines=False)

    assert normalized.has_crlf is True
    assert normalized.raw_sha256 == raw.raw_sha256
    assert normalized.digest != raw.digest
    assert normalized.path == "entrypoint.sh"


def test_unhealed_targets_are_not_certified_and_auto_healed_targets_are_certified() -> None:
    for name in [
        "nightmare_ml_service",
        "case_sensitive_webapp",
        "rust_crypto_worker",
    ]:
        target = DEMO_ROOT / name
        before = generate_certificate(target)
        report = run_full_audit(target, auto_heal=True)

        assert before.is_cleanroom_certified is False
        assert report.after_certificate is not None
        assert report.after_certificate.is_cleanroom_certified is True
        assert report.after_certificate.linux_readiness_score == 100.0
        assert report.after_certificate.dependency_lock_score == 100.0
        assert report.timeline


def test_certificate_comparator_reports_healing_drift() -> None:
    target = DEMO_ROOT / "nightmare_ml_service"
    report = run_full_audit(target, auto_heal=True)

    assert report.before_certificate is not None
    assert report.after_certificate is not None
    drift = compare_certificates(report.before_certificate, report.after_certificate)

    assert "app.py" in drift["modified_files"]
    assert "Dockerfile.broken" in drift["modified_files"]
    assert "entrypoint.sh" in drift["modified_files"]
    assert ".env.example" in drift["modified_files"]
    assert "requirements.lock" in drift["added_files"]
    assert "entrypoint.sh" in drift["line_ending_drifts"]
    assert drift["score_delta"] > 0
    assert drift["merkle_match"] is False


def test_cli_scan_parse_log_certify_and_heal_commands() -> None:
    runner = CliRunner()

    scan_result = runner.invoke(main, ["scan", "nightmare_ml_service"])
    parse_result = runner.invoke(main, ["parse-log", "nightmare_ml_service"])
    certify_result = runner.invoke(main, ["certify", "nightmare_ml_service", "--json"])
    heal_result = runner.invoke(main, ["heal", "nightmare_ml_service", "--json"])

    assert scan_result.exit_code == 0, scan_result.output
    assert "Readiness score:" in scan_result.output
    assert parse_result.exit_code == 0, parse_result.output
    assert "Python.h" in parse_result.output
    assert "apt-get install" in parse_result.output
    assert certify_result.exit_code == 0, certify_result.output
    assert '"root_hash"' in certify_result.output
    assert heal_result.exit_code == 0, heal_result.output
    assert '"after_certificate"' in heal_result.output


def test_python_module_help_works_cleanly() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-m", "worksonmymachine", "--help"],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "certify" in result.stdout
    assert "heal" in result.stdout


def test_reproducibility_api_endpoints() -> None:
    client = TestClient(app)

    certify_response = client.post(
        "/api/v1/certify", json={"target": "nightmare_ml_service"}
    )
    compare_response = client.post(
        "/api/v1/compare",
        json={"target": "nightmare_ml_service", "auto_heal": True},
    )
    pair_response = client.post(
        "/api/v1/compare",
        json={
            "target_a": "nightmare_ml_service",
            "target_b": "case_sensitive_webapp",
        },
    )
    audit_response = client.post(
        "/api/v1/audit",
        json={"target": "nightmare_ml_service", "auto_heal": True},
    )

    assert certify_response.status_code == 200
    assert certify_response.json()["is_cleanroom_certified"] is False
    assert compare_response.status_code == 200
    assert compare_response.json()["modified_files"]
    assert compare_response.json()["score_delta"] > 0
    assert pair_response.status_code == 200
    assert "added_files" in pair_response.json()
    assert audit_response.status_code == 200
    audit_body = audit_response.json()
    assert audit_body["after_certificate"]["is_cleanroom_certified"] is True
    assert audit_body["timeline"]
