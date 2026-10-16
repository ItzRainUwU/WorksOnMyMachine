"""Focused coverage for optional certificate signatures."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient

from worksonmymachine.app import app
from worksonmymachine.cli import main
from worksonmymachine.exports import certificate_json
from worksonmymachine.models import AuditReport, ReproducibilityCertificate
from worksonmymachine.repro_hash import generate_certificate
from worksonmymachine.signing import (
    sign_certificate,
    verify_certificate_signature,
)


def _certificate() -> ReproducibilityCertificate:
    return ReproducibilityCertificate(
        certificate_id="cert-test",
        root_hash="root-test",
        runtime="python-3.11.9",
    )


def test_unsigned_certificate_is_legacy_compatible() -> None:
    certificate = _certificate()

    assert certificate.signature is None
    payload = json.loads(certificate.model_dump_json())
    assert "signature" not in payload
    assert "signature" not in certificate_json(AuditReport(target="test", certificate=certificate))


def test_signed_certificate_roundtrip_and_wrong_key_fail_closed() -> None:
    certificate = sign_certificate(_certificate(), signing_key="offline-secret", key_id="ci")

    assert certificate.signature is not None
    assert certificate.signature.algorithm == "hmac-sha256"
    assert certificate.signature.key_id == "ci"
    assert verify_certificate_signature(certificate, "offline-secret") is True
    assert verify_certificate_signature(certificate, "wrong-secret") is False
    assert verify_certificate_signature(certificate) is False


def test_tampered_signature_and_payload_are_invalid() -> None:
    signed = sign_certificate(_certificate(), signing_key="offline-secret")
    assert signed.signature is not None
    tampered_signature = signed.model_copy(
        update={
            "signature": signed.signature.model_copy(update={"value": "tampered"})
        }
    )
    tampered_payload = signed.model_copy(update={"root_hash": "changed"})

    assert verify_certificate_signature(tampered_signature, "offline-secret") is False
    assert verify_certificate_signature(tampered_payload, "offline-secret") is False


def test_signing_key_is_not_in_export_or_api_response() -> None:
    secret = "super-secret-do-not-export"
    signed = sign_certificate(_certificate(), signing_key=secret)
    assert secret not in certificate_json(AuditReport(target="test", certificate=signed))

    response = TestClient(app).post(
        "/api/v1/certify",
        json={
            "target": "nightmare_ml_service",
            "sign": True,
            "signing_key": secret,
            "signature_key_id": "api-ci",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["signature"]["key_id"] == "api-ci"
    assert secret not in response.text

    verification = TestClient(app).post(
        "/api/v1/verify-certificate",
        json={"certificate": body, "verification_key": secret},
    )
    assert verification.status_code == 200
    assert verification.json()["valid"] is True


def test_cli_signed_roundtrip_does_not_echo_key(tmp_path: Path) -> None:
    output = tmp_path / "certificate.json"
    secret = "cli-secret-do-not-export"
    result = CliRunner().invoke(
        main,
        [
            "certify",
            "nightmare_ml_service",
            "--json",
            "--output",
            str(output),
            "--signing-key",
            secret,
        ],
    )

    assert result.exit_code == 0, result.output
    assert secret not in result.output
    assert secret not in output.read_text(encoding="utf-8")
    verify = CliRunner().invoke(
        main,
        ["verify-certificate", str(output), "--verification-key", secret, "--json"],
    )
    assert verify.exit_code == 0, verify.output
    assert '"valid": true' in verify.output


def test_generate_certificate_accepts_explicit_signing_only(tmp_path: Path) -> None:
    (tmp_path / "entrypoint.py").write_text("print('ok')\n", encoding="utf-8")
    unsigned = generate_certificate(tmp_path)
    signed = generate_certificate(tmp_path, signing_key=b"key")

    assert unsigned.signature is None
    assert signed.signature is not None
