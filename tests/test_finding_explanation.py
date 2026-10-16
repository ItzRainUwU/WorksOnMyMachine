"""Focused API coverage for selected-finding explanations."""

import json

from fastapi.testclient import TestClient

from worksonmymachine.app import app


client = TestClient(app)


def test_finding_explanation_includes_rule_context_and_bounded_source() -> None:
    response = client.post(
        "/api/v1/finding-explanation",
        json={
            "target": "demo_targets/nightmare_ml_service",
            "issue_id": "PATH-WINDOWS-DRIVE",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule"]["id"] == "PATH-WINDOWS-DRIVE"
    assert body["category"] == "HARDCODED_PATH"
    assert body["why_detected"]
    assert body["likely_cross_platform_scenario"]
    assert body["remediation"]
    assert body["status"]["state"] == "not_evaluated"
    assert body["after_scan_verification"]["mode"] == "baseline"
    context = body["source_context"]
    assert context["available"] is True
    assert len(context["lines"]) <= 7
    assert any(line["number"] == 13 for line in context["lines"])


def test_finding_explanation_reports_staged_post_heal_fix() -> None:
    response = client.post(
        "/api/v1/finding-explanation",
        json={
            "target": "demo_targets/nightmare_ml_service",
            "issue_id": "PATH-WINDOWS-DRIVE",
            "auto_heal": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"]["state"] == "fixed"
    assert body["status"]["fixed"] is True
    assert body["after_scan_verification"]["mode"] == "post-heal"
    assert body["after_scan_verification"]["finding_present"] is False


def test_finding_explanation_redacts_secret_evidence_and_rejects_escape() -> None:
    raw_secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    response = client.post(
        "/api/v1/finding-explanation",
        json={
            "target": "demo_targets/nightmare_ml_service",
            "issue_id": "SECRET-TOKEN",
            "category": "SECRET_EXPOSURE",
            "message": "token was committed",
            "severity": "critical",
            "evidence": [f"token={raw_secret}"],
        },
    )

    assert response.status_code == 200
    encoded = json.dumps(response.json())
    assert raw_secret not in encoded
    assert "[REDACTED]" in encoded

    traversal = client.post(
        "/api/v1/finding-explanation",
        json={
            "target": "demo_targets/nightmare_ml_service",
            "issue_id": "PATH-WINDOWS-DRIVE",
            "category": "HARDCODED_PATH",
            "message": "path issue",
            "file_path": "../secret.txt",
        },
    )
    assert traversal.status_code == 400
