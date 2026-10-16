"""Focused offline coverage for explicit post-heal audit verification."""

from pathlib import Path

from fastapi.testclient import TestClient

from worksonmymachine.app import app
from worksonmymachine.exports import markdown_summary
from worksonmymachine.repro_hash import run_full_audit


def test_auto_heal_summary_reports_a_clean_target(tmp_path: Path) -> None:
    report = run_full_audit(tmp_path, auto_heal=True)

    assert report.post_heal_summary is not None
    summary = report.post_heal_summary
    assert summary.before_findings == 0
    assert summary.fixed_findings == 0
    assert summary.remaining_findings == 0
    assert summary.changed_files == []
    assert summary.readiness_delta == 0.0
    assert summary.dependency_score_delta == 0.0
    assert summary.certificate_status == "certified"
    assert summary.blocking_reasons == []


def test_auto_heal_summary_distinguishes_fixed_and_remaining_findings(
    tmp_path: Path,
) -> None:
    # The portable path is deterministic to repair; the syntax error is an
    # actual remaining scanner finding and is intentionally not auto-fixed.
    (tmp_path / "app.py").write_text(
        "print(r'C:\\Users\\dev\\artifact')\n", encoding="utf-8"
    )
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    report = run_full_audit(tmp_path, auto_heal=True)

    assert report.post_heal_summary is not None
    summary = report.post_heal_summary
    assert summary.before_findings == 2
    assert summary.fixed_findings == 1
    assert summary.remaining_findings == 1
    assert "app.py" in summary.changed_files
    assert summary.readiness_delta > 0
    assert summary.certificate_status == "not_certified"
    assert any("PYTHON-PARSE" in reason for reason in summary.blocking_reasons)
    assert any("broken.py" in reason for reason in summary.blocking_reasons)


def test_auto_heal_summary_explains_dependency_certificate_blockers(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.1.0"\n'
        'dependencies = ["requests>=2.31"]\n',
        encoding="utf-8",
    )

    report = run_full_audit(tmp_path, auto_heal=True)

    assert report.post_heal_summary is not None
    summary = report.post_heal_summary
    assert summary.certificate_status == "not_certified"
    assert summary.remaining_findings >= 1
    assert summary.dependency_score_after < 100.0
    assert summary.dependency_score_delta <= 0.0
    assert any(
        "PYPROJECT-LOCK-MISSING" in reason for reason in summary.blocking_reasons
    )
    assert any(
        "dependency-lock evidence" in reason
        for reason in summary.blocking_reasons
    )


def test_auto_heal_summary_is_exposed_by_api_and_markdown_export() -> None:
    response = TestClient(app).post(
        "/api/v1/audit",
        json={"target": "nightmare_ml_service", "auto_heal": True},
    )

    assert response.status_code == 200
    body = response.json()
    summary = body["post_heal_summary"]
    assert summary["before_findings"] > 0
    assert summary["fixed_findings"] == summary["before_findings"]
    assert summary["remaining_findings"] == 0
    assert summary["changed_files"]
    assert summary["readiness_delta"] > 0
    assert summary["dependency_score_delta"] > 0
    assert summary["certificate_status"] == "certified"
    assert summary["blocking_reasons"] == []

    report = run_full_audit(
        Path("demo_targets") / "nightmare_ml_service", auto_heal=True
    )
    markdown = markdown_summary(report)
    assert "## Post-heal verification" in markdown
    assert "Certificate status: **certified**" in markdown
