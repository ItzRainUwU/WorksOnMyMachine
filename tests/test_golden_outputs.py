"""Golden regression coverage for the supported audit export formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_repro_and_cli import _export_fixture
from worksonmymachine.exports import (
    certificate_json,
    report_json,
    sarif_report,
    unified_patch,
)
from worksonmymachine.repro_hash import run_full_audit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_ROOT = Path(__file__).resolve().parent / "golden"
DEMO_ROOT = PROJECT_ROOT / "demo_targets"
_NONDETERMINISTIC_FIELDS = frozenset({"scanned_at", "generated_at"})


def _normalize_nondeterministic_fields(value: Any, field_name: str | None = None) -> Any:
    """Replace only timestamps that are generated as part of serialization."""

    if field_name in _NONDETERMINISTIC_FIELDS and isinstance(value, str):
        return "<timestamp>"
    if isinstance(value, dict):
        return {
            key: _normalize_nondeterministic_fields(item, key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_nondeterministic_fields(item) for item in value]
    return value


def _normalized_json(text: str) -> str:
    payload = _normalize_nondeterministic_fields(json.loads(text))
    return json.dumps(payload, indent=2) + "\n"


def _assert_golden(name: str, actual: str) -> None:
    expected = (GOLDEN_ROOT / name).read_text(encoding="utf-8")
    if actual == expected:
        return

    expected_lines = expected.splitlines(keepends=True)
    actual_lines = actual.splitlines(keepends=True)
    for line_number in range(1, max(len(expected_lines), len(actual_lines)) + 1):
        expected_line = (
            expected_lines[line_number - 1]
            if line_number <= len(expected_lines)
            else "<missing>"
        )
        actual_line = (
            actual_lines[line_number - 1]
            if line_number <= len(actual_lines)
            else "<missing>"
        )
        if expected_line != actual_line:
            pytest.fail(
                f"{name} drift at line {line_number}: "
                f"expected {expected_line!r}, got {actual_line!r}"
            )

    pytest.fail(f"{name} drift: output lengths differ")


def test_json_certificate_and_sarif_exports_match_golden_outputs() -> None:
    report, _, _ = _export_fixture()

    _assert_golden("audit.golden.json", _normalized_json(report_json(report)))
    _assert_golden(
        "certificate.golden.json", _normalized_json(certificate_json(report))
    )
    _assert_golden("sarif.golden.json", sarif_report(report))


def test_unified_patch_export_matches_golden_output() -> None:
    report = run_full_audit(DEMO_ROOT / "case_sensitive_webapp", auto_heal=True)

    _assert_golden("case_sensitive_webapp.golden.diff", unified_patch(report))
