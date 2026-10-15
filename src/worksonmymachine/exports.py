"""Portable audit exports, baselines, and CI policy helpers."""

from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
from typing import Iterable

from .config import SuppressionRule, WorkspaceConfig
from .models import AuditReport, LandmineIssue


def issue_fingerprint(issue: LandmineIssue) -> str:
    """Return a stable fingerprint for baseline and new-issue comparisons."""

    payload = json.dumps(
        [issue.issue_id, issue.category, issue.file_path, issue.line_number, issue.message],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_baseline(path: Path) -> set[str]:
    """Read fingerprints from a JSON baseline; missing baselines are empty."""

    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return set()
    entries = payload.get("issues", []) if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        return set()
    fingerprints: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            fingerprints.add(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
            fingerprints.add(entry["fingerprint"])
    return fingerprints


def write_baseline(path: Path, target: str, issues: Iterable[LandmineIssue]) -> None:
    """Write a reviewable baseline containing issue metadata and fingerprints."""

    entries = [
        {
            "fingerprint": issue_fingerprint(issue),
            "issue_id": issue.issue_id,
            "category": issue.category,
            "file_path": issue.file_path,
            "line_number": issue.line_number,
            "message": issue.message,
        }
        for issue in issues
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "target": target, "issues": entries}, indent=2) + "\n",
        encoding="utf-8",
    )


def _suppression_matches(rule: SuppressionRule, issue: LandmineIssue) -> bool:
    if rule.issue_id and rule.issue_id != issue.issue_id:
        return False
    if rule.category and rule.category != issue.category:
        return False
    if rule.path:
        path = issue.file_path or ""
        if path != rule.path and not path.startswith(rule.path.rstrip("/") + "/"):
            return False
    if rule.expires:
        try:
            if date.fromisoformat(rule.expires) < date.today():
                return False
        except ValueError:
            return False
    return bool(rule.issue_id or rule.category or rule.path)


def filter_issues(
    issues: Iterable[LandmineIssue],
    config: WorkspaceConfig,
    baseline: set[str] | None = None,
    new_only: bool = False,
) -> tuple[list[LandmineIssue], list[LandmineIssue]]:
    """Apply configured suppressions and optional baseline filtering."""

    baseline = baseline or set()
    active: list[LandmineIssue] = []
    suppressed: list[LandmineIssue] = []
    for issue in issues:
        if any(_suppression_matches(rule, issue) for rule in config.suppressions):
            suppressed.append(issue)
            continue
        if new_only and issue_fingerprint(issue) in baseline:
            suppressed.append(issue)
            continue
        active.append(issue)
    return active, suppressed


def report_with_issues(
    report: AuditReport,
    issues: list[LandmineIssue],
    *,
    suppressed_count: int | None = None,
    baseline_applied: bool | None = None,
) -> AuditReport:
    """Return an export-safe report copy with effective issue rows."""

    update: dict[str, object] = {"issues": issues}
    if suppressed_count is not None:
        update["suppressed_issue_count"] = suppressed_count
    if baseline_applied is not None:
        update["baseline_applied"] = baseline_applied
    return report.model_copy(update=update)


def report_json(report: AuditReport) -> str:
    return report.model_dump_json(indent=2) + "\n"


def certificate_json(report: AuditReport) -> str:
    certificate = report.certificate or report.after_certificate or report.before_certificate
    return (json.dumps(certificate.model_dump(mode="json"), indent=2) if certificate else "{}") + "\n"


def unified_patch(report: AuditReport) -> str:
    return "".join(diff if diff.endswith("\n") else diff + "\n" for diff in report.unified_diffs)


def markdown_summary(report: AuditReport) -> str:
    certificate = report.certificate or report.after_certificate or report.before_certificate
    readiness = certificate.linux_readiness_score if certificate else 0.0
    lines = [
        f"# WorksOnMyMachine audit: `{report.target}`",
        "",
        f"- Scanned: `{report.scanned_at.isoformat()}`",
        f"- Readiness: **{readiness:.2f}/100**",
        f"- Reproducible: **{'yes' if report.reproducible else 'no'}**",
        f"- Findings: **{len(report.issues)}**",
        f"- Unified diffs: **{len(report.unified_diffs)}**",
        "",
        "## Findings",
        "",
        "| ID | Severity | Category | File | Line | Message |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for issue in report.issues:
        message = issue.message.replace("|", "\\|")
        lines.append(
            f"| `{issue.issue_id}` | `{issue.severity.value}` | `{issue.category}` | `{issue.file_path or '-'} ` | {issue.line_number or '-'} | {message} |"
        )
    if not report.issues:
        lines.append("| - | - | - | - | - | No findings |")
    lines.extend(["", "## Certificate", "", "```json", certificate_json(report).rstrip(), "```", ""])
    return "\n".join(lines)


def sarif_report(report: AuditReport) -> str:
    """Render SARIF 2.1.0 for GitHub code scanning and other CI consumers."""

    results = []
    rules = {}
    for issue in report.issues:
        rule_id = issue.issue_id
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(issue.severity.value, "warning")
        rules[rule_id] = {
            "id": rule_id,
            "name": issue.category,
            "shortDescription": {"text": issue.message},
            "help": {"text": issue.remediation or "Review the portability assumption."},
        }
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": issue.message},
            "properties": {"category": issue.category, "fingerprint": issue_fingerprint(issue)},
        }
        if issue.file_path:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": issue.file_path}, "region": {"startLine": issue.line_number or 1}}}]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "WorksOnMyMachine", "version": "0.1.0", "rules": list(rules.values())}}, "results": results}],
    }
    return json.dumps(payload, indent=2) + "\n"


def ci_exit_code(
    report: AuditReport,
    issues: Iterable[LandmineIssue],
    fail_on: str | None = None,
    min_readiness: float | None = None,
    require_reproducible: bool = False,
) -> int:
    """Return stable CI exit codes: 0 clean, 1 policy failure, 2 certificate failure."""

    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if fail_on and any(rank.get(issue.severity.value, 0) >= rank[fail_on] for issue in issues):
        return 1
    certificate = report.certificate or report.after_certificate or report.before_certificate
    readiness = certificate.linux_readiness_score if certificate else 0.0
    if min_readiness is not None and readiness < min_readiness:
        return 1
    if require_reproducible and (not certificate or not certificate.is_cleanroom_certified):
        return 2
    return 0
