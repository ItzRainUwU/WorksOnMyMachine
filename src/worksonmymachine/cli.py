"""Command-line interface for WorksOnMyMachine audits and repairs."""

from __future__ import annotations

from pathlib import Path
import re

import click
from rich.console import Console
from rich.table import Table

from .apt_healer import analyze_log_hybrid
from .config import PROJECT_ROOT
from .models import LandmineIssue, ReproducibilityCertificate
from .repro_hash import generate_certificate, run_full_audit
from .scanner import readiness_score, scan_repository


_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def _demo_root() -> Path:
    """Return the workspace demo-target directory."""

    return (PROJECT_ROOT / "demo_targets").resolve()


def _validate_relative_target(value: str) -> tuple[str, tuple[str, ...]]:
    """Validate a normalized target name and return its path segments."""

    raw = value.strip()
    normalized = raw.replace("\\", "/")
    parts = tuple(normalized.split("/")) if normalized else ()
    if (
        not parts
        or raw != normalized
        or normalized.startswith("/")
        or _DRIVE_PATH.match(normalized)
        or (len(normalized) >= 2 and normalized[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise click.BadParameter(
            "target must be a normalized relative path inside demo_targets"
        )
    return normalized, parts


def _resolve_target(value: str) -> Path:
    """Resolve a target below ``demo_targets`` and reject escape paths."""

    normalized, parts = _validate_relative_target(value)
    demo_root = _demo_root()
    candidate = (demo_root.joinpath(*parts)).resolve()
    try:
        candidate.relative_to(demo_root)
    except ValueError as exc:
        raise click.BadParameter(
            "target must resolve inside demo_targets"
        ) from exc
    if not candidate.is_dir():
        raise click.BadParameter(f"target not found: {normalized}")
    return candidate


def _resolve_log_input(value: str) -> tuple[str | None, Path]:
    """Resolve a target-backed build log or a directly supplied logfile."""

    raw = value.strip()
    if not raw:
        raise click.BadParameter("target_or_logfile must not be empty")

    # A valid target always wins over logfile interpretation, as documented by
    # the command.  Invalid target syntax is still rejected rather than being
    # allowed to turn into a parent-directory logfile escape.
    try:
        normalized, parts = _validate_relative_target(raw)
    except click.BadParameter:
        normalized = ""
        parts = ()
    if parts:
        target_candidate = (_demo_root().joinpath(*parts)).resolve()
        try:
            target_candidate.relative_to(_demo_root())
        except ValueError as exc:
            raise click.BadParameter(
                "target must resolve inside demo_targets"
            ) from exc
        if target_candidate.is_dir():
            log_path = target_candidate / "build_error.log"
            if not log_path.is_file():
                raise click.ClickException(
                    f"target has no build_error.log: {normalized}"
                )
            resolved_log_path = log_path.resolve()
            try:
                resolved_log_path.relative_to(target_candidate)
            except ValueError as exc:
                raise click.ClickException(
                    "target build_error.log must remain inside the target"
                ) from exc
            return normalized, resolved_log_path

    # Direct logfiles may be absolute (for example, a CI artifact in a temp
    # directory), but relative paths must not contain traversal segments.
    logfile = Path(raw)
    logfile_parts = raw.replace("\\", "/").split("/")
    absolute_logfile = logfile.is_absolute() or raw.startswith("/") or bool(
        _DRIVE_PATH.match(raw)
    )
    if any(part == ".." for part in logfile_parts) or (
        not absolute_logfile
        and ("\\" in raw or any(part in {"", "."} for part in logfile_parts))
    ):
        raise click.BadParameter("logfile must be a normalized path")
    if not logfile.is_absolute():
        logfile = (Path.cwd() / logfile).resolve()
    else:
        logfile = logfile.resolve()
    if not logfile.is_file():
        raise click.BadParameter(f"logfile not found: {raw}")
    return None, logfile


def _console() -> Console:
    """Create a console after Click has installed its output capture."""

    return Console()


def _print_issue_table(console: Console, issues: list[LandmineIssue]) -> None:
    """Render scanner issues in a compact, stable Rich table."""

    table = Table(title="Landmine issues", show_lines=False)
    table.add_column("Issue")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Message")
    for issue in issues:
        # LandmineIssue is intentionally kept behind this small presentation
        # helper so the command only relies on its public model attributes.
        table.add_row(
            str(issue.issue_id),
            str(issue.category),
            str(issue.severity.value),
            str(issue.file_path or "-"),
            str(issue.line_number or "-"),
            str(issue.message),
        )
    if not issues:
        table.add_row("-", "-", "-", "-", "-", "No landmine issues found.")
    console.print(table)


def _apt_install_command(packages: list[str]) -> str:
    """Render the exact offline package-manager fix used by the API."""

    if not packages:
        return ""
    return (
        "apt-get update && apt-get install -y --no-install-recommends "
        + " ".join(packages)
    )


@click.group()
def main() -> None:
    """Inspect, certify, and heal reproducibility landmines."""


@main.command("scan")
@click.argument("target")
def scan(target: str) -> None:
    """Scan TARGET for portability and reproducibility landmines."""

    target_path = _resolve_target(target)
    issues = scan_repository(target_path)
    console = _console()
    _print_issue_table(console, issues)
    console.print(f"Readiness score: {readiness_score(issues):.2f}/100")


@main.command("parse-log")
@click.argument("target_or_logfile")
def parse_log(target_or_logfile: str) -> None:
    """Parse a demo target build log or a supplied logfile."""

    target_name, log_path = _resolve_log_input(target_or_logfile)
    try:
        log_text = log_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise click.ClickException(f"could not read logfile: {log_path}") from exc
    analysis = analyze_log_hybrid(log_text)
    console = _console()

    title = "Build diagnostics"
    if target_name:
        title += f" ({target_name})"
    table = Table(title=title, show_lines=False)
    table.add_column("Tool")
    table.add_column("Severity")
    table.add_column("Code")
    table.add_column("Artifact")
    table.add_column("Line", justify="right")
    table.add_column("Message")
    for diagnostic in analysis.diagnostics:
        table.add_row(
            diagnostic.tool,
            diagnostic.severity.value,
            diagnostic.code or "-",
            diagnostic.missing_artifact or "-",
            str(diagnostic.line_number or "-"),
            diagnostic.message,
        )
    if not analysis.diagnostics:
        table.add_row("-", "-", "-", "-", "-", "No recognized diagnostics.")
    console.print(table)
    console.print(f"Root cause: {analysis.root_cause_summary}")
    command = _apt_install_command(analysis.apt_packages)
    console.print(
        f"Exact apt-get install fix: {command}"
        if command
        else "Exact apt-get install fix: none identified"
    )


def _print_certificate(
    console: Console, certificate: ReproducibilityCertificate
) -> None:
    """Render a human-readable certificate summary."""

    table = Table(title="Reproducibility certificate", show_lines=False)
    table.add_column("Field")
    table.add_column("Value")
    fields = (
        ("Certificate ID", certificate.certificate_id),
        ("Runtime", certificate.runtime),
        ("Verified", str(certificate.verified)),
        ("Cleanroom certified", str(certificate.is_cleanroom_certified)),
        ("Merkle root", certificate.root_hash),
        ("Dependency lock hash", certificate.dependency_lock_hash or "-"),
        ("Dependency lock score", f"{certificate.dependency_lock_score:.2f}/100"),
        ("Linux readiness score", f"{certificate.linux_readiness_score:.2f}/100"),
        ("Dockerfile hardened", str(certificate.dockerfile_hardened)),
        ("Verification hash", certificate.verification_hash),
        ("Issues", str(len(certificate.issues))),
    )
    for label, value in fields:
        table.add_row(label, str(value))
    console.print(table)


@main.command("certify")
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit the certificate as JSON.")
def certify(target: str, as_json: bool) -> None:
    """Generate a reproducibility certificate for TARGET."""

    certificate = generate_certificate(_resolve_target(target))
    if as_json:
        click.echo(certificate.model_dump_json())
        return
    _print_certificate(_console(), certificate)


@main.command("heal")
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit the audit report as JSON.")
def heal(target: str, as_json: bool) -> None:
    """Audit TARGET with copy-on-write healing enabled."""

    report = run_full_audit(_resolve_target(target), auto_heal=True)
    if as_json:
        click.echo(report.model_dump_json())
        return

    console = _console()
    before = report.before_certificate
    after = report.after_certificate or report.certificate
    console.print(
        f"Before readiness score: "
        f"{before.linux_readiness_score if before else 0.0:.2f}/100"
    )
    console.print(
        f"After readiness score: "
        f"{after.linux_readiness_score if after else 0.0:.2f}/100"
    )
    console.print(f"Before Merkle hash: {before.root_hash if before else '-'}")
    console.print(f"After Merkle hash: {after.root_hash if after else '-'}")
    if after is not None and after.is_cleanroom_certified:
        console.print("CleanRoom status: Uncertified -> CleanRoom Certified (100%)")
    else:
        console.print("CleanRoom status: healing did not reach certification")
    if report.unified_diffs:
        console.print("Unified diffs:")
        for diff in report.unified_diffs:
            click.echo(diff, nl=not diff.endswith("\n"))
    else:
        console.print("Unified diffs: none")


__all__ = ["main"]
