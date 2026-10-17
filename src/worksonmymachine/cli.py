"""Command-line interface for WorksOnMyMachine audits and repairs."""

from __future__ import annotations

import json
from pathlib import Path
import re

import click
from rich.console import Console
from rich.table import Table

from .apt_healer import analyze_log_hybrid
from .config import (
    PROJECT_ROOT,
    Policy,
    WorkspaceConfig,
    load_workspace_config,
    workspace_config,
)
from .exports import (
    ci_exit_code,
    filter_issues,
    load_baseline,
    markdown_summary,
    report_json,
    report_with_issues,
    sarif_report,
    unified_patch,
    write_baseline,
)
from .models import LandmineIssue, ReproducibilityCertificate
from .repro_hash import generate_certificate, run_full_audit
from .signing import certificate_signature_status
from .scanner import (
    HealingConflictError,
    apply_healing,
    readiness_score,
    scan_repository,
)
from .watch import (
    DEFAULT_DEBOUNCE_SECONDS,
    DEFAULT_POLL_INTERVAL,
    watch_directory,
)


_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def _resolve_workspace_root(value: str | Path | None) -> Path:
    """Resolve an optional caller workspace root.

    With no option the package's historical project root is retained.  An
    explicit relative path is resolved from the caller's current directory,
    which is the important distinction for installed GitHub Action and
    pre-commit entry points.
    """

    if value is None:
        return PROJECT_ROOT.resolve()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise click.BadParameter(f"workspace root is not accessible: {value}") from exc
    if not resolved.is_dir():
        raise click.BadParameter(f"workspace root is not a directory: {value}")
    return resolved


def _demo_root() -> Path:
    """Return the workspace demo-target directory."""

    return (PROJECT_ROOT / "demo_targets").resolve()


def _validate_relative_target(value: str) -> tuple[str, tuple[str, ...]]:
    """Validate a normalized target name and return its path segments."""

    raw = value.strip()
    normalized = raw.replace("\\", "/")
    parts = tuple(normalized.split("/")) if normalized else ()
    if raw in {".", "./", "workspace"}:
        return "workspace", ("workspace",)
    if (
        not parts
        or raw != normalized
        or normalized.startswith("/")
        or _DRIVE_PATH.match(normalized)
        or (len(normalized) >= 2 and normalized[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise click.BadParameter(
            "target must be a normalized workspace-relative path"
        )
    return normalized, parts


def _resolve_target(value: str, workspace_root: str | Path | None = None) -> Path:
    """Resolve a fixture or workspace-relative target and reject escapes."""

    normalized, parts = _validate_relative_target(value)
    workspace = _resolve_workspace_root(workspace_root)
    if normalized == "workspace":
        return workspace
    candidates = [(workspace / Path(*parts)).resolve()]
    # The package's bundled fixtures remain available under the default
    # invocation.  A caller-selected root must never fall back to the
    # installed package directory.
    if workspace_root is None:
        candidates.insert(0, (_demo_root() / Path(*parts)).resolve())
    for candidate in candidates:
        try:
            candidate.relative_to(workspace)
        except ValueError:
            continue
        if candidate.is_dir():
            return candidate
    raise click.BadParameter(f"target not found inside workspace: {normalized}")


def _resolve_log_input(
    value: str, workspace_root: str | Path | None = None
) -> tuple[str | None, Path]:
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
        try:
            target_candidate = _resolve_target(normalized, workspace_root)
        except click.BadParameter:
            # A normalized name that is not a target can still be a logfile
            # in the caller's current directory.  Keep the target error for
            # missing/invalid paths unless the local file actually exists.
            if not Path(raw).is_file():
                raise
            target_candidate = None
        if target_candidate is not None and target_candidate.is_dir():
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


def _baseline_path(
    value: str | None,
    workspace_root: str | Path | None = None,
    config: WorkspaceConfig | None = None,
) -> Path:
    path = Path(value or (config or workspace_config).baseline_file)
    return path if path.is_absolute() else _resolve_workspace_root(workspace_root) / path


def _default_target(workspace_root: str | Path | None) -> str:
    """Choose the default target without redirecting explicit roots."""

    if workspace_root is not None:
        return "workspace"
    return workspace_config.target_paths[0]


def _workspace_config_for(workspace_root: str | Path | None) -> WorkspaceConfig:
    """Load policy from an explicitly selected caller workspace."""

    if workspace_root is None:
        return workspace_config
    root = _resolve_workspace_root(workspace_root)
    return load_workspace_config(root / ".worksonmymachine.toml")


def _effective_policy_values(
    config: WorkspaceConfig,
    *,
    fail_on: str | None,
    min_readiness: float | None,
    require_reproducible: bool | None,
    allow_floating_docker_tags: bool | None,
    require_lockfiles: bool | None,
) -> tuple[str | None, float | None, bool, bool | None, bool | None]:
    """Merge explicit CLI values over an active workspace policy.

    A missing policy table intentionally leaves the historical CLI defaults in
    place.  ``policy_configured`` also lets a policy table containing only
    default values remain distinguishable from no policy at all.
    """

    active = config.policy_configured or config.policy != Policy()
    policy = config.policy if active else None
    return (
        fail_on if fail_on is not None else (policy.fail_on if policy else None),
        min_readiness
        if min_readiness is not None
        else (policy.min_readiness if policy else None),
        require_reproducible
        if require_reproducible is not None
        else (policy.require_reproducible if policy else False),
        allow_floating_docker_tags
        if allow_floating_docker_tags is not None
        else (policy.allow_floating_docker_tags if policy else None),
        require_lockfiles
        if require_lockfiles is not None
        else (policy.require_lockfiles if policy else None),
    )


def _confirm_apply(yes: bool) -> None:
    """Require an explicit confirmation before mutating a source repository."""

    if yes:
        return
    stdin = click.get_text_stream("stdin")
    if not getattr(stdin, "isatty", lambda: False)():
        raise click.UsageError(
            "--apply requires an interactive confirmation or the explicit --yes flag"
        )
    if not click.confirm("Apply staged healing changes to the workspace?", default=False):
        raise click.Abort()


def _write_or_echo(payload: str, output: str | None) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        click.echo(f"Wrote {path}", err=True)
    else:
        click.echo(payload, nl=not payload.endswith("\n"))


def _load_signing_key(
    value: str | None,
    key_file: str | Path | None,
) -> str | bytes | None:
    """Load explicitly requested signing material without ever printing it."""

    if value and key_file:
        raise click.UsageError("use --signing-key or --signing-key-file, not both")
    if key_file:
        path = Path(key_file)
        try:
            key = path.read_bytes()
        except OSError as exc:
            raise click.ClickException("could not read signing key file") from exc
        if not key:
            raise click.ClickException("signing key file is empty")
        return key
    return value


def _run_audit_command(
    target: str,
    auto_heal: bool,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    min_readiness: float | None,
    new_only: bool,
    baseline: str | None,
    write_baseline_file: bool,
    require_reproducible: bool | None,
    workspace_root: str | Path | None = None,
    apply: bool = False,
    yes: bool = False,
    signing_key: str | bytes | None = None,
    signing_key_file: str | Path | None = None,
    signature_key_id: str = "local",
    allow_floating_docker_tags: bool | None = None,
    require_lockfiles: bool | None = None,
) -> None:
    if apply and not auto_heal:
        raise click.UsageError("--auto-heal is required when using --apply")
    if yes and not apply:
        raise click.UsageError("--yes is only valid together with --apply")

    config = _workspace_config_for(workspace_root)
    (
        fail_on,
        min_readiness,
        require_reproducible,
        allow_floating_docker_tags,
        require_lockfiles,
    ) = _effective_policy_values(
        config,
        fail_on=fail_on,
        min_readiness=min_readiness,
        require_reproducible=require_reproducible,
        allow_floating_docker_tags=allow_floating_docker_tags,
        require_lockfiles=require_lockfiles,
    )
    target_path = _resolve_target(target, workspace_root)
    key = _load_signing_key(signing_key, signing_key_file)
    report = run_full_audit(
        target_path,
        auto_heal=auto_heal,
        signing_key=key,
        key_id=signature_key_id,
    )
    applied_result = None
    if apply:
        _confirm_apply(yes)
        try:
            applied_result = apply_healing(target_path)
        except HealingConflictError as exc:
            raise click.ClickException(str(exc)) from exc
        report.timeline.append(
            {
                "event": "applied",
                "issues_found": applied_result.issues_found,
                "issues_fixed": applied_result.issues_fixed,
                "readiness_score_before": applied_result.readiness_score_before,
                "readiness_score_after": applied_result.readiness_score_after,
                "unified_diff_count": len(applied_result.unified_diffs),
            }
        )
    baseline_file = _baseline_path(baseline, workspace_root, config)
    baseline_values = load_baseline(baseline_file) if new_only else set()
    effective, suppressed = filter_issues(report.issues, config, baseline_values, new_only)
    if write_baseline_file:
        write_baseline(baseline_file, target, report.issues)
        click.echo(f"Wrote baseline {baseline_file}", err=True)
    export_report = report_with_issues(
        report,
        effective,
        suppressed_count=len(suppressed),
        baseline_applied=new_only,
    )
    if output_format == "json":
        payload = report_json(export_report)
    elif output_format == "sarif":
        payload = sarif_report(export_report)
    elif output_format == "markdown":
        payload = markdown_summary(export_report)
    elif output_format == "patch":
        payload = unified_patch(export_report)
    else:
        console = _console()
        _print_issue_table(console, effective)
        certificate = report.certificate or report.after_certificate or report.before_certificate
        score = certificate.linux_readiness_score if certificate else readiness_score(effective)
        console.print(f"Readiness score: {score:.2f}/100")
        if suppressed:
            console.print(f"Suppressed or baselined findings: {len(suppressed)}")
        if applied_result is not None:
            console.print(
                f"Applied healing changes: {applied_result.issues_fixed} issue(s) fixed"
            )
        code = ci_exit_code(
            report,
            effective,
            fail_on,
            min_readiness,
            require_reproducible,
            allow_floating_docker_tags=allow_floating_docker_tags,
            require_lockfiles=require_lockfiles,
        )
        if code:
            raise click.exceptions.Exit(code)
        return
    _write_or_echo(payload, output)
    code = ci_exit_code(
        report,
        effective,
        fail_on,
        min_readiness,
        require_reproducible,
        allow_floating_docker_tags=allow_floating_docker_tags,
        require_lockfiles=require_lockfiles,
    )
    if code:
        raise click.exceptions.Exit(code)


@click.group()
def main() -> None:
    """Inspect, certify, and heal reproducibility landmines."""


@main.command("audit")
@click.argument("target", required=False, default=None)
@click.option("--auto-heal", is_flag=True, help="Run copy-on-write healing before certification.")
@click.option(
    "--apply",
    is_flag=True,
    help="Apply staged healing changes after confirmation (requires --auto-heal).",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Confirm --apply without an interactive prompt.",
)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Scan this caller repository instead of the installed package workspace.",
)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif", "markdown", "patch"]), default="text", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False), help="Write the selected artifact to a file.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), help="Fail CI when a finding reaches this severity.")
@click.option("--min-readiness", type=click.FloatRange(0.0, 100.0), help="Fail CI below this readiness score.")
@click.option("--new-only", is_flag=True, help="Exclude findings already present in the baseline.")
@click.option("--baseline", type=click.Path(dir_okay=False), help="Baseline JSON path.")
@click.option("--write-baseline", is_flag=True, help="Write the current raw findings as the baseline.")
@click.option(
    "--require-reproducible/--no-require-reproducible",
    default=None,
    help="Require (or do not require) a reproducible CleanRoom certificate.",
)
@click.option(
    "--allow-floating-docker-tags/--disallow-floating-docker-tags",
    default=None,
    help="Allow (or reject) floating Docker base-image tags.",
)
@click.option(
    "--require-lockfiles/--no-require-lockfiles",
    default=None,
    help="Require (or do not require) a dependency lockfile.",
)
@click.option("--signing-key", help="Explicit HMAC signing key; omitted by default.",)
@click.option("--signing-key-file", type=click.Path(dir_okay=False), help="Read the explicit signing key from a file.")
@click.option("--signature-key-id", default="local", show_default=True, help="Public identifier stored with a signature.")
def audit_command(
    target: str | None,
    auto_heal: bool,
    apply: bool,
    yes: bool,
    workspace_root: Path | None,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    min_readiness: float | None,
    new_only: bool,
    baseline: str | None,
    write_baseline: bool,
    require_reproducible: bool | None,
    allow_floating_docker_tags: bool | None,
    require_lockfiles: bool | None,
    signing_key: str | None,
    signing_key_file: str | None,
    signature_key_id: str,
) -> None:
    """Run a CI-friendly audit for TARGET or the configured workspace target."""

    _run_audit_command(
        target or _default_target(workspace_root),
        auto_heal,
        output_format,
        output,
        fail_on,
        min_readiness,
        new_only,
        baseline,
        write_baseline,
        require_reproducible,
        workspace_root,
        apply,
        yes,
        signing_key,
        signing_key_file,
        signature_key_id,
        allow_floating_docker_tags,
        require_lockfiles,
    )


@main.command("check")
@click.argument("target", required=False, default=None)
@click.option("--auto-heal", is_flag=True)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Scan this caller repository instead of the installed package workspace.",
)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif", "markdown", "patch"]), default="text", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--min-readiness", type=click.FloatRange(0.0, 100.0))
@click.option("--new-only", is_flag=True)
@click.option("--baseline", type=click.Path(dir_okay=False))
@click.option("--write-baseline", is_flag=True)
@click.option(
    "--require-reproducible/--no-require-reproducible",
    default=None,
)
@click.option(
    "--allow-floating-docker-tags/--disallow-floating-docker-tags",
    default=None,
)
@click.option(
    "--require-lockfiles/--no-require-lockfiles",
    default=None,
)
@click.option("--signing-key", help="Explicit HMAC signing key; omitted by default.")
@click.option("--signing-key-file", type=click.Path(dir_okay=False), help="Read the explicit signing key from a file.")
@click.option("--signature-key-id", default="local", show_default=True, help="Public identifier stored with a signature.")
def check_command(
    target: str | None,
    auto_heal: bool,
    workspace_root: Path | None,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    min_readiness: float | None,
    new_only: bool,
    baseline: str | None,
    write_baseline: bool,
    require_reproducible: bool | None,
    allow_floating_docker_tags: bool | None,
    require_lockfiles: bool | None,
    signing_key: str | None,
    signing_key_file: str | None,
    signature_key_id: str,
) -> None:
    """Run a CI check with the same policy and artifact formats as audit."""

    _run_audit_command(
        target or _default_target(workspace_root),
        auto_heal,
        output_format,
        output,
        fail_on,
        min_readiness,
        new_only,
        baseline,
        write_baseline,
        require_reproducible,
        workspace_root,
        False,
        False,
        signing_key,
        signing_key_file,
        signature_key_id,
        allow_floating_docker_tags,
        require_lockfiles,
    )


@main.command("scan")
@click.argument("target", required=False, default=None)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Scan this caller repository instead of the installed package workspace.",
)
def scan(target: str | None, workspace_root: Path | None) -> None:
    """Scan TARGET for portability and reproducibility landmines."""

    target_path = _resolve_target(
        target or _default_target(workspace_root), workspace_root
    )
    issues = scan_repository(target_path)
    console = _console()
    _print_issue_table(console, issues)
    console.print(f"Readiness score: {readiness_score(issues):.2f}/100")


def _resolve_watch_target(
    value: str | Path | None, workspace_root: str | Path | None = None
) -> Path:
    """Resolve a watch path from the caller's current directory or workspace."""

    if value is None or str(value).strip() in {"", "workspace"}:
        candidate = _resolve_workspace_root(workspace_root)
    else:
        raw = Path(value).expanduser()
        if raw.is_absolute():
            candidate = raw
        elif str(value).replace("\\", "/") in {".", "./"}:
            candidate = (
                _resolve_workspace_root(workspace_root)
                if workspace_root
                else Path.cwd()
            )
        else:
            base = _resolve_workspace_root(workspace_root) if workspace_root else Path.cwd()
            candidate = base / raw
            if not candidate.is_dir() and workspace_root is None:
                try:
                    return _resolve_target(str(value), workspace_root)
                except click.BadParameter:
                    pass
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise click.BadParameter(
            f"watch target is not accessible: {value or 'workspace'}"
        ) from exc
    if not resolved.is_dir():
        raise click.BadParameter(f"watch target is not a directory: {value or 'workspace'}")
    return resolved


@main.command("watch")
@click.argument("target", required=False, default=None)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Watch this caller repository instead of the installed package workspace.",
)
@click.option(
    "--interval",
    "poll_interval",
    type=click.FloatRange(min=0.05),
    default=DEFAULT_POLL_INTERVAL,
    show_default=True,
    help="Seconds between metadata polls.",
)
@click.option(
    "--debounce",
    "debounce_seconds",
    type=click.FloatRange(min=0.0),
    default=DEFAULT_DEBOUNCE_SECONDS,
    show_default=True,
    help="Seconds a changed snapshot must remain stable before rescanning.",
)
def watch(
    target: str | None,
    workspace_root: Path | None,
    poll_interval: float,
    debounce_seconds: float,
) -> None:
    """Watch TARGET for changes and print new scan findings (scan-only)."""

    target_path = _resolve_watch_target(target, workspace_root)
    click.echo(f"Watching {target_path} (Ctrl+C to stop)")
    result = watch_directory(
        target_path,
        poll_interval=poll_interval,
        debounce_seconds=debounce_seconds,
    )
    if result.stopped:
        click.echo("Stopped watching.")


@main.command("parse-log")
@click.argument("target_or_logfile")
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Resolve target names inside this caller repository.",
)
def parse_log(target_or_logfile: str, workspace_root: Path | None) -> None:
    """Parse a demo target build log or a supplied logfile."""

    target_name, log_path = _resolve_log_input(target_or_logfile, workspace_root)
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
        (
            "Signature",
            certificate.signature.algorithm if certificate.signature else "unsigned",
        ),
        (
            "Signature key ID",
            certificate.signature.key_id if certificate.signature else "-",
        ),
        ("Issues", str(len(certificate.issues))),
    )
    for label, value in fields:
        table.add_row(label, str(value))
    console.print(table)


@main.command("certify")
@click.argument("target", required=False, default=None)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Certify this caller repository instead of the installed package workspace.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the certificate as JSON.")
@click.option("--output", type=click.Path(dir_okay=False), help="Write the certificate JSON to a file.")
@click.option("--signing-key", help="Explicit HMAC signing key; omitted by default.")
@click.option("--signing-key-file", type=click.Path(dir_okay=False), help="Read the explicit signing key from a file.")
@click.option("--signature-key-id", default="local", show_default=True, help="Public identifier stored with a signature.")
def certify(
    target: str | None,
    workspace_root: Path | None,
    as_json: bool,
    output: str | None,
    signing_key: str | None,
    signing_key_file: str | None,
    signature_key_id: str,
) -> None:
    """Generate a reproducibility certificate for TARGET."""

    key = _load_signing_key(signing_key, signing_key_file)
    try:
        target_path = _resolve_target(target or _default_target(workspace_root), workspace_root)
        if key is None:
            certificate = generate_certificate(target_path)
        else:
            certificate = generate_certificate(
                target_path,
                signing_key=key,
                key_id=signature_key_id,
            )
    except ValueError as exc:
        raise click.ClickException("certificate signing request is invalid") from exc
    if as_json or output:
        _write_or_echo(certificate.model_dump_json(indent=2) + "\n", output)
        return
    _print_certificate(_console(), certificate)


@main.command("verify-certificate")
@click.argument("certificate_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--verification-key", help="Explicit HMAC verification key.")
@click.option("--verification-key-file", type=click.Path(dir_okay=False), help="Read the verification key from a file.")
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable status object.")
def verify_certificate(
    certificate_file: str,
    verification_key: str | None,
    verification_key_file: str | None,
    as_json: bool,
) -> None:
    """Verify a signed certificate without printing key material."""

    key = _load_signing_key(verification_key, verification_key_file)
    try:
        certificate = ReproducibilityCertificate.model_validate_json(
            Path(certificate_file).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise click.ClickException("certificate file is invalid") from exc
    status = certificate_signature_status(certificate, key)
    if as_json:
        click.echo(json.dumps(status, sort_keys=True))
    else:
        click.echo(
            "valid" if status["valid"] else ("unsigned" if not status["signed"] else "invalid")
        )
    if status["signed"] and not status["valid"]:
        raise click.exceptions.Exit(1)


@main.command("heal")
@click.argument("target", required=False, default=None)
@click.option(
    "--workspace-root",
    "--root",
    "workspace_root",
    type=click.Path(file_okay=False, path_type=Path),
    help="Heal a target inside this caller repository.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the audit report as JSON.")
def heal(target: str | None, workspace_root: Path | None, as_json: bool) -> None:
    """Audit TARGET with copy-on-write healing enabled."""

    report = run_full_audit(
        _resolve_target(target or _default_target(workspace_root), workspace_root),
        auto_heal=True,
    )
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


if __name__ == "__main__":
    main()
