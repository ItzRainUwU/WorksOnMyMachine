"""FastAPI service surface for target discovery, scanning, and healing."""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import PROJECT_ROOT, settings, workspace_config
from .apt_healer import analyze_log_hybrid, heal_dockerfile
from .models import (
    CompilerDiagnostic,
    BuildVerification,
    DockerfilePatchResult,
    HealResult,
    LandmineIssue,
    AuditReport,
    ReproducibilityCertificate,
)
from .repro_hash import (
    compare_certificates,
    generate_certificate,
    run_full_audit,
)
from .scanner import heal_repository, readiness_score, scan_repository


app = FastAPI(
    title="WorksOnMyMachine",
    description="Cross-OS reproducibility diagnostics and deterministic build evidence.",
    version=__version__,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the self-contained CleanRoom engineering dashboard."""

    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


class TargetRequest(BaseModel):
    """A demo target name or a safe relative workspace path."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)


class ScanResponse(BaseModel):
    """Stable API response for a deterministic target scan."""

    target: str
    issues: list[LandmineIssue]
    category_breakdown: dict[str, int]
    readiness_score: float


class ParseLogRequest(BaseModel):
    """Either a target name or raw compiler output, but never both."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    target: str | None = None
    log_text: str | None = None


class ParseLogResponse(BaseModel):
    """Offline-first compiler analysis response."""

    target: str | None = None
    diagnostics: list[CompilerDiagnostic]
    apt_packages: list[str]
    apt_install_command: str
    root_cause_summary: str
    llm_used: bool


class DockerfileHealRequest(BaseModel):
    """A target-backed or fully in-memory Dockerfile healing request."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    target: str | None = None
    dockerfile_content: str | None = None
    log_text: str | None = None


class CompareRequest(BaseModel):
    """Compare two targets or a target before and after copy-on-write healing."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_a: str | None = None
    target_b: str | None = None
    target: str | None = None
    auto_heal: bool = False


class AuditRequest(BaseModel):
    """Request a full scanner, build-log, Dockerfile, and certificate audit."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)
    auto_heal: bool = False


class BuildVerificationRequest(BaseModel):
    """Request an explicit Docker build from an isolated target copy."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)
    auto_heal: bool = True
    timeout_seconds: int = Field(default=120, ge=5, le=900)


class IssueContextRequest(BaseModel):
    """Request bounded source context for one workspace-relative finding."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)


@app.get("/health")
def health() -> dict[str, str]:
    """Return a dependency-free liveness response."""

    return {"status": "ok", "service": "worksonmymachine", "version": __version__}


@app.get("/api/v1/targets")
def targets(scope: str = "sandbox") -> dict[str, object]:
    """List configured fixtures or repository candidates inside the workspace.

    The default response remains the stable fixture list used by existing API
    consumers. The dashboard requests ``scope=workspace`` to expose the
    current workspace and repository-shaped directories without permitting
    arbitrary host paths.
    """

    sandbox = settings.sandbox_path
    if scope == "sandbox":
        if not sandbox.is_dir():
            return {"targets": []}
        names = sorted(
            directory.name
            for directory in sandbox.iterdir()
            if directory.is_dir() and not directory.name.startswith(".")
        )
        return {"targets": names}
    if scope != "workspace":
        raise HTTPException(status_code=400, detail="scope must be sandbox or workspace")

    workspace = PROJECT_ROOT.resolve()
    candidates = list(workspace_config.target_paths) or ["workspace"]
    if sandbox.is_dir():
        candidates.extend(
            "demo_targets/" + directory.name
            for directory in sorted(sandbox.iterdir(), key=lambda item: item.name)
            if directory.is_dir() and not directory.name.startswith(".")
        )
    for directory in sorted(workspace.iterdir(), key=lambda item: item.name):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        if _looks_like_repository(directory):
            candidates.append(directory.name)
    return {
        "targets": sorted(set(candidates)),
        "default_target": workspace_config.target_paths[0] if workspace_config.target_paths else "workspace",
    }


def _looks_like_repository(directory: Path) -> bool:
    """Return whether a workspace directory looks like a project target."""

    markers = {
        ".git",
        "Cargo.toml",
        "Dockerfile",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
    }
    try:
        return any((directory / marker).exists() for marker in markers)
    except OSError:
        return False


def _resolve_target(value: str) -> Path:
    """Resolve a target name while keeping requests inside the workspace."""

    raw = value.strip()
    normalized = raw.replace("\\", "/")
    parts = normalized.split("/")
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or raw != normalized
        or normalized.startswith("/")
        or (len(parts[0]) >= 2 and parts[0][1] == ":")
    ):
        raise ValueError("target must be a normalized relative path")
    workspace = PROJECT_ROOT.resolve()
    if normalized == "workspace":
        return workspace
    relative = Path(*parts)
    sandbox = settings.sandbox_path.resolve()
    candidates = [sandbox / relative, workspace / relative]
    for candidate in candidates:
        resolved = candidate.resolve()
        try:
            resolved.relative_to(workspace)
        except ValueError:
            continue
        if resolved.is_dir():
            return resolved
    raise ValueError("target directory was not found inside the workspace")


@app.post("/api/v1/scan", response_model=ScanResponse)
def scan(request: TargetRequest) -> ScanResponse:
    """Scan a demo or workspace-relative target without changing it."""

    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    issues = scan_repository(target_path)
    breakdown = dict(sorted(Counter(issue.category for issue in issues).items()))
    return ScanResponse(
        target=request.target,
        issues=issues,
        category_breakdown=breakdown,
        readiness_score=readiness_score(issues),
    )


@app.post("/api/v1/heal", response_model=HealResult)
def heal(request: TargetRequest) -> HealResult:
    """Copy, heal, and re-scan a target without modifying the source fixture."""

    try:
        target_path = _resolve_target(request.target)
        # HTTP healing is a one-shot operation. Keep its staging directory
        # private to the request and remove it before returning; the result
        # still records the cleaned staging location for a complete response.
        staging = Path(tempfile.mkdtemp(prefix="worksonmymachine-api-healed-"))
        try:
            result = heal_repository(target_path, staging)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


def _apt_install_command(packages: list[str]) -> str:
    if not packages:
        return ""
    return (
        "apt-get update && apt-get install -y --no-install-recommends "
        + " ".join(packages)
    )


@app.post("/api/v1/parse-log", response_model=ParseLogResponse)
def parse_log(request: ParseLogRequest) -> ParseLogResponse:
    """Parse a target build log or raw compiler output without network access."""

    if bool(request.target) == bool(request.log_text):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of target or log_text",
        )
    target_name: str | None = None
    log_text = request.log_text or ""
    if request.target:
        try:
            target_path = _resolve_target(request.target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        log_path = target_path / "build_error.log"
        if not log_path.is_file():
            raise HTTPException(status_code=404, detail="target has no build_error.log")
        try:
            log_text = log_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise HTTPException(status_code=400, detail="build log is unreadable") from exc
        target_name = request.target

    analysis = analyze_log_hybrid(log_text)
    return ParseLogResponse(
        target=target_name,
        diagnostics=analysis.diagnostics,
        apt_packages=analysis.apt_packages,
        apt_install_command=_apt_install_command(analysis.apt_packages),
        root_cause_summary=analysis.root_cause_summary,
        llm_used=analysis.llm_used,
    )


@app.post("/api/v1/heal-dockerfile", response_model=DockerfilePatchResult)
def heal_dockerfile_endpoint(request: DockerfileHealRequest) -> DockerfilePatchResult:
    """Stage and harden a target Dockerfile or an in-memory Dockerfile."""

    has_target = bool(request.target)
    has_custom = request.dockerfile_content is not None
    if has_target == has_custom:
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of target or dockerfile_content",
        )

    if has_target:
        try:
            target_path = _resolve_target(request.target or "")
            result = heal_dockerfile(target_path)
            staged = result.staged_output_path
            if staged:
                shutil.rmtree(staged, ignore_errors=True)
            return result.model_copy(update={"staged_output_path": None})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    input_path = Path(tempfile.mkdtemp(prefix="worksonmymachine-api-docker-input-"))
    try:
        (input_path / "Dockerfile.broken").write_text(
            request.dockerfile_content or "",
            encoding="utf-8",
        )
        if request.log_text is not None:
            (input_path / "build_error.log").write_text(
                request.log_text,
                encoding="utf-8",
            )
        result = heal_dockerfile(input_path)
        staged = result.staged_output_path
        if staged:
            shutil.rmtree(staged, ignore_errors=True)
        return result.model_copy(update={"staged_output_path": None})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        shutil.rmtree(input_path, ignore_errors=True)


@app.post("/api/v1/certify", response_model=ReproducibilityCertificate)
def certify(request: TargetRequest) -> ReproducibilityCertificate:
    """Generate a deterministic reproducibility certificate for a target."""

    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return generate_certificate(target_path)


@app.post("/api/v1/compare")
def compare(request: CompareRequest) -> dict[str, object]:
    """Return exact file and score drift between certificates."""

    try:
        if request.target:
            if request.target_a or request.target_b:
                raise ValueError("target cannot be combined with target_a or target_b")
            if not request.auto_heal:
                raise ValueError("target comparisons require auto_heal=true")
            report = run_full_audit(_resolve_target(request.target), auto_heal=True)
            if report.before_certificate is None or report.after_certificate is None:
                raise ValueError("healed comparison did not produce two certificates")
            drift = compare_certificates(
                report.before_certificate,
                report.after_certificate,
            )
            return {
                **drift,
                "before_certificate": report.before_certificate.model_dump(mode="json"),
                "after_certificate": report.after_certificate.model_dump(mode="json"),
            }
        if not request.target_a or not request.target_b or request.auto_heal:
            raise ValueError("provide target_a and target_b, or target with auto_heal=true")
        first = generate_certificate(_resolve_target(request.target_a))
        second = generate_certificate(_resolve_target(request.target_b))
        return {
            **compare_certificates(first, second),
            "before_certificate": first.model_dump(mode="json"),
            "after_certificate": second.model_dump(mode="json"),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


_BUILD_IGNORED_DIRECTORIES = (
    ".git",
    ".opencode",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
)
_SECRET_OUTPUT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*)([^\s,;]+)"
)


def _redact_build_output(value: str, limit: int = 12000) -> str:
    """Keep build receipts useful without persisting common secret values."""

    redacted = _SECRET_OUTPUT.sub(r"\1[REDACTED]", value or "")
    return redacted[-limit:]


def _verification_response(
    *,
    verification_id: str,
    target: str,
    status: str,
    started_at: datetime,
    command: list[str],
    exit_code: int | None = None,
    output: str = "",
    detail: str = "",
    auto_heal: bool,
) -> BuildVerification:
    completed_at = datetime.now(timezone.utc)
    return BuildVerification(
        verification_id=verification_id,
        target=target,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=max(0.0, (completed_at - started_at).total_seconds()),
        command=command,
        exit_code=exit_code,
        output=_redact_build_output(output),
        detail=detail,
        auto_heal=auto_heal,
    )


@app.post("/api/v1/verify-build", response_model=BuildVerification)
def verify_build(request: BuildVerificationRequest) -> BuildVerification:
    """Build a temporary staged copy with Docker when explicitly requested."""

    started_at = datetime.now(timezone.utc)
    verification_id = uuid.uuid4().hex
    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    configured_build = workspace_config.build_command
    configured_test = workspace_config.test_command
    dockerfile_name = "Dockerfile" if (target_path / "Dockerfile").is_file() else "Dockerfile.broken"
    display_command = (
        [configured_build] + ([configured_test] if configured_test else [])
        if configured_build
        else [
            "docker",
            "build",
            "--progress=plain",
            "--file",
            dockerfile_name,
            "--tag",
            "<verification-image>",
            "<staged-context>",
        ]
    )
    if not configured_build and not (target_path / dockerfile_name).is_file():
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="blocked",
            started_at=started_at,
            command=display_command,
            detail="No Dockerfile or Dockerfile.broken was found in the selected target.",
            auto_heal=request.auto_heal,
        )
    if not configured_build and shutil.which("docker") is None:
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="blocked",
            started_at=started_at,
            command=display_command,
            detail="Docker is not installed or is not available on PATH.",
            auto_heal=request.auto_heal,
        )

    staging = Path(tempfile.mkdtemp(prefix="worksonmymachine-build-"))
    tag = "worksonmymachine-verify:" + verification_id[:12]
    actual_command = [
        "docker",
        "build",
        "--progress=plain",
        "--file",
        str(staging / dockerfile_name),
        "--tag",
        tag,
        str(staging),
    ]
    output = ""
    try:
        if request.auto_heal:
            heal_repository(target_path, staging)
        else:
            shutil.copytree(
                target_path,
                staging,
                symlinks=True,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(*_BUILD_IGNORED_DIRECTORIES),
            )
        if configured_build:
            process = subprocess.run(
                configured_build,
                cwd=staging,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=request.timeout_seconds,
                check=False,
            )
            output = (process.stdout or "") + ("\n" + process.stderr if process.stderr else "")
            if process.returncode == 0 and configured_test:
                test_process = subprocess.run(
                    configured_test,
                    cwd=staging,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=request.timeout_seconds,
                    check=False,
                )
                output += ("\n[test]\n" + (test_process.stdout or "")) + ("\n" + test_process.stderr if test_process.stderr else "")
                process = test_process
        else:
            process = subprocess.run(
                actual_command,
                cwd=staging,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=request.timeout_seconds,
                check=False,
            )
            output = (process.stdout or "") + ("\n" + process.stderr if process.stderr else "")
        detail_prefix = "Configured staged build" if configured_build else "Staged Docker build"
        if workspace_config.runtime:
            detail_prefix += " (runtime hint: " + workspace_config.runtime + ")"
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="passed" if process.returncode == 0 else "failed",
            started_at=started_at,
            command=display_command,
            exit_code=process.returncode,
            output=output,
            detail=detail_prefix + " completed." if process.returncode == 0 else detail_prefix + " exited with a non-zero status.",
            auto_heal=request.auto_heal,
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="timed_out",
            started_at=started_at,
            command=display_command,
            output=output,
            detail=f"Staged build exceeded the {request.timeout_seconds}-second timeout.",
            auto_heal=request.auto_heal,
        )
    except (OSError, ValueError) as exc:
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="failed",
            started_at=started_at,
            command=display_command,
            output=output,
            detail=f"Could not prepare the staged build: {exc}",
            auto_heal=request.auto_heal,
        )
    finally:
        if not configured_build and shutil.which("docker") is not None:
            subprocess.run(
                ["docker", "image", "rm", "--force", tag],
                capture_output=True,
                text=True,
                check=False,
            )
        shutil.rmtree(staging, ignore_errors=True)


@app.post("/api/v1/issue-context")
def issue_context(request: IssueContextRequest) -> dict[str, object]:
    """Return bounded source context for a finding inside a selected target."""

    raw_path = request.file_path.strip()
    parts = raw_path.split("/")
    if (
        not raw_path
        or "\\" in raw_path
        or raw_path.startswith("/")
        or (len(parts[0]) >= 2 and parts[0][1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise HTTPException(status_code=400, detail="file_path must be a normalized relative POSIX path")
    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    root = target_path.resolve()
    source = (root / Path(*parts)).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="file_path must remain inside the target") from exc
    if not source.is_file() or source.stat().st_size > 2_000_000:
        raise HTTPException(status_code=404, detail="source file is unavailable for context")
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=404, detail="source file is unreadable") from exc
    center = request.line_number or 1
    start = max(1, center - 3)
    end = min(len(lines), center + 3)
    return {
        "target": request.target,
        "file_path": raw_path,
        "line_number": request.line_number,
        "start_line": start,
        "end_line": end,
        "lines": [{"number": index, "text": lines[index - 1]} for index in range(start, end + 1)],
    }


@app.post("/api/v1/audit", response_model=AuditReport)
def audit(request: AuditRequest) -> AuditReport:
    """Run the unified offline audit workflow for a target."""

    try:
        target_path = _resolve_target(request.target)
        return run_full_audit(target_path, auto_heal=request.auto_heal)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
