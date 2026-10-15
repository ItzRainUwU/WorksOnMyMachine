"""FastAPI service surface for target discovery, scanning, and healing."""

from collections import Counter
from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import PROJECT_ROOT, settings
from .apt_healer import analyze_log_hybrid, heal_dockerfile
from .models import (
    CompilerDiagnostic,
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


@app.get("/health")
def health() -> dict[str, str]:
    """Return a dependency-free liveness response."""

    return {"status": "ok", "service": "worksonmymachine", "version": __version__}


@app.get("/api/v1/targets")
def targets(scope: str = "sandbox") -> dict[str, list[str]]:
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
    candidates = ["workspace"]
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
    return {"targets": sorted(set(candidates))}


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


@app.post("/api/v1/audit", response_model=AuditReport)
def audit(request: AuditRequest) -> AuditReport:
    """Run the unified offline audit workflow for a target."""

    try:
        target_path = _resolve_target(request.target)
        return run_full_audit(target_path, auto_heal=request.auto_heal)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
