"""FastAPI service surface for target discovery, scanning, and healing."""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unicodedata
import uuid
import zipfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import PROJECT_ROOT, settings, workspace_config
from .apt_healer import analyze_log_hybrid, heal_dockerfile, redact_sensitive_text
from .exports import (
    certificate_json,
    filter_issues,
    load_baseline,
    markdown_summary,
    report_json,
    report_with_issues,
    sarif_report,
    unified_patch,
)
from .models import (
    CompilerDiagnostic,
    BuildVerification,
    DockerfilePatchResult,
    HealResult,
    LandmineIssue,
    AuditReport,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .repro_hash import (
    compare_certificates,
    generate_certificate,
    run_full_audit,
)
from .scanner import heal_repository, readiness_score, scan_repository
from .signing import certificate_signature_status


app = FastAPI(
    title="WorksOnMyMachine",
    description="Cross-OS reproducibility diagnostics and deterministic build evidence.",
    version=__version__,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
UPLOADS_DIR = PROJECT_ROOT / ".worksonmymachine" / "uploads"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
# Context is deliberately small enough for a drawer response and a log-safe
# enough size for API consumers.  The source file itself remains capped below.
MAX_CONTEXT_FILE_BYTES = 2_000_000
MAX_CONTEXT_LINES = 7
MAX_CONTEXT_LINE_CHARS = 500
MAX_CONTEXT_TOTAL_CHARS = 4_000
MAX_EXPLANATION_EVIDENCE = 12
MAX_EXPLANATION_TEXT = 2_000
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the self-contained CleanRoom engineering dashboard."""

    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


class TargetRequest(BaseModel):
    """A demo target name or a safe relative workspace path."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)


class CertificateRequest(TargetRequest):
    """Certificate request with opt-in offline signing controls."""

    sign: bool = False
    signing_key: str | None = Field(default=None, min_length=1, repr=False)
    signature_key_id: str = Field(default="local", min_length=1, max_length=64)


class VerifyCertificateRequest(BaseModel):
    """Verify a certificate with caller-supplied key material."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    certificate: ReproducibilityCertificate
    verification_key: str | None = Field(default=None, min_length=1, repr=False)


class ScanResponse(BaseModel):
    """Stable API response for a deterministic target scan."""

    target: str
    issues: list[LandmineIssue]
    category_breakdown: dict[str, int]
    readiness_score: float


class UploadResponse(BaseModel):
    """Metadata for a ZIP archive extracted into the managed upload area."""

    target: str
    path: str
    upload_id: str
    filename: str
    content_type: str | None = None
    file_count: int = Field(ge=0)
    directory_count: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)


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
    new_only: bool = False
    sign: bool = False
    signing_key: str | None = Field(default=None, min_length=1, repr=False)
    signature_key_id: str = Field(default="local", min_length=1, max_length=64)


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


class FindingExplanationRequest(BaseModel):
    """Request an explanation for one selected finding.

    The flat fields keep this request compatible with the issue rows already
    rendered by the dashboard.  ``issue`` is also accepted for API clients
    that already retain a complete :class:`LandmineIssue` object.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1)
    issue: LandmineIssue | None = None
    issue_id: str | None = Field(default=None, min_length=1)
    category: str | None = Field(default=None, min_length=1)
    message: str | None = Field(default=None, min_length=1)
    severity: str = "medium"
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    remediation: str | None = None
    evidence: list[str] = Field(default_factory=list)
    auto_heal: bool = False


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
    candidates.extend(_managed_upload_targets())
    for directory in sorted(workspace.iterdir(), key=lambda item: item.name):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        if _looks_like_repository(directory):
            candidates.append(directory.name)
    return {
        "targets": sorted(set(candidates)),
        "default_target": workspace_config.target_paths[0] if workspace_config.target_paths else "workspace",
    }


def _upload_root() -> Path:
    """Return the managed upload directory and ensure it stays in the workspace."""

    workspace = PROJECT_ROOT.resolve()
    root = UPLOADS_DIR.resolve()
    try:
        root.relative_to(workspace)
    except ValueError as exc:
        raise RuntimeError("upload directory must remain inside the workspace") from exc
    root.mkdir(parents=True, exist_ok=True)
    return root


def _archive_path(name: str, *, directory: bool) -> str:
    """Validate and normalize one ZIP member name as a POSIX path."""

    normalized = unicodedata.normalize("NFC", name)
    if not normalized or "\x00" in normalized or "\\" in normalized:
        raise ValueError("archive contains a non-normalized path")
    if normalized.startswith("/") or (
        len(normalized) >= 2 and normalized[1] == ":"
    ):
        raise ValueError("archive contains an absolute path")

    parts = normalized.split("/")
    if directory and parts[-1] == "":
        parts.pop()
    if not parts or any(not part or part == "." or part == ".." for part in parts):
        raise ValueError("archive contains a traversal or non-normalized path")
    return "/".join(parts)


def _validate_archive(archive: zipfile.ZipFile) -> tuple[list[tuple[zipfile.ZipInfo, str, bool]], int]:
    """Validate ZIP members before writing any extracted data."""

    infos = archive.infolist()
    if not infos:
        raise ValueError("archive is empty")
    if len(infos) > MAX_ARCHIVE_FILES:
        raise ValueError(f"archive contains more than {MAX_ARCHIVE_FILES} entries")

    members: list[tuple[zipfile.ZipInfo, str, bool]] = []
    seen: dict[str, str] = {}
    component_spellings: dict[tuple[str, int, str], str] = {}
    file_paths: set[str] = set()
    total_size = 0
    for info in infos:
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("archive contains a symlink")
        directory = info.is_dir() or info.filename.endswith("/")
        path = _archive_path(info.filename, directory=directory)
        key = path.casefold()
        if key in seen:
            raise ValueError(f"archive contains duplicate or conflicting path: {path}")
        seen[key] = path
        parts = path.split("/")
        for index, part in enumerate(parts):
            component_key = ("/".join(parts[:index]).casefold(), index, part.casefold())
            previous = component_spellings.setdefault(component_key, part)
            if previous != part:
                raise ValueError(f"archive contains duplicate or conflicting path: {path}")
        if not directory:
            if info.file_size < 0:
                raise ValueError("archive contains an invalid file size")
            total_size += info.file_size
            if total_size > MAX_EXTRACTED_BYTES:
                raise ValueError("archive expands beyond the permitted size")
            file_paths.add(path)
        members.append((info, path, directory))

    file_keys = {path.casefold() for path in file_paths}
    for path in file_paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent.casefold() in file_keys:
                raise ValueError(f"archive contains conflicting file paths: {path}")

    return members, total_size


def _extract_archive(
    archive: zipfile.ZipFile,
    members: list[tuple[zipfile.ZipInfo, str, bool]],
    destination: Path,
) -> None:
    """Extract validated members without trusting ZIP extraction helpers."""

    for info, path, directory in members:
        output = destination.joinpath(*path.split("/"))
        if directory:
            output.mkdir(parents=True, exist_ok=True)
            continue
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise ValueError(f"archive contains conflicting file paths: {path}")
        try:
            with archive.open(info, "r") as source, output.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ValueError("archive could not be extracted safely") from exc


def _upload_target(bundle: Path) -> Path:
    """Choose the scan target, unwrapping the common single-root ZIP layout."""

    children = [child for child in bundle.iterdir() if child.name != "metadata.json"]
    if len(children) == 1 and children[0].is_dir() and not children[0].is_symlink():
        return children[0]
    return bundle


def _managed_upload_targets() -> list[str]:
    """List previously uploaded targets using the same relative-path contract."""

    root = UPLOADS_DIR.resolve()
    workspace = PROJECT_ROOT.resolve()
    if not root.is_dir():
        return []
    output: list[str] = []
    for bundle in sorted(root.iterdir(), key=lambda item: item.name):
        if not bundle.is_dir() or bundle.name.startswith("."):
            continue
        try:
            output.append(_upload_target(bundle).resolve().relative_to(workspace).as_posix())
        except (OSError, ValueError):
            continue
    return output


@app.post("/api/v1/upload", response_model=UploadResponse)
def upload_zip(file: UploadFile = File(...)) -> UploadResponse:
    """Safely extract a ZIP upload into a unique, workspace-relative target."""

    if not file.filename:
        raise HTTPException(status_code=400, detail="uploaded file must have a filename")
    try:
        file.file.seek(0, 2)
        upload_size = file.file.tell()
        file.file.seek(0)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="uploaded file could not be read") from exc
    if upload_size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="uploaded file is too large")

    staging: Path | None = None
    bundle: Path | None = None
    committed = False
    try:
        try:
            archive = zipfile.ZipFile(file.file)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise HTTPException(status_code=400, detail="uploaded file must be a valid ZIP archive") from exc
        with archive:
            try:
                members, total_size = _validate_archive(archive)
                root = _upload_root()
                staging = Path(tempfile.mkdtemp(prefix=".upload-", dir=root))
                _extract_archive(archive, members, staging)
            except HTTPException:
                raise
            except (OSError, ValueError, RuntimeError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        upload_id = uuid.uuid4().hex
        bundle = root / f"upload-{upload_id}"
        # Create the final directory without replacement, then move only into
        # that newly-created empty directory.  This keeps an ID collision or a
        # pre-existing target from ever being overwritten.
        bundle.mkdir()
        for child in staging.iterdir():
            child.rename(bundle / child.name)
        staging.rmdir()
        staging = None
        committed = True
        target_path = _upload_target(bundle).resolve()
        workspace = PROJECT_ROOT.resolve()
        target_path.relative_to(workspace)
        target = target_path.relative_to(workspace).as_posix()
        return UploadResponse(
            target=target,
            path=target,
            upload_id=upload_id,
            filename=Path(file.filename).name,
            content_type=file.content_type,
            file_count=sum(not directory for _, _, directory in members),
            directory_count=sum(directory for _, _, directory in members),
            total_size_bytes=total_size,
        )
    except HTTPException:
        raise
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="upload could not be stored safely") from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if bundle is not None and not committed:
            shutil.rmtree(bundle, ignore_errors=True)


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
def certify(request: CertificateRequest) -> ReproducibilityCertificate:
    """Generate a deterministic reproducibility certificate for a target."""

    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if request.signing_key is not None and not request.sign:
        # Supplying key material is itself an explicit opt-in, so accepting it
        # as an implicit sign request keeps clients concise without ever
        # requiring a secret for the default unsigned route.
        should_sign = True
    else:
        should_sign = request.sign
    if should_sign and request.signing_key is None:
        raise HTTPException(
            status_code=400,
            detail="sign=true requires an explicit signing_key",
        )
    try:
        if not should_sign:
            return generate_certificate(target_path)
        return generate_certificate(
            target_path,
            signing_key=request.signing_key,
            key_id=request.signature_key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="certificate signing request is invalid") from exc


@app.post("/api/v1/verify-certificate")
def verify_certificate(request: VerifyCertificateRequest) -> dict[str, object]:
    """Verify detached certificate evidence without returning key material."""

    status = certificate_signature_status(
        request.certificate,
        request.verification_key,
    )
    return status


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
def _redact_sensitive_text(value: object, limit: int = MAX_EXPLANATION_TEXT) -> str:
    """Redact common assignment and bearer-token values before API output."""

    return redact_sensitive_text(value, limit)


def _redact_build_output(value: str, limit: int = 12000) -> str:
    """Keep build receipts useful without persisting common secret values."""

    if limit <= 0:
        return ""
    redacted = redact_sensitive_text(value or "")
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
        command=[_redact_sensitive_text(item, limit=2_000) for item in command],
        exit_code=exit_code,
        output=_redact_build_output(output),
        detail=_redact_sensitive_text(detail),
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
    if configured_build and not settings.allow_configured_build_commands:
        return _verification_response(
            verification_id=verification_id,
            target=request.target,
            status="blocked",
            started_at=started_at,
            command=display_command,
            detail=(
                "Configured build commands are disabled for API requests. "
                "Set ALLOW_CONFIGURED_BUILD_COMMANDS=true only in a trusted local environment."
            ),
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

    target_path = _resolve_context_target(request.target, request.file_path)
    return _read_bounded_context(
        request.target,
        target_path,
        request.file_path,
        request.line_number,
        missing_status=404,
    )


def _resolve_context_target(target: str, file_path: str) -> tuple[Path, str, list[str]]:
    """Resolve a target and validate a relative source path before reading it."""

    raw_path = file_path.strip()
    parts = raw_path.split("/")
    _validate_context_path(raw_path, parts)
    try:
        target_path = _resolve_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    root = target_path.resolve()
    source = (root / Path(*parts)).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="file_path must remain inside the target") from exc
    return root, raw_path, parts


def _validate_context_path(raw_path: str, parts: list[str] | None = None) -> None:
    """Reject host-absolute, traversal, and non-normalized source paths."""

    parts = parts if parts is not None else raw_path.split("/")
    if (
        not raw_path
        or "\\" in raw_path
        or raw_path.startswith("/")
        or (len(parts[0]) >= 2 and parts[0][1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise HTTPException(status_code=400, detail="file_path must be a normalized relative POSIX path")


def _read_bounded_context(
    target: str,
    context_target: tuple[Path, str, list[str]],
    file_path: str,
    line_number: int | None,
    *,
    missing_status: int | None,
) -> dict[str, object]:
    """Read a small, redacted source window without crossing the target root."""

    root, raw_path, parts = context_target
    source = (root / Path(*parts)).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="file_path must remain inside the target") from exc
    try:
        source_size = source.stat().st_size if source.is_file() else -1
    except OSError:
        source_size = -1
    if source_size < 0 or source_size > MAX_CONTEXT_FILE_BYTES:
        if missing_status is not None:
            raise HTTPException(status_code=missing_status, detail="source file is unavailable for context")
        return {
            "available": False,
            "target": target,
            "file_path": raw_path,
            "line_number": line_number,
            "reason": "source file is unavailable for bounded context",
        }
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        if missing_status is not None:
            raise HTTPException(status_code=missing_status, detail="source file is unreadable") from exc
        return {
            "available": False,
            "target": target,
            "file_path": raw_path,
            "line_number": line_number,
            "reason": "source file is unreadable",
        }
    center = line_number or 1
    start = max(1, center - 3)
    end = min(len(lines), center + 3, start + MAX_CONTEXT_LINES - 1)
    bounded_lines: list[dict[str, object]] = []
    total_chars = 0
    for index in range(start, end + 1):
        text = _redact_sensitive_text(lines[index - 1], MAX_CONTEXT_LINE_CHARS)
        remaining = MAX_CONTEXT_TOTAL_CHARS - total_chars
        if remaining <= 0:
            break
        if len(text) > remaining:
            text = text[:remaining]
        bounded_lines.append({"number": index, "text": text})
        total_chars += len(text)
    return {
        "available": True,
        "target": target,
        "file_path": raw_path,
        "line_number": line_number,
        "start_line": start,
        "end_line": bounded_lines[-1]["number"] if bounded_lines else start - 1,
        "lines": bounded_lines,
    }


def _issue_key(issue: LandmineIssue) -> tuple[object, ...]:
    """Return the stable fields used to match a finding across scans."""

    return (issue.issue_id, issue.file_path, issue.line_number, issue.message)


def _matching_issue(issues: list[LandmineIssue], selected: LandmineIssue) -> LandmineIssue | None:
    """Match a selected row to scan evidence, tolerating small message drift."""

    selected_key = _issue_key(selected)
    exact = next((issue for issue in issues if _issue_key(issue) == selected_key), None)
    if exact is not None:
        return exact
    location = (selected.issue_id, selected.file_path, selected.line_number)
    located = [
        issue
        for issue in issues
        if (issue.issue_id, issue.file_path, issue.line_number) == location
    ]
    if len(located) == 1:
        return located[0]
    same_rule = [issue for issue in issues if issue.issue_id == selected.issue_id]
    return same_rule[0] if len(same_rule) == 1 else None


def _scenario_for_issue(issue: LandmineIssue) -> str:
    """Describe the likely cross-platform failure without inventing runtime facts."""

    text = " ".join(
        [issue.issue_id, issue.category, issue.message, *issue.evidence]
    ).lower()
    if "secret" in text or "token" in text or "password" in text or "credential" in text:
        return "A credential committed in source control can be exposed in every build environment; rotate it and inject it through the deployment environment instead."
    if "case" in text or "import" in text:
        return "A case-insensitive development filesystem may resolve this import, while Linux filesystems commonly require the exact on-disk casing."
    if "crlf" in text or "line ending" in text:
        return "Windows line endings can change shell parsing or generated-file hashes on Linux and macOS, making the same checkout behave differently."
    if "backslash" in text or "windows" in text or "drive" in text or "absolute" in text or "path" in text:
        return "A host-specific path can work on the developer's Windows machine but fail in a Linux or macOS clean room where that drive, separator, or home directory does not exist."
    if "docker" in text or "base" in text or "apt" in text or "native" in text or "openssl" in text:
        return "A host-provided native toolchain or floating container base can differ across Linux distributions and CPU architectures, causing a clean build to resolve different headers or binaries."
    if "lock" in text or "pin" in text or "depend" in text or "version" in text:
        return "An unpinned dependency can resolve a different transitive graph on another operating system or on a later install, so the build is not reproducible across clean environments."
    return "The detected project assumption can resolve differently on another operating system or filesystem, so a clean-room build may fail or produce different artifacts."


def _selected_issue(request: FindingExplanationRequest, scanned: list[LandmineIssue]) -> LandmineIssue:
    """Select a complete issue row from the request or the target scan."""

    if request.issue is not None:
        return _matching_issue(scanned, request.issue) or request.issue
    if request.issue_id:
        found = next((issue for issue in scanned if issue.issue_id == request.issue_id), None)
        if found is not None:
            return found
    if not request.issue_id or not request.category or not request.message:
        raise HTTPException(
            status_code=400,
            detail="provide issue or issue_id, category, and message",
        )
    try:
        severity = SeverityLevel(str(request.severity).lower())
        issue_data: dict[str, object] = {
            "issue_id": request.issue_id,
            "category": request.category,
            "message": request.message,
            "severity": severity,
            "evidence": request.evidence,
        }
        if request.file_path is not None:
            issue_data["file_path"] = request.file_path
        if request.line_number is not None:
            issue_data["line_number"] = request.line_number
        if request.remediation is not None:
            issue_data["remediation"] = request.remediation
        return LandmineIssue(**issue_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="severity must be low, medium, high, or critical") from exc


def _safe_issue_payload(issue: LandmineIssue) -> dict[str, object]:
    """Return finding metadata suitable for an explanation response."""

    return {
        "issue_id": _redact_sensitive_text(issue.issue_id),
        "category": _redact_sensitive_text(issue.category),
        "message": _redact_sensitive_text(issue.message),
        "severity": issue.severity.value,
        "file_path": _redact_sensitive_text(issue.file_path) if issue.file_path else None,
        "line_number": issue.line_number,
        "remediation": _redact_sensitive_text(issue.remediation) if issue.remediation else None,
        "evidence": [
            _redact_sensitive_text(item)
            for item in issue.evidence[:MAX_EXPLANATION_EVIDENCE]
        ],
    }


@app.post("/api/v1/finding-explanation")
@app.post("/api/v1/explain-finding", include_in_schema=False)
@app.post("/api/v1/issue-explanation", include_in_schema=False)
def finding_explanation(request: FindingExplanationRequest) -> dict[str, object]:
    """Explain one selected finding using bounded source and after-scan evidence."""

    if request.file_path is not None:
        _validate_context_path(request.file_path.strip())
    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # The scan is deterministic and never changes the source tree. Auto-heal
    # uses the same copy-on-write audit path as the existing dashboard action.
    report = run_full_audit(target_path, auto_heal=request.auto_heal)
    baseline = list(report.before_certificate.issues if report.before_certificate else report.issues)
    selected = _selected_issue(request, baseline)
    baseline_match = _matching_issue(baseline, selected)
    after = list(report.after_certificate.issues) if report.after_certificate else []
    after_match = _matching_issue(after, selected) if report.after_certificate else None

    if report.after_certificate is None:
        status = "not_evaluated"
        status_detail = "Run Auto-Heal & Certify to perform a post-heal scan for this finding."
    elif after_match is None:
        if baseline_match is None:
            status = "not_found"
            status_detail = "The selected finding was not present in the baseline scan for this target."
        else:
            status = "fixed"
            status_detail = "The matching finding was absent from the post-heal scan of the staged copy."
    else:
        status = "open"
        status_detail = "The matching finding remains in the post-heal scan of the staged copy."

    verification = report.after_certificate or report.before_certificate
    summary = report.post_heal_summary
    after_scan: dict[str, object] = {
        "performed": True,
        "mode": "post-heal" if report.after_certificate is not None else "baseline",
        "status": status,
        "finding_present": after_match is not None if report.after_certificate is not None else baseline_match is not None,
        "certificate_status": (
            "certified" if verification and verification.is_cleanroom_certified else "not_certified"
        ),
        "verification_hash": verification.verification_hash if verification else "",
        "readiness_score": verification.linux_readiness_score if verification else 0.0,
        "dependency_lock_score": verification.dependency_lock_score if verification else 0.0,
    }
    if summary is not None:
        after_scan["summary"] = {
            "before_findings": summary.before_findings,
            "fixed_findings": summary.fixed_findings,
            "remaining_findings": summary.remaining_findings,
            "changed_files": summary.changed_files[:MAX_EXPLANATION_EVIDENCE],
            "readiness_delta": summary.readiness_delta,
            "dependency_score_delta": summary.dependency_score_delta,
            "certificate_status": summary.certificate_status,
            "blocking_reasons": [
                _redact_sensitive_text(reason)
                for reason in summary.blocking_reasons[:MAX_EXPLANATION_EVIDENCE]
            ],
        }

    source_context: dict[str, object] | None = None
    if selected.file_path:
        context_target = _resolve_context_target(request.target, selected.file_path)
        source_context = _read_bounded_context(
            request.target,
            context_target,
            selected.file_path,
            selected.line_number,
            missing_status=None,
        )

    safe_issue = _safe_issue_payload(selected)
    evidence = list(safe_issue["evidence"])
    evidence_text = "; ".join(str(item) for item in evidence[:3])
    why_detected = (
        f"Rule {safe_issue['issue_id']} detected this {safe_issue['category']} finding because "
        f"{safe_issue['message']}"
    )
    if evidence_text:
        why_detected += f" Evidence: {evidence_text}."
    else:
        why_detected += "."
    scenario = _redact_sensitive_text(_scenario_for_issue(selected))
    return {
        "target": request.target,
        "issue": safe_issue,
        "rule": {
            "id": safe_issue["issue_id"],
            "category": safe_issue["category"],
            "severity": safe_issue["severity"],
        },
        "rule_id": safe_issue["issue_id"],
        "category": safe_issue["category"],
        "why_detected": _redact_sensitive_text(why_detected),
        "source_context": source_context,
        "source_lines": list(source_context.get("lines", [])) if source_context else [],
        "evidence": evidence,
        "likely_cross_platform_scenario": scenario,
        "cross_platform_scenario": scenario,
        "remediation": safe_issue["remediation"] or "Review the portability assumption and replace the host-specific behavior with a deterministic project-relative configuration.",
        "fixed": status == "fixed",
        "fix_applied": status == "fixed",
        "status": {
            "state": status,
            "fixed": status == "fixed",
            "post_heal_requested": bool(request.auto_heal),
            "post_heal_scanned": report.after_certificate is not None,
            "detail": status_detail,
        },
        "post_heal_status": status,
        "after_scan_verification": after_scan,
        "after_scan": after_scan,
    }


@app.post("/api/v1/audit", response_model=AuditReport)
def audit(request: AuditRequest) -> AuditReport:
    """Run the unified offline audit workflow for a target."""

    try:
        target_path = _resolve_target(request.target)
        should_sign = request.signing_key is not None or request.sign
        if should_sign and request.signing_key is None:
            raise ValueError("sign=true requires an explicit signing_key")
        if not should_sign:
            report = run_full_audit(target_path, auto_heal=request.auto_heal)
        else:
            report = run_full_audit(
                target_path,
                auto_heal=request.auto_heal,
                signing_key=request.signing_key,
                key_id=request.signature_key_id,
            )
        baseline_path = PROJECT_ROOT / workspace_config.baseline_file
        baseline = load_baseline(baseline_path) if request.new_only else set()
        effective, suppressed = filter_issues(
            report.issues,
            workspace_config,
            baseline,
            request.new_only,
        )
        return report_with_issues(
            report,
            effective,
            suppressed_count=len(suppressed),
            baseline_applied=request.new_only,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/export")
def export_artifact(
    target: str = "workspace",
    format: str = "json",
    auto_heal: bool = True,
    download: bool = True,
) -> Response:
    """Stream an audit artifact with proper content-disposition and MIME type."""

    try:
        target_path = _resolve_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    report = run_full_audit(target_path, auto_heal=auto_heal)
    effective, suppressed = filter_issues(report.issues, workspace_config)
    report = report_with_issues(report, effective, suppressed_count=len(suppressed))

    clean_target = target.replace("/", "-").replace("\\", "-")
    format_clean = format.lower().strip()

    if format_clean == "json":
        content = report_json(report)
        media_type = "application/json"
        filename = f"audit-{clean_target}.json"
    elif format_clean == "certificate":
        content = certificate_json(report)
        media_type = "application/json"
        filename = f"cleanroom-certificate-{clean_target}.json"
    elif format_clean == "patch":
        content = unified_patch(report)
        media_type = "text/x-diff"
        filename = f"healed-{clean_target}.patch"
    elif format_clean == "sarif":
        content = sarif_report(report)
        media_type = "application/sarif+json"
        filename = f"audit-{clean_target}.sarif"
    elif format_clean in ("markdown", "md"):
        content = markdown_summary(report)
        media_type = "text/markdown"
        filename = f"audit-{clean_target}.md"
    else:
        raise HTTPException(status_code=400, detail="unsupported export format")

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=content, media_type=media_type, headers=headers)


@app.post("/api/v1/save-to-workspace")
def save_to_workspace(request: TargetRequest) -> dict[str, object]:
    """Write audit.json, certificate.json, and audit.md directly into the workspace root."""

    try:
        target_path = _resolve_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    report = run_full_audit(target_path, auto_heal=True)
    audit_file = PROJECT_ROOT / "audit.json"
    cert_file = PROJECT_ROOT / "certificate.json"
    md_file = PROJECT_ROOT / "audit.md"
    audit_file.write_text(report_json(report), encoding="utf-8")
    cert_file.write_text(certificate_json(report), encoding="utf-8")
    md_file.write_text(markdown_summary(report), encoding="utf-8")
    saved_files = ["audit.json", "certificate.json", "audit.md"]
    if report.unified_diffs:
        patch_file = PROJECT_ROOT / "healed.patch"
        patch_file.write_text(unified_patch(report), encoding="utf-8")
        saved_files.append("healed.patch")
    return {
        "status": "saved",
        "directory": str(PROJECT_ROOT),
        "files": saved_files,
    }
