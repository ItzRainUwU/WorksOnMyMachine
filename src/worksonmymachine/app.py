"""FastAPI service surface for target discovery, scanning, and healing."""

from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import PROJECT_ROOT, settings
from .models import HealResult, LandmineIssue
from .scanner import heal_repository, readiness_score, scan_repository


app = FastAPI(
    title="WorksOnMyMachine",
    description="Cross-OS reproducibility diagnostics and deterministic build evidence.",
    version=__version__,
)


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


@app.get("/health")
def health() -> dict[str, str]:
    """Return a dependency-free liveness response."""

    return {"status": "ok", "service": "worksonmymachine", "version": __version__}


@app.get("/api/v1/targets")
def targets() -> dict[str, list[str]]:
    """List available demo or user targets using POSIX-relative names only."""

    sandbox = settings.sandbox_path
    if not sandbox.is_dir():
        return {"targets": []}
    names = sorted(
        directory.name
        for directory in sandbox.iterdir()
        if directory.is_dir() and not directory.name.startswith(".")
    )
    return {"targets": names}


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
    relative = Path(*parts)
    workspace = PROJECT_ROOT.resolve()
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
        result = heal_repository(target_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result
