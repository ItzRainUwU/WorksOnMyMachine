"""Initial FastAPI service surface for the five-phase platform."""

from fastapi import FastAPI

from . import __version__
from .config import settings


app = FastAPI(
    title="WorksOnMyMachine",
    description="Cross-OS reproducibility diagnostics and deterministic build evidence.",
    version=__version__,
)


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
