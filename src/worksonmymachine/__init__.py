"""Public package metadata and schema exports for WorksOnMyMachine."""

__title__ = "WorksOnMyMachine"
__description__ = "Cross-platform reproducibility diagnostics for Linux builds."
__version__ = "0.1.0"

from .models import (
    AuditReport,
    CompilerDiagnostic,
    DockerfilePatchResult,
    FileHashNode,
    HealResult,
    LandmineIssue,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .scanner import heal_repository, readiness_score, scan_repository

__all__ = [
    "AuditReport",
    "CompilerDiagnostic",
    "DockerfilePatchResult",
    "FileHashNode",
    "HealResult",
    "LandmineIssue",
    "ReproducibilityCertificate",
    "SeverityLevel",
    "heal_repository",
    "readiness_score",
    "scan_repository",
    "__version__",
]
