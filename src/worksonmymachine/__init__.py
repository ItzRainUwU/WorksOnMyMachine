"""Public package metadata and schema exports for WorksOnMyMachine."""

__title__ = "WorksOnMyMachine"
__description__ = "Cross-platform reproducibility diagnostics for Linux builds."
__version__ = "0.1.0"

from .models import (
    AuditReport,
    BuildVerification,
    CompilerDiagnostic,
    DockerfilePatchResult,
    FileHashNode,
    HealResult,
    HybridAnalysisResult,
    LandmineIssue,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .scanner import heal_repository, readiness_score, scan_repository
from .apt_healer import analyze_log_hybrid, heal_dockerfile, parse_compiler_log
from .repro_hash import (
    calculate_dependency_lock_score,
    compare_certificates,
    compute_file_hash,
    compute_merkle_root,
    generate_certificate,
    run_full_audit,
)

__all__ = [
    "AuditReport",
    "BuildVerification",
    "CompilerDiagnostic",
    "DockerfilePatchResult",
    "FileHashNode",
    "HealResult",
    "HybridAnalysisResult",
    "LandmineIssue",
    "ReproducibilityCertificate",
    "SeverityLevel",
    "heal_repository",
    "readiness_score",
    "scan_repository",
    "analyze_log_hybrid",
    "heal_dockerfile",
    "parse_compiler_log",
    "calculate_dependency_lock_score",
    "compare_certificates",
    "compute_file_hash",
    "compute_merkle_root",
    "generate_certificate",
    "run_full_audit",
    "__version__",
]
