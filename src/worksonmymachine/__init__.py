"""Public package metadata and schema exports for WorksOnMyMachine."""

__title__ = "WorksOnMyMachine"
__description__ = "Cross-platform reproducibility diagnostics for Linux builds."
__version__ = "0.1.0"

from .models import (
    AuditReport,
    BuildVerification,
    DependencyTelemetry,
    CompilerDiagnostic,
    DockerfilePatchResult,
    FileHashNode,
    HealResult,
    HybridAnalysisResult,
    LandmineIssue,
    PostHealVerificationSummary,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .scanner import (
    HealingConflictError,
    apply_heal_result,
    apply_healing,
    heal_repository,
    readiness_score,
    scan_repository,
)
from .apt_healer import (
    analyze_log_hybrid,
    detect_dockerfile_distro,
    heal_dockerfile,
    parse_compiler_log,
)
from .repro_hash import (
    calculate_dependency_lock_score,
    dependency_telemetry,
    compare_certificates,
    compute_file_hash,
    compute_merkle_root,
    generate_certificate,
    run_full_audit,
)
from .config import Policy, WorkspacePolicy, load_policy, load_workspace_policy

__all__ = [
    "AuditReport",
    "BuildVerification",
    "DependencyTelemetry",
    "CompilerDiagnostic",
    "DockerfilePatchResult",
    "FileHashNode",
    "HealResult",
    "HybridAnalysisResult",
    "LandmineIssue",
    "PostHealVerificationSummary",
    "ReproducibilityCertificate",
    "SeverityLevel",
    "HealingConflictError",
    "apply_heal_result",
    "apply_healing",
    "heal_repository",
    "readiness_score",
    "scan_repository",
    "analyze_log_hybrid",
    "detect_dockerfile_distro",
    "heal_dockerfile",
    "parse_compiler_log",
    "calculate_dependency_lock_score",
    "dependency_telemetry",
    "compare_certificates",
    "compute_file_hash",
    "compute_merkle_root",
    "generate_certificate",
    "run_full_audit",
    "Policy",
    "WorkspacePolicy",
    "load_policy",
    "load_workspace_policy",
    "__version__",
]
