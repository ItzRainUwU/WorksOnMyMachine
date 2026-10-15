"""Pydantic contracts shared by the scanner and its API.

The models intentionally use POSIX-relative paths.  A scanner may inspect a
Windows-originated project, but it must never allow a host-absolute path to
cross the API boundary.
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SeverityLevel(StrEnum):
    """Impact level assigned to a reproducibility finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _relative_posix_path(value: str) -> str:
    """Validate a project-relative POSIX path without touching the filesystem."""

    normalized = value.strip()
    if not normalized:
        raise ValueError("path must not be empty")
    if "\\" in normalized:
        raise ValueError("path must use POSIX separators")
    if normalized.startswith("/") or (
        len(normalized) >= 2 and normalized[1] == ":"
    ):
        raise ValueError("path must be relative")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("path must not contain empty, dot, or parent segments")
    return normalized


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LandmineIssue(_StrictModel):
    """A portability, dependency, or environment assumption found in a target."""

    issue_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    message: str = Field(min_length=1)
    severity: SeverityLevel
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    remediation: str | None = None
    evidence: list[str] = Field(default_factory=list)

    _validate_file_path = field_validator("file_path")(_relative_posix_path)


class CompilerDiagnostic(_StrictModel):
    """Normalized compiler or package-manager output."""

    # Keep raw compiler output intact so an API consumer can inspect the exact
    # evidence that produced the normalized finding.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    tool: str = Field(min_length=1)
    message: str = Field(min_length=1)
    severity: SeverityLevel = SeverityLevel.HIGH
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    code: str | None = None
    raw_output: str | None = None
    error_signature: str = "unclassified-build-error"
    missing_artifact: str | None = None
    recommended_apt_packages: list[str] = Field(default_factory=list)
    root_cause_explanation: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("recommended_apt_packages", mode="before")
    @classmethod
    def _sort_apt_packages(cls, value: list[str] | None) -> list[str]:
        """Keep package recommendations stable and free of duplicates."""

        if value is None:
            return []
        return sorted({str(package).strip() for package in value if str(package).strip()})

    _validate_file_path = field_validator("file_path")(_relative_posix_path)


class DockerfilePatchResult(_StrictModel):
    """A proposed or applied deterministic Dockerfile repair."""

    # Dockerfile content and unified diffs are byte-for-byte evidence; the
    # shared API model's whitespace stripping would otherwise remove a final
    # newline from these fields.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    source_path: str
    patched_content: str
    changes: list[str] = Field(default_factory=list)
    applied: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    before_content: str = ""
    after_content: str = ""
    unified_diff: str = ""
    apt_packages: list[str] = Field(default_factory=list)
    security_fixes: list[str] = Field(default_factory=list)
    staged_output_path: str | None = None

    @field_validator("apt_packages", mode="before")
    @classmethod
    def _sort_patch_packages(cls, value: list[str] | None) -> list[str]:
        """Keep Dockerfile package layers reproducible."""

        if value is None:
            return []
        return sorted({str(package).strip() for package in value if str(package).strip()})

    _validate_source_path = field_validator("source_path")(_relative_posix_path)

    @property
    def diff(self) -> str:
        """Compatibility alias for callers that use the short diff name."""

        return self.unified_diff

    @property
    def output_path(self) -> str | None:
        """Compatibility alias for the copied/staged target directory."""

        return self.staged_output_path

    @property
    def recommended_apt_packages(self) -> list[str]:
        """Expose the package list under the parser's vocabulary as well."""

        return self.apt_packages


class HybridAnalysisResult(_StrictModel):
    """Structured output from deterministic parsing plus optional LLM context."""

    diagnostics: list[CompilerDiagnostic] = Field(default_factory=list)
    apt_packages: list[str] = Field(default_factory=list)
    recommended_apt_packages: list[str] = Field(default_factory=list)
    root_cause_summary: str = ""
    llm_used: bool = False

    @field_validator("apt_packages", "recommended_apt_packages", mode="before")
    @classmethod
    def _sort_analysis_packages(cls, value: list[str] | None) -> list[str]:
        """Normalize both package-name aliases to sorted unique values."""

        if value is None:
            return []
        return sorted({str(package).strip() for package in value if str(package).strip()})


class FileHashNode(_StrictModel):
    """One node in the deterministic file/Merkle hash tree."""

    path: str
    digest: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    raw_sha256: str = ""
    has_crlf: bool = False
    children: list["FileHashNode"] = Field(default_factory=list)

    _validate_path = field_validator("path")(_relative_posix_path)


class ReproducibilityCertificate(_StrictModel):
    """Signed-ready evidence that a target was checked deterministically."""

    certificate_id: str = Field(min_length=1)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    root_hash: str = Field(min_length=1)
    runtime: str = Field(min_length=1)
    dependency_lock_hash: str | None = None
    verified: bool = False
    issues: list[LandmineIssue] = Field(default_factory=list)
    # Phase 4 evidence.  All of these fields have defaults so certificates
    # produced by earlier phases remain valid API payloads.
    file_nodes: list[FileHashNode] = Field(default_factory=list)
    dependency_lock_score: float = Field(default=0.0, ge=0.0, le=100.0)
    linux_readiness_score: float = Field(default=0.0, ge=0.0, le=100.0)
    dockerfile_hardened: bool = False
    verification_hash: str = ""
    is_cleanroom_certified: bool = False

    @property
    def merkle_root(self) -> str:
        """Compatibility alias for callers using the descriptive name."""

        return self.root_hash


class AuditReport(_StrictModel):
    """Complete Phase 1 contract for a target audit."""

    target: str
    scanned_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    reproducible: bool = False
    issues: list[LandmineIssue] = Field(default_factory=list)
    diagnostics: list[CompilerDiagnostic] = Field(default_factory=list)
    dockerfile_patches: list[DockerfilePatchResult] = Field(default_factory=list)
    merkle_root: str | None = None
    certificate: ReproducibilityCertificate | None = None
    before_certificate: ReproducibilityCertificate | None = None
    after_certificate: ReproducibilityCertificate | None = None
    dockerfile_patch: DockerfilePatchResult | None = None
    unified_diffs: list[str] = Field(default_factory=list)
    compiler_diagnostics: list[CompilerDiagnostic] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def timeline_data(self) -> list[dict[str, Any]]:
        """Compatibility alias for consumers using the descriptive name."""

        return self.timeline

    _validate_target = field_validator("target")(_relative_posix_path)


class HealResult(_StrictModel):
    """The deterministic result of healing a copied repository tree."""

    output_path: str = Field(min_length=1)
    issues_found: int = Field(default=0, ge=0)
    issues_fixed: int = Field(default=0, ge=0)
    fixed_issues: list[LandmineIssue] = Field(default_factory=list)
    remaining_issues: list[LandmineIssue] = Field(default_factory=list)
    unified_diffs: list[str] = Field(default_factory=list)
    readiness_score_before: float = Field(ge=0.0, le=100.0)
    readiness_score_after: float = Field(ge=0.0, le=100.0)

    @property
    def fixed_count(self) -> int:
        """Compatibility alias for callers using the short count name."""

        return self.issues_fixed

    @property
    def remaining_count(self) -> int:
        """Return the number of issues left in the staged tree."""

        return len(self.remaining_issues)

    @property
    def before_score(self) -> float:
        """Compatibility alias for callers using the short score name."""

        return self.readiness_score_before

    @property
    def after_score(self) -> float:
        """Compatibility alias for callers using the short score name."""

        return self.readiness_score_after

    @property
    def before_readiness_score(self) -> float:
        """Readable alias for callers that prefer the full score name."""

        return self.readiness_score_before

    @property
    def after_readiness_score(self) -> float:
        """Readable alias for callers that prefer the full score name."""

        return self.readiness_score_after

    @property
    def counts(self) -> dict[str, int]:
        """Return the two headline issue counts as a small mapping."""

        return {"fixed": self.issues_fixed, "remaining": self.remaining_count}

    @property
    def fixed_issue_count(self) -> int:
        """Compatibility alias for callers using an explicit count name."""

        return self.issues_fixed

    @property
    def remaining_issue_count(self) -> int:
        """Compatibility alias for callers using an explicit count name."""

        return self.remaining_count

    @property
    def diffs(self) -> dict[str, str]:
        """Compatibility mapping keyed by the unified diff header path."""

        return {
            diff.splitlines()[0][4:]: diff
            for diff in self.unified_diffs
            if diff.splitlines() and diff.splitlines()[0].startswith("--- ")
        }


FileHashNode.model_rebuild()
