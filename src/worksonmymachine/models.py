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

    tool: str = Field(min_length=1)
    message: str = Field(min_length=1)
    severity: SeverityLevel = SeverityLevel.HIGH
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    code: str | None = None
    raw_output: str | None = None

    _validate_file_path = field_validator("file_path")(_relative_posix_path)


class DockerfilePatchResult(_StrictModel):
    """A proposed or applied deterministic Dockerfile repair."""

    source_path: str
    patched_content: str
    changes: list[str] = Field(default_factory=list)
    applied: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    _validate_source_path = field_validator("source_path")(_relative_posix_path)


class FileHashNode(_StrictModel):
    """One node in the deterministic file/Merkle hash tree."""

    path: str
    digest: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
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

    _validate_target = field_validator("target")(_relative_posix_path)


FileHashNode.model_rebuild()
