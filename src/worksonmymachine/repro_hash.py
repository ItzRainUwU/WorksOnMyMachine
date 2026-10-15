"""Cross-platform reproducibility hashes, certificates, and audit composition.

The implementation in this module is intentionally filesystem-only.  It does
not execute target code, call a package manager, or depend on the host's file
metadata.  A healed audit is performed against a temporary copy and the copy
is removed before :func:`run_full_audit` returns.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import tomllib
from typing import Any, Iterable

from .apt_healer import heal_dockerfile, parse_compiler_log
from .models import (
    AuditReport,
    CompilerDiagnostic,
    DockerfilePatchResult,
    FileHashNode,
    LandmineIssue,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .scanner import heal_repository, readiness_score, scan_repository


_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
    }
)

_SOURCE_SUFFIXES = frozenset(
    {
        ".bash",
        ".c",
        ".cc",
        ".cfg",
        ".conf",
        ".cpp",
        ".css",
        ".cxx",
        ".go",
        ".h",
        ".hpp",
        ".htm",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kts",
        ".kt",
        ".lock",
        ".mjs",
        ".php",
        ".py",
        ".pyi",
        ".rb",
        ".rs",
        ".rst",
        ".sh",
        ".sql",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

_REQUIREMENT_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?P<spec>[^;#]*)(?:[;#].*)?$"
)
_FROM_LINE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", re.I)
_USER_LINE = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.I)


def _relative_path(path: Path) -> str:
    """Return a model-safe POSIX path for a standalone file hash."""

    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return PurePosixPath(candidate.name).as_posix()


def _is_text_source(path: Path, raw: bytes) -> bool:
    """Recognize UTF-8 text without treating arbitrary binary as source."""

    if b"\x00" in raw:
        return False
    if path.suffix.lower() in _SOURCE_SUFFIXES or path.name.lower().startswith("dockerfile"):
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _hash_bytes(path: Path, raw: bytes, relative_path: str, normalize_newlines: bool) -> FileHashNode:
    has_crlf = b"\r\n" in raw
    normalized = raw
    if normalize_newlines and has_crlf and _is_text_source(path, raw):
        normalized = raw.replace(b"\r\n", b"\n")
    return FileHashNode(
        path=relative_path,
        digest=hashlib.sha256(normalized).hexdigest(),
        size_bytes=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        has_crlf=has_crlf,
    )


def compute_file_hash(file_path: Path, normalize_newlines: bool = True) -> FileHashNode:
    """Hash one file while preserving raw hash and line-ending metadata.

    ``digest`` is the normalized content hash for UTF-8 text/source files and
    the raw content hash for binary files.  Only content-derived values are
    included; mtime, ownership, inode, and filesystem enumeration order never
    affect the result.
    """

    path = Path(file_path)
    if not path.is_file():
        raise ValueError("file_path must be a regular file")
    raw = path.read_bytes()
    return _hash_bytes(path, raw, _relative_path(path), normalize_newlines)


def compute_merkle_root(file_nodes: list[FileHashNode]) -> str:
    """Return the deterministic root of sorted ``<path>:<digest>`` records."""

    payload = "".join(
        f"{node.path}:{node.digest}\n"
        for node in sorted(file_nodes, key=lambda item: item.path)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _iter_files(root: Path) -> Iterable[tuple[Path, str]]:
    """Yield regular files and relative POSIX paths in stable order."""

    def walk(directory: Path, prefix: tuple[str, ...]) -> Iterable[tuple[Path, str]]:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except (OSError, ValueError):
            return
        for entry in entries:
            if entry.name.casefold() in _EXCLUDED_DIRECTORIES:
                continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    yield from walk(entry, (*prefix, entry.name))
                elif entry.is_file():
                    relative = PurePosixPath(*(prefix + (entry.name,))).as_posix()
                    yield entry, relative
            except OSError:
                continue

    yield from walk(Path(root), ())


def _collect_file_nodes(target: Path) -> list[FileHashNode]:
    nodes: list[FileHashNode] = []
    for path, relative in _iter_files(target):
        try:
            nodes.append(_hash_bytes(path, path.read_bytes(), relative, True))
        except OSError:
            continue
    return sorted(nodes, key=lambda item: item.path)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _requirement_status(path: Path) -> tuple[int, int, set[str]]:
    """Return declared count, unpinned count, and exact pin names."""

    declared = 0
    unpinned = 0
    pinned_names: set[str] = set()
    for raw_line in _read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        match = _REQUIREMENT_LINE.match(line)
        if match is None:
            declared += 1
            unpinned += 1
            continue
        declared += 1
        name = match.group("name").lower().replace("_", "-")
        spec = match.group("spec").strip()
        if re.match(r"^==\s*[^=\s]+(?:\s|$)", spec):
            pinned_names.add(name)
        else:
            unpinned += 1
    return declared, unpinned, pinned_names


def _toml_dependencies(path: Path) -> tuple[list[str], bool]:
    text = _read_text(path)
    if not text:
        return [], False
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], False
    project = parsed.get("project", {})
    if not isinstance(project, dict):
        return [], False
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        return [], False
    return [str(value) for value in dependencies], True


def _dependency_name(specification: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", specification)
    return (match.group(1) if match else "").lower().replace("_", "-")


def _pinned_image(image: str) -> bool:
    if "@sha256:" in image.lower():
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    tag = last.rsplit(":", 1)[1].lower()
    if tag in {"latest", "stable", "edge", "nightly"}:
        return False
    if last.lower().startswith("python:") and not re.search(
        r"\d+\.\d+\.\d+", tag
    ):
        return False
    return bool(re.search(r"\d+\.\d+(?:\.\d+)?", tag))


def _dockerfile_paths(target: Path) -> list[tuple[Path, str]]:
    return [
        (path, relative)
        for path, relative in _iter_files(target)
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.")
    ]


def _dockerfile_is_hardened(path: Path) -> bool:
    text = _read_text(path)
    if not text:
        return False
    from_lines = [match.group("image") for line in text.splitlines() if (match := _FROM_LINE.match(line))]
    if not from_lines or not all(_pinned_image(image) for image in from_lines):
        return False
    users = [match.group("user").split()[0] for line in text.splitlines() if (match := _USER_LINE.match(line))]
    if not users or users[-1].lower() in {"root", "0"}:
        return False
    lowered = text.lower()
    if "apt-get install" in lowered and "rm -rf /var/lib/apt/lists" not in lowered:
        return False
    return True


def _dockerfiles_hardened(target: Path) -> bool:
    dockerfiles = _dockerfile_paths(target)
    return not dockerfiles or all(_dockerfile_is_hardened(path) for path, _ in dockerfiles)


def calculate_dependency_lock_score(target_path: Path) -> float:
    """Score dependency reproducibility from local lock/configuration evidence.

    The score is intentionally conservative for declared Python requirements,
    Cargo lockfiles, and Docker base tags.  A JavaScript project with no
    ``package-lock.json`` is not penalized merely for having a package manifest;
    when a lockfile is present it must at least be a valid lockfile.  This
    matches the copy-on-write healer's supported repairs while still inspecting
    all dependency formats named by the Phase 4 contract.
    """

    target = Path(target_path)
    if not target.is_dir():
        return 0.0
    declared_dependencies = 0
    pinned_dependencies = 0
    lock_score = 100.0
    pinned_requirement_names: set[str] = set()
    requirement_files = [
        (path, relative)
        for path, relative in _iter_files(target)
        if path.name.lower().startswith("requirements")
        and path.suffix.lower() in {"", ".txt", ".in", ".lock"}
    ]
    for path, _ in requirement_files:
        if path.name.lower() == "requirements.lock":
            continue
        declared, unpinned, names = _requirement_status(path)
        declared_dependencies += declared
        pinned_dependencies += declared - unpinned
        pinned_requirement_names.update(names)

    if any(path.name.lower() == "requirements.txt" for path, _ in requirement_files) and not any(
        path.name.lower() == "requirements.lock" for path, _ in requirement_files
    ):
        lock_score = 0.0

    for path, _ in _iter_files(target):
        if path.name.lower() != "pyproject.toml":
            continue
        dependencies, valid = _toml_dependencies(path)
        if not valid:
            continue
        for dependency in dependencies:
            name = _dependency_name(dependency)
            declared_dependencies += 1
            if name in pinned_requirement_names:
                pinned_dependencies += 1
                continue
            if re.search(r"==\s*[^=\s,;]+", dependency):
                pinned_dependencies += 1

    cargo_manifests = [path for path, _ in _iter_files(target) if path.name == "Cargo.toml"]
    cargo_locks = [path for path, _ in _iter_files(target) if path.name == "Cargo.lock"]
    if cargo_manifests:
        if not cargo_locks:
            lock_score = 0.0
        else:
            for lock in cargo_locks:
                lock_text = _read_text(lock)
                if "[[package]]" not in lock_text or not re.search(
                    r"(?m)^version\s*=\s*[\"'][^\"']+[\"']", lock_text
                ):
                    lock_score = 0.0

    for path, _ in _iter_files(target):
        if path.name.lower() != "package-lock.json":
            continue
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            lock_score = 0.0
            continue
        if not isinstance(parsed, dict) or not isinstance(
            parsed.get("lockfileVersion"), int
        ):
            lock_score = 0.0

    for path, _ in _dockerfile_paths(target):
        text = _read_text(path)
        images = [match.group("image") for line in text.splitlines() if (match := _FROM_LINE.match(line))]
        if any(not _pinned_image(image) for image in images):
            lock_score = 0.0

    pin_score = (
        100.0
        if declared_dependencies == 0
        else 100.0 * pinned_dependencies / declared_dependencies
    )
    return round(pin_score * 0.6 + lock_score * 0.4, 2)


def _runtime_for(target: Path, nodes: list[FileHashNode]) -> str:
    for name in (".python-version", "runtime.txt"):
        value = _read_text(target / name).strip()
        if value:
            return value if name == "runtime.txt" else f"python-{value}"
    pyproject = _read_text(target / "pyproject.toml")
    match = re.search(r"requires-python\s*=\s*[\"']([^\"']+)", pyproject)
    if match:
        version = re.search(r"\d+(?:\.\d+)+", match.group(1))
        if version:
            return f"python-{version.group(0)}"
    if any(node.path.endswith(".py") for node in nodes):
        return "python"
    if any(node.path.endswith(".rs") for node in nodes):
        return "rust"
    return "unknown"


def _dependency_lock_hash(nodes: list[FileHashNode]) -> str | None:
    selected = [
        node
        for node in nodes
        if (
            Path(node.path).name.lower().startswith("requirements")
            or Path(node.path).name.lower()
            in {"pyproject.toml", "cargo.lock", "package-lock.json"}
            or Path(node.path).name.lower().startswith("dockerfile")
        )
    ]
    if not selected:
        return None
    return compute_merkle_root(selected)


def _issue_payload(issues: Iterable[LandmineIssue]) -> list[dict[str, Any]]:
    return [
        {
            "issue_id": issue.issue_id,
            "category": issue.category,
            "message": issue.message,
            "severity": issue.severity.value,
            "file_path": issue.file_path,
            "line_number": issue.line_number,
            "evidence": list(issue.evidence),
        }
        for issue in sorted(
            issues,
            key=lambda item: (
                item.file_path or "",
                item.line_number or 0,
                item.issue_id,
                item.message,
            ),
        )
    ]


def _verification_hash(
    root_hash: str,
    dependency_lock_hash: str | None,
    dependency_score: float,
    readiness: float,
    dockerfile_hardened: bool,
    issues: list[LandmineIssue],
) -> str:
    payload = {
        "root_hash": root_hash,
        "dependency_lock_hash": dependency_lock_hash,
        "dependency_lock_score": dependency_score,
        "linux_readiness_score": readiness,
        "dockerfile_hardened": dockerfile_hardened,
        "issues": _issue_payload(issues),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def generate_certificate(target_path: Path) -> ReproducibilityCertificate:
    """Generate deterministic evidence for a target without changing it."""

    target = Path(target_path)
    nodes = _collect_file_nodes(target) if target.is_dir() else []
    issues = scan_repository(target)
    readiness = readiness_score(issues)
    dependency_score = calculate_dependency_lock_score(target)
    hardened = _dockerfiles_hardened(target) if target.is_dir() else False
    root_hash = compute_merkle_root(nodes)
    dependency_hash = _dependency_lock_hash(nodes)
    verification_hash = _verification_hash(
        root_hash,
        dependency_hash,
        dependency_score,
        readiness,
        hardened,
        issues,
    )
    blocking_issue = any(
        issue.severity in {SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        for issue in issues
    )
    certified = (
        readiness == 100.0
        and dependency_score == 100.0
        and hardened
        and not blocking_issue
    )
    return ReproducibilityCertificate(
        certificate_id=f"cert-{verification_hash[:16]}",
        root_hash=root_hash,
        runtime=_runtime_for(target, nodes),
        dependency_lock_hash=dependency_hash,
        verified=certified,
        issues=issues,
        file_nodes=nodes,
        dependency_lock_score=dependency_score,
        linux_readiness_score=readiness,
        dockerfile_hardened=hardened,
        verification_hash=verification_hash,
        is_cleanroom_certified=certified,
    )


def _node_map(certificate: ReproducibilityCertificate) -> dict[str, FileHashNode]:
    return {node.path: node for node in certificate.file_nodes}


def compare_certificates(
    cert_a: ReproducibilityCertificate, cert_b: ReproducibilityCertificate
) -> dict[str, Any]:
    """Compare two certificates using only their deterministic file evidence."""

    a_nodes = _node_map(cert_a)
    b_nodes = _node_map(cert_b)
    a_paths = set(a_nodes)
    b_paths = set(b_nodes)
    modified = sorted(
        path for path in a_paths & b_paths if a_nodes[path].digest != b_nodes[path].digest
    )
    line_drifts = sorted(
        path
        for path in a_paths & b_paths
        if (
            a_nodes[path].has_crlf != b_nodes[path].has_crlf
            or (
                a_nodes[path].digest == b_nodes[path].digest
                and bool(a_nodes[path].raw_sha256 and b_nodes[path].raw_sha256)
                and a_nodes[path].raw_sha256 != b_nodes[path].raw_sha256
            )
        )
    )
    return {
        "modified_files": modified,
        "added_files": sorted(b_paths - a_paths),
        "removed_files": sorted(a_paths - b_paths),
        "line_ending_drifts": line_drifts,
        "score_delta": round(
            cert_b.linux_readiness_score - cert_a.linux_readiness_score, 2
        ),
        "merkle_match": cert_a.root_hash == cert_b.root_hash,
    }


def _target_label(target: Path) -> str:
    """Choose the existing API's short, relative target label."""

    return target.name or target.as_posix()


def _compiler_diagnostics(target: Path) -> list[CompilerDiagnostic]:
    log_path = target / "build_error.log"
    if not log_path.is_file():
        return []
    return parse_compiler_log(_read_text(log_path))


def _timeline(
    before: ReproducibilityCertificate,
    after: ReproducibilityCertificate | None,
    heal_result: Any = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "event": "before_certificate",
            "verification_hash": before.verification_hash,
            "linux_readiness_score": before.linux_readiness_score,
            "dependency_lock_score": before.dependency_lock_score,
        }
    ]
    if heal_result is not None:
        events.append(
            {
                "event": "copy_on_write_heal",
                "issues_found": heal_result.issues_found,
                "issues_fixed": heal_result.issues_fixed,
                "readiness_score_before": heal_result.readiness_score_before,
                "readiness_score_after": heal_result.readiness_score_after,
                "unified_diff_count": len(heal_result.unified_diffs),
            }
        )
    if after is not None:
        events.append(
            {
                "event": "after_certificate",
                "verification_hash": after.verification_hash,
                "linux_readiness_score": after.linux_readiness_score,
                "dependency_lock_score": after.dependency_lock_score,
            }
        )
    return events


def run_full_audit(target_path: Path, auto_heal: bool = False) -> AuditReport:
    """Run a complete audit, healing only a temporary copy when requested."""

    target = Path(target_path)
    if not target.is_dir():
        raise ValueError("target_path must be a directory")
    before = generate_certificate(target)
    diagnostics = _compiler_diagnostics(target)
    after: ReproducibilityCertificate | None = None
    heal_result: Any = None
    patch: DockerfilePatchResult | None = None
    diffs: list[str] = []
    if auto_heal:
        staging_parent = Path(tempfile.mkdtemp(prefix="worksonmymachine-audit-"))
        staged = staging_parent / "target"
        try:
            heal_result = heal_repository(target, staged)
            after = generate_certificate(staged)
            diffs = list(heal_result.unified_diffs)
            if _dockerfile_paths(target):
                patch_stage = staging_parent / "docker-patch"
                try:
                    docker_patch = heal_dockerfile(target, patch_stage)
                    # The patch evidence is retained, while its temporary
                    # copied output is deliberately not exposed after cleanup.
                    patch = docker_patch.model_copy(update={"staged_output_path": None})
                except ValueError:
                    patch = None
                finally:
                    shutil.rmtree(patch_stage, ignore_errors=True)
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)

    selected = after if after is not None else before
    patches = [patch] if patch is not None else []
    return AuditReport(
        target=_target_label(target),
        reproducible=selected.is_cleanroom_certified,
        issues=before.issues,
        diagnostics=diagnostics,
        dockerfile_patches=patches,
        merkle_root=selected.root_hash,
        certificate=selected,
        before_certificate=before,
        after_certificate=after,
        dockerfile_patch=patch,
        unified_diffs=diffs,
        compiler_diagnostics=diagnostics,
        timeline=_timeline(before, after, heal_result),
    )


__all__ = [
    "calculate_dependency_lock_score",
    "compare_certificates",
    "compute_file_hash",
    "compute_merkle_root",
    "generate_certificate",
    "run_full_audit",
]
