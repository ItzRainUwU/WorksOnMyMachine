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
from .config import workspace_config
from .models import (
    AuditReport,
    CompilerDiagnostic,
    DependencyTelemetry,
    DockerfilePatchResult,
    FileHashNode,
    LandmineIssue,
    PostHealVerificationSummary,
    ReproducibilityCertificate,
    SeverityLevel,
)
from .scanner import heal_repository, readiness_score, scan_repository


_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".opencode",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "node_modules",
        "build",
        "dist",
        ".mypy_cache",
        ".ruff_cache",
    }
) | frozenset(Path(path).name for path in workspace_config.ignore_paths)

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


def _requirement_declarations(path: Path) -> list[tuple[str, str]]:
    """Return normalized requirement names and their version specifications."""

    declarations: list[tuple[str, str]] = []
    for raw_line in _read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        match = _REQUIREMENT_LINE.match(line)
        if match is None:
            declarations.append(("", ""))
            continue
        name = match.group("name").lower().replace("_", "-")
        spec = match.group("spec").strip()
        declarations.append((name, spec))
    return declarations


def _requirement_status(path: Path) -> tuple[int, int, set[str]]:
    """Return declared count, unpinned count, and exact pin names."""

    declarations = _requirement_declarations(path)
    pinned_names = {
        name
        for name, spec in declarations
        if name and re.match(r"^==\s*[^=\s]+(?:\s|$)", spec)
    }
    return len(declarations), len(declarations) - len(pinned_names), pinned_names


def _pinned_requirement_version(specification: str) -> str | None:
    match = re.match(r"^==\s*([^=\s,;]+)", specification.strip())
    return match.group(1) if match else None


def _read_requirements_lock(path: Path) -> tuple[bool, dict[str, str]]:
    """Parse a local requirements lock and return its exact pins.

    A lock containing only comments, directives, malformed lines, or floating
    requirements is not useful evidence for a reproducible installation.  The
    parser intentionally accepts hash suffixes and common pip comments while
    keeping the package/version portion strict and deterministic.
    """

    entries: dict[str, str] = {}
    saw_requirement = False
    for raw_line in _read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "--")):
            continue
        match = _REQUIREMENT_LINE.match(line)
        if match is None:
            return False, {}
        name = match.group("name").lower().replace("_", "-")
        version = _pinned_requirement_version(match.group("spec"))
        if not version:
            return False, {}
        previous = entries.get(name)
        if previous is not None and previous != version:
            return False, {}
        entries[name] = version
        saw_requirement = True
    return saw_requirement, entries


def _read_toml(path: Path) -> dict[str, Any] | None:
    """Parse a local TOML file without consulting a package manager."""

    text = _read_text(path)
    if not text:
        return None
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _poetry_dependency_declarations(path: Path) -> tuple[list[tuple[str, str]], bool]:
    """Read Poetry's dependency table from a pyproject manifest."""

    parsed = _read_toml(path)
    if parsed is None:
        return [], False
    tool = parsed.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if poetry is None:
        return [], True
    if not isinstance(poetry, dict):
        return [], False
    dependencies = poetry.get("dependencies", {})
    dev_dependencies = poetry.get("dev-dependencies", {})
    groups = poetry.get("group", {})
    if not isinstance(dependencies, dict) or not isinstance(dev_dependencies, dict):
        return [], False
    declarations: list[tuple[str, str]] = []

    def add_table(table: Any) -> bool:
        if not isinstance(table, dict):
            return False
        for name, specification in table.items():
            # Poetry uses this key for the supported interpreter rather than a
            # package that must be installed into the environment.
            if str(name).lower() == "python":
                continue
            if isinstance(specification, str):
                spec = specification
            elif isinstance(specification, dict):
                spec = str(specification.get("version", ""))
            else:
                return False
            declarations.append((str(name), spec))
        return True

    if not add_table(dependencies) or not add_table(dev_dependencies):
        return [], False
    if groups:
        if not isinstance(groups, dict):
            return [], False
        for group in groups.values():
            if not isinstance(group, dict) or not add_table(group.get("dependencies", {})):
                return [], False
    return declarations, True


def _pipfile_dependency_declarations(path: Path) -> tuple[list[tuple[str, str]], bool]:
    """Read Pipenv package declarations from a local Pipfile."""

    parsed = _read_toml(path)
    if parsed is None:
        return [], False
    declarations: list[tuple[str, str]] = []
    for section in ("packages", "dev-packages"):
        values = parsed.get(section, {})
        if not isinstance(values, dict):
            return [], False
        for name, specification in values.items():
            if isinstance(specification, str):
                spec = specification
            elif isinstance(specification, dict):
                # Pipenv permits git/path/file sources.  They are represented
                # as floating in the direct-manifest pin score unless a lock
                # subsequently resolves them.
                spec = str(specification.get("version", ""))
            else:
                return [], False
            declarations.append((str(name), spec))
    return declarations, True


def _read_poetry_lock(path: Path) -> tuple[bool, dict[str, str]]:
    """Validate the package-bearing shape of a Poetry lockfile."""

    parsed = _read_toml(path)
    if parsed is None:
        return False, {}
    metadata = parsed.get("metadata")
    lock_version = parsed.get("lock-version")
    if isinstance(metadata, dict):
        lock_version = metadata.get("lock-version", lock_version)
    if not isinstance(lock_version, (str, int)) or not str(lock_version).strip():
        return False, {}
    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        return False, {}
    entries: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            return False, {}
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip():
            return False, {}
        if not isinstance(version, str) or not version.strip():
            return False, {}
        normalized = name.lower().replace("_", "-")
        previous = entries.get(normalized)
        if previous is not None and previous != version:
            return False, {}
        entries[normalized] = version
    return True, entries


def _read_uv_lock(path: Path) -> tuple[bool, dict[str, str]]:
    """Validate uv.lock's local TOML structure and package identities."""

    parsed = _read_toml(path)
    if parsed is None or not isinstance(parsed.get("version"), int):
        return False, {}
    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        return False, {}
    entries: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            return False, {}
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            return False, {}
        version = package.get("version", "")
        source = package.get("source")
        # uv's editable workspace package intentionally has no version.  All
        # registry/git/path packages must still carry a version string.
        if version is not None and not isinstance(version, str):
            return False, {}
        if not str(version).strip() and (
            not isinstance(source, dict) or not source
        ):
            return False, {}
        normalized = name.lower().replace("_", "-")
        previous = entries.get(normalized)
        if previous is not None and previous != str(version):
            return False, {}
        entries[normalized] = str(version)
    return True, entries


def _read_pipfile_lock(path: Path) -> tuple[bool, dict[str, str]]:
    """Validate Pipenv's JSON lock metadata and exact package versions."""

    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, {}
    if not isinstance(parsed, dict):
        return False, {}
    metadata = parsed.get("_meta")
    if not isinstance(metadata, dict):
        return False, {}
    lock_hash = metadata.get("hash")
    if (
        not isinstance(lock_hash, dict)
        or not isinstance(lock_hash.get("sha256"), str)
        or not lock_hash["sha256"].strip()
    ):
        return False, {}
    entries: dict[str, str] = {}
    for section in ("default", "develop"):
        values = parsed.get(section, {})
        if not isinstance(values, dict):
            return False, {}
        for name, package in values.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(package, dict):
                return False, {}
            version = package.get("version")
            if not isinstance(version, str) or _pinned_requirement_version(version) is None:
                return False, {}
            normalized = name.lower().replace("_", "-")
            previous = entries.get(normalized)
            if previous is not None and previous != version:
                return False, {}
            entries[normalized] = version
    # A lock with no package records is not useful evidence, even when its
    # metadata is syntactically valid.
    return bool(entries), entries


def _toml_dependencies(path: Path) -> tuple[list[str], bool]:
    parsed = _read_toml(path)
    if parsed is None:
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


def _cargo_dependency_is_pinned(specification: Any) -> bool:
    """Return whether a Cargo dependency uses an exact, immutable source."""

    if isinstance(specification, str):
        return bool(re.fullmatch(r"\s*=\s*v?\d+(?:\.\d+)+(?:[-+][^\s]+)?\s*", specification))
    if not isinstance(specification, dict):
        return False
    version = specification.get("version")
    if isinstance(version, str) and _cargo_dependency_is_pinned(version):
        return True
    # A revision identifies an immutable git source.  A branch or tag does
    # not, and a bare git URL therefore remains floating.
    if isinstance(specification.get("rev"), str) and specification["rev"].strip():
        return True
    # A path dependency is content-addressed by the project tree itself.
    return isinstance(specification.get("path"), str) and bool(specification["path"].strip())


def _cargo_dependency_status(
    path: Path,
) -> tuple[int, int, set[str], set[str], bool]:
    """Return Cargo dependency counts, names, and manifest validity."""

    text = _read_text(path)
    if not text:
        return 0, 0, set(), set(), False
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return 0, 0, set(), set(), False

    declared = 0
    pinned = 0
    names: set[str] = set()
    pinned_names: set[str] = set()

    def visit(value: Any, key: str = "") -> None:
        nonlocal declared, pinned
        if isinstance(value, dict):
            if key.endswith("dependencies"):
                for dependency_name, specification in value.items():
                    declared += 1
                    names.add(str(dependency_name).lower().replace("_", "-"))
                    if _cargo_dependency_is_pinned(specification):
                        pinned += 1
                        pinned_names.add(str(dependency_name).lower().replace("_", "-"))
            else:
                for child_key, child_value in value.items():
                    visit(child_value, str(child_key))

    visit(parsed)
    return declared, pinned, names, pinned_names, True


def _cargo_lock_package_names(path: Path) -> set[str] | None:
    """Return resolved package names when a Cargo lock has valid TOML shape."""

    text = _read_text(path)
    if not text:
        return None
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(parsed.get("version"), int):
        return None
    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        return None
    package_names: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            return None
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            return None
        package_names.add(name.lower().replace("_", "-"))
    return package_names


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
    PEP 621/Poetry/Pipenv manifests, Cargo lockfiles, and Docker base tags.  A
    JavaScript project with no ``package-lock.json`` is not penalized merely for
    having a package manifest; when a lockfile is present it must at least be a
    valid lockfile.  This matches the copy-on-write healer's supported repairs
    while still inspecting all dependency formats named by the Phase 4 contract.
    """

    target = Path(target_path)
    if not target.is_dir():
        return 0.0
    declared_dependencies = 0
    pinned_dependencies = 0
    lock_score = 100.0
    pinned_requirement_names: set[str] = set()
    declared_requirement_specs: list[tuple[str, str]] = []
    pep621_declarations: list[tuple[str, str]] = []
    poetry_declarations: list[tuple[str, str]] = []
    pipfile_declarations: list[tuple[str, str]] = []
    requirement_files = [
        (path, relative)
        for path, relative in _iter_files(target)
        if path.name.lower().startswith("requirements")
        and path.suffix.lower() in {"", ".txt", ".in", ".lock"}
    ]
    for path, _ in requirement_files:
        if path.name.lower() == "requirements.lock":
            continue
        declared_requirement_specs.extend(_requirement_declarations(path))
        declared, unpinned, names = _requirement_status(path)
        declared_dependencies += declared
        pinned_dependencies += declared - unpinned
        pinned_requirement_names.update(names)

    pyproject_paths = [
        path for path, _ in _iter_files(target) if path.name.lower() == "pyproject.toml"
    ]
    for path in pyproject_paths:
        if path.name.lower() != "pyproject.toml":
            continue
        dependencies, valid = _toml_dependencies(path)
        if not valid:
            continue
        for dependency in dependencies:
            name = _dependency_name(dependency)
            requirement = _REQUIREMENT_LINE.match(dependency)
            declared_requirement_specs.append(
                (name, requirement.group("spec").strip() if requirement else "")
            )
            pep621_declarations.append((name, requirement.group("spec").strip() if requirement else ""))
            declared_dependencies += 1
            if name in pinned_requirement_names:
                pinned_dependencies += 1
                continue
            if re.search(r"==\s*[^=\s,;]+", dependency):
                pinned_dependencies += 1

        poetry, poetry_valid = _poetry_dependency_declarations(path)
        if poetry_valid:
            poetry_declarations.extend(
                (name.lower().replace("_", "-"), specification)
                for name, specification in poetry
            )
            declared_dependencies += len(poetry)
            pinned_dependencies += sum(
                1
                for name, specification in poetry
                if _package_spec_is_pinned(specification)
            )

    pipfile_paths = [
        path for path, _ in _iter_files(target) if path.name.lower() == "pipfile"
    ]
    for path in pipfile_paths:
        declarations, valid = _pipfile_dependency_declarations(path)
        if not valid:
            continue
        normalized = [
            (name.lower().replace("_", "-"), specification)
            for name, specification in declarations
        ]
        pipfile_declarations.extend(normalized)
        declared_dependencies += len(normalized)
        pinned_dependencies += sum(
            1 for _, specification in normalized if _package_spec_is_pinned(specification)
        )

    lock_paths = [
        path for path, _ in requirement_files if path.name.lower() == "requirements.lock"
    ]
    poetry_lock_paths = [
        path for path, _ in _iter_files(target) if path.name.lower() == "poetry.lock"
    ]
    uv_lock_paths = [
        path for path, _ in _iter_files(target) if path.name.lower() == "uv.lock"
    ]
    pipfile_lock_paths = [
        path for path, _ in _iter_files(target) if path.name.lower() == "pipfile.lock"
    ]

    def single_lock(
        paths: list[Path], reader: Any
    ) -> dict[str, str] | None:
        if len(paths) != 1:
            return None
        valid_lock, entries = reader(paths[0])
        return entries if valid_lock else None

    requirement_entries = single_lock(lock_paths, _read_requirements_lock)
    poetry_entries = single_lock(poetry_lock_paths, _read_poetry_lock)
    uv_entries = single_lock(uv_lock_paths, _read_uv_lock)
    pipfile_entries = single_lock(pipfile_lock_paths, _read_pipfile_lock)

    def covers(entries: dict[str, str] | None, declarations: list[tuple[str, str]]) -> bool:
        if entries is None:
            return False
        for name, specification in declarations:
            if not name or name not in entries:
                return False
            declared_version = _pinned_requirement_version(specification)
            if declared_version is None and _package_spec_is_pinned(specification):
                declared_version = specification.strip().lstrip("=")
                if declared_version.startswith("v"):
                    declared_version = declared_version[1:]
            locked_version = entries[name]
            if declared_version is not None and locked_version and declared_version != locked_version:
                return False
        return True

    def choose_lock(
        declarations: list[tuple[str, str]],
        candidates: list[tuple[str, dict[str, str] | None]],
    ) -> tuple[str, dict[str, str]] | None:
        for kind, entries in candidates:
            if covers(entries, declarations):
                return kind, entries  # type: ignore[return-value]
        return None

    modern_resolutions: list[tuple[list[tuple[str, str]], tuple[str, dict[str, str]]]] = []
    if declared_requirement_specs:
        # Requirements files retain their existing strict requirements.lock
        # behavior.  The additional declarations below may use modern locks,
        # but a requirements.txt still needs its own matching lock.
        requirement_declarations = [
            declaration
            for path, _ in requirement_files
            if path.name.lower() != "requirements.lock"
            for declaration in _requirement_declarations(path)
        ]
        if requirement_declarations and not covers(requirement_entries, requirement_declarations):
            lock_score = 0.0

    if pep621_declarations:
        selected = choose_lock(
            pep621_declarations,
            [
                ("requirements", requirement_entries),
                ("poetry", poetry_entries),
                ("uv", uv_entries),
            ],
        )
        if selected is None:
            lock_score = 0.0
        elif selected[0] in {"poetry", "uv"}:
            modern_resolutions.append((pep621_declarations, selected))

    if poetry_declarations:
        selected = choose_lock(
            poetry_declarations,
            [
                ("poetry", poetry_entries),
                ("uv", uv_entries),
                ("requirements", requirement_entries),
            ],
        )
        if selected is None:
            lock_score = 0.0
        elif selected[0] in {"poetry", "uv"}:
            modern_resolutions.append((poetry_declarations, selected))

    if pipfile_declarations:
        selected = choose_lock(pipfile_declarations, [("pipfile", pipfile_entries)])
        if selected is None:
            lock_score = 0.0
        else:
            modern_resolutions.append((pipfile_declarations, selected))

    # A resolved modern lock is the pinning evidence for PEP 621, Poetry, and
    # Pipenv manifests.  Their manifest constraints are intentionally allowed
    # to be ranges; the lock is what makes the installation deterministic.
    for declarations, (_, entries) in modern_resolutions:
        for name, specification in declarations:
            if name in entries and not (
                _pinned_requirement_version(specification)
                or _package_spec_is_pinned(specification)
                or (name in pinned_requirement_names and name in {item[0] for item in pep621_declarations})
            ):
                pinned_dependencies += 1

    # If a lockfile is present without a corresponding declaration, it still
    # needs a valid local shape.  This keeps malformed standalone lockfiles
    # from silently claiming reproducibility while allowing a valid Poetry or
    # uv lock to back a PEP 621 project even if another lock type is stale.
    if not (
        pep621_declarations
        or poetry_declarations
        or pipfile_declarations
        or declared_requirement_specs
    ):
        for paths, reader in (
            (lock_paths, _read_requirements_lock),
            (poetry_lock_paths, _read_poetry_lock),
            (uv_lock_paths, _read_uv_lock),
            (pipfile_lock_paths, _read_pipfile_lock),
        ):
            if paths and single_lock(paths, reader) is None:
                lock_score = 0.0

    cargo_manifests = [path for path, _ in _iter_files(target) if path.name == "Cargo.toml"]
    cargo_locks = [path for path, _ in _iter_files(target) if path.name == "Cargo.lock"]
    if cargo_manifests:
        if not cargo_locks:
            lock_score = 0.0
        else:
            cargo_lock_packages: set[str] = set()
            for manifest in cargo_manifests:
                _, _, cargo_names, cargo_pinned_names, manifest_valid = (
                    _cargo_dependency_status(manifest)
                )
                if not manifest_valid:
                    lock_score = 0.0
                    continue
                for lock in cargo_locks:
                    package_names = _cargo_lock_package_names(lock)
                    if package_names is None:
                        lock_score = 0.0
                        break
                    cargo_lock_packages.update(package_names)
                # A stale lock can contain only the workspace package.  Do
                # not invent resolution evidence for dependencies it does not
                # describe; when direct packages are present, their manifest
                # specs contribute to the pin score below.
                resolved_names = cargo_names & cargo_lock_packages
                if resolved_names:
                    declared_dependencies += len(cargo_names)
                    pinned_dependencies += len(resolved_names & cargo_pinned_names)
                elif not declared_requirement_specs:
                    # A standalone Cargo project must not receive a perfect
                    # pin score when its lock lacks all declared packages.
                    declared_dependencies += len(cargo_names)
                    pinned_dependencies += len(cargo_names & cargo_pinned_names)

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


def _package_spec_is_pinned(specification: Any) -> bool:
    """Return whether a package manifest spec is an exact version."""

    if not isinstance(specification, str):
        return False
    value = specification.strip()
    return bool(re.fullmatch(r"=?v?\d+(?:\.\d+)+(?:[-+][^\s]+)?", value))


def dependency_telemetry(target_path: Path) -> DependencyTelemetry:
    """Collect direct, resolved, and pinning evidence without network access."""

    target = Path(target_path)
    direct: set[str] = set()
    transitive: set[str] = set()
    pinned: set[str] = set()
    floating: set[str] = set()
    manifests: set[str] = set()

    def add_direct(ecosystem: str, name: str, is_pinned: bool) -> None:
        normalized = name.lower().replace("_", "-").strip()
        if not normalized:
            return
        key = ecosystem + ":" + normalized
        direct.add(key)
        (pinned if is_pinned else floating).add(key)

    def add_transitive(ecosystem: str, name: str) -> None:
        normalized = name.lower().replace("_", "-").strip()
        if normalized:
            transitive.add(ecosystem + ":" + normalized)
            pinned.add(ecosystem + ":" + normalized)

    for path, relative in _iter_files(target):
        name = path.name.lower()
        if name in {"requirements.txt", "requirements.in"}:
            manifests.add(relative)
            for specification in _requirement_declarations(path):
                dependency_name = _dependency_name(specification[0])
                add_direct("python", dependency_name, bool(_pinned_requirement_version(specification[1])))
        elif name == "requirements.lock":
            manifests.add(relative)
            valid, entries = _read_requirements_lock(path)
            if valid:
                for dependency_name in entries:
                    add_transitive("python", dependency_name)
        elif name == "pyproject.toml":
            dependencies, valid = _toml_dependencies(path)
            if valid:
                manifests.add(relative)
                for specification in dependencies:
                    match = _REQUIREMENT_LINE.match(specification)
                    is_pinned = bool(match and _pinned_requirement_version(match.group("spec")))
                    add_direct("python", _dependency_name(specification), is_pinned)
            poetry, poetry_valid = _poetry_dependency_declarations(path)
            if poetry_valid:
                manifests.add(relative)
                for dependency_name, specification in poetry:
                    add_direct(
                        "python",
                        dependency_name,
                        _package_spec_is_pinned(specification),
                    )
        elif name == "poetry.lock":
            valid, entries = _read_poetry_lock(path)
            if valid:
                manifests.add(relative)
                for dependency_name in entries:
                    add_transitive("python", dependency_name)
        elif name == "uv.lock":
            valid, entries = _read_uv_lock(path)
            if valid:
                manifests.add(relative)
                for dependency_name in entries:
                    add_transitive("python", dependency_name)
        elif name == "pipfile":
            declarations, valid = _pipfile_dependency_declarations(path)
            if valid:
                manifests.add(relative)
                for dependency_name, specification in declarations:
                    add_direct(
                        "python",
                        dependency_name,
                        _package_spec_is_pinned(specification),
                    )
        elif name == "pipfile.lock":
            valid, entries = _read_pipfile_lock(path)
            if valid:
                manifests.add(relative)
                for dependency_name in entries:
                    add_transitive("python", dependency_name)
        elif name == "package.json":
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                parsed = {}
            if isinstance(parsed, dict):
                package_values = {}
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    values = parsed.get(section, {})
                    if isinstance(values, dict):
                        package_values.update(values)
                if package_values:
                    manifests.add(relative)
                    for dependency_name, specification in package_values.items():
                        add_direct("node", str(dependency_name), _package_spec_is_pinned(specification))
        elif name == "package-lock.json":
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                parsed = {}
            if isinstance(parsed, dict) and isinstance(parsed.get("packages"), dict):
                manifests.add(relative)
                packages = parsed["packages"]
                root = packages.get("", {})
                if isinstance(root, dict):
                    for section in ("dependencies", "devDependencies", "optionalDependencies"):
                        values = root.get(section, {})
                        if isinstance(values, dict):
                            for dependency_name in values:
                                add_direct("node", str(dependency_name), True)
                for package_path, package_info in packages.items():
                    if not package_path or "node_modules/" not in package_path or not isinstance(package_info, dict):
                        continue
                    dependency_name = package_path.rsplit("node_modules/", 1)[-1]
                    add_transitive("node", dependency_name)
        elif name == "cargo.toml":
            declared, _, names, pinned_names, valid = _cargo_dependency_status(path)
            if valid and declared:
                manifests.add(relative)
                for dependency_name in names:
                    add_direct("cargo", dependency_name, dependency_name in pinned_names)
        elif name == "cargo.lock":
            package_names = _cargo_lock_package_names(path)
            if package_names:
                manifests.add(relative)
                for dependency_name in package_names:
                    add_transitive("cargo", dependency_name)

    vulnerabilities: list[str] = []
    database_name = workspace_config.vulnerability_database or ".worksonmymachine-vulnerabilities.json"
    database_path = target / database_name
    if database_path.is_file() and database_path.resolve().is_relative_to(target.resolve()):
        try:
            database = json.loads(database_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            database = None
        if isinstance(database, dict):
            entries = database.get("vulnerabilities", database)
            if isinstance(entries, dict):
                for key in sorted(direct | transitive):
                    package_name = key.split(":", 1)[-1]
                    if package_name in entries:
                        vulnerabilities.append(package_name + ": " + str(entries[package_name]))
    vulnerability_status = "unavailable"
    if database_path.is_file():
        vulnerability_status = "findings" if vulnerabilities else "clear"

    all_dependencies = direct | transitive
    return DependencyTelemetry(
        total=len(all_dependencies),
        direct=len(direct),
        transitive=len(transitive - direct),
        pinned=len(pinned & all_dependencies),
        floating=len(floating - pinned),
        manifests=sorted(manifests),
        vulnerability_status=vulnerability_status,
        vulnerabilities=vulnerabilities,
    )


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
            in {
                "pyproject.toml",
                "poetry.lock",
                "uv.lock",
                "pipfile",
                "pipfile.lock",
                "cargo.lock",
                "package-lock.json",
            }
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
        "dependency_score_delta": round(
            cert_b.dependency_lock_score - cert_a.dependency_lock_score, 2
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


def _blocking_reasons(certificate: ReproducibilityCertificate) -> list[str]:
    """Explain failed certification from the after-certificate evidence.

    Every reason comes from an after-scan finding or a concrete certificate
    value.  This intentionally avoids a catch-all message such as
    ``"verification failed"`` that cannot tell an API consumer what remains
    to fix.
    """

    if certificate.is_cleanroom_certified:
        return []

    reasons: list[str] = []
    for issue in certificate.issues:
        location = ""
        if issue.file_path:
            location = f" ({issue.file_path}"
            if issue.line_number is not None:
                location += f":{issue.line_number}"
            location += ")"
        reasons.append(f"{issue.issue_id}: {issue.message}{location}")

    if certificate.linux_readiness_score < 100.0:
        reasons.append(
            "Certificate readiness evidence is "
            f"{certificate.linux_readiness_score:.2f}/100."
        )
    if certificate.dependency_lock_score < 100.0:
        reasons.append(
            "Certificate dependency-lock evidence is "
            f"{certificate.dependency_lock_score:.2f}/100."
        )
    if not certificate.dockerfile_hardened:
        reasons.append("Certificate Dockerfile hardening evidence is false.")
    if not certificate.verified and not reasons:
        # This branch should be rare, but the boolean itself is still concrete
        # evidence and is preferable to inventing a reason.
        reasons.append("Certificate evidence reports verified=false.")

    return list(dict.fromkeys(reasons))


def _post_heal_summary(
    before: ReproducibilityCertificate,
    after: ReproducibilityCertificate,
    heal_result: Any,
) -> PostHealVerificationSummary:
    """Compose the explicit before/after contract for an auto-heal audit."""

    drift = compare_certificates(before, after)
    changed_files = sorted(
        set(drift["modified_files"])
        | set(drift["added_files"])
        | set(drift["removed_files"])
        | set(drift["line_ending_drifts"])
    )
    return PostHealVerificationSummary(
        before_findings=len(before.issues),
        fixed_findings=heal_result.issues_fixed,
        remaining_findings=len(after.issues),
        changed_files=changed_files,
        readiness_before=before.linux_readiness_score,
        readiness_after=after.linux_readiness_score,
        readiness_delta=round(
            after.linux_readiness_score - before.linux_readiness_score, 2
        ),
        dependency_score_before=before.dependency_lock_score,
        dependency_score_after=after.dependency_lock_score,
        dependency_score_delta=round(
            after.dependency_lock_score - before.dependency_lock_score, 2
        ),
        certificate_status=(
            "certified" if after.is_cleanroom_certified else "not_certified"
        ),
        blocking_reasons=_blocking_reasons(after),
    )


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
    post_heal_summary: PostHealVerificationSummary | None = None
    patch: DockerfilePatchResult | None = None
    diffs: list[str] = []
    dependency_data = dependency_telemetry(target)
    if auto_heal:
        staging_parent = Path(tempfile.mkdtemp(prefix="worksonmymachine-audit-"))
        staged = staging_parent / "target"
        try:
            heal_result = heal_repository(target, staged)
            after = generate_certificate(staged)
            post_heal_summary = _post_heal_summary(before, after, heal_result)
            dependency_data = dependency_telemetry(staged)
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
        dependency_telemetry=dependency_data,
        post_heal_summary=post_heal_summary,
    )


__all__ = [
    "calculate_dependency_lock_score",
    "dependency_telemetry",
    "compare_certificates",
    "compute_file_hash",
    "compute_merkle_root",
    "generate_certificate",
    "run_full_audit",
]
