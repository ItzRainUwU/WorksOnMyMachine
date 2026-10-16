"""Deterministic portability scanner and copy-on-write healer.

The scanner deliberately avoids importing or executing target code.  Import
casing is resolved by enumerating each directory and comparing names, rather
than asking the host filesystem for an existence result (which is not a valid
case-sensitivity check on Windows or macOS).
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
import difflib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
from typing import Any, Iterable, Sequence

from .apt_healer import heal_dockerfile
from .config import workspace_config
from .models import HealResult, LandmineIssue, SeverityLevel


_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"}
_JS_INDEX_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_CONFIG_SUFFIXES = {".cfg", ".conf", ".ini", ".toml", ".yaml", ".yml"}
_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".opencode",
        ".pytest_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
) | frozenset(Path(path).name for path in workspace_config.ignore_paths)

# These versions are intentionally conservative, known-good versions for the
# small demo projects.  Unknown packages are reported but left for a human to
# choose, rather than inventing a potentially incompatible version.
_KNOWN_VERSIONS = {
    "aiohttp": "3.10.5",
    "boto3": "1.35.24",
    "cffi": "1.17.1",
    "click": "8.1.7",
    "cryptography": "43.0.1",
    "fastapi": "0.115.0",
    "flask": "3.0.3",
    "gunicorn": "23.0.0",
    "httpx": "0.27.2",
    "numpy": "2.0.2",
    "opencv-python": "4.10.0.84",
    "pandas": "2.2.3",
    "psycopg2": "2.9.9",
    "psycopg2-binary": "2.9.9",
    "pydantic": "2.9.2",
    "pytest": "8.3.3",
    "python-dotenv": "1.0.1",
    "requests": "2.32.3",
    "rich": "13.8.1",
    "scikit-learn": "1.5.1",
    "scipy": "1.14.1",
    "setuptools": "75.1.0",
    "sqlalchemy": "2.0.35",
    "torch": "2.4.1",
    "typer": "0.12.5",
    "uvicorn": "0.30.6",
    "wheel": "0.44.0",
}

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_HOME_PATH = re.compile(r"^/(?:Users|home)(?:/|$)")
_PATH_LITERAL = re.compile(
    r"(?P<prefix>[rRuUbBfF]{0,3})(?P<quote>'''|\"\"\"|'|\")"
    r"(?P<body>(?:\\.|(?! (?P=quote)).)*?)(?P=quote)",
    re.VERBOSE | re.DOTALL,
)
_JS_IMPORT = re.compile(
    r"(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|"
    r"\bimport\s*\(\s*)['\"](?P<spec>[^'\"]+)['\"]"
)
_JS_ENV = re.compile(
    r"\bprocess\.env(?:\.(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|"
    r"\[\s*['\"](?P<bracket>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*\])"
)
_DOCKER_SHELL_REF = re.compile(r"(?P<path>(?:\.?\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.sh)")
_EXACT_PYTHON_VERSION = re.compile(
    r"^\s*(?:===|==)?\s*v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?\s*$"
)
_PYTHON_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)

# Secret rules intentionally use bounded, high-signal forms.  In particular,
# there is no catch-all "high entropy" rule: ordinary identifiers, hashes, and
# documentation prose are too easy to mistake for credentials.  Values are
# retained only long enough to create redacted evidence and are never placed in
# an issue message or evidence item.
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<label>(?:ENCRYPTED |RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY)-----"
)
_AWS_ACCESS_KEY = re.compile(r"\b(?P<value>(?:AKIA|ASIA)[0-9A-Z]{16})\b")
_GITHUB_TOKEN = re.compile(
    r"\b(?P<value>(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}))\b"
)
_SLACK_TOKEN = re.compile(r"\b(?P<value>xox[baprs]-[A-Za-z0-9-]{10,})\b")
_STRIPE_TOKEN = re.compile(
    r"\b(?P<value>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"
)
_OPENAI_TOKEN = re.compile(r"\b(?P<value>sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b")
_GOOGLE_API_KEY = re.compile(r"\b(?P<value>AIza[A-Za-z0-9_-]{30,})\b")
_NPM_TOKEN = re.compile(r"\b(?P<value>npm_[A-Za-z0-9]{30,})\b")
_JWT = re.compile(
    r"\b(?P<value>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"\.[A-Za-z0-9_-]{10,})\b"
)
_BEARER_TOKEN = re.compile(
    r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9_./~+\-]{20,})\b"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?ix)(?P<key>\b[A-Za-z_][A-Za-z0-9_-]*\b)\s*(?:=|:)\s*"
    r"(?:[\"'](?P<quoted>[^\"'\r\n]*)[\"']|"
    r"(?P<bare>[^\s,;#}\]]+))"
)
_SAFE_ENV_NAMES = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.defaults",
        ".env.dist",
    }
)
_SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".defaults", ".dist")
_DOCUMENTATION_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".adoc"})
_PLACEHOLDER_WORDS = frozenset(
    {
        "api-key",
        "api_key",
        "changeme",
        "change-me",
        "change_me",
        "dummy",
        "dummy-key",
        "dummy_key",
        "example",
        "example-key",
        "example_key",
        "fake",
        "invalid",
        "none",
        "null",
        "password",
        "placeholder",
        "redacted",
        "replace-me",
        "replace_me",
        "sample",
        "secret",
        "token",
        "undefined",
        "your-api-key",
        "your_api_key",
        "your-secret",
        "your_secret",
        "your-token",
        "your_token",
    }
)


@dataclass(frozen=True)
class _CaseResolution:
    """A case-aware path result used by import scanners and the healer."""

    path: Path
    corrected: str
    mismatch: bool


@dataclass(frozen=True)
class _TextReplacement:
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class _PythonDependency:
    """One dependency declaration found in a Python packaging manifest."""

    name: str
    specification: str
    source: str
    pinned: bool


def _iter_files(root: Path) -> list[Path]:
    """Return regular files in stable, directory-enumeration order."""

    found: list[Path] = []

    def walk(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except (OSError, ValueError):
            return
        for entry in entries:
            try:
                # Keep links in staged copies, but never scan through them.
                # Junctions/reparse points need the same treatment as symlinks
                # on Windows because they can lead outside the target tree.
                if _is_link_like(entry):
                    continue
                if entry.is_dir() and entry.name not in _IGNORED_DIRECTORIES:
                    walk(entry)
                elif entry.is_file():
                    found.append(entry)
            except OSError:
                continue

    walk(root)
    return found


def _relative(root: Path, path: Path) -> str:
    """Convert a path under *root* to the model's POSIX path contract."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return PurePosixPath(path.name).as_posix()


def _issue(
    root: Path,
    path: Path | None,
    issue_id: str,
    category: str,
    message: str,
    severity: SeverityLevel,
    *,
    line_number: int | None = None,
    remediation: str | None = None,
    evidence: Iterable[str] = (),
) -> LandmineIssue:
    """Construct one validated issue while keeping paths target-relative."""

    return LandmineIssue(
        issue_id=issue_id,
        category=category,
        message=message,
        severity=severity,
        file_path=_relative(root, path) if path is not None else None,
        line_number=line_number,
        remediation=remediation,
        evidence=list(evidence),
    )


def _sorted_issues(issues: Iterable[LandmineIssue]) -> list[LandmineIssue]:
    """Sort and de-duplicate issues so repeated scans have identical output."""

    unique: dict[tuple[object, ...], LandmineIssue] = {}
    for issue in issues:
        key = (
            issue.issue_id,
            issue.file_path,
            issue.line_number,
            issue.message,
            tuple(issue.evidence),
        )
        unique[key] = issue
    return sorted(
        unique.values(),
        key=lambda item: (
            item.file_path or "",
            item.line_number or 0,
            item.issue_id,
            item.message,
        ),
    )


def _children(directory: Path) -> list[Path]:
    """Enumerate a directory once, swallowing inaccessible-directory errors."""

    try:
        return sorted(directory.iterdir(), key=lambda item: item.name)
    except (OSError, ValueError):
        return []


def _is_reparse_point(path: Path) -> bool:
    """Return whether *path* is a Windows reparse point or junction.

    ``Path.is_symlink`` does not identify directory junctions on every Python
    version, and following one while scanning or copying would cross the
    repository boundary.  ``Path.is_junction`` is available on newer Python
    versions; the file-attribute fallback keeps this detectable on older
    Windows builds without importing platform-specific modules.
    """

    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except (OSError, NotImplementedError):
            return True
    try:
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except (OSError, NotImplementedError):
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _is_link_like(path: Path) -> bool:
    """Return whether a path must never be traversed as a directory."""

    try:
        if path.is_symlink():
            return True
    except (OSError, NotImplementedError):
        return True
    return _is_reparse_point(path)


def _safe_relative_parts(relative: str) -> tuple[str, ...]:
    """Validate a staged POSIX-relative name before it reaches the OS.

    Staged paths originate from directory enumeration, but an apply result can
    also be supplied by a caller.  Rejecting alternate separators, drive/UNC
    syntax, traversal, NULs, and Windows ADS syntax prevents a crafted result
    from escaping the target or addressing a surprising object on Windows.
    """

    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise HealingConflictError(f"unsafe healing path: {relative!r}")
    if "\\" in relative or relative.startswith("/"):
        raise HealingConflictError(f"unsafe healing path: {relative!r}")
    if re.match(r"^[A-Za-z]:", relative) or relative.startswith("//"):
        raise HealingConflictError(f"unsafe healing path: {relative!r}")
    parts = tuple(relative.split("/"))
    if any(
        not part
        or part in {".", ".."}
        or ":" in part
        or any(character in part for character in '<>"|?*')
        or part != part.rstrip(" .")
        or part.casefold().split(".", 1)[0] in _WINDOWS_RESERVED_NAMES
        for part in parts
    ):
        raise HealingConflictError(f"unsafe healing path: {relative!r}")
    return parts


def _ensure_safe_parent_components(root: Path, path: Path) -> None:
    """Reject link-like or non-directory components below a target root."""

    root = root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise HealingConflictError(f"healing path escapes target: {path}") from exc
    current = root
    for part in relative.parts[:-1]:
        current /= part
        try:
            if _is_link_like(current):
                raise HealingConflictError(
                    f"healing path traverses a link or reparse point: {relative}"
                )
            if current.exists() and not current.is_dir():
                raise HealingConflictError(
                    f"healing path traverses a non-directory: {relative}"
                )
        except OSError as exc:
            raise HealingConflictError(
                f"cannot validate healing path component: {relative}"
            ) from exc


def _ensure_no_link_components(path: Path) -> None:
    """Reject an output path whose existing parent traverses a link."""

    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if _is_link_like(current):
            raise HealingConflictError(
                f"path traverses a link or reparse point: {path}"
            )


def _resolve_segments(base: Path, segments: Sequence[str]) -> _CaseResolution | None:
    """Resolve exact/case-folded segments using ``iterdir`` only.

    This function intentionally has no ``Path.exists`` call.  A case-folded
    match is useful only when every segment can be found, so unrelated imports
    are not reported merely because a similarly named directory exists.
    """

    current = base
    corrected: list[str] = []
    mismatch = False
    for segment in segments:
        entries = [entry for entry in _children(current) if not _is_link_like(entry)]
        exact = next((entry for entry in entries if entry.name == segment), None)
        selected = exact
        if selected is None:
            matches = [
                entry for entry in entries if entry.name.casefold() == segment.casefold()
            ]
            if len(matches) != 1:
                return None
            selected = matches[0]
            mismatch = True
        corrected.append(selected.name)
        current = selected
    return _CaseResolution(current, "/".join(corrected), mismatch)


def _resolve_module(base: Path, module: str) -> _CaseResolution | None:
    """Resolve a Python module to a file/package and report casing drift."""

    segments = [part for part in module.split(".") if part]
    if not segments:
        return None
    if len(segments) == 1:
        parent_segments: list[str] = []
    else:
        parent_segments = segments[:-1]
    parent = _resolve_segments(base, parent_segments)
    if parent_segments and parent is None:
        return None
    parent_path = parent.path if parent else base
    parent_corrected = parent.corrected.split("/") if parent else []
    leaf = segments[-1]
    candidates = [leaf]
    if not leaf.endswith(".py"):
        candidates.append(leaf + ".py")
    entries = [entry for entry in _children(parent_path) if not _is_link_like(entry)]
    exact = next((entry for entry in entries if entry.name in candidates), None)
    selected = exact
    mismatch = bool(parent and parent.mismatch)
    if selected is None:
        folded = {
            entry.name.casefold(): entry
            for entry in entries
            if entry.name.casefold() in {candidate.casefold() for candidate in candidates}
        }
        # A package directory and a .py module can differ only by extension;
        # prefer the explicitly requested spelling where possible.
        matches = [entry for entry in entries if entry.name.casefold() in folded]
        if len(matches) != 1:
            return None
        selected = matches[0]
        mismatch = True
    corrected_leaf = selected.stem if selected.name.endswith(".py") else selected.name
    corrected = ".".join(parent_corrected + [corrected_leaf])
    return _CaseResolution(selected, corrected, mismatch or selected.name != leaf and selected.name != leaf + ".py")


def _python_roots(target: Path) -> list[Path]:
    """Return likely import roots without assuming a particular build layout."""

    roots = [target]
    roots.extend(
        entry
        for entry in _children(target)
        if not _is_link_like(entry) and entry.is_dir()
    )
    return roots


def _resolve_python_import(
    target: Path, source: Path, module: str, level: int
) -> _CaseResolution | None:
    if level:
        base = source.parent
        for _ in range(max(0, level - 1)):
            base = base.parent
        return _resolve_module(base, module)
    for root in _python_roots(target):
        result = _resolve_module(root, module)
        if result is not None:
            return result
    return None


def _python_imports(
    target: Path, path: Path, tree: ast.AST
) -> list[tuple[str, str, int, int]]:
    """Return ``(typed module, corrected module, line, column)`` imports."""

    references: list[tuple[str, str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                typed = alias.name
                result = _resolve_python_import(target, path, typed, 0)
                if result is None or not result.mismatch or result.corrected == typed:
                    continue
                references.append(
                    (
                        typed,
                        result.corrected,
                        getattr(alias, "lineno", getattr(node, "lineno", 1)),
                        getattr(alias, "col_offset", getattr(node, "col_offset", 0)),
                    )
                )
            continue
        if not isinstance(node, ast.ImportFrom):
            continue

        module = node.module or ""
        level = node.level
        if module:
            result = _resolve_python_import(target, path, module, level)
            if result is not None and result.mismatch and result.corrected != module:
                references.append(
                    (
                        module,
                        result.corrected,
                        getattr(node, "lineno", 1),
                        getattr(node, "col_offset", 0),
                    )
                )

        for alias in node.names:
            if alias.name == "*":
                continue
            imported = f"{module}.{alias.name}" if module else alias.name
            result = _resolve_python_import(target, path, imported, level)
            if result is None or not result.mismatch:
                continue
            corrected_name = result.corrected.rsplit(".", 1)[-1]
            if corrected_name == alias.name:
                continue
            references.append(
                (
                    alias.name,
                    corrected_name,
                    getattr(alias, "lineno", getattr(node, "lineno", 1)),
                    getattr(alias, "col_offset", getattr(node, "col_offset", 0)),
                )
            )
    return references


def _resolve_js_import(source: Path, spec: str) -> _CaseResolution | None:
    if not (spec.startswith("./") or spec.startswith("../")):
        return None
    base = source.parent
    raw_parts = spec.split("/")
    while raw_parts and raw_parts[0] in {".", ""}:
        raw_parts.pop(0)
    while raw_parts and raw_parts[0] == "..":
        base = base.parent
        raw_parts.pop(0)
    if not raw_parts:
        return None
    parent = _resolve_segments(base, raw_parts[:-1])
    if raw_parts[:-1] and parent is None:
        return None
    directory = parent.path if parent else base
    parent_corrected = parent.corrected.split("/") if parent else []
    leaf = raw_parts[-1]
    candidates = [leaf] if Path(leaf).suffix else [leaf, *[leaf + ext for ext in sorted(_JS_SUFFIXES)]]
    entries = _children(directory)
    exact = next((entry for entry in entries if entry.name in candidates), None)
    selected = exact
    mismatch = bool(parent and parent.mismatch)
    if selected is None:
        matches = [
            entry for entry in entries if entry.name.casefold() in {item.casefold() for item in candidates}
        ]
        if len(matches) != 1:
            return None
        selected = matches[0]
        mismatch = True
    if selected.is_dir():
        index_entries = _children(selected)
        index = next(
            (
                entry
                for suffix in _JS_INDEX_SUFFIXES
                for entry in index_entries
                if entry.name == f"index{suffix}"
            ),
            None,
        )
        if index is None:
            return None
        selected = index
    relative = posixpath.relpath(selected.as_posix(), source.parent.as_posix())
    if spec.startswith("./") and not relative.startswith("."):
        relative = "./" + relative
    corrected = relative
    typed_selected = leaf
    mismatch = mismatch or selected.name != typed_selected
    return _CaseResolution(selected, corrected, mismatch)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _path_kind(value: str) -> str | None:
    if _DRIVE_PATH.match(value):
        return "windows-drive"
    if _HOME_PATH.match(value.replace("\\", "/")):
        return "host-absolute"
    if "\\" in value and re.search(r"\\[A-Za-z0-9_.-]+(?:[\\/]|$)", value):
        return "backslash"
    return None


def _path_issue(
    target: Path, path: Path, line: int, value: str, kind: str
) -> LandmineIssue:
    names = {
        "windows-drive": ("PATH-WINDOWS-DRIVE", "Windows drive path", SeverityLevel.HIGH),
        "host-absolute": ("PATH-HOST-ABSOLUTE", "Host absolute path", SeverityLevel.HIGH),
        "backslash": ("PATH-BACKSLASH", "Backslash path literal", SeverityLevel.MEDIUM),
    }
    issue_id, label, severity = names[kind]
    return _issue(
        target,
        path,
        issue_id,
        {
            "windows-drive": "HARDCODED_PATH",
            "host-absolute": "HARDCODED_PATH",
            "backslash": "BACKSLASH_PATH",
        }[kind],
        f"{label} is not portable across build hosts.",
        severity,
        line_number=line,
        remediation="Use a project-relative path with forward slashes or pathlib.",
        evidence=[value],
    )


def _scan_python(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError) as exc:
        issues.append(
            _issue(
                target,
                path,
                "PYTHON-PARSE",
                "syntax",
                "Python source could not be parsed with the standard AST parser.",
                SeverityLevel.HIGH,
                line_number=getattr(exc, "lineno", 1),
                evidence=[str(exc)],
            )
        )
        return

    for typed, corrected, line, _column in _python_imports(target, path, tree):
        issues.append(
            _issue(
                target,
                path,
                "IMPORT-CASE",
                "CASE_MISMATCH",
                f"Python import '{typed}' does not match the on-disk casing '{corrected}'.",
                SeverityLevel.HIGH,
                line_number=line,
                remediation=f"Change the import to '{corrected}'.",
                evidence=[f"{typed} -> {corrected}"],
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            kind = _path_kind(node.value)
            if kind:
                issues.append(_path_issue(target, path, node.lineno, node.value, kind))

        key: str | None = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Name)
                and receiver.id == "os"
                and node.func.attr == "getenv"
            ) or (
                isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name)
                and receiver.value.id == "os"
                and receiver.attr == "environ"
                and node.func.attr == "get"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    key = node.args[0].value if isinstance(node.args[0].value, str) else None
        elif isinstance(node, ast.Subscript):
            value = node.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "os"
                and value.attr == "environ"
            ):
                index = node.slice
                if isinstance(index, ast.Constant) and isinstance(index.value, str):
                    key = index.value
        if key and _ENV_NAME.fullmatch(key):
            _append_missing_env_issue(target, path, node.lineno, key, issues)


def _scan_js(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    for match in _JS_IMPORT.finditer(text):
        spec = match.group("spec")
        result = _resolve_js_import(path, spec)
        if result is not None and result.mismatch and result.corrected != spec:
            issues.append(
                _issue(
                    target,
                    path,
                    "IMPORT-CASE",
                    "CASE_MISMATCH",
                    f"JavaScript import '{spec}' does not match the on-disk casing '{result.corrected}'.",
                    SeverityLevel.HIGH,
                    line_number=_line_number(text, match.start()),
                    remediation=f"Change the import to '{result.corrected}'.",
                    evidence=[f"{spec} -> {result.corrected}"],
                )
            )
    for match in _JS_ENV.finditer(text):
        key = match.group("dot") or match.group("bracket")
        _append_missing_env_issue(
            target, path, _line_number(text, match.start()), key, issues
        )
    for match in _PATH_LITERAL.finditer(text):
        value = match.group("body")
        kind = _path_kind(value)
        if kind:
            issues.append(
                _path_issue(target, path, _line_number(text, match.start()), value, kind)
            )


def _scan_config(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    """Inspect text configuration values without interpreting the format."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    for match in _PATH_LITERAL.finditer(text):
        value = match.group("body")
        kind = _path_kind(value)
        if kind:
            issues.append(
                _path_issue(target, path, _line_number(text, match.start()), value, kind)
            )


def _is_env_style_file(path: Path) -> bool:
    """Return whether *path* looks like a runtime dotenv file."""

    name = path.name.casefold()
    if name in _SAFE_ENV_NAMES or name.endswith(_SAFE_ENV_SUFFIXES):
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def _is_placeholder_secret(value: str) -> bool:
    """Return whether a candidate is a documentation/configuration placeholder."""

    candidate = value.strip().strip("\"'").strip()
    if not candidate:
        return True
    folded = candidate.casefold()
    if folded in _PLACEHOLDER_WORDS:
        return True
    words = set(re.split(r"[^a-z0-9]+", folded))
    if words & {"dummy", "example", "fake", "invalid", "sample"}:
        return True
    if (
        folded.endswith("example")
        or "examplekey" in folded
        or "placeholder" in folded
        or "changeme" in folded.replace("-", "").replace("_", "")
        or "notareal" in folded.replace("-", "").replace("_", "")
        or folded.startswith(("your-", "your_", "replace-", "replace_"))
    ):
        return True
    if candidate.startswith(("${", "{{", "<", "[")) or candidate.endswith(("}", ">")):
        return True
    if candidate.startswith(("$", "os.", "process.", "env.")):
        return True
    if any(marker in candidate for marker in ("••", "***", "…")):
        return True
    if len(set(candidate)) == 1:
        return True
    # AWS publishes this exact value in documentation; it is not a credential.
    if folded == "akiaiosfodnn7example":
        return True
    return False


def _is_documentation_example(path: Path, line: str, value: str) -> bool:
    """Suppress clearly labelled examples while preserving real-secret scans."""

    context = line.casefold()
    if any(
        marker in context
        for marker in (
            "example",
            "placeholder",
            "dummy",
            "replace this",
            "redacted",
            "sample",
            "not real",
            "not a real",
        )
    ):
        return True
    path_parts = {part.casefold() for part in path.parts}
    example_path = bool(
        path_parts
        & {"doc", "docs", "documentation", "example", "examples", "sample", "samples"}
    )
    if path.suffix.casefold() not in _DOCUMENTATION_SUFFIXES and not example_path:
        return False
    return _is_placeholder_secret(value)


def _secret_kind_for_key(key: str, value: str) -> tuple[str, str] | None:
    """Map a credential-shaped assignment to ``(issue id, display label)``."""

    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    if normalized == "googleapplicationcredentials" and (
        value.casefold().endswith((".json", ".jsonc"))
        or value.lstrip().startswith(("/", "./", "../"))
    ):
        # This conventional variable usually points to a service-account file;
        # the path is not itself a credential value.
        return None
    if normalized.endswith(("path", "file", "filename")):
        # Likewise, *_KEY_FILE and *_PASSWORD_PATH are secret references rather
        # than the material being protected.
        return None
    if normalized in {"databaseurl"}:
        # A connection URL alone is ordinary configuration.  Only report it
        # when it contains user-info, where a password can be embedded.
        if "@" not in value or "://" not in value:
            return None
        return "SECRET-PASSWORD", "password"
    if any(
        marker in normalized
        for marker in (
            "awsaccesskeyid",
            "awssecretaccesskey",
            "awssessiontoken",
            "azureclientsecret",
            "azurestoragekey",
            "azureconnectionstring",
            "googleapplicationcredentials",
            "googleprivatekey",
            "gcpcredentials",
            "gcpprivatekey",
            "accountkey",
            "cloudkey",
            "cloudsecret",
            "cloudtoken",
            "cloudcredential",
            "credential",
            "credentials",
            "connectionstring",
            "storagekey",
        )
    ):
        return "SECRET-CLOUD-CREDENTIAL", "cloud credential"
    if "privatekey" in normalized and not normalized.endswith(
        ("keyid", "keyname", "path", "file", "filename")
    ):
        return "SECRET-PRIVATE-KEY", "private key"
    if any(marker in normalized for marker in ("password", "passwd", "pwd")):
        return "SECRET-PASSWORD", "password"
    if any(
        marker in normalized
        for marker in ("token", "accesstoken", "authtoken", "bearertoken")
    ):
        return "SECRET-TOKEN", "token"
    if any(marker in normalized for marker in ("apikey", "clientsecret", "secret")):
        return "SECRET-API-KEY", "API key"
    return None


def _redacted_secret_evidence(label: str, value: str) -> str:
    """Format evidence with a short prefix and fixed-ish bullet padding."""

    candidate = value.strip().strip("\"'").strip()
    prefix = candidate[:4] if len(candidate) >= 4 else candidate[:2]
    bullet_count = min(16, max(8, len(candidate) - len(prefix)))
    return f"{label} detected: {prefix}{'•' * bullet_count}"


def _append_secret_issue(
    target: Path,
    path: Path,
    issues: list[LandmineIssue],
    *,
    issue_id: str,
    label: str,
    line_number: int | None,
    evidence: str,
) -> None:
    """Append a secret finding without accepting raw candidate material."""

    issues.append(
        _issue(
            target,
            path,
            issue_id,
            "SECRET_EXPOSURE",
            f"Likely {label} material is committed in plaintext; rotate it and remove it from source control.",
            SeverityLevel.CRITICAL,
            line_number=line_number,
            remediation="Remove the credential from source control, rotate it, and use a secret store or environment injection.",
            evidence=[evidence],
        )
    )


def _scan_secrets(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    """Find high-confidence credentials while keeping their values redacted."""

    name = path.name.casefold()
    if name in _SAFE_ENV_NAMES or name.endswith(_SAFE_ENV_SUFFIXES):
        return
    if _is_env_style_file(path):
        # The filename itself is useful evidence and contains no credential
        # value.  Templates are excluded above; real dotenv files are not.
        _append_secret_issue(
            target,
            path,
            issues,
            issue_id="SECRET-ENV-FILE",
            label="dotenv file",
            line_number=None,
            evidence=f"Environment file detected: {path.name}",
        )

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    if not text or "\x00" in text:
        return

    # Keep value spans only for in-memory overlap suppression.  They are never
    # copied into an issue, exception, log, or report.
    value_spans: list[tuple[int, int]] = []
    for match in _SECRET_ASSIGNMENT.finditer(text):
        key = match.group("key")
        value = match.group("quoted")
        if value is None:
            value = match.group("bare") or ""
            # A bare Python/JavaScript expression such as ``os.getenv(...)``
            # or ``settings.API_KEY`` is a lookup, not a committed credential.
            # Dotenv and YAML bare values remain eligible.
            if any(character in value for character in "()[]"):
                continue
            if path.suffix.lower() in _SOURCE_SUFFIXES and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_.]*", value
            ):
                continue
        value_start = match.start("quoted") if match.group("quoted") is not None else match.start("bare")
        value_end = match.end("quoted") if match.group("quoted") is not None else match.end("bare")
        if _is_placeholder_secret(value) or len(value.strip()) < 8:
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        line = text[line_start:] if line_end < 0 else text[line_start:line_end]
        if _is_documentation_example(path, line, value):
            continue
        kind = _secret_kind_for_key(key, value)
        if kind is None:
            continue
        issue_id, label = kind
        if _PEM_PRIVATE_KEY.search(value):
            issue_id, label = "SECRET-PRIVATE-KEY", "private key"
        value_spans.append((value_start, value_end))
        _append_secret_issue(
            target,
            path,
            issues,
            issue_id=issue_id,
            label=label,
            line_number=_line_number(text, match.start()),
            evidence=_redacted_secret_evidence(label, value),
        )

    provider_patterns: tuple[tuple[re.Pattern[str], str, str], ...] = (
        (_PEM_PRIVATE_KEY, "SECRET-PRIVATE-KEY", "private key"),
        (_AWS_ACCESS_KEY, "SECRET-CLOUD-CREDENTIAL", "AWS access key"),
        (_GITHUB_TOKEN, "SECRET-TOKEN", "token"),
        (_SLACK_TOKEN, "SECRET-TOKEN", "token"),
        (_STRIPE_TOKEN, "SECRET-API-KEY", "API key"),
        (_OPENAI_TOKEN, "SECRET-API-KEY", "API key"),
        (_GOOGLE_API_KEY, "SECRET-API-KEY", "API key"),
        (_NPM_TOKEN, "SECRET-TOKEN", "token"),
        (_JWT, "SECRET-TOKEN", "token"),
        (_BEARER_TOKEN, "SECRET-TOKEN", "token"),
    )
    for pattern, issue_id, label in provider_patterns:
        for match in pattern.finditer(text):
            value = match.group("value") if "value" in match.groupdict() else match.group(0)
            if pattern is _PEM_PRIVATE_KEY:
                value = match.group("label")
            if _is_placeholder_secret(value):
                continue
            if any(start <= match.start() < end or start < match.end() <= end for start, end in value_spans):
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start:] if line_end < 0 else text[line_start:line_end]
            if _is_documentation_example(path, line, value):
                continue
            evidence = (
                "Private key material detected: [REDACTED]"
                if pattern is _PEM_PRIVATE_KEY
                else _redacted_secret_evidence(label, value)
            )
            _append_secret_issue(
                target,
                path,
                issues,
                issue_id=issue_id,
                label=label,
                line_number=_line_number(text, match.start()),
                evidence=evidence,
            )


def _env_keys(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return set()
    keys: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match:
            keys.add(match.group(1))
    return keys


def _append_missing_env_issue(
    target: Path, path: Path, line: int, key: str, issues: list[LandmineIssue]
) -> None:
    if key not in _env_keys(target / ".env.example"):
        issues.append(
            _issue(
                target,
                path,
                "ENV-MISSING",
                "ENV_DRIFT",
                f"Environment key '{key}' is used but missing from .env.example.",
                SeverityLevel.HIGH,
                line_number=line,
                remediation=f"Add a safe placeholder for {key} to .env.example.",
                evidence=[key],
            )
        )


def _python_dependency_name(value: str) -> str:
    match = _PYTHON_REQUIREMENT_NAME.match(value)
    if match is None:
        return ""
    return match.group(1).lower().replace("_", "-")


def _pep621_dependency_is_pinned(value: str) -> bool:
    """Return whether a PEP 508 requirement has an exact version pin."""

    name = _python_dependency_name(value)
    if not name:
        return False
    match = re.match(r"^\s*[A-Za-z0-9_.-]+(?:\[[^\]]+\])?(?P<rest>.*)$", value)
    remainder = match.group("rest") if match else ""
    return bool(re.match(r"\s*(?:===|==)\s*[^=\s,;*]+", remainder))


def _poetry_dependency_is_pinned(value: Any) -> bool:
    """Return whether a Poetry dependency identifies an immutable version/source."""

    if isinstance(value, str):
        return bool(_EXACT_PYTHON_VERSION.fullmatch(value))
    if not isinstance(value, dict):
        return False
    version = value.get("version")
    if isinstance(version, str) and _EXACT_PYTHON_VERSION.fullmatch(version):
        return True
    # A git revision and a local path are immutable enough to be useful local
    # evidence. Branches, tags, and bare URLs intentionally remain floating.
    if isinstance(value.get("rev"), str) and value["rev"].strip():
        return True
    if isinstance(value.get("path"), str) and value["path"].strip():
        return True
    if (
        isinstance(value.get("url"), str)
        and value["url"].strip()
        and isinstance(value.get("hash"), str)
        and value["hash"].strip()
    ):
        return True
    return False


def _poetry_dependency_specification(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return str(value)
    for key in ("version", "rev", "path", "url", "git"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return f"{key}={item}"
    return ", ".join(f"{key}={value[key]}" for key in sorted(value))


def _pyproject_dependencies(parsed: dict[str, Any]) -> list[_PythonDependency]:
    """Extract PEP 621, PEP 735, and Poetry declarations from TOML data."""

    dependencies: list[_PythonDependency] = []
    project = parsed.get("project")
    if isinstance(project, dict):
        raw_dependencies = project.get("dependencies", [])
        if isinstance(raw_dependencies, list):
            for value in raw_dependencies:
                if not isinstance(value, str):
                    continue
                name = _python_dependency_name(value)
                if name:
                    dependencies.append(
                        _PythonDependency(
                            name,
                            value,
                            "project.dependencies",
                            _pep621_dependency_is_pinned(value),
                        )
                    )
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in sorted(optional.items(), key=lambda item: str(item[0])):
                if not isinstance(values, list):
                    continue
                for value in values:
                    if not isinstance(value, str):
                        continue
                    name = _python_dependency_name(value)
                    if name:
                        dependencies.append(
                            _PythonDependency(
                                name,
                                value,
                                f"project.optional-dependencies.{group}",
                                _pep621_dependency_is_pinned(value),
                            )
                        )

    # PEP 735 dependency groups use the same PEP 508 string syntax. They are
    # included when present but do not make arbitrary tool-only TOML Python.
    groups = parsed.get("dependency-groups")
    if isinstance(groups, dict):
        for group, values in sorted(groups.items(), key=lambda item: str(item[0])):
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                name = _python_dependency_name(value)
                if name:
                    dependencies.append(
                        _PythonDependency(
                            name,
                            value,
                            f"dependency-groups.{group}",
                            _pep621_dependency_is_pinned(value),
                        )
                    )

    tool = parsed.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        tables: list[tuple[str, Any]] = []
        for key in ("dependencies", "dev-dependencies"):
            tables.append((f"tool.poetry.{key}", poetry.get(key)))
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group, group_table in sorted(groups.items(), key=lambda item: str(item[0])):
                if isinstance(group_table, dict):
                    tables.append(
                        (
                            f"tool.poetry.group.{group}.dependencies",
                            group_table.get("dependencies"),
                        )
                    )
        for source, table in tables:
            if not isinstance(table, dict):
                continue
            for raw_name, value in sorted(table.items(), key=lambda item: str(item[0])):
                name = str(raw_name).lower().replace("_", "-")
                # Poetry's python constraint selects the interpreter and is not
                # a package dependency that needs a lock entry.
                if name == "python" or not _PYTHON_REQUIREMENT_NAME.fullmatch(name):
                    continue
                dependencies.append(
                    _PythonDependency(
                        name,
                        _poetry_dependency_specification(value),
                        source,
                        _poetry_dependency_is_pinned(value),
                    )
                )

    unique: dict[tuple[str, str], _PythonDependency] = {}
    for dependency in dependencies:
        unique.setdefault((dependency.name, dependency.specification), dependency)
    return list(unique.values())


def _valid_requirements_lock(path: Path) -> bool:
    """Validate a simple local requirements lock without invoking pip."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    saw_entry = False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        match = re.match(
            r"^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*==\s*[^=\s,;]+(?:\s+#.*)?$",
            line,
        )
        if match is None:
            return False
        saw_entry = True
    return saw_entry


def _valid_python_lock(path: Path) -> bool:
    """Check the local shape of recognized Python lockfiles only."""

    name = path.name.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    if name == "pipfile.lock":
        try:
            parsed = json.loads(text)
        except (UnicodeError, json.JSONDecodeError):
            return False
        return bool(
            isinstance(parsed, dict)
            and isinstance(parsed.get("_meta"), dict)
            and any(isinstance(parsed.get(section), dict) for section in ("default", "develop"))
        )
    try:
        parsed = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError):
        return False
    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        return False
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            return False
        if name == "poetry.lock" and not isinstance(package.get("version"), str):
            return False
    if name == "uv.lock" and not isinstance(parsed.get("version"), int):
        return False
    return True


def _scan_pyproject(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    """Inspect recognized Python packaging declarations and nearby lockfiles."""

    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return
    if not isinstance(parsed, dict):
        return
    # ``pyproject.toml`` is also used as metadata for native Cargo projects
    # built with maturin. Their Python-facing metadata is not an independent
    # install manifest, and Cargo.lock is the lock evidence handled elsewhere.
    # Skipping this combination avoids reporting Python lock findings for a
    # non-Python repository while still scanning standalone PEP 621 projects.
    build_system = parsed.get("build-system")
    backend = build_system.get("build-backend") if isinstance(build_system, dict) else ""
    if (
        isinstance(backend, str)
        and "maturin" in backend.lower()
        and (path.parent / "Cargo.toml").is_file()
    ):
        return
    dependencies = _pyproject_dependencies(parsed)
    if not dependencies:
        # A pyproject containing only tool configuration is common in non-
        # Python repositories; do not invent dependency or lock findings.
        return
    for dependency in dependencies:
        if dependency.pinned:
            continue
        issues.append(
            _issue(
                target,
                path,
                "PYPROJECT-UNPINNED",
                "UNPINNED_DEPENDENCY",
                f"Python dependency '{dependency.name}' in {dependency.source} is not pinned to an exact version.",
                SeverityLevel.MEDIUM,
                remediation="Pin the dependency to an exact version (for example, ==1.2.3).",
                evidence=[dependency.specification],
            )
        )

    lock_names = ("poetry.lock", "uv.lock", "Pipfile.lock", "requirements.lock")
    lock_path = next(
        (path.parent / name for name in lock_names if (path.parent / name).is_file()),
        None,
    )
    if lock_path is None:
        issues.append(
            _issue(
                target,
                path,
                "PYPROJECT-LOCK-MISSING",
                "DEPENDENCY_LOCK",
                "Python dependencies are declared in pyproject.toml but no recognized lockfile is present.",
                SeverityLevel.MEDIUM,
                remediation="Generate and commit poetry.lock, uv.lock, Pipfile.lock, or requirements.lock.",
                evidence=list(lock_names),
            )
        )
    elif not _valid_python_lock(lock_path):
        relative_lock = _relative(target, lock_path)
        issues.append(
            _issue(
                target,
                lock_path,
                "PYPROJECT-LOCK-INVALID",
                "DEPENDENCY_LOCK",
                f"Recognized Python lockfile '{relative_lock}' has an invalid or incomplete local structure.",
                SeverityLevel.MEDIUM,
                remediation="Regenerate the lockfile with the project package manager and commit it.",
                evidence=[relative_lock],
            )
        )


def _scan_requirements(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if (
            not line
            or line.startswith("#")
            or line.lower().startswith(("-", "git+", "http:", "https:"))
        ):
            continue
        body = line.split(" #", 1)[0].strip()
        match = re.match(r"(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?(?P<spec>.*)$", body)
        if match is None or "==" in match.group("spec"):
            continue
        name = match.group("name")
        issues.append(
            _issue(
                target,
                path,
                "REQ-UNPINNED",
                "UNPINNED_DEPENDENCY",
                f"Requirement '{name}' is not pinned to an exact version.",
                SeverityLevel.MEDIUM,
                line_number=number,
                remediation="Pin the dependency with an exact == version.",
                evidence=[raw],
            )
        )


def _git_index_shell_modes(target: Path) -> list[tuple[str, str]]:
    """Return ``(target-relative path, Git mode)`` for tracked shell files.

    Git stores executable state in its index, while Windows filesystem mode
    bits are generally unavailable or synthetic. The command is read-only;
    failures (including a non-Git target or an unavailable Git executable) are
    deliberately treated as no metadata rather than scanner errors.
    """

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(target),
                "ls-files",
                "--stage",
                "--",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []

    entries: list[tuple[str, str]] = []
    for raw_line in (result.stdout or "").splitlines():
        if not raw_line.strip():
            continue
        metadata, separator, git_path = raw_line.partition("\t")
        if not separator:
            continue
        if git_path.startswith('"') and git_path.endswith('"'):
            try:
                decoded_path = ast.literal_eval(git_path)
            except (SyntaxError, ValueError):
                decoded_path = git_path
            if isinstance(decoded_path, str):
                git_path = decoded_path
        fields = metadata.split()
        if len(fields) < 3 or not git_path.lower().endswith(".sh"):
            continue
        if git_path:
            entries.append((git_path, fields[0]))
    return entries


def _scan_tracked_shell_modes(
    target: Path, issues: list[LandmineIssue], scanned_files: set[str]
) -> None:
    for relative, mode in _git_index_shell_modes(target):
        try:
            executable = bool(int(mode, 8) & 0o111)
        except ValueError:
            continue
        if executable:
            continue
        if relative not in scanned_files:
            # A deleted index entry is not a shell script in the scanned
            # working tree and should not produce a finding.
            continue
        path = target / Path(*PurePosixPath(relative).parts)
        issues.append(
            _issue(
                target,
                path,
                "SHELL-NOT-EXECUTABLE",
                "EXEC_PERMISSIONS",
                f"Tracked shell script has Git index mode {mode} without an execute bit.",
                SeverityLevel.MEDIUM,
                remediation=f"Run git update-index --chmod=+x {relative}",
                evidence=[f"{relative} mode {mode}"],
            )
        )


def _scan_shell(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        content = path.read_bytes()
    except OSError:
        return
    first_line = content.splitlines()[0] if content.splitlines() else b""
    if b"\r\n" in content:
        issues.append(
            _issue(
                target,
                path,
                "SHELL-CRLF",
                "CRLF_LINE_ENDINGS",
                "Shell script uses CRLF line endings.",
                SeverityLevel.MEDIUM,
                remediation="Normalize shell input to LF line endings.",
            )
        )
    if not first_line.startswith(b"#!"):
        issues.append(
            _issue(
                target,
                path,
                "SHELL-SHEBANG",
                "MISSING_SHEBANG",
                "Shell script is missing a shebang.",
                SeverityLevel.MEDIUM,
                line_number=1,
                remediation="Add a portable /usr/bin/env shebang.",
            )
        )


def _scan_dockerfile(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return
    chmod_lines = [line for line in lines if re.search(r"\bchmod\s+[^#\n]*\+x", line)]
    for number, line in enumerate(lines, 1):
        if re.match(r"\s*COPY\b", line, re.IGNORECASE) and ".sh" in line.lower():
            for match in _DOCKER_SHELL_REF.finditer(line):
                reference = match.group("path")
                if _docker_chmod_covers(reference, chmod_lines):
                    continue
                issues.append(
                    _issue(
                        target,
                        path,
                        "DOCKER-COPY-SHELL-EXEC",
                        "EXEC_PERMISSIONS",
                        f"Dockerfile copies '{reference}' without chmod +x.",
                        SeverityLevel.HIGH,
                        line_number=number,
                        remediation=f"Add RUN chmod +x {reference} after copying it.",
                        evidence=[reference],
                    )
                )
        if not re.match(r"\s*(?:ENTRYPOINT|CMD)\b", line, re.IGNORECASE):
            continue
        for match in _DOCKER_SHELL_REF.finditer(line):
            reference = match.group("path")
            if not _docker_chmod_covers(reference, chmod_lines):
                issues.append(
                    _issue(
                        target,
                        path,
                        "DOCKER-SHELL-EXEC",
                        "EXEC_PERMISSIONS",
                        f"Dockerfile invokes '{reference}' without chmod +x.",
                        SeverityLevel.HIGH,
                        line_number=number,
                        remediation=f"Add RUN chmod +x {reference} before invoking it.",
                        evidence=[reference],
                    )
                )


def _docker_chmod_covers(reference: str, chmod_lines: Sequence[str]) -> bool:
    """Return whether a Dockerfile chmod line covers a referenced shell path."""

    normalized = reference.removeprefix("./")
    basename = PurePosixPath(normalized).name
    return any(
        "*.sh" in line or normalized in line or basename in line
        for line in chmod_lines
    )


def scan_repository(target_path: Path) -> list[LandmineIssue]:
    """Scan a repository without executing target code or changing its files."""

    target = Path(target_path)
    try:
        _ensure_no_link_components(target.parent)
    except HealingConflictError:
        return [
            _issue(
                target,
                None,
                "TARGET-REPARSE-POINT",
                "input",
                "Scanner target path traverses a symlink, junction, or reparse point.",
                SeverityLevel.CRITICAL,
            )
        ]
    if _is_link_like(target):
        return [
            _issue(
                target,
                None,
                "TARGET-REPARSE-POINT",
                "input",
                "Scanner target must not be a symlink, junction, or reparse point.",
                SeverityLevel.CRITICAL,
            )
        ]
    if not target.is_dir():
        return [
            _issue(
                target,
                None,
                "TARGET-NOT-DIRECTORY",
                "input",
                "Scanner target is not a directory.",
                SeverityLevel.CRITICAL,
            )
        ]
    issues: list[LandmineIssue] = []
    files = _iter_files(target)
    for path in files:
        suffix = path.suffix.lower()
        if suffix == ".py":
            _scan_python(target, path, issues)
        elif suffix in _JS_SUFFIXES:
            _scan_js(target, path, issues)
        elif suffix in _CONFIG_SUFFIXES:
            _scan_config(target, path, issues)
        elif suffix == ".sh":
            _scan_shell(target, path, issues)
        if path.name.lower() == "pyproject.toml":
            _scan_pyproject(target, path, issues)
        if path.name.lower() == "requirements.txt":
            _scan_requirements(target, path, issues)
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            _scan_dockerfile(target, path, issues)
        _scan_secrets(target, path, issues)
    _scan_tracked_shell_modes(
        target, issues, {_relative(target, path) for path in files}
    )
    return _sorted_issues(issues)


def readiness_score(value: Path | Sequence[LandmineIssue]) -> float:
    """Return a deterministic 0--100 readiness score.

    A repository path is accepted for convenience; passing an already scanned
    issue sequence avoids scanning twice when composing a report.
    """

    if isinstance(value, (str, Path)):
        issues = scan_repository(Path(value))
    else:
        issues = list(value)
    weights = {
        SeverityLevel.LOW: 5.0,
        SeverityLevel.MEDIUM: 10.0,
        SeverityLevel.HIGH: 20.0,
        SeverityLevel.CRITICAL: 35.0,
    }
    penalty = sum(weights.get(issue.severity, 10.0) for issue in issues)
    return round(max(0.0, 100.0 - penalty), 2)


def _apply_replacements(text: str, replacements: Iterable[_TextReplacement]) -> str:
    result = text
    for replacement in sorted(replacements, key=lambda item: item.start, reverse=True):
        result = result[: replacement.start] + replacement.replacement + result[replacement.end :]
    return result


def _python_import_replacements(target: Path, path: Path, text: str) -> list[_TextReplacement]:
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    replacements: list[_TextReplacement] = []
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    running = 0
    for line in lines:
        offsets.append(running)
        running += len(line)
    for typed, corrected, line, _column in _python_imports(target, path, tree):
        if line < 1 or line > len(lines):
            continue
        line_text = lines[line - 1]
        search_start = min(max(_column, 0), len(line_text))
        match = re.search(
            rf"(?<![\w.]){re.escape(typed)}(?![\w.])",
            line_text[search_start:],
        )
        if match:
            replacements.append(
                _TextReplacement(
                    offsets[line - 1] + search_start + match.start(),
                    offsets[line - 1] + search_start + match.end(),
                    corrected,
                )
            )
    return replacements


def _js_import_replacements(path: Path, text: str) -> list[_TextReplacement]:
    replacements: list[_TextReplacement] = []
    for match in _JS_IMPORT.finditer(text):
        spec = match.group("spec")
        result = _resolve_js_import(path, spec)
        if result is not None and result.mismatch and result.corrected != spec:
            replacements.append(
                _TextReplacement(match.start("spec"), match.end("spec"), result.corrected)
            )
    return replacements


def _normalise_path_value(value: str) -> str:
    """Turn an absolute or backslash path into a safe project-relative value."""

    normalized = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized):
        normalized = normalized[3:]
        parts = [part for part in normalized.split("/") if part]
        if len(parts) >= 2 and parts[0].lower() in {"users", "home"}:
            parts = parts[2:]
        normalized = "/".join(parts)
    elif normalized.startswith("/Users/") or normalized.startswith("/home/"):
        parts = [part for part in normalized.split("/") if part]
        normalized = "/".join(parts[2:])
    normalized = re.sub(r"/+", "/", normalized).lstrip("/")
    return normalized or "relative-path"


def _path_replacements(text: str) -> list[_TextReplacement]:
    replacements: list[_TextReplacement] = []
    for match in _PATH_LITERAL.finditer(text):
        body = match.group("body")
        if _path_kind(body):
            replacements.append(
                _TextReplacement(
                    match.start("body"), match.end("body"), _normalise_path_value(body)
                )
            )
    return replacements


def _repair_source_file(target: Path, path: Path) -> tuple[str, str]:
    try:
        before = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "", ""
    replacements: list[_TextReplacement] = []
    if path.suffix.lower() == ".py":
        replacements.extend(_python_import_replacements(target, path, before))
    elif path.suffix.lower() in _JS_SUFFIXES:
        replacements.extend(_js_import_replacements(path, before))
    if path.suffix.lower() in _SOURCE_SUFFIXES | _CONFIG_SUFFIXES:
        replacements.extend(_path_replacements(before))
    after = _apply_replacements(before, replacements)
    if after != before:
        path.write_text(after, encoding="utf-8", newline="")
    return before, after


def _repair_requirements(path: Path) -> tuple[str, str]:
    try:
        before = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "", ""
    output: list[str] = []
    changed = False
    for line in before.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        content = line[:-1] if ending else line
        match = re.match(
            r"(?P<leading>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^\]]+\])?(?P<spec>[^#]*?)(?P<comment>\s+#.*)?$",
            content,
        )
        if match is None or "==" in match.group("spec"):
            output.append(line)
            continue
        name = match.group("name").lower().replace("_", "-")
        version = _KNOWN_VERSIONS.get(name)
        if version is None:
            output.append(line)
            continue
        comment = match.group("comment") or ""
        extras = match.group("extras") or ""
        replacement = f"{match.group('leading')}{match.group('name')}{extras}=={version}{comment}{ending}"
        output.append(replacement)
        changed = changed or replacement != line
    after = "".join(output)
    if after != before:
        path.write_text(after, encoding="utf-8", newline="")
    return before, after


def _repair_shell(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return "", ""
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if not normalized.startswith(b"#!"):
        normalized = b"#!/usr/bin/env bash\n" + normalized
    if normalized and not normalized.endswith(b"\n"):
        normalized += b"\n"
    try:
        before = raw.decode("utf-8")
        after = normalized.decode("utf-8")
    except UnicodeDecodeError:
        return "", ""
    if normalized != raw:
        path.write_bytes(normalized)
    if os.name != "nt":
        try:
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass
    return before, after


def _repair_env(target: Path, keys: set[str]) -> tuple[str, str]:
    if not keys:
        return "", ""
    path = target / ".env.example"
    if _is_link_like(path):
        return "", ""
    try:
        before = path.read_text(encoding="utf-8") if path.is_file() else ""
    except (OSError, UnicodeError):
        before = ""
    present = _env_keys(path)
    missing = sorted(keys - present)
    if not missing:
        return before, before
    after = before
    if after and not after.endswith("\n"):
        after += "\n"
    after += "".join(f"{key}=\n" for key in missing)
    path.write_text(after, encoding="utf-8", newline="")
    return before, after


def _repair_dockerfile(path: Path) -> tuple[str, str]:
    try:
        before = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "", ""
    lines = before.splitlines(keepends=True)
    chmod_lines = [line for line in lines if re.search(r"\bchmod\s+[^#\n]*\+x", line)]
    output: list[str] = []
    changed = False
    for line in lines:
        if re.match(r"\s*COPY\b", line, re.IGNORECASE) and ".sh" in line.lower():
            refs = [m.group("path") for m in _DOCKER_SHELL_REF.finditer(line)]
            for reference in refs:
                if _docker_chmod_covers(reference, chmod_lines):
                    continue
                newline = "\n" if line.endswith("\n") else ""
                output.append(f"RUN chmod +x {reference}{newline}")
                changed = True
                chmod_lines.append(f"RUN chmod +x {reference}\n")
        if re.match(r"\s*(?:ENTRYPOINT|CMD)\b", line, re.IGNORECASE):
            refs = [m.group("path") for m in _DOCKER_SHELL_REF.finditer(line)]
            for reference in refs:
                if _docker_chmod_covers(reference, chmod_lines):
                    continue
                newline = "\n" if line.endswith("\n") else ""
                output.append(f"RUN chmod +x {reference}{newline}")
                changed = True
                chmod_lines.append(f"RUN chmod +x {reference}\n")
        output.append(line)
    after = "".join(output)
    if changed:
        path.write_text(after, encoding="utf-8", newline="")
    return before, after


def _collect_env_keys(target: Path) -> set[str]:
    keys: set[str] = set()
    for path in _iter_files(target):
        if path.suffix.lower() == ".py":
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                key: str | None = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    receiver = node.func.value
                    if (
                        isinstance(receiver, ast.Name)
                        and receiver.id == "os"
                        and node.func.attr == "getenv"
                    ) or (
                        isinstance(receiver, ast.Attribute)
                        and isinstance(receiver.value, ast.Name)
                        and receiver.value.id == "os"
                        and receiver.attr == "environ"
                        and node.func.attr == "get"
                    ):
                        if node.args and isinstance(node.args[0], ast.Constant):
                            key = node.args[0].value if isinstance(node.args[0].value, str) else None
                elif isinstance(node, ast.Subscript):
                    receiver = node.value
                    if (
                        isinstance(receiver, ast.Attribute)
                        and isinstance(receiver.value, ast.Name)
                        and receiver.value.id == "os"
                        and receiver.attr == "environ"
                    ):
                        index = node.slice
                        if isinstance(index, ast.Constant) and isinstance(index.value, str):
                            key = index.value
                if key and _ENV_NAME.fullmatch(key):
                    keys.add(key)
        elif path.suffix.lower() in _JS_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            keys.update(
                match.group("dot") or match.group("bracket")
                for match in _JS_ENV.finditer(text)
            )
    return keys


def _copy_tree(target: Path, output: Path) -> None:
    """Copy a target without traversing symlinks or Windows reparse points."""

    _ensure_no_link_components(target.parent)
    if _is_link_like(target):
        raise HealingConflictError("target must not be a link or reparse point")

    def remove_entry(path: Path) -> None:
        if _is_link_like(path):
            path.unlink()
            return
        if path.is_dir():
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                remove_entry(child)
            path.rmdir()
        elif path.exists():
            path.unlink()

    _ensure_no_link_components(output.parent)
    if _is_link_like(output):
        raise HealingConflictError("output_path must not be a link or reparse point")
    if output.exists():
        try:
            remove_entry(output)
        except OSError as exc:
            raise HealingConflictError("cannot safely clear output_path") from exc
    output.parent.mkdir(parents=True, exist_ok=True)

    def copy_entry(source: Path, destination: Path) -> None:
        if source.name in _IGNORED_DIRECTORIES:
            return
        if _is_link_like(source):
            # Recreate links without dereferencing them.  A junction may be
            # exposed as a reparse point rather than a symlink on Windows; a
            # symlink representation is still safe, and failure is explicit
            # rather than silently copying data from outside the target.
            try:
                link_target = os.readlink(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(
                    link_target,
                    destination,
                    target_is_directory=source.is_dir(),
                )
            except (OSError, ValueError) as exc:
                raise HealingConflictError(
                    f"cannot safely stage link or reparse point: {source}"
                ) from exc
            return
        try:
            if source.is_dir():
                destination.mkdir()
                for child in sorted(source.iterdir(), key=lambda item: item.name):
                    copy_entry(child, destination / child.name)
            elif source.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination, follow_symlinks=False)
            else:
                raise HealingConflictError(f"cannot safely stage path: {source}")
        except OSError as exc:
            raise HealingConflictError(f"cannot safely stage path: {source}") from exc

    output.mkdir()
    for entry in sorted(target.iterdir(), key=lambda item: item.name):
        copy_entry(entry, output / entry.name)


class HealingConflictError(RuntimeError):
    """Raised when the source changes while a staged healing is prepared."""


_SnapshotValue = tuple[str, bytes | str, int]
_STAGED_BASELINES: dict[str, dict[str, _SnapshotValue]] = {}


def _snapshot_tree(root: Path) -> dict[str, _SnapshotValue]:
    """Capture content, type, and mode for a target without following links.

    The snapshot is deliberately independent of timestamps.  Ignored
    directories are excluded because the copy-on-write healer does not copy
    them and they cannot be part of an apply operation.
    """

    snapshot: dict[str, _SnapshotValue] = {}

    def walk(directory: Path, prefix: tuple[str, ...]) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except (OSError, ValueError):
            return
        for entry in entries:
            if entry.name in _IGNORED_DIRECTORIES:
                continue
            relative = PurePosixPath(*(prefix + (entry.name,))).as_posix()
            try:
                if _is_link_like(entry):
                    try:
                        link_target = os.readlink(entry)
                    except OSError:
                        link_target = ""
                    snapshot[relative] = ("symlink", link_target, 0)
                elif entry.is_dir():
                    walk(entry, (*prefix, entry.name))
                elif entry.is_file():
                    snapshot[relative] = (
                        "file",
                        entry.read_bytes(),
                        stat.S_IMODE(entry.stat().st_mode),
                    )
            except OSError:
                # A disappearing or inaccessible path is represented by the
                # next snapshot comparison as a conflict rather than being
                # silently overwritten.
                snapshot[relative] = ("unreadable", "", 0)

    walk(Path(root), ())
    return snapshot


def _safe_target_path(root: Path, relative: str) -> Path:
    """Resolve a staged relative path and reject symlink/parent escapes."""

    parts = _safe_relative_parts(relative)
    if _is_link_like(root):
        raise HealingConflictError("healing root must not be a link or reparse point")
    _ensure_no_link_components(root.parent)
    root = root.resolve()
    raw_candidate = root / Path(*parts)
    _ensure_safe_parent_components(root, raw_candidate)
    if _is_link_like(raw_candidate):
        raise HealingConflictError(
            f"healing path is a link or reparse point: {relative}"
        )
    candidate = raw_candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise HealingConflictError(f"healing path escapes target: {relative}") from exc
    _ensure_safe_parent_components(root, candidate)
    # Retain the non-resolved spelling for the write.  This lets the atomic
    # writer re-check the actual leaf and parent components instead of writing
    # through an alias that appeared after the resolution check.
    return raw_candidate


def _atomic_write(
    path: Path, content: bytes, mode: int, *, root: Path | None = None
) -> None:
    """Write one file atomically in its destination directory."""

    if root is not None:
        _ensure_safe_parent_components(root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if root is not None:
        _ensure_safe_parent_components(root, path)
    if _is_link_like(path):
        raise HealingConflictError(f"refusing to replace link or reparse point: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.worksonmymachine-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _restore_snapshot(path: Path, value: _SnapshotValue | None) -> None:
    """Restore one path after a failed multi-file apply."""

    _ensure_no_link_components(path.parent)
    if _is_link_like(path):
        path.unlink()
    elif path.exists():
        if not path.is_file():
            raise HealingConflictError(f"cannot remove non-regular file: {path}")
        path.unlink()
    if value is None:
        return
    kind, payload, mode = value
    if kind != "file" or not isinstance(payload, bytes):
        raise HealingConflictError(f"cannot restore non-regular file: {path}")
    _atomic_write(path, payload, mode)


def _apply_staged_output(
    target: Path,
    staged: Path,
    result: HealResult,
    expected_snapshot: dict[str, _SnapshotValue],
) -> HealResult:
    """Apply a completed staged heal after validating the source snapshot."""

    current_snapshot = _snapshot_tree(target)
    if current_snapshot != expected_snapshot:
        raise HealingConflictError(
            "target changed while healing was prepared; no files were applied"
        )
    staged_snapshot = _snapshot_tree(staged)
    changed = sorted(
        relative
        for relative in set(expected_snapshot) | set(staged_snapshot)
        if expected_snapshot.get(relative) != staged_snapshot.get(relative)
    )
    for relative in changed:
        _safe_relative_parts(relative)

    prepared: dict[str, tuple[bytes, int]] = {}
    originals: dict[str, _SnapshotValue | None] = {}
    for relative in changed:
        staged_value = staged_snapshot.get(relative)
        if staged_value is None:
            # Current healers only add or modify files.  Refusing a deletion
            # keeps future healer changes from silently deleting user files.
            raise HealingConflictError(f"healing would delete source file: {relative}")
        kind, payload, mode = staged_value
        if kind != "file" or not isinstance(payload, bytes):
            raise HealingConflictError(
                f"healing would apply a non-regular path: {relative}"
            )
        destination = _safe_target_path(target, relative)
        if _is_link_like(destination) or (
            destination.exists() and not destination.is_file()
        ):
            raise HealingConflictError(f"refusing to replace non-regular path: {relative}")
        prepared[relative] = (payload, mode)
        originals[relative] = expected_snapshot.get(relative)

    if changed:
        try:
            git_status = subprocess.run(
                [
                    "git",
                    "-C",
                    str(target),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    "--",
                    *changed,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            git_status = None
        if git_status is not None and git_status.returncode == 0:
            dirty = [line for line in git_status.stdout.splitlines() if line.strip()]
            if dirty:
                raise HealingConflictError(
                    "refusing to overwrite locally modified files: "
                    + ", ".join(line[3:].strip() for line in dirty)
                )

    # Validate once more immediately before the first replacement.  This
    # closes the normal race between staging and the first write.
    if _snapshot_tree(target) != expected_snapshot:
        raise HealingConflictError(
            "target changed before healing could be applied; no files were applied"
        )
    if _snapshot_tree(staged) != staged_snapshot:
        raise HealingConflictError(
            "staged output changed before healing could be applied"
        )

    applied: list[str] = []
    working_snapshot = dict(expected_snapshot)
    try:
        for relative in changed:
            if _snapshot_tree(target) != working_snapshot:
                raise HealingConflictError(
                    "target changed while healing was being applied"
                )
            destination = _safe_target_path(target, relative)
            content, mode = prepared[relative]
            _atomic_write(destination, content, mode, root=target)
            applied.append(relative)
            working_snapshot[relative] = ("file", content, mode)
    except Exception:
        for relative in reversed(applied):
            try:
                _restore_snapshot(_safe_target_path(target, relative), originals[relative])
            except OSError:
                pass
        raise

    return result.model_copy(update={"output_path": str(target)})


def apply_heal_result(target_path: Path, result: HealResult) -> HealResult:
    """Safely apply a previously staged :class:`HealResult`.

    The result's staging directory must still exist.  Applying is transactional
    for all changed regular files and refuses source changes, symlinks, and
    deletions.  The returned result points at the target after a successful
    apply; the original result remains unchanged.
    """

    raw_target = Path(target_path)
    if _is_link_like(raw_target):
        raise ValueError("target_path must not be a link or reparse point")
    try:
        _ensure_no_link_components(raw_target.parent)
    except HealingConflictError as exc:
        raise ValueError(str(exc)) from exc
    target = raw_target.resolve()
    raw_staged = Path(result.output_path)
    if _is_link_like(raw_staged):
        raise ValueError("result.output_path must not be a link or reparse point")
    try:
        _ensure_no_link_components(raw_staged.parent)
    except HealingConflictError as exc:
        raise ValueError(str(exc)) from exc
    staged = raw_staged.resolve()
    if not target.is_dir() or not staged.is_dir():
        raise ValueError("target_path and result.output_path must be directories")
    if target == staged:
        raise ValueError("result.output_path must be a staging directory")
    try:
        common = os.path.commonpath(
            [os.path.normcase(str(target)), os.path.normcase(str(staged))]
        )
    except ValueError:
        common = ""
    if common == os.path.normcase(str(target)):
        raise ValueError(
            "result.output_path must not be the target or one of its descendants"
        )
    expected_snapshot = _STAGED_BASELINES.get(str(staged))
    if expected_snapshot is None:
        expected_snapshot = _snapshot_tree(target)
    applied = _apply_staged_output(target, staged, result, expected_snapshot)
    _STAGED_BASELINES.pop(str(staged), None)
    return applied


def apply_healing(target_path: Path) -> HealResult:
    """Stage and transactionally apply deterministic repairs to a target.

    This is the explicit mutation primitive used by the CLI's opt-in audit
    flow.  Normal audits continue to use :func:`heal_repository` on a temporary
    copy and therefore remain read-only.
    """

    raw_target = Path(target_path)
    if _is_link_like(raw_target):
        raise ValueError("target_path must not be a link or reparse point")
    try:
        _ensure_no_link_components(raw_target.parent)
    except HealingConflictError as exc:
        raise ValueError(str(exc)) from exc
    target = raw_target.resolve()
    if not target.is_dir():
        raise ValueError("target_path must be a directory")
    expected_snapshot = _snapshot_tree(target)
    staging_parent = Path(tempfile.mkdtemp(prefix="worksonmymachine-apply-"))
    staged = staging_parent / "target"
    try:
        result = heal_repository(target, staged)
        applied = _apply_staged_output(target, staged, result, expected_snapshot)
        _STAGED_BASELINES.pop(str(staged.resolve()), None)
        return applied
    finally:
        shutil.rmtree(staging_parent, ignore_errors=True)


def _ensure_requirements_lock(output: Path, changed_files: dict[str, tuple[str, str]]) -> None:
    """Create a deterministic local lock companion for a healed requirements file."""

    requirements = output / "requirements.txt"
    lock = output / "requirements.lock"
    if (
        _is_link_like(requirements)
        or _is_link_like(lock)
        or not requirements.is_file()
        or lock.is_file()
    ):
        return
    try:
        content = requirements.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    if content and not content.endswith("\n"):
        content += "\n"
    lock.write_text(
        "# Generated by WorksOnMyMachine from the healed requirements.txt\n" + content,
        encoding="utf-8",
        newline="",
    )
    changed_files["requirements.lock"] = ("", lock.read_text(encoding="utf-8"))


def heal_repository(target_path: Path, output_path: Path | None = None) -> HealResult:
    """Copy *target_path*, apply safe deterministic repairs, and report the result."""

    raw_target = Path(target_path)
    if _is_link_like(raw_target):
        raise ValueError("target_path must not be a link or reparse point")
    try:
        _ensure_no_link_components(raw_target.parent)
    except HealingConflictError as exc:
        raise ValueError(str(exc)) from exc
    target = raw_target
    if not target.is_dir():
        raise ValueError("target_path must be a directory")
    output = (
        Path(output_path)
        if output_path is not None
        else Path(tempfile.mkdtemp(prefix="worksonmymachine-healed-"))
    )
    try:
        _ensure_no_link_components(output.parent)
    except HealingConflictError as exc:
        raise ValueError(str(exc)) from exc
    target_resolved = target.resolve()
    if _is_link_like(output):
        raise ValueError("output_path must not be a link or reparse point")
    output_resolved = output.resolve()
    try:
        common = os.path.commonpath(
            [os.path.normcase(str(target_resolved)), os.path.normcase(str(output_resolved))]
        )
    except ValueError:
        # Different drives on Windows are safe.
        common = ""
    if output_resolved == target_resolved or common == os.path.normcase(str(target_resolved)):
        raise ValueError("output_path must not be the target or one of its descendants")

    _STAGED_BASELINES.pop(str(output_resolved), None)
    expected_snapshot = _snapshot_tree(target)
    before_issues = scan_repository(target)
    if _snapshot_tree(target) != expected_snapshot:
        raise HealingConflictError("target changed while it was being scanned")
    before_score = readiness_score(before_issues)
    _copy_tree(target, output)

    changed_files: dict[str, tuple[str, str]] = {}
    for path in _iter_files(output):
        relative = _relative(output, path)
        before = after = ""
        if path.suffix.lower() in _SOURCE_SUFFIXES | _CONFIG_SUFFIXES:
            before, after = _repair_source_file(output, path)
        elif path.suffix.lower() == ".sh":
            before, after = _repair_shell(path)
        if path.name.lower() == "requirements.txt":
            req_before, req_after = _repair_requirements(path)
            if req_before or req_after:
                before = req_before
                after = req_after
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            docker_before, docker_after = _repair_dockerfile(path)
            if docker_before or docker_after:
                before = docker_before
                after = docker_after
        if before != after:
            changed_files[relative] = (before, after)

    _ensure_requirements_lock(output, changed_files)

    env_before, env_after = _repair_env(output, _collect_env_keys(output))
    if env_before != env_after or (env_after and ".env.example" not in changed_files):
        # A newly created .env.example has no before text; include it in the
        # unified diff just like every other generated repair.
        if env_before != env_after:
            changed_files[".env.example"] = (env_before, env_after)

    dockerfile_names = {"dockerfile", "dockerfile.broken"}
    dockerfile = next(
        (
            path
            for path in _iter_files(output)
            if path.parent == output and path.name.lower() in dockerfile_names
        ),
        None,
    )
    if dockerfile is not None:
        docker_stage = Path(tempfile.mkdtemp(prefix="worksonmymachine-docker-stage-"))
        try:
            docker_result = heal_dockerfile(output, docker_stage)
            docker_before = docker_result.before_content
            docker_after = docker_result.after_content
            existing_before = changed_files.get(docker_result.source_path, (docker_before, ""))[0]
            dockerfile.write_text(docker_after, encoding="utf-8", newline="")
            changed_files[docker_result.source_path] = (existing_before, docker_after)
        finally:
            shutil.rmtree(docker_stage, ignore_errors=True)

    if _snapshot_tree(target) != expected_snapshot:
        raise HealingConflictError(
            "target changed while healing was being staged; no source files were modified"
        )

    after_issues = scan_repository(output)
    after_score = readiness_score(after_issues)
    remaining_counter = Counter(_issue_fingerprint(issue) for issue in after_issues)
    fixed: list[LandmineIssue] = []
    for issue in before_issues:
        fingerprint = _issue_fingerprint(issue)
        if remaining_counter[fingerprint]:
            remaining_counter[fingerprint] -= 1
        else:
            fixed.append(issue)

    diffs: list[str] = []
    for relative in sorted(changed_files):
        before, after = changed_files[relative]
        diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
        if diff:
            diffs.append(diff)
    result = HealResult(
        output_path=str(output),
        issues_found=len(before_issues),
        issues_fixed=len(fixed),
        fixed_issues=_sorted_issues(fixed),
        remaining_issues=after_issues,
        unified_diffs=diffs,
        readiness_score_before=before_score,
        readiness_score_after=after_score,
    )
    if len(_STAGED_BASELINES) >= 128:
        _STAGED_BASELINES.pop(next(iter(_STAGED_BASELINES)))
    _STAGED_BASELINES[str(output.resolve())] = expected_snapshot
    return result


def _issue_fingerprint(issue: LandmineIssue) -> tuple[object, ...]:
    """Match issues across healing when line numbers shift after edits."""

    return (
        issue.issue_id,
        issue.file_path,
        issue.message,
        tuple(issue.evidence),
    )


__all__ = [
    "HealingConflictError",
    "apply_heal_result",
    "apply_healing",
    "heal_repository",
    "readiness_score",
    "scan_repository",
]
