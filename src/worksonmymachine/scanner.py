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
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import tempfile
from typing import Iterable, Sequence

from .apt_healer import heal_dockerfile
from .models import HealResult, LandmineIssue, SeverityLevel


_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"}
_CONFIG_SUFFIXES = {".cfg", ".conf", ".ini", ".toml", ".yaml", ".yml"}

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
                # Keep symlinks in staged copies, but never scan through them.
                # Repair functions write in place and could otherwise write
                # through a link to a file outside the target tree.
                if entry.is_symlink():
                    continue
                if entry.is_dir():
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
        entries = _children(current)
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
    entries = _children(parent_path)
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
        entry for entry in _children(target) if entry.is_dir() and not entry.is_symlink()
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
        module = ""
        level = 0
        if isinstance(node, ast.Import):
            aliases = [(alias.name, alias) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level
            aliases = [(module, node)] if module else []
        else:
            continue
        for typed, anchor in aliases:
            result = _resolve_python_import(target, path, typed, level)
            if result is None or not result.mismatch or result.corrected == typed:
                continue
            references.append(
                (
                    typed,
                    result.corrected,
                    getattr(anchor, "lineno", getattr(node, "lineno", 1)),
                    getattr(anchor, "col_offset", getattr(node, "col_offset", 0)),
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
            (entry for entry in index_entries if entry.name == "index.js"), None
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


def _scan_requirements(target: Path, path: Path, issues: list[LandmineIssue]) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(("-", "git+", "http:")):
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
    if os.name != "nt":
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            mode = 0
        if not mode & 0o111:
            issues.append(
                _issue(
                    target,
                    path,
                    "SHELL-NOT-EXECUTABLE",
                    "EXEC_PERMISSIONS",
                    "Shell script has no execute bit on this POSIX host.",
                    SeverityLevel.MEDIUM,
                    remediation="Mark the copied shell script executable.",
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
        if path.name.lower() == "requirements.txt":
            _scan_requirements(target, path, issues)
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            _scan_dockerfile(target, path, issues)
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
        match = re.search(rf"(?<![\w.]){re.escape(typed)}(?![\w.])", line_text)
        if match:
            replacements.append(
                _TextReplacement(
                    offsets[line - 1] + match.start(),
                    offsets[line - 1] + match.end(),
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
    if path.is_symlink():
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
    if output.is_symlink():
        output.unlink()
    elif output.is_dir():
        shutil.rmtree(output)
    elif output.is_file():
        output.unlink()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Preserve links rather than copying data from outside the target tree.
    shutil.copytree(target, output, symlinks=True)


def _ensure_requirements_lock(output: Path, changed_files: dict[str, tuple[str, str]]) -> None:
    """Create a deterministic local lock companion for a healed requirements file."""

    requirements = output / "requirements.txt"
    lock = output / "requirements.lock"
    if (
        requirements.is_symlink()
        or lock.is_symlink()
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

    target = Path(target_path)
    if not target.is_dir():
        raise ValueError("target_path must be a directory")
    output = (
        Path(output_path)
        if output_path is not None
        else Path(tempfile.mkdtemp(prefix="worksonmymachine-healed-"))
    )
    target_resolved = target.resolve()
    output_resolved = output.resolve()
    try:
        common = os.path.commonpath([str(target_resolved), str(output_resolved)])
    except ValueError:
        # Different drives on Windows are safe.
        common = ""
    if target_resolved == output_resolved or common == str(target_resolved):
        raise ValueError("output_path must not be the target or one of its descendants")

    before_issues = scan_repository(target)
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
            if path.name.lower() in dockerfile_names
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
    return HealResult(
        output_path=str(output),
        issues_found=len(before_issues),
        issues_fixed=len(fixed),
        fixed_issues=_sorted_issues(fixed),
        remaining_issues=after_issues,
        unified_diffs=diffs,
        readiness_score_before=before_score,
        readiness_score_after=after_score,
    )


def _issue_fingerprint(issue: LandmineIssue) -> tuple[object, ...]:
    """Match issues across healing when line numbers shift after edits."""

    return (
        issue.issue_id,
        issue.file_path,
        issue.message,
        tuple(issue.evidence),
    )


__all__ = ["heal_repository", "readiness_score", "scan_repository"]
