"""Incremental repository scanning with a portable, deterministic cache.

The regular scanner remains the source of truth for individual rules.  This
module only supplies the orchestration around it: file snapshots are compared
with cached snapshots, unchanged per-file findings are reused, and the final
issue list is sorted with the scanner's repository-wide ordering function.

The cache deliberately stores only target-relative paths and validated issue
models.  A cache may be kept in memory, supplied as a mapping by a caller, or
backed by a JSON file outside the target repository.  Cache failures are
treated as misses so a damaged or inaccessible cache can never prevent a
normal scan.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any

from . import scanner
from .models import LandmineIssue


# These values are intentionally explicit.  A change to scanner behavior or a
# rule pack must bump the corresponding value so old per-file results cannot be
# reused accidentally.
SCANNER_VERSION = "scanner-1"
RULE_SET_VERSION = "rules-1"
CACHE_FORMAT_VERSION = 1


@dataclass(frozen=True)
class IncrementalScanStats:
    """Counters from the most recent call using an ``IncrementalScanCache``."""

    files_seen: int = 0
    files_scanned: int = 0
    cache_hits: int = 0
    files_removed: int = 0


class IncrementalScanCache:
    """Validated cache storage, optionally persisted as deterministic JSON.

    ``path`` is expected to be outside the target being scanned.  The scanner
    does not require that arrangement, but keeping the cache outside the target
    avoids making the cache itself a scan input.  Existing invalid cache data is
    ignored rather than trusted.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.entries: dict[str, dict[str, Any]] = {}
        self.last_stats = IncrementalScanStats()
        if self.path is not None:
            self._load()

    def _load(self) -> None:
        """Load only entries that satisfy the cache's safety contract."""

        if self.path is None:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            return
        if not isinstance(raw, dict) or raw.get("format") != CACHE_FORMAT_VERSION:
            return
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            return
        for key, value in entries.items():
            if not isinstance(key, str) or not _safe_relative(key):
                continue
            validated = _validate_entry(key, value)
            if validated is not None:
                self.entries[key] = validated

    def save(self) -> None:
        """Atomically persist the cache, if this instance has a backing path."""

        if self.path is None:
            return
        payload = {
            "format": CACHE_FORMAT_VERSION,
            "entries": {
                key: self.entries[key]
                for key in sorted(self.entries)
                if _safe_relative(key)
                and _validate_entry(key, self.entries[key]) is not None
            },
        }
        temporary: Path | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(
                    payload,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except (OSError, TypeError, ValueError):
            if temporary is not None:
                try:
                    temporary.unlink()
                except OSError:
                    pass


# A short alias keeps the call site readable while retaining the descriptive
# public class name for callers that want to be explicit.
IncrementalCache = IncrementalScanCache


def _safe_relative(value: str) -> bool:
    """Return whether *value* is a portable, target-relative cache path."""

    if not value or "\\" in value or value.startswith("/"):
        return False
    if len(value) >= 2 and value[1] == ":":
        return False
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return False
    parts = PurePosixPath(value).parts
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def _issue_payload(issues: list[LandmineIssue]) -> list[dict[str, Any]]:
    return [issue.model_dump(mode="json") for issue in issues]


def _validate_entry(key: str, value: Any) -> dict[str, Any] | None:
    """Validate and normalize one untrusted cache entry."""

    if not _safe_relative(key) or not isinstance(value, dict):
        return None
    if value.get("path") != key:
        return None
    content_hash = value.get("content_sha256")
    if (
        not isinstance(content_hash, str)
        or len(content_hash) != hashlib.sha256().digest_size * 2
        or any(
            character not in "0123456789abcdef"
            for character in content_hash.lower()
        )
    ):
        return None
    size = value.get("size_bytes")
    mtime_ns = value.get("mtime_ns")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(mtime_ns, int)
        or isinstance(mtime_ns, bool)
        or mtime_ns < 0
    ):
        return None
    scanner_version = value.get("scanner_version")
    rule_set_version = value.get("rule_set_version")
    context = value.get("context", "")
    if not isinstance(scanner_version, str) or not isinstance(
        rule_set_version, str
    ):
        return None
    if not isinstance(context, str):
        return None
    raw_issues = value.get("issues")
    if not isinstance(raw_issues, list):
        return None
    try:
        issues = [LandmineIssue.model_validate(issue) for issue in raw_issues]
    except (TypeError, ValueError):
        return None
    return {
        "path": key,
        "content_sha256": content_hash.lower(),
        "size_bytes": size,
        "mtime_ns": mtime_ns,
        "scanner_version": scanner_version,
        "rule_set_version": rule_set_version,
        "context": context,
        "issues": _issue_payload(issues),
    }


def _cache_entries(
    cache: IncrementalScanCache | MutableMapping[str, Any] | Path | str | None,
) -> tuple[dict[str, Any], IncrementalScanCache | None]:
    if isinstance(cache, IncrementalScanCache):
        return cache.entries, cache
    if isinstance(cache, (Path, str)):
        storage = IncrementalScanCache(cache)
        return storage.entries, storage
    if cache is None:
        return {}, None
    # A caller-owned mapping is intentionally used directly.  Invalid values
    # are ignored on read and overwritten with validated values on write.
    return cache, None


def _content_sha256(path: Path) -> tuple[str, int, int] | None:
    try:
        metadata = path.stat(follow_symlinks=False)
        if not path.is_file() or path.is_symlink():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest(), metadata.st_size, metadata.st_mtime_ns
    except (OSError, ValueError):
        return None


def _relative_path(root: Path, path: Path) -> str | None:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return None
    return relative if _safe_relative(relative) else None


def _topology_hash(paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _context_token(
    relative: str,
    paths: list[str],
    snapshots: dict[str, dict[str, Any]],
    topology: str,
) -> str:
    """Capture small cross-file inputs that affect a per-file rule result."""

    suffix = Path(relative).suffix.lower()
    context: list[Any] = []
    if suffix == ".py" or suffix in scanner._JS_SUFFIXES:
        # Import casing is resolved against the repository's file topology and
        # environment findings read the root .env.example file.
        context.append(("topology", topology))
        env = snapshots.get(".env.example")
        context.append(("env", env.get("content_sha256") if env else None))
    if Path(relative).name.lower() == "pyproject.toml":
        lock_names = {"poetry.lock", "uv.lock", "pipfile.lock", "requirements.lock"}
        parent = PurePosixPath(relative).parent
        context.append(
            (
                "locks",
                [
                    (path, snapshots[path].get("content_sha256"))
                    for path in paths
                    if PurePosixPath(path).parent == parent
                    and PurePosixPath(path).name.lower() in lock_names
                ],
            )
        )
    return json.dumps(context, sort_keys=True, separators=(",", ":"))


def _snapshot_files(target: Path) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    files: list[Path] = []
    snapshots: dict[str, dict[str, Any]] = {}
    for path in scanner._iter_files(target):
        relative = _relative_path(target, path)
        if relative is None:
            continue
        file_hash = _content_sha256(path)
        if file_hash is None:
            continue
        digest, size, mtime_ns = file_hash
        files.append(path)
        snapshots[relative] = {
            "path": relative,
            "content_sha256": digest,
            "size_bytes": size,
            "mtime_ns": mtime_ns,
        }
    files.sort(key=lambda item: _relative_path(target, item) or "")
    return files, snapshots


def _scan_file(target: Path, path: Path) -> list[LandmineIssue]:
    """Run exactly the scanner rules that apply to one regular file."""

    issues: list[LandmineIssue] = []
    suffix = path.suffix.lower()
    if suffix == ".py":
        scanner._scan_python(target, path, issues)
    elif suffix in scanner._JS_SUFFIXES:
        scanner._scan_js(target, path, issues)
    elif suffix in scanner._CONFIG_SUFFIXES:
        scanner._scan_config(target, path, issues)
    elif suffix == ".sh":
        scanner._scan_shell(target, path, issues)
    if path.name.lower() == "pyproject.toml":
        scanner._scan_pyproject(target, path, issues)
    if path.name.lower() == "requirements.txt":
        scanner._scan_requirements(target, path, issues)
    if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
        scanner._scan_dockerfile(target, path, issues)
    return issues


def _issues_from_entry(value: dict[str, Any]) -> list[LandmineIssue] | None:
    validated = _validate_entry(str(value.get("path", "")), value)
    if validated is None:
        return None
    try:
        return [LandmineIssue.model_validate(issue) for issue in validated["issues"]]
    except (TypeError, ValueError):
        return None


def scan_repository_incremental(
    target_path: Path | str,
    cache: IncrementalScanCache | MutableMapping[str, Any] | Path | str | None = None,
    *,
    scanner_version: str = SCANNER_VERSION,
    rule_set_version: str = RULE_SET_VERSION,
) -> list[LandmineIssue]:
    """Scan *target_path*, reusing unchanged per-file findings from *cache*.

    The returned value has the same type and deterministic ordering as
    :func:`worksonmymachine.scanner.scan_repository`.  ``cache`` may be an
    :class:`IncrementalScanCache`, a caller-owned mapping, or a JSON path.  A
    path-backed cache is loaded and saved automatically.  Version changes make
    every cached entry a miss; removed files are discarded from the cache.
    """

    target = Path(target_path)
    if not target.is_dir():
        return scanner.scan_repository(target)
    if not isinstance(scanner_version, str) or not isinstance(
        rule_set_version, str
    ):
        raise TypeError("scanner_version and rule_set_version must be strings")

    entries, persistent = _cache_entries(cache)
    files, snapshots = _snapshot_files(target)
    paths = sorted(snapshots)
    topology = _topology_hash(paths)
    current_issues: list[LandmineIssue] = []
    next_entries: dict[str, dict[str, Any]] = {}
    cache_hits = 0
    files_scanned = 0

    for path in files:
        relative = _relative_path(target, path)
        if relative is None:
            continue
        snapshot = snapshots[relative]
        context = _context_token(relative, paths, snapshots, topology)
        candidate = entries.get(relative)
        candidate = _validate_entry(relative, candidate)
        matches = bool(
            candidate
            and candidate["content_sha256"] == snapshot["content_sha256"]
            and candidate["size_bytes"] == snapshot["size_bytes"]
            and candidate["mtime_ns"] == snapshot["mtime_ns"]
            and candidate["scanner_version"] == scanner_version
            and candidate["rule_set_version"] == rule_set_version
            and candidate.get("context", "") == context
        )
        if matches and candidate is not None:
            file_issues = _issues_from_entry(candidate) or []
            cache_hits += 1
            next_entries[relative] = candidate
        else:
            file_issues = _scan_file(target, path)
            files_scanned += 1
            next_entries[relative] = {
                **snapshot,
                "scanner_version": scanner_version,
                "rule_set_version": rule_set_version,
                "context": context,
                "issues": _issue_payload(file_issues),
            }
        current_issues.extend(file_issues)

    # Git index executable-bit findings are repository metadata rather than
    # content belonging to one file.  Evaluate this small global rule on every
    # call while still reusing all ordinary per-file findings above.
    scanner._scan_tracked_shell_modes(target, current_issues, set(paths))
    ordered = scanner._sorted_issues(current_issues)

    removed = len(
        {
            key
            for key in entries
            if isinstance(key, str) and _safe_relative(key) and key not in next_entries
        }
    )
    if persistent is not None:
        persistent.entries = next_entries
        persistent.last_stats = IncrementalScanStats(
            files_seen=len(paths),
            files_scanned=files_scanned,
            cache_hits=cache_hits,
            files_removed=removed,
        )
        persistent.save()
    elif isinstance(cache, MutableMapping):
        cache.clear()
        cache.update(next_entries)
    return ordered


__all__ = [
    "CACHE_FORMAT_VERSION",
    "IncrementalCache",
    "IncrementalScanCache",
    "IncrementalScanStats",
    "RULE_SET_VERSION",
    "SCANNER_VERSION",
    "scan_repository_incremental",
]
