"""Dependency-free polling watcher for scan-only workspace monitoring.

The watcher deliberately observes file metadata only.  It does not open files,
run commands, or write to the target.  A small set of pure helpers keeps the
polling and debounce behavior straightforward to test without real sleeps.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time
from typing import Callable, Iterable, Mapping

from .config import workspace_config
from .models import LandmineIssue
from .scanner import scan_repository


DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_DEBOUNCE_SECONDS = 0.35

# These names cover the common generated, cache, and virtual-environment trees
# without depending on a platform-specific filesystem notification API.
DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".cache",
        ".gradle",
        ".hg",
        ".hypothesis",
        ".mypy_cache",
        ".next",
        ".nox",
        ".parcel-cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "_build",
        "build",
        "cache",
        "coverage",
        "dist",
        "env",
        "node_modules",
        "out",
        "target",
        "venv",
    }
)


@dataclass(frozen=True)
class FileMetadata:
    """Metadata used to detect a file change without reading its contents."""

    size: int
    mtime_ns: int
    mode: int
    inode: int


Snapshot = dict[str, FileMetadata]


@dataclass(frozen=True)
class SnapshotChanges:
    """The stable, relative paths changed between two snapshots."""

    added: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def any(self) -> bool:
        return bool(self.added or self.changed or self.removed)


@dataclass(frozen=True)
class FindingChanges:
    """Findings introduced or altered by one completed scan."""

    new: tuple[LandmineIssue, ...] = ()
    changed: tuple[LandmineIssue, ...] = ()
    resolved: tuple[LandmineIssue, ...] = ()

    @property
    def any(self) -> bool:
        return bool(self.new or self.changed or self.resolved)


@dataclass(frozen=True)
class WatchResult:
    """Summary returned by :func:`watch_directory` for callers and tests."""

    initial_findings: tuple[LandmineIssue, ...]
    events: int
    stopped: bool


def _normalise_configured_path(value: str) -> tuple[str, ...]:
    normalized = value.strip().replace("\\", "/").strip("/")
    if not normalized or normalized in {".", "./"}:
        return ()
    return tuple(part for part in normalized.split("/") if part not in {"", "."})


def _is_ignored(
    relative_parts: tuple[str, ...], configured: tuple[tuple[str, ...], ...]
) -> bool:
    if any(part in DEFAULT_IGNORED_DIRECTORIES for part in relative_parts):
        return True
    for ignored in configured:
        if not ignored:
            continue
        # A configured single directory name follows the scanner's existing
        # behavior and applies at any depth; nested paths are root-relative.
        if len(ignored) == 1 and ignored[0] in relative_parts:
            return True
        if relative_parts[: len(ignored)] == ignored:
            return True
    return False


def snapshot_tree(
    root: Path,
    ignored_paths: Iterable[str] | None = None,
) -> Snapshot:
    """Return file metadata below *root*, excluding generated trees.

    Directory traversal uses ``os.scandir`` from the standard library and does
    not follow symlinks.  Permission and race errors are skipped so a file
    disappearing during a poll cannot terminate the watcher.
    """

    root = root.resolve()
    configured = tuple(
        item
        for item in (
            _normalise_configured_path(value)
            for value in (
                workspace_config.ignore_paths
                if ignored_paths is None
                else ignored_paths
            )
        )
        if item
    )
    snapshot: Snapshot = {}

    def walk(directory: Path, parts: tuple[str, ...]) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except (OSError, ValueError):
            return
        for entry in entries:
            relative_parts = parts + (entry.name,)
            if _is_ignored(relative_parts, configured):
                continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    walk(Path(entry.path), relative_parts)
                elif entry.is_file(follow_symlinks=False):
                    info = entry.stat(follow_symlinks=False)
                    snapshot["/".join(relative_parts)] = FileMetadata(
                        size=info.st_size,
                        mtime_ns=info.st_mtime_ns,
                        mode=stat.S_IMODE(info.st_mode),
                        inode=getattr(info, "st_ino", 0),
                    )
            except OSError:
                continue

    if root.is_dir():
        walk(root, ())
    return snapshot


def diff_snapshots(
    before: Mapping[str, FileMetadata], after: Mapping[str, FileMetadata]
) -> SnapshotChanges:
    """Compare metadata snapshots and return sorted added/changed/removed paths."""

    before_paths = set(before)
    after_paths = set(after)
    return SnapshotChanges(
        added=tuple(sorted(after_paths - before_paths)),
        changed=tuple(
            sorted(
                path
                for path in before_paths & after_paths
                if before[path] != after[path]
            )
        ),
        removed=tuple(sorted(before_paths - after_paths)),
    )


def compare_findings(
    before: Iterable[LandmineIssue], after: Iterable[LandmineIssue]
) -> FindingChanges:
    """Classify findings as new, changed, or resolved without mutating either list."""

    before_by_identity = {
        (issue.issue_id, issue.category, issue.file_path, issue.line_number): issue
        for issue in before
    }
    after_by_identity = {
        (issue.issue_id, issue.category, issue.file_path, issue.line_number): issue
        for issue in after
    }
    new: list[LandmineIssue] = []
    changed: list[LandmineIssue] = []
    resolved: list[LandmineIssue] = []
    for identity in sorted(
        after_by_identity, key=lambda item: tuple(str(value) for value in item)
    ):
        issue = after_by_identity[identity]
        old = before_by_identity.get(identity)
        if old is None:
            new.append(issue)
        elif old != issue:
            changed.append(issue)
    for identity in sorted(
        before_by_identity, key=lambda item: tuple(str(value) for value in item)
    ):
        if identity not in after_by_identity:
            resolved.append(before_by_identity[identity])
    return FindingChanges(tuple(new), tuple(changed), tuple(resolved))


WaitFunction = Callable[[float], bool]
SnapshotFunction = Callable[[Path], Snapshot]
ClockFunction = Callable[[], float]


def wait_for_debounced_snapshot(
    root: Path,
    previous: Mapping[str, FileMetadata],
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    wait: WaitFunction | None = None,
    snapshot_fn: SnapshotFunction = snapshot_tree,
    clock: ClockFunction = time.monotonic,
    stop_requested: Callable[[], bool] | None = None,
) -> Snapshot | None:
    """Poll until a changed snapshot remains stable for the debounce period.

    ``wait`` returns ``True`` when stopping was requested.  It is injectable so
    tests can advance a fake clock and never sleep indefinitely.
    """

    if poll_interval <= 0:
        raise ValueError("poll_interval must be greater than zero")
    if debounce_seconds < 0:
        raise ValueError("debounce_seconds must not be negative")

    if wait is None:
        wait = lambda seconds: (time.sleep(seconds) or False)
    latest: Snapshot = dict(previous)
    changed_at: float | None = None
    while not (stop_requested and stop_requested()):
        if wait(poll_interval):
            return None
        current = snapshot_fn(root)
        changes = diff_snapshots(previous, current)
        if not changes.any:
            latest = current
            changed_at = None
            continue
        if current != latest:
            latest = current
            changed_at = clock()
            if debounce_seconds == 0:
                return latest
            continue
        if changed_at is not None and clock() - changed_at >= debounce_seconds:
            return latest
    return None


def _default_wait(stop_event: object | None) -> WaitFunction:
    if stop_event is None:
        return lambda seconds: (time.sleep(seconds) or False)
    return lambda seconds: bool(stop_event.wait(seconds))  # type: ignore[attr-defined]


def _finding_output(label: str, issue: LandmineIssue) -> str:
    location = issue.file_path or "workspace"
    if issue.line_number:
        location += f":{issue.line_number}"
    return f"{label}: [{issue.severity.value}] {location} — {issue.message}"


def watch_directory(
    root: Path,
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    ignored_paths: Iterable[str] | None = None,
    emit: Callable[[str], None] = print,
    scan_fn: Callable[[Path], list[LandmineIssue]] = scan_repository,
    snapshot_fn: SnapshotFunction | None = None,
    wait: WaitFunction | None = None,
    clock: ClockFunction = time.monotonic,
    stop_event: object | None = None,
    max_events: int | None = None,
) -> WatchResult:
    """Initial-scan and continuously poll *root* until stopped.

    ``max_events`` is intended for deterministic callers and tests; normal CLI
    use leaves it unset and stops via Ctrl+C.
    """

    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if poll_interval <= 0:
        raise ValueError("poll_interval must be greater than zero")
    if debounce_seconds < 0:
        raise ValueError("debounce_seconds must not be negative")

    if snapshot_fn is None:
        snapshot_fn = lambda path: snapshot_tree(path, ignored_paths)
    if wait is None:
        wait = _default_wait(stop_event)

    initial_findings = tuple(scan_fn(root))
    initial_snapshot = snapshot_fn(root)
    emit(f"Initial scan: {len(initial_findings)} finding(s)")
    for issue in initial_findings:
        emit(_finding_output("Finding", issue))

    current_snapshot = initial_snapshot
    current_findings = list(initial_findings)
    events = 0
    stopped = False
    try:
        while max_events is None or events < max_events:
            next_snapshot = wait_for_debounced_snapshot(
                root,
                current_snapshot,
                poll_interval=poll_interval,
                debounce_seconds=debounce_seconds,
                wait=wait,
                snapshot_fn=snapshot_fn,
                clock=clock,
                stop_requested=(
                    (lambda: bool(stop_event.is_set()))  # type: ignore[attr-defined]
                    if stop_event is not None
                    else None
                ),
            )
            if next_snapshot is None:
                stopped = True
                break
            snapshot_changes = diff_snapshots(current_snapshot, next_snapshot)
            current_snapshot = next_snapshot
            next_findings = scan_fn(root)
            finding_changes = compare_findings(current_findings, next_findings)
            current_findings = next_findings
            events += 1
            emit(
                "Change detected: "
                f"{len(snapshot_changes.added)} added, "
                f"{len(snapshot_changes.changed)} changed, "
                f"{len(snapshot_changes.removed)} removed"
            )
            for issue in finding_changes.new:
                emit(_finding_output("New finding", issue))
            for issue in finding_changes.changed:
                emit(_finding_output("Changed finding", issue))
            if not finding_changes.new and not finding_changes.changed:
                emit("No new or changed findings.")
            if finding_changes.resolved:
                emit(f"Resolved findings: {len(finding_changes.resolved)}")
    except KeyboardInterrupt:
        stopped = True
    return WatchResult(initial_findings, events, stopped)


__all__ = [
    "DEFAULT_DEBOUNCE_SECONDS",
    "DEFAULT_IGNORED_DIRECTORIES",
    "DEFAULT_POLL_INTERVAL",
    "FileMetadata",
    "FindingChanges",
    "SnapshotChanges",
    "WatchResult",
    "compare_findings",
    "diff_snapshots",
    "snapshot_tree",
    "wait_for_debounced_snapshot",
    "watch_directory",
]
