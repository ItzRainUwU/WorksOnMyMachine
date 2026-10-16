"""Focused tests for the scan-only polling watcher."""

from pathlib import Path

from click.testing import CliRunner

from worksonmymachine.cli import _resolve_watch_target, main
from worksonmymachine.models import LandmineIssue
from worksonmymachine.watch import (
    FileMetadata,
    compare_findings,
    diff_snapshots,
    snapshot_tree,
    watch_directory,
)


def _issue(message: str, *, path: str = "app.py") -> LandmineIssue:
    return LandmineIssue(
        issue_id="TEST-FINDING",
        category="TEST",
        message=message,
        severity="low",
        file_path=path,
        line_number=1,
    )


def test_watch_target_resolves_current_directory_workspace_and_absolute_paths(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert _resolve_watch_target(".") == tmp_path.resolve()
    assert _resolve_watch_target(None, tmp_path) == tmp_path.resolve()
    assert _resolve_watch_target(tmp_path) == tmp_path.resolve()


def test_snapshot_ignores_generated_cache_and_configured_paths(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("keep", encoding="utf-8")
    for directory in (".git", ".cache", "venv", "build", "vendor", "generated"):
        path = tmp_path / directory
        path.mkdir()
        (path / "ignored.txt").write_text("ignored", encoding="utf-8")

    snapshot = snapshot_tree(tmp_path, ignored_paths=("vendor", "generated"))

    assert set(snapshot) == {"keep.txt"}


def test_snapshot_diff_and_finding_comparison_classify_changes() -> None:
    unchanged = FileMetadata(1, 1, 0o644, 1)
    changed = FileMetadata(2, 2, 0o644, 1)
    assert diff_snapshots(
        {"same": unchanged, "old": unchanged, "edit": unchanged},
        {"same": unchanged, "new": unchanged, "edit": changed},
    ).__dict__ == {
        "added": ("new",),
        "changed": ("edit",),
        "removed": ("old",),
    }

    delta = compare_findings(
        [_issue("old"), _issue("gone", path="gone.py")], [_issue("new")]
    )
    assert [issue.message for issue in delta.changed] == ["new"]
    assert [issue.message for issue in delta.resolved] == ["gone"]


def test_watch_debounces_transient_snapshots_without_sleeping(tmp_path: Path) -> None:
    snapshots = [
        {"app.py": FileMetadata(1, 1, 0o644, 1)},
        {"app.py": FileMetadata(2, 2, 0o644, 1)},
        {"app.py": FileMetadata(3, 3, 0o644, 1)},
        {"app.py": FileMetadata(3, 3, 0o644, 1)},
    ]
    calls = iter(snapshots)
    now = iter((0.0, 0.1, 0.6))
    waits: list[float] = []
    output: list[str] = []

    def wait(seconds: float) -> bool:
        waits.append(seconds)
        return False

    result = watch_directory(
        tmp_path,
        poll_interval=0.1,
        debounce_seconds=0.4,
        emit=output.append,
        scan_fn=lambda _root: [],
        snapshot_fn=lambda _root: next(calls),
        wait=wait,
        clock=lambda: next(now),
        max_events=1,
    )

    assert result.events == 1
    assert waits == [0.1, 0.1, 0.1]
    assert "Change detected: 0 added, 1 changed, 0 removed" in output


def test_watch_returns_cleanly_when_stop_is_requested(tmp_path: Path) -> None:
    output: list[str] = []
    result = watch_directory(
        tmp_path,
        emit=output.append,
        scan_fn=lambda _root: [],
        wait=lambda _seconds: True,
    )

    assert result.stopped is True
    assert result.events == 0
    assert output[0] == "Initial scan: 0 finding(s)"


def test_watch_handles_keyboard_interrupt_cleanly(tmp_path: Path) -> None:
    output: list[str] = []

    def interrupt(_seconds: float) -> bool:
        raise KeyboardInterrupt

    result = watch_directory(
        tmp_path,
        emit=output.append,
        scan_fn=lambda _root: [],
        wait=interrupt,
    )

    assert result.stopped is True
    assert result.events == 0
    assert output == ["Initial scan: 0 finding(s)"]


def test_watch_cli_accepts_interval_and_help() -> None:
    result = CliRunner().invoke(main, ["watch", "--help"])

    assert result.exit_code == 0, result.output
    assert "--interval" in result.output
    assert "--debounce" in result.output
