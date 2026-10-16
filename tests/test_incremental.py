"""Focused coverage for incremental scanning and its cache contract."""

from pathlib import Path

import pytest

from worksonmymachine import incremental
from worksonmymachine.scanner import scan_repository


def _portable_path_source(name: str) -> str:
    return f"value = r'C:\\Users\\demo\\{name}'\n"


def test_unchanged_files_reuse_disk_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text(_portable_path_source("a.txt"), encoding="utf-8")
    (target / "b.py").write_text(_portable_path_source("b.txt"), encoding="utf-8")
    cache_path = tmp_path / "scan-cache.json"
    calls: list[str] = []
    original = incremental.scanner._scan_python

    def counted_scan(root: Path, path: Path, issues: list[object]) -> None:
        calls.append(path.name)
        original(root, path, issues)  # type: ignore[arg-type]

    monkeypatch.setattr(incremental.scanner, "_scan_python", counted_scan)
    first = incremental.scan_repository_incremental(target, cache_path)
    assert sorted(calls) == ["a.py", "b.py"]
    assert cache_path.is_file()

    calls.clear()
    second = incremental.scan_repository_incremental(
        target, incremental.IncrementalScanCache(cache_path)
    )

    assert second == first
    assert calls == []


def test_changed_file_is_rescanned_while_unchanged_file_is_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "changed.py").write_text(
        _portable_path_source("before.txt"), encoding="utf-8"
    )
    (target / "unchanged.py").write_text(
        _portable_path_source("same.txt"), encoding="utf-8"
    )
    cache = incremental.IncrementalScanCache(tmp_path / "cache.json")
    calls: list[str] = []
    original = incremental.scanner._scan_python

    def counted_scan(root: Path, path: Path, issues: list[object]) -> None:
        calls.append(path.name)
        original(root, path, issues)  # type: ignore[arg-type]

    monkeypatch.setattr(incremental.scanner, "_scan_python", counted_scan)
    incremental.scan_repository_incremental(target, cache)
    calls.clear()

    (target / "changed.py").write_text(
        _portable_path_source("after.txt"), encoding="utf-8"
    )
    result = incremental.scan_repository_incremental(target, cache)

    assert calls == ["changed.py"]
    assert any("after.txt" in evidence for issue in result for evidence in issue.evidence)
    assert not any("before.txt" in evidence for issue in result for evidence in issue.evidence)
    assert cache.last_stats.files_scanned == 1
    assert cache.last_stats.cache_hits == 1


def test_removed_file_is_pruned_and_its_findings_disappear(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    removed = target / "removed.py"
    removed.write_text(_portable_path_source("gone.txt"), encoding="utf-8")
    cache = incremental.IncrementalScanCache(tmp_path / "cache.json")

    first = incremental.scan_repository_incremental(target, cache)
    assert first
    assert "removed.py" in cache.entries

    removed.unlink()
    second = incremental.scan_repository_incremental(target, cache)

    assert second == []
    assert "removed.py" not in cache.entries
    assert cache.last_stats.files_removed == 1


def test_scanner_and_rule_versions_invalidate_cached_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text(
        _portable_path_source("source.txt"), encoding="utf-8"
    )
    cache = incremental.IncrementalScanCache()
    calls: list[str] = []
    original = incremental.scanner._scan_python

    def counted_scan(root: Path, path: Path, issues: list[object]) -> None:
        calls.append(path.name)
        original(root, path, issues)  # type: ignore[arg-type]

    monkeypatch.setattr(incremental.scanner, "_scan_python", counted_scan)
    incremental.scan_repository_incremental(
        target, cache, scanner_version="scanner-a", rule_set_version="rules-a"
    )

    calls.clear()
    incremental.scan_repository_incremental(
        target, cache, scanner_version="scanner-b", rule_set_version="rules-a"
    )
    assert calls == ["source.py"]

    calls.clear()
    incremental.scan_repository_incremental(
        target, cache, scanner_version="scanner-b", rule_set_version="rules-b"
    )
    assert calls == ["source.py"]


def test_incremental_result_keeps_scanner_ordering_and_rejects_unsafe_cache_paths(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "z.py").write_text(_portable_path_source("z.txt"), encoding="utf-8")
    (target / "a.py").write_text(_portable_path_source("a.txt"), encoding="utf-8")

    cache: dict[str, object] = {
        "../outside.py": {"path": "../outside.py", "issues": []},
        "C:/outside.py": {"path": "C:/outside.py", "issues": []},
    }
    expected = scan_repository(target)
    actual = incremental.scan_repository_incremental(target, cache)

    assert actual == expected
    assert list(cache) == ["a.py", "z.py"]
    assert all(".." not in key and not key.startswith("/") for key in cache)


def test_external_symlink_is_not_scanned_or_cached(tmp_path: Path) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    external = outside / "external.py"
    external.write_text(_portable_path_source("outside.txt"), encoding="utf-8")
    link = target / "external.py"
    try:
        link.symlink_to(external)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    cache = incremental.IncrementalScanCache()

    assert incremental.scan_repository_incremental(target, cache) == []
    assert "external.py" not in cache.entries
