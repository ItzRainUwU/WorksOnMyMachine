"""Contract tests for the published pre-commit hook metadata."""

from pathlib import Path
import re
import shlex


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOOK_PATH = PROJECT_ROOT / ".pre-commit-hooks.yaml"


def _hook_value(name: str) -> str:
    text = HOOK_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"(?m)^[ \t]*(?:-\s+)?{re.escape(name)}:\s*(.+?)\s*$", text
    )
    assert match is not None, f"missing hook metadata field: {name}"
    return match.group(1)


def test_published_hook_has_scan_only_metadata() -> None:
    assert HOOK_PATH.is_file()
    assert _hook_value("id") == "worksonmymachine-check"
    assert _hook_value("language") == "python"
    assert _hook_value("pass_filenames") == "false"
    assert _hook_value("always_run") == "true"
    assert "Scan the caller repository root" in _hook_value("description")


def test_hook_uses_explicit_caller_root_without_healing() -> None:
    entry = shlex.split(_hook_value("entry"))

    assert entry == ["worksonmymachine", "check", "--root", "."]
    assert "--auto-heal" not in entry
    assert "audit" not in entry


def test_hook_cannot_forward_staged_filenames_and_leaves_args_configurable() -> None:
    text = HOOK_PATH.read_text(encoding="utf-8")
    entry = _hook_value("entry")
    command = shlex.split(entry)
    caller_args = ["--fail-on", "high"]

    assert _hook_value("pass_filenames") == "false"
    assert "{filenames}" not in entry
    assert "$@" not in entry
    assert "--fail-on" not in entry
    assert "args:" not in text
    assert command + caller_args == [
        "worksonmymachine",
        "check",
        "--root",
        ".",
        "--fail-on",
        "high",
    ]
