"""Static, offline checks for the cross-platform GitHub Actions workflow."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "cross-platform.yml"


def test_ci_workflow_covers_all_supported_host_operating_systems() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "runs-on: ${{ matrix.os }}" in workflow
    for runner in ("windows-latest", "ubuntu-latest", "macos-latest"):
        assert f"- {runner}" in workflow


def test_ci_workflow_uses_the_pinned_python_and_locked_dependencies() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "uses: actions/setup-python@v5" in workflow
    assert "python-version-file: .python-version" in workflow
    assert "--requirement requirements.txt" in workflow
    assert "--constraint requirements.lock" in workflow
    assert "pip install ." not in workflow
    assert "pip install -e" not in workflow


def test_ci_workflow_runs_offline_tests_and_optional_node_checks() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "make test" in workflow
    assert "python -m pytest" in workflow
    assert "command -v node" in workflow
    assert "node --check" in workflow
    assert "git ls-files -z -- '*.js'" in workflow
    assert "docker build" not in workflow
    assert "docker run" not in workflow
