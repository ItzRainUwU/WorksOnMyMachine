"""Offline structural checks for the copy-ready CI templates."""

from pathlib import Path


CI_ROOT = Path(__file__).resolve().parents[1] / "docs" / "ci"


def test_all_requested_ci_templates_exist() -> None:
    for name in (
        "gitlab-ci.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        "buildkite.pipeline.yml",
        "shell-ci.sh",
    ):
        assert (CI_ROOT / name).is_file()


def test_ci_templates_pin_runtime_and_locked_dependencies() -> None:
    for path in CI_ROOT.iterdir():
        if path.name in {"README.md"}:
            continue
        content = path.read_text(encoding="utf-8")
        assert "3.11.9" in content
        assert "requirements.lock" in content
        assert "pytest" in content


def test_ci_templates_do_not_require_docker_for_offline_tests() -> None:
    for name in (
        "gitlab-ci.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        "buildkite.pipeline.yml",
        "shell-ci.sh",
    ):
        content = (CI_ROOT / name).read_text(encoding="utf-8").lower()
        assert "docker build" not in content
        assert "docker run" not in content
