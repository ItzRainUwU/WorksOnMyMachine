from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTION_FILE = PROJECT_ROOT / "action.yml"


def test_github_action_metadata_declares_inputs_outputs_and_python_setup() -> None:
    action = ACTION_FILE.read_text(encoding="utf-8")

    assert "name: WorksOnMyMachine" in action
    assert "using: composite" in action
    assert "uses: actions/setup-python@v5" in action
    assert "python-version: '3.11'" in action
    assert 'python -m pip install --disable-pip-version-check "${{ github.action_path }}"' in action

    for input_name in (
        "target:",
        "fail-on:",
        "min-readiness:",
        "new-only:",
        "baseline:",
        "output:",
        "sarif-path:",
    ):
        assert input_name in action

    assert "report-path:" in action
    assert "value: ${{ steps.check.outputs.report-path }}" in action


def test_github_action_uses_the_caller_root_and_emits_sarif() -> None:
    action = ACTION_FILE.read_text(encoding="utf-8")

    assert "WORKSPACE_ROOT: ${{ github.workspace }}" in action
    assert "args=(check \"${TARGET}\" --root \"${WORKSPACE_ROOT}\"" in action
    assert "--format sarif --output \"${report_path}\"" in action
    assert "args+=(--fail-on \"${FAIL_ON}\")" in action
    assert "args+=(--min-readiness \"${MIN_READINESS}\")" in action
    assert "args+=(--baseline \"${BASELINE}\")" in action
    assert "args+=(--new-only)" in action
    assert 'printf \'report-path=%s\\n\' "${report_path}" >> "${GITHUB_OUTPUT}"' in action
    assert 'status=$?' in action
    assert 'exit "${status}"' in action
    assert "--auto-heal" not in action
