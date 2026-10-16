"""Deterministic, standard-library generative checks for safety boundaries.

The generators intentionally use fixed ``random.Random`` seeds rather than a
property-testing dependency.  This keeps the suite offline and makes a failed
case reproducible from the test source alone.
"""

from pathlib import Path
import random

import pytest

from worksonmymachine import apt_healer, scanner
from worksonmymachine.apt_healer import heal_dockerfile, parse_compiler_log
from worksonmymachine.models import FileHashNode
from worksonmymachine.repro_hash import compute_merkle_root


def _safe_component(rng: random.Random) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 10)))


def test_generated_paths_normalize_to_project_relative_values() -> None:
    rng = random.Random(18_01)

    for _ in range(96):
        user = _safe_component(rng)
        parts = [_safe_component(rng) for _ in range(rng.randint(1, 4))]
        relative = "/".join(parts)
        candidates = (
            relative.replace("/", "\\"),
            f"/home/{user}/{relative}".replace("/", "\\"),
            f"/Users/{user}/{relative}",
            f"C:\\Users\\{user}\\{relative.replace('/', chr(92))}",
        )

        for candidate in candidates:
            normalized = scanner._normalise_path_value(candidate)

            assert normalized
            assert "\\" not in normalized
            assert not normalized.startswith("/")
            assert scanner._normalise_path_value(normalized) == normalized


def test_generated_staged_paths_cannot_escape_target_root(tmp_path: Path) -> None:
    rng = random.Random(18_02)
    target = tmp_path / "target"
    target.mkdir()

    for _ in range(80):
        components = [_safe_component(rng) for _ in range(rng.randint(1, 4))]
        safe = "/".join(components)
        resolved = scanner._safe_target_path(target, safe)
        assert resolved == target.joinpath(*components)

        unsafe_values = [
            f"{safe}/../outside.txt",
            f"{safe}/./file.txt",
            f"{safe}//file.txt",
            f"../{safe}",
            f"{safe}/file.txt:stream",
        ]
        if "/" in safe:
            unsafe_values.append(safe.replace("/", "\\"))
        for unsafe in unsafe_values:
            with pytest.raises(scanner.HealingConflictError):
                scanner._safe_target_path(target, unsafe)


def test_generated_output_containment_rejects_both_sides_of_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "container" / "target"
    target.mkdir(parents=True)

    rejected = [
        target,
        target / "nested",
        target / "nested" / "staging",
        target.parent,
        target.parent.parent,
    ]
    for output in rejected:
        with pytest.raises(ValueError):
            apt_healer._safe_output(target, output)

    for index in range(24):
        sibling = target.parent / f"output-{index}"
        assert apt_healer._safe_output(target, sibling) == sibling


def test_generated_malformed_compiler_logs_are_total_and_deterministic() -> None:
    rng = random.Random(18_03)
    alphabet = " \t\r\n\x00[]{}()<>/\\:'\";=+-_"
    fragments = (
        "fatal error: Python.h: No such file or directory\n",
        "gcc: command not found\n",
        "npm ERR! sharp native build failed\n",
        "unterminated 'quote\n",
        "\x00\xff\ufffd\n",
    )
    inputs: list[object] = [None, 0, b"\x00\xff"]
    for _ in range(128):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 240)))
        if rng.random() < 0.45:
            text += rng.choice(fragments)
        inputs.append(text)

    for value in inputs:
        first = parse_compiler_log(value)  # type: ignore[arg-type]
        second = parse_compiler_log(value)  # type: ignore[arg-type]

        assert first == second
        for diagnostic in first:
            assert diagnostic.tool
            assert diagnostic.line_number is None or diagnostic.line_number >= 1
            assert 0.0 <= diagnostic.confidence <= 1.0
            assert diagnostic.raw_output == str(value or "")


def test_generated_merkle_inputs_are_order_independent() -> None:
    rng = random.Random(18_04)
    nodes = [
        FileHashNode(
            path=f"{_safe_component(rng)}/{_safe_component(rng)}.txt",
            digest=f"{rng.getrandbits(256):064x}",
            size_bytes=rng.randint(0, 4096),
        )
        for _ in range(48)
    ]
    expected = compute_merkle_root(nodes)

    for _ in range(96):
        shuffled = list(nodes)
        rng.shuffle(shuffled)
        assert compute_merkle_root(shuffled) == expected


def test_generated_docker_repairs_have_stable_unified_diffs(tmp_path: Path) -> None:
    rng = random.Random(18_05)
    images = (
        "python:latest",
        "python:3.11",
        "rust:latest",
        "node:latest",
        "ubuntu:latest",
        "alpine:latest",
    )

    for index in range(16):
        target = tmp_path / f"target-{index}"
        target.mkdir()
        image = rng.choice(images)
        dockerfile = (
            f"FROM {image}\n"
            "WORKDIR /app\n"
            "RUN pip install -r requirements.txt\n"
        )
        (target / "Dockerfile.broken").write_text(dockerfile, encoding="utf-8")
        (target / "build_error.log").write_text(
            "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
        )

        first = heal_dockerfile(target, tmp_path / f"output-{index}-a")
        second = heal_dockerfile(target, tmp_path / f"output-{index}-b")

        assert first.before_content == second.before_content
        assert first.after_content == second.after_content
        assert first.unified_diff == second.unified_diff
        assert first.unified_diff == first.diff
        assert first.changes == second.changes
        assert first.packages == second.packages
        assert first.install_command == second.install_command


def _stage_fixture(
    left_image: str,
    right_image: str,
    left_tool: str,
    right_tool: str,
) -> list[str]:
    return [
        f"FROM {left_image} AS left\n",
        f"RUN {left_tool}\n",
        f"FROM {right_image} AS right\n",
        f"RUN {right_tool}\n",
    ]


def test_generated_mixed_docker_stages_refuse_equal_tooling_ambiguity() -> None:
    rng = random.Random(18_06)
    images = {
        "debian": ("python:3.11-slim", "ubuntu:24.04"),
        "alpine": ("alpine:3.20", "python:3.11-alpine3.20"),
        "fedora": ("fedora:40", "ubi9"),
    }
    distro_pairs = (
        ("debian", "alpine"),
        ("debian", "fedora"),
        ("alpine", "fedora"),
    )
    tools = ("pip install package", "cargo build", "npm install")

    for _ in range(64):
        left_distro, right_distro = rng.choice(distro_pairs)
        left_image = rng.choice(images[left_distro])
        right_image = rng.choice(images[right_distro])
        tool = rng.choice(tools)
        lines = _stage_fixture(left_image, right_image, tool, tool)

        stages = apt_healer._docker_stages(lines)
        assert len(stages) == 2
        assert apt_healer._select_package_stage(lines) is None


def test_generated_ambiguous_docker_stages_are_not_package_modified(
    tmp_path: Path,
) -> None:
    rng = random.Random(18_08)
    images = (
        ("python:3.11-slim", "alpine:3.20"),
        ("ubuntu:24.04", "fedora:40"),
        ("alpine:3.20", "ubi9"),
    )
    tools = ("pip install package", "cargo build", "npm install")

    for index in range(24):
        left_image, right_image = rng.choice(images)
        tool = rng.choice(tools)
        lines = _stage_fixture(left_image, right_image, tool, tool)
        target = tmp_path / f"ambiguous-{index}"
        target.mkdir()
        before = "".join(lines)
        (target / "Dockerfile.broken").write_text(before, encoding="utf-8")
        (target / "build_error.log").write_text(
            "fatal error: Python.h: No such file or directory\n", encoding="utf-8"
        )

        result = heal_dockerfile(target, tmp_path / f"ambiguous-output-{index}")

        assert result.package_manager is None
        assert result.packages == []
        assert not any(
            command in result.after_content
            for command in ("apt-get install", "apk add", "dnf install")
        )
        assert result.after_content.count(f"RUN {tool}") == 2


def test_generated_stage_selection_only_chooses_a_unique_best_stage() -> None:
    rng = random.Random(18_07)
    images = (
        ("python:3.11-slim", "alpine:3.20"),
        ("ubuntu:24.04", "fedora:40"),
        ("alpine:3.20", "ubi9"),
    )
    strong_tools = ("pip install package", "cargo build", "npm install")

    for _ in range(64):
        left_image, right_image = rng.choice(images)
        lines = _stage_fixture(
            left_image,
            right_image,
            rng.choice(strong_tools),
            "make",
        )
        selected = apt_healer._select_package_stage(lines)

        assert selected is not None
        assert selected.alias == "left"
        assert selected.start == 0
        assert selected.end == 1
