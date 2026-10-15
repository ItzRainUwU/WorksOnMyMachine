"""Offline-first compiler-log analysis and copy-on-write Dockerfile healing.

The parser in this module is deliberately rule based.  Build logs are often
produced in environments where a network call is the thing that already
failed, so the local result is complete without an LLM.  A bounded,
OpenAI-compatible request is available only when ``LLM_API_KEY`` is present
and is treated as optional context rather than as the source of package
recommendations.
"""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile
from dataclasses import dataclass

from .models import (
    CompilerDiagnostic,
    DockerfilePatchResult,
    HybridAnalysisResult,
    SeverityLevel,
)


_FIXED_BASE_IMAGE = "python:3.11.9-slim"
_APT_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_SHELL_REFERENCE = re.compile(
    r"(?P<path>(?:/|\.\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.sh)"
)


@dataclass(frozen=True)
class _DiagnosticRule:
    signature: str
    artifact: str
    packages: tuple[str, ...]
    pattern: re.Pattern[str]
    explanation: str
    tool: str
    confidence: float
    severity: SeverityLevel = SeverityLevel.HIGH


def _rule(
    signature: str,
    artifact: str,
    packages: tuple[str, ...],
    pattern: str,
    explanation: str,
    tool: str,
    confidence: float = 0.98,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> _DiagnosticRule:
    return _DiagnosticRule(
        signature=signature,
        artifact=artifact,
        packages=packages,
        pattern=re.compile(pattern, re.IGNORECASE),
        explanation=explanation,
        tool=tool,
        confidence=confidence,
        severity=severity,
    )


_RULES: tuple[_DiagnosticRule, ...] = (
    _rule(
        "missing-python-header",
        "Python.h",
        ("build-essential", "python3-dev"),
        r"\bpython\.h\b",
        "A Python extension is being compiled without the CPython development header.",
        "gcc",
    ),
    _rule(
        "missing-postgresql-development-files",
        "pg_config/libpq-fe.h",
        ("gcc", "libpq-dev"),
        r"(?:\bpg_config\b.*(?:not found|executable|missing|required)|\blibpq-fe\.h\b|"
        r"psycopg2.*(?:source|pg_config))",
        "The PostgreSQL client development files are absent, so a psycopg2 or similar extension cannot compile.",
        "pip",
    ),
    _rule(
        "missing-libgl-runtime",
        "libGL.so.1",
        ("libgl1", "libglib2.0-0"),
        r"\blibgl\.so\.1\b",
        "The image lacks the runtime OpenGL library required by a computer-vision dependency.",
        "runtime",
    ),
    _rule(
        "missing-libffi-development-files",
        "ffi.h/libffi",
        ("libffi-dev", "pkg-config"),
        r"(?:\bffi\.h\b|\blibffi\b|-lffi\b)",
        "A native extension or bindgen build needs libffi headers, which are not installed in the image.",
        "gcc",
    ),
    _rule(
        "missing-openssl-development-files",
        "openssl/ssl.h",
        ("libssl-dev", "pkg-config"),
        r"(?:\bopenssl/ssl\.h\b|\bopenssl-sys\b|\bopenssl_dir\b|"
        r"(?:package|library)\s+openssl\b|\bopenssl\b.*(?:header|missing|"
         r"not found|development)|could not find directory of openssl)",
        "OpenSSL headers and pkg-config metadata are missing while compiling an OpenSSL-backed extension.",
        "cargo",
    ),
    _rule(
        "missing-rust-toolchain",
        "Cargo/Rust",
        ("cargo", "rustc"),
        r"(?:cargo|rustc).*(?:not found|not installed|not available|no such file)|"
        r"cargo,?\s+the\s+rust\s+package\s+manager,?\s+is\s+not\s+installed|"
        r"could not find cargo|no such command.*\bcargo\b|cannot find cargo",
        "The target builds Rust code but the Cargo and rustc toolchain is not available in the image.",
        "cargo",
        0.99,
        SeverityLevel.CRITICAL,
    ),
    _rule(
        "missing-gcc",
        "gcc",
        ("build-essential", "g++", "gcc"),
        r"(?:command\s+['\"]?gcc['\"]?\s+failed|\bgcc\s*:\s*(?:command\s+)?"
        r"(?:not found|no such file|not installed)|(?:\bgcc\b|/usr/bin/cc\b|"
        r"x86_64-linux-gnu-gcc\b).*?(?:failed|"
        r"not found|no such file|not installed))",
        "A native dependency is compiling C code but the GNU C compiler is not installed.",
        "gcc",
        0.96,
    ),
    _rule(
        "missing-mysql-development-config",
        "mysql_config",
        ("default-libmysqlclient-dev", "pkg-config"),
        r"\bmysql_config\b.*(?:not found|executable|missing)",
        "The MySQL client development package, including mysql_config, is absent.",
        "pip",
    ),
    _rule(
        "missing-cmake",
        "cmake",
        ("cmake",),
        r"\bcmake\b.*(?:not found|missing|could not find|command .*failed|required|"
        r"not installed|must be installed)",
        "The build invokes CMake but the CMake executable is unavailable.",
        "cmake",
    ),
    _rule(
        "missing-libxml-development-files",
        "libxml/xmlversion.h/xmlsec1",
        ("libxml2-dev", "libxmlsec1-dev", "libxslt1-dev"),
        r"(?:\blibxml/xmlversion\.h\b|\bxmlversion\.h\b|\bxmlsec1\b)",
        "XML or XML security bindings are compiling without libxml2 and xmlsec1 development headers.",
        "gcc",
    ),
    _rule(
        "missing-portaudio-development-files",
        "portaudio.h",
        ("portaudio19-dev",),
        r"(?:\bportaudio\.h\b|\bportaudio\b.*(?:not found|missing))",
        "An audio extension needs PortAudio headers, which are missing from the image.",
        "gcc",
    ),
    _rule(
        "missing-libsndfile-development-files",
        "sndfile.h",
        ("libsndfile1-dev",),
        r"(?:\bsndfile\.h\b|\blibsndfile\b.*(?:not found|missing))",
        "An audio extension needs libsndfile headers, which are missing from the image.",
        "gcc",
    ),
)


def _normalise_packages(packages: object) -> list[str]:
    """Return valid Debian package tokens in deterministic order."""

    if isinstance(packages, str):
        values = packages.split()
    elif isinstance(packages, (list, tuple, set)):
        values = list(packages)
    elif packages is not None and not isinstance(packages, (bytes, dict)):
        try:
            values = list(packages)  # type: ignore[arg-type]
        except TypeError:
            values = []
    else:
        values = []
    return sorted(
        {
            str(package).strip()
            for package in values
            if str(package).strip() and _APT_PACKAGE.fullmatch(str(package).strip())
        }
    )


def _matched_line(log_text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    """Find the first useful evidence line for a rule."""

    for number, line in enumerate(log_text.splitlines(), 1):
        if pattern.search(line):
            return line.strip(), number
    return log_text.strip().splitlines()[0][:500], 1


def parse_compiler_log(log_text: str) -> list[CompilerDiagnostic]:
    """Parse common native-build failures without executing or fetching anything."""

    text = str(log_text or "")
    if not text.strip():
        return []
    diagnostics: list[CompilerDiagnostic] = []
    for rule in _RULES:
        if not rule.pattern.search(text):
            continue
        message, line_number = _matched_line(text, rule.pattern)
        diagnostics.append(
            CompilerDiagnostic(
                tool=rule.tool,
                message=message or rule.explanation,
                severity=rule.severity,
                line_number=line_number,
                code=rule.signature,
                raw_output=text,
                error_signature=message,
                missing_artifact=rule.artifact,
                recommended_apt_packages=list(rule.packages),
                root_cause_explanation=rule.explanation,
                confidence=rule.confidence,
            )
        )
    return sorted(
        diagnostics,
        key=lambda diagnostic: (
            diagnostic.line_number or 0,
            diagnostic.error_signature,
        ),
    )


def _deterministic_root_cause(diagnostics: list[CompilerDiagnostic]) -> str:
    if not diagnostics:
        return "No recognized compiler or native-package failure was found in the log."
    explanations = sorted(
        {diagnostic.root_cause_explanation for diagnostic in diagnostics if diagnostic.root_cause_explanation}
    )
    return " ".join(explanations)


def _llm_analysis(log_text: str) -> tuple[bool, str | None, list[str]]:
    """Optionally ask an OpenAI-compatible endpoint for explanatory context."""

    api_key = os.environ.get("LLM_API_KEY", "").strip()
    if not api_key:
        return False, None, []
    try:
        import httpx

        base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        endpoint = (
            base_url
            if base_url.endswith("/chat/completions")
            else f"{base_url}/chat/completions"
        )
        prompt = (
            "Analyze this build log as optional context. Return JSON with only "
            "root_cause_summary (string) and apt_packages (array of Debian package "
            "names). Do not invent packages when the evidence is weak.\n\n"
            + str(log_text or "")[:12000]
        )
        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                endpoint,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": os.environ.get("LLM_MODEL", "gpt-4o-mini"),
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": "You are a build diagnostics assistant."},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            response.raise_for_status()
            body = response.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not isinstance(content, str):
            return True, None, []
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content, flags=re.IGNORECASE)
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return True, None, []
        summary = parsed.get("root_cause_summary")
        if not isinstance(summary, str) or not summary.strip():
            summary = None
        packages = _normalise_packages(parsed.get("apt_packages", []))
        return True, summary.strip() if summary else None, packages
    except Exception:
        # An unavailable optional provider must never turn local diagnostics into
        # an unavailable API response.
        return False, None, []


def analyze_log_hybrid(log_text: str) -> HybridAnalysisResult:
    """Return deterministic diagnostics and optional LLM-enriched context."""

    diagnostics = parse_compiler_log(log_text)
    packages = _normalise_packages(
        package
        for diagnostic in diagnostics
        for package in diagnostic.recommended_apt_packages
    )
    summary = _deterministic_root_cause(diagnostics)
    llm_used, llm_summary, llm_packages = _llm_analysis(log_text)
    if llm_summary:
        summary = llm_summary
    packages = _normalise_packages([*packages, *llm_packages])
    return HybridAnalysisResult(
        diagnostics=diagnostics,
        apt_packages=packages,
        recommended_apt_packages=packages,
        root_cause_summary=summary,
        llm_used=llm_used,
    )


def _copy_target(target: Path, output: Path) -> None:
    if output.is_dir():
        shutil.rmtree(output)
    elif output.exists() or output.is_symlink():
        output.unlink()
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(target, output)


def _safe_output(target: Path, output_path: Path | None) -> Path:
    target_resolved = target.resolve()
    output = (
        Path(output_path)
        if output_path is not None
        else Path(tempfile.mkdtemp(prefix="worksonmymachine-docker-healed-"))
    )
    output_resolved = output.resolve()
    try:
        common = os.path.commonpath([str(target_resolved), str(output_resolved)])
    except ValueError:
        common = ""
    if output_resolved == target_resolved or common == str(target_resolved):
        raise ValueError("output_path must not be the target or one of its descendants")
    try:
        target_resolved.relative_to(output_resolved)
    except ValueError:
        pass
    else:
        raise ValueError("output_path must not contain the target directory")
    return output


def _dockerfile_path(target: Path) -> Path:
    broken = target / "Dockerfile.broken"
    if broken.is_file():
        return broken
    regular = target / "Dockerfile"
    if regular.is_file():
        return regular
    raise ValueError("target_path does not contain Dockerfile or Dockerfile.broken")


def _pin_base_images(lines: list[str]) -> tuple[list[str], bool]:
    output: list[str] = []
    changed = False
    from_pattern = re.compile(
        r"^(?P<indent>\s*FROM\s+)(?P<prefix>(?:--platform=\S+\s+)?)(?P<image>\S+)(?P<tail>.*)$",
        re.IGNORECASE,
    )
    for line in lines:
        newline = "\n" if line.endswith("\n") else ""
        content = line[:-1] if newline else line
        match = from_pattern.match(content)
        if match is None:
            output.append(line)
            continue
        image = match.group("image")
        if "@" in image:
            output.append(line)
            continue
        last_part = image.rsplit("/", 1)[-1]
        if ":" in last_part:
            tag = last_part.rsplit(":", 1)[1]
        else:
            tag = ""
        floating = not tag or tag.lower() in {"latest", "stable"}
        if last_part.lower().startswith("python:") and not re.search(r"\d+\.\d+\.\d+", tag):
            floating = True
        if not floating:
            output.append(line)
            continue
        replacement = (
            f"{match.group('indent')}{match.group('prefix')}{_FIXED_BASE_IMAGE}"
            f"{match.group('tail')}{newline}"
        )
        output.append(replacement)
        changed = True
    return output, changed


def _apt_blocks(lines: list[str]) -> list[tuple[int, int, set[str]]]:
    blocks: list[tuple[int, int, set[str]]] = []
    index = 0
    while index < len(lines):
        if (
            lines[index].lstrip().startswith("#")
            or "apt-get" not in lines[index].lower()
            or "install" not in lines[index].lower()
        ):
            index += 1
            continue
        end = index
        while lines[end].rstrip().endswith("\\") and end + 1 < len(lines):
            end += 1
        joined = " ".join(lines[index : end + 1]).replace("\\", " ")
        match = re.search(r"apt-get\s+install\b(?P<body>.*?)(?:&&|$)", joined, re.IGNORECASE)
        packages: set[str] = set()
        if match:
            try:
                tokens = shlex.split(match.group("body"))
            except ValueError:
                tokens = match.group("body").split()
            packages.update(
                token
                for token in tokens
                if _APT_PACKAGE.fullmatch(token) and not token.startswith("-")
            )
        blocks.append((index, end, packages))
        index = end + 1
    return blocks


def _render_apt_layer(packages: list[str]) -> list[str]:
    if not packages:
        return []
    rendered = ["RUN apt-get update && apt-get install -y --no-install-recommends \\\n"]
    for package in packages:
        rendered.append(f"    {package} \\\n")
    rendered.append("    && rm -rf /var/lib/apt/lists/*\n")
    return rendered


def _install_anchor(lines: list[str]) -> int:
    for index, line in enumerate(lines):
        if re.match(r"\s*RUN\b", line, re.IGNORECASE) and re.search(
            r"\b(?:pip(?:3)?|cargo)\b", line, re.IGNORECASE
        ):
            return index
    for index, line in enumerate(lines):
        if re.match(r"\s*WORKDIR\b", line, re.IGNORECASE):
            return index + 1
    return 1 if lines else 0


def _inject_apt_layer(lines: list[str], packages: list[str]) -> tuple[list[str], bool]:
    blocks = _apt_blocks(lines)
    existing = set().union(*(block[2] for block in blocks)) if blocks else set()
    combined = _normalise_packages([*existing, *packages])
    if not combined:
        return lines, False
    if blocks:
        removed: list[str] = []
        block_starts = {index for index, _end, _packages in blocks}
        block_ends = {end for _index, end, _packages in blocks}
        index = 0
        while index < len(lines):
            if index in block_starts:
                end = next(end for start, end, _packages in blocks if start == index)
                index = end + 1
                continue
            removed.append(lines[index])
            index += 1
        lines = removed
    anchor = _install_anchor(lines)
    lines[anchor:anchor] = _render_apt_layer(combined)
    return lines, True


def _chmod_shell_entrypoints(lines: list[str]) -> tuple[list[str], bool, list[str]]:
    references: list[str] = []
    for line in lines:
        if re.match(r"\s*(?:ENTRYPOINT|CMD)\b", line, re.IGNORECASE):
            references.extend(match.group("path") for match in _SHELL_REFERENCE.finditer(line))
        elif re.match(r"\s*COPY\b", line, re.IGNORECASE) and ".sh" in line.lower():
            copied = [match.group("path") for match in _SHELL_REFERENCE.finditer(line)]
            if copied:
                references.append(copied[-1])
    references = sorted(set(references))
    if not references:
        return lines, False, []
    chmod_lines = [line for line in lines if re.search(r"\bchmod\s+[^#\n]*\+x", line)]

    def covered(reference: str) -> bool:
        normalized = reference.removeprefix("./")
        basename = Path(normalized).name
        return any(
            "*.sh" in line or normalized in line or basename in line for line in chmod_lines
        )

    missing = [reference for reference in references if not covered(reference)]
    if not missing:
        return lines, False, []
    output: list[str] = []
    inserted = False
    for line in lines:
        if not inserted and re.match(r"\s*(?:ENTRYPOINT|CMD)\b", line, re.IGNORECASE):
            output.extend(f"RUN chmod +x {reference}\n" for reference in missing)
            inserted = True
        output.append(line)
    if not inserted:
        output.extend(f"RUN chmod +x {reference}\n" for reference in missing)
    return output, True, missing


def _enforce_appuser(lines: list[str]) -> tuple[list[str], bool]:
    if any(re.match(r"\s*USER\s+appuser\b", line, re.IGNORECASE) for line in lines):
        return lines, False
    workdir = "/app"
    for line in lines:
        match = re.match(r"\s*WORKDIR\s+(\S+)", line, re.IGNORECASE)
        if match:
            workdir = match.group(1)
    setup = [
        "RUN useradd -m -u 10001 appuser && "
        f"chown -R appuser:appuser {workdir}\n",
        "USER appuser\n",
    ]
    output: list[str] = []
    inserted = False
    for line in lines:
        if not inserted and re.match(r"\s*(?:ENTRYPOINT|CMD)\b", line, re.IGNORECASE):
            output.extend(setup)
            inserted = True
        output.append(line)
    if not inserted:
        output.extend(setup)
    return output, True


def _native_and_rust_packages(
    log_text: str, dockerfile: str, target: Path | None = None
) -> set[str]:
    combined = f"{log_text}\n{dockerfile}".lower()
    source_indicators: list[str] = []
    if target is not None:
        try:
            source_indicators = [
                path.name.lower()
                for path in target.rglob("*")
                if path.is_file()
            ]
        except OSError:
            source_indicators = []
    packages: set[str] = set()
    rust_indicator = bool(
        re.search(r"(?:\bcargo\b|\brustc\b|cargo\.toml|\.rs\b|\bfrom\s+rust)", combined)
        or any(name in {"cargo.toml", "build.rs"} or name.endswith(".rs") for name in source_indicators)
    )
    if rust_indicator:
        packages.update({"cargo", "rustc"})
    native_indicator = bool(
        re.search(
            r"(?:native extension|build wheels|bindgen|\bcompiler\b|\bbuilding wheel|"
            r"\b/usr/bin/cc\b|\bgcc\b|\b\.h\b)",
            combined,
        )
        or any(
            name.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"))
            for name in source_indicators
        )
    )
    if native_indicator:
        packages.add("gcc")
    return packages


def _write_staged_entrypoint_modes(output: Path) -> None:
    for path in output.rglob("*.sh"):
        try:
            path.chmod(path.stat().st_mode | 0o111)
        except OSError:
            continue


def heal_dockerfile(target_path: Path, output_path: Path | None = None) -> DockerfilePatchResult:
    """Copy a target and apply a deterministic Dockerfile-only build repair."""

    target = Path(target_path)
    if not target.is_dir():
        raise ValueError("target_path must be a directory")
    dockerfile = _dockerfile_path(target)
    output = _safe_output(target, output_path)
    _copy_target(target, output)
    staged_dockerfile = output / dockerfile.relative_to(target)
    before = staged_dockerfile.read_text(encoding="utf-8")
    log_path = target / "build_error.log"
    log_text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
    analysis = analyze_log_hybrid(log_text)
    packages = set(analysis.apt_packages)
    packages.update(_native_and_rust_packages(log_text, before, target))

    lines = before.splitlines(keepends=True)
    lines, base_changed = _pin_base_images(lines)
    lines, apt_changed = _inject_apt_layer(lines, _normalise_packages(packages))
    lines, chmod_changed, chmod_refs = _chmod_shell_entrypoints(lines)
    lines, user_changed = _enforce_appuser(lines)
    after = "".join(lines)
    staged_dockerfile.write_text(after, encoding="utf-8", newline="")
    _write_staged_entrypoint_modes(output)

    source_path = dockerfile.relative_to(target).as_posix()
    unified_diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{source_path}",
            tofile=f"b/{source_path}",
        )
    )
    changes: list[str] = []
    security_fixes: list[str] = []
    if base_changed:
        changes.append(f"pin floating base image to {_FIXED_BASE_IMAGE}")
        security_fixes.append(f"pinned floating base image to {_FIXED_BASE_IMAGE}")
    if apt_changed:
        changes.append(f"install apt packages: {', '.join(_normalise_packages(packages))}")
        security_fixes.append("clean apt package lists in the deterministic install layer")
    if chmod_changed:
        changes.append("ensure executable shell entrypoints: " + ", ".join(chmod_refs))
        security_fixes.append("shell entrypoints are explicitly executable")
    if user_changed:
        changes.append("create and select non-root appuser")
        security_fixes.append("run the application as non-root appuser")
    if after != before and not changes:
        changes.append("apply deterministic Dockerfile repair")
    return DockerfilePatchResult(
        source_path=source_path,
        patched_content=after,
        changes=changes,
        applied=True,
        confidence=0.99 if analysis.diagnostics else 0.9,
        before_content=before,
        after_content=after,
        unified_diff=unified_diff,
        apt_packages=_normalise_packages(packages),
        security_fixes=sorted(set(security_fixes)),
        staged_output_path=str(output),
    )


__all__ = [
    "analyze_log_hybrid",
    "heal_dockerfile",
    "parse_compiler_log",
]
