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


# Keep this policy explicit and local to Dockerfile healing.  These tags are
# deterministic release tags for the supported official images; they are not
# inferred from a build log or replaced with a cross-runtime fallback.
_RUNTIME_BASE_IMAGES: dict[str, tuple[str, str]] = {
    "python": ("debian", "python:3.11.9-slim"),
    "rust": ("debian", "rust:1.85-slim-bookworm"),
    "node": ("debian", "node:22-bookworm-slim"),
    "ubuntu": ("debian", "ubuntu:24.04"),
    "alpine": ("alpine", "alpine:3.20"),
}
# Retain the old private constant for callers that imported it while making
# Python's policy entry the source of truth for new healing behavior.
_FIXED_BASE_IMAGE = _RUNTIME_BASE_IMAGES["python"][1]
_APT_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_PACKAGE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:@/-]*$")
_SHELL_REFERENCE = re.compile(
    r"(?P<path>(?:/|\.\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.sh)"
)

# Build logs are evidence, not a safe place to preserve the original bytes.
# Keep this redaction policy local and deterministic so parser/API callers get
# the same treatment without depending on a network provider or a scanner.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:[a-z_][a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|signing[_-]?key)[a-z0-9_.-]*|password|passwd|"
    r"secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|"
    r"credential|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"signing[_-]?key)\b\s*(?:=|:)(?:\s*bearer\s+)?)([^\s,;]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)(\bbearer\s+)([^\s,;]+)")
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_KNOWN_PROVIDER_TOKEN = re.compile(
    r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
    r"|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{20,}\b"
    r"|\bAIza[A-Za-z0-9_-]{30,}\b"
    r"|\bnpm_[A-Za-z0-9]{30,}\b"
    r"|\b(?:hf|r8|vercel)_[A-Za-z0-9_]{20,}\b"
    r"|\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"
    r"|\b(?:glpat-|dckr_pat_|dop_v1_|pypi-|sbp_|lin_api_)[A-Za-z0-9_-]{20,}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_REDACTED_PRIVATE_KEY = "[REDACTED PRIVATE KEY]"
_REDACTED_SECRET = "[REDACTED]"
_TRUNCATION_MARKER = "\n...[truncated]"
MAX_DIAGNOSTIC_OUTPUT = 12_000
MAX_DIAGNOSTIC_LINE = 500


def redact_sensitive_text(value: object, limit: int | None = None) -> str:
    """Redact common credentials while retaining bounded diagnostic context."""

    text = str(value or "")
    if limit is not None and limit <= 0:
        return ""
    text = _PEM_PRIVATE_KEY.sub(_REDACTED_PRIVATE_KEY, text)
    text = _SECRET_ASSIGNMENT.sub(r"\1" + _REDACTED_SECRET, text)
    text = _BEARER_TOKEN.sub(r"\1" + _REDACTED_SECRET, text)
    text = _KNOWN_PROVIDER_TOKEN.sub(_REDACTED_SECRET, text)
    if limit is not None and len(text) > limit:
        marker = _TRUNCATION_MARKER
        available = max(0, limit - len(marker))
        head = (available + 1) // 2
        tail = available - head
        text = text[:head] + marker + (text[-tail:] if tail else "")
    return text
# ``apt_packages`` is retained as the stable, Debian-oriented vocabulary used
# by the parser and existing API clients.  Dockerfile healing translates that
# vocabulary only when the base image gives us a supported package ecosystem.
# Keeping this table explicit is intentional: a package that is not listed is
# skipped on a non-Debian image instead of being guessed from a similar name.
_PACKAGE_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "build-essential": {
        "apt": ("build-essential",),
        "apk": ("build-base",),
        "dnf": ("gcc", "gcc-c++", "make"),
    },
    "python3-dev": {
        "apt": ("python3-dev",),
        "apk": ("python3-dev",),
        "dnf": ("python3-devel",),
    },
    "gcc": {"apt": ("gcc",), "apk": ("gcc",), "dnf": ("gcc",)},
    "g++": {"apt": ("g++",), "apk": ("g++",), "dnf": ("gcc-c++",)},
    "libpq-dev": {
        "apt": ("libpq-dev",),
        "apk": ("postgresql-dev",),
        "dnf": ("libpq-devel",),
    },
    "libgl1": {
        "apt": ("libgl1",),
        "apk": ("mesa-gl",),
        "dnf": ("mesa-libGL",),
    },
    "libglib2.0-0": {
        "apt": ("libglib2.0-0",),
        "apk": ("glib",),
        "dnf": ("glib2",),
    },
    "libffi-dev": {
        "apt": ("libffi-dev",),
        "apk": ("libffi-dev",),
        "dnf": ("libffi-devel",),
    },
    "pkg-config": {
        "apt": ("pkg-config",),
        "apk": ("pkgconf",),
        "dnf": ("pkgconf-pkg-config",),
    },
    "libssl-dev": {
        "apt": ("libssl-dev",),
        "apk": ("openssl-dev",),
        "dnf": ("openssl-devel",),
    },
    "cargo": {"apt": ("cargo",), "apk": ("cargo",), "dnf": ("cargo",)},
    "rustc": {"apt": ("rustc",), "apk": ("rust",), "dnf": ("rust",)},
    "default-libmysqlclient-dev": {
        "apt": ("default-libmysqlclient-dev",),
        "apk": ("mariadb-dev",),
        "dnf": ("mariadb-connector-c-devel",),
    },
    "cmake": {"apt": ("cmake",), "apk": ("cmake",), "dnf": ("cmake",)},
    "libxml2-dev": {
        "apt": ("libxml2-dev",),
        "apk": ("libxml2-dev",),
        "dnf": ("libxml2-devel",),
    },
    "libxmlsec1-dev": {
        "apt": ("libxmlsec1-dev",),
        "apk": ("xmlsec-dev",),
        "dnf": ("xmlsec1-devel",),
    },
    "libxslt1-dev": {
        "apt": ("libxslt1-dev",),
        "apk": ("libxslt-dev",),
        "dnf": ("libxslt-devel",),
    },
    "portaudio19-dev": {
        "apt": ("portaudio19-dev",),
        "apk": ("portaudio-dev",),
        "dnf": ("portaudio-devel",),
    },
    "libsndfile1-dev": {
        "apt": ("libsndfile1-dev",),
        "apk": ("libsndfile-dev",),
        "dnf": ("libsndfile-devel",),
    },
    "libvips-dev": {
        "apt": ("libvips-dev",),
        "apk": ("vips-dev",),
        "dnf": ("vips-devel",),
    },
    "libcairo2-dev": {
        "apt": ("libcairo2-dev",),
        "apk": ("cairo-dev",),
        "dnf": ("cairo-devel",),
    },
    "libpango1.0-dev": {
        "apt": ("libpango1.0-dev",),
        "apk": ("pango-dev",),
        "dnf": ("pango-devel",),
    },
    "libgif-dev": {
        "apt": ("libgif-dev",),
        "apk": ("giflib-dev",),
        "dnf": ("giflib-devel",),
    },
    "python3": {
        "apt": ("python3",),
        "apk": ("python3",),
        "dnf": ("python3",),
    },
    "make": {
        "apt": ("make",),
        "apk": ("make",),
        "dnf": ("make",),
    },
}

_DISTRO_TO_MANAGER = {"debian": "apt", "alpine": "apk", "fedora": "dnf"}


def _redact_sensitive_output(value: object) -> str:
    """Redact likely credentials before compiler evidence leaves this module."""

    return redact_sensitive_text(value, MAX_DIAGNOSTIC_OUTPUT)


@dataclass(frozen=True)
class _DockerStage:
    """One FROM-to-next-FROM section of a Dockerfile."""

    start: int
    end: int
    image: str
    alias: str | None
    distro: str | None


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
    _rule(
        "missing-sharp-libvips-development-files",
        "sharp/libvips",
        ("libvips-dev",),
        r"(?is)(?=.*\bsharp\b)(?=.*\b(?:native|source|libvips|prebuilt|node-gyp|"
        r"build(?:ing)?|built|compil(?:e|ed|ing|ation)?)\b)(?=.*(?:\berror\b|"
        r"\bfail(?:ed|ure|ures)?\b|"
        r"\bfailure\b|\bnot found\b|\bmissing\b|\bunable\b|\bcannot\b|"
        r"\bcould not\b|\bno such file\b|\bfatal\b))",
        "The sharp native/source build cannot use its libvips development files.",
        "npm",
    ),
    _rule(
        "missing-canvas-development-files",
        "canvas/cairo/pango/giflib",
        ("libcairo2-dev", "libpango1.0-dev", "libgif-dev"),
        r"(?is)(?=.*\bcanvas\b)(?=.*\b(?:native|source|node-gyp|node-pre-gyp|gyp|"
        r"build(?:ing)?|built|compil(?:e|ed|ing|ation)?)\b)(?=.*(?:\berror\b|"
        r"\bfail(?:ed|ure|ures)?\b|"
        r"\bfailure\b|\bnot found\b|\bmissing\b|\bunable\b|\bcannot\b|"
        r"\bcould not\b|\bno such file\b|\bfatal\b))",
        "The canvas native build is missing Cairo, Pango, and GIF development files.",
        "npm",
    ),
    _rule(
        "missing-node-gyp-build-tools",
        "node-gyp/Python/make/g++",
        ("python3", "make", "g++"),
        r"(?is)(?=.*\b(?:node-gyp|gyp)\b)(?=.*(?:(?:\bpython3?\b|\bmake\b|"
        r"\bg\+\+(?!\w)|\bgcc\b).{0,180}(?:not found|missing|not installed|"
        r"unable|cannot|can't find|couldn't find|could not|no such file|not in path|"
        r"not set|produced an error)|(?:not found|missing|not installed|unable|"
        r"cannot|can't find|couldn't find|could not|no such file|not in path|not set|"
        r"produced an error).{0,180}(?:\bpython3?\b|\bmake\b|\bg\+\+(?!\w)|"
        r"\bgcc\b)))",
        "The node-gyp native build is missing Python or its make/C++ toolchain.",
        "node-gyp",
    ),
)


_FROM_PATTERN = re.compile(
    r"^\s*FROM\s+(?P<options>(?:--\S+\s+)*)?(?P<image>\S+)"
    r"(?:\s+AS\s+(?P<alias>[A-Za-z0-9_.-]+))?\s*(?:#.*)?$",
    re.IGNORECASE,
)


def _classify_base_image(image: str) -> str | None:
    """Classify a base image conservatively as Debian, Alpine, or Fedora.

    Official language images inherit Debian unless their tag explicitly names
    another family.  Custom images and images such as ``scratch`` remain
    unknown; package installation on those images is unsafe to infer.
    """

    value = image.strip().lower()
    if not value or value.startswith("${"):
        return None
    value = value.split("@", 1)[0]
    basename = value.rsplit("/", 1)[-1]
    image_name, _, tag = basename.partition(":")
    identity = f"{image_name} {tag}"
    full_identity = f"{value} {tag}"

    if image_name == "alpine" or re.search(
        r"(?:^|[/_-])alpine(?:[-_.0-9/:]|$)", full_identity
    ):
        return "alpine"
    if image_name in {
        "fedora",
        "rhel",
        "centos",
        "centosstream",
        "rocky",
        "rockylinux",
        "alma",
        "almalinux",
        "oraclelinux",
        "amazonlinux",
    } or re.fullmatch(r"ubi\d*", image_name) or re.search(
        r"(?:^|[/_-])(fedora|rhel|ubi\d*|centos(?:stream)?|rocky|rockylinux|"
        r"alma(?:linux)?|almalinux|oraclelinux|amazonlinux)(?:[-_.0-9/:]|$)",
        full_identity,
    ):
        return "fedora"
    if image_name in {"debian", "ubuntu"} or re.search(
        r"(?:^|[/_-])(debian|ubuntu|bookworm|bullseye|buster|trixie|sid|"
        r"stretch|jammy|focal|noble|kinetic|lunar|mantic|xenial|slim)(?:[-_.0-9]|$)",
        identity,
    ):
        return "debian"

    # These official images default to Debian when no Alpine/Fedora marker is
    # present.  This keeps the established python:3.x behavior compatible.
    if "/" not in value and image_name in {
        "python",
        "node",
        "golang",
        "rust",
        "ruby",
        "php",
    }:
        return "debian"
    return None


def detect_dockerfile_distro(dockerfile: str) -> str | None:
    """Return the supported distro of a simple Dockerfile's first base image.

    For multi-stage files this returns the first recognized distro.  Healing
    uses the stage-aware selector below rather than relying on this convenience
    function, so mixed-stage files do not accidentally inherit this answer.
    """

    for line in str(dockerfile or "").splitlines():
        match = _FROM_PATTERN.match(line)
        if match:
            distro = _classify_base_image(match.group("image"))
            if distro is not None:
                return distro
    return None


def _docker_stages(lines: list[str]) -> list[_DockerStage]:
    starts: list[tuple[int, str, str | None, str | None]] = []
    for index, line in enumerate(lines):
        match = _FROM_PATTERN.match(line.rstrip("\r\n"))
        if match:
            image = match.group("image")
            starts.append(
                (index, image, match.group("alias"), _classify_base_image(image))
            )
    return [
        _DockerStage(
            start=index,
            end=(
                starts[position + 1][0] - 1
                if position + 1 < len(starts)
                else len(lines) - 1
            ),
            image=image,
            alias=alias,
            distro=distro,
        )
        for position, (index, image, alias, distro) in enumerate(starts)
    ]


def _select_package_stage(lines: list[str]) -> _DockerStage | None:
    """Choose a supported build stage without guessing across mixed stages."""

    stages = _docker_stages(lines)
    supported = [stage for stage in stages if stage.distro in _DISTRO_TO_MANAGER]
    if not supported:
        return None

    def score(stage: _DockerStage) -> int:
        section = " ".join(lines[stage.start : stage.end + 1]).lower()
        value = 0
        if re.search(r"\b(?:pip|pip3|cargo|rustc|npm|yarn|gem)\b", section):
            value += 3
        if re.search(r"\b(?:gcc|g\+\+|cc|cmake|make)\b", section):
            value += 1
        return value

    # An unknown stage may be a scratch/distroless builder or final image.  Do
    # not silently select the supported stage unless its build tooling makes
    # the intended package-install location clear.
    if len(stages) > 1 and any(
        stage.distro not in _DISTRO_TO_MANAGER for stage in stages
    ):
        candidates = [stage for stage in supported if score(stage)]
        if len(candidates) == 1:
            return candidates[0]
        return None
    if len({stage.distro for stage in supported}) == 1:
        candidates = supported
    else:
        candidates = []
        for stage in supported:
            stage_score = score(stage)
            if stage_score:
                candidates.append((stage_score, stage))
        if not candidates:
            return None
        highest = max(score for score, _stage in candidates)
        best = [stage for score, stage in candidates if score == highest]
        if len(best) != 1:
            return None
        return best[0]

    # Prefer a stage that actually runs the build tooling.  If none does, the
    # first supported stage is the least surprising single-stage-compatible
    # behavior, while still avoiding unknown stages.
    for stage in candidates:
        if score(stage) >= 3:
            return stage
    return candidates[0]


def _map_packages(packages: object, manager: str) -> list[str]:
    """Map parser package vocabulary to one supported manager."""

    source = _normalise_packages(packages)
    if manager == "apt":
        return source
    mapped: set[str] = set()
    for package in source:
        mapped.update(_PACKAGE_MAP.get(package, {}).get(manager, ()))
    return sorted(mapped, key=lambda value: value.lower())


def _generic_install_command(manager: str, packages: list[str]) -> str:
    if not packages:
        return ""
    joined = " ".join(packages)
    if manager == "apt":
        return "apt-get update && apt-get install -y --no-install-recommends " + joined
    if manager == "apk":
        return "apk add --no-cache " + joined
    if manager == "dnf":
        return "dnf install -y " + joined + " && dnf clean all"
    return ""


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
            return redact_sensitive_text(line.strip(), MAX_DIAGNOSTIC_LINE), number
    return redact_sensitive_text(
        log_text.strip().splitlines()[0], MAX_DIAGNOSTIC_LINE
    ), 1


def parse_compiler_log(log_text: str) -> list[CompilerDiagnostic]:
    """Parse common native-build failures without executing or fetching anything."""

    text = str(log_text or "")
    if not text.strip():
        return []
    safe_text = redact_sensitive_text(text, MAX_DIAGNOSTIC_OUTPUT)
    diagnostics: list[CompilerDiagnostic] = []
    for rule in _RULES:
        if not rule.pattern.search(text):
            continue
        message, line_number = _matched_line(text, rule.pattern)
        diagnostics.append(
            CompilerDiagnostic(
                tool=rule.tool,
                message=_redact_sensitive_output(message or rule.explanation),
                severity=rule.severity,
                line_number=line_number,
                code=rule.signature,
                raw_output=safe_text,
                error_signature=_redact_sensitive_output(message),
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
            + redact_sensitive_text(log_text, MAX_DIAGNOSTIC_OUTPUT)
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
        else:
            summary = redact_sensitive_text(summary, MAX_DIAGNOSTIC_LINE)
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
    if output.is_symlink():
        output.unlink()
    elif output.is_dir():
        shutil.rmtree(output)
    elif output.exists():
        output.unlink()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Preserve links rather than copying data from outside the target tree.
    shutil.copytree(target, output, symlinks=True)


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
    if broken.is_file() and not broken.is_symlink():
        return broken
    regular = target / "Dockerfile"
    if regular.is_file() and not regular.is_symlink():
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
        image_name, _, tag = last_part.partition(":")
        policy = _RUNTIME_BASE_IMAGES.get(image_name.lower())
        # Only official runtime images participate in this small policy.  In
        # particular, keep custom images and runtime variants such as
        # python:3.11-alpine3.20 on their original package ecosystem.
        if policy is None or _classify_base_image(image) != policy[0]:
            output.append(line)
            continue
        floating = not tag or tag.lower() in {"latest", "stable"}
        if image_name.lower() == "python" and not re.search(r"\d+\.\d+\.\d+", tag):
            floating = True
        if not floating:
            output.append(line)
            continue
        replacement_image = policy[1]
        replacement = (
            f"{match.group('indent')}{match.group('prefix')}{replacement_image}"
            f"{match.group('tail')}{newline}"
        )
        output.append(replacement)
        changed = True
    return output, changed


def _package_blocks(
    lines: list[str], manager: str, start: int = 0, end: int | None = None
) -> list[tuple[int, int, set[str]]]:
    """Find existing install blocks for one package manager in one stage."""

    if end is None:
        end = len(lines) - 1
    if manager == "apt":
        command = r"apt-get\s+install\b"
    elif manager == "apk":
        command = r"apk\s+add\b"
    elif manager == "dnf":
        command = r"(?:dnf|yum)\s+install\b"
    else:
        return []
    blocks: list[tuple[int, int, set[str]]] = []
    index = start
    stage_end = end
    while index <= stage_end:
        if (
            lines[index].lstrip().startswith("#")
            or not re.search(command, lines[index], re.IGNORECASE)
        ):
            index += 1
            continue
        block_end = index
        while block_end < stage_end and lines[block_end].rstrip().endswith("\\"):
            block_end += 1
        joined = " ".join(lines[index : block_end + 1]).replace("\\", " ")
        match = re.search(command + r"(?P<body>.*?)(?:&&|$)", joined, re.IGNORECASE)
        packages: set[str] = set()
        if match:
            try:
                tokens = shlex.split(match.group("body"))
            except ValueError:
                tokens = match.group("body").split()
            packages.update(
                token
                for token in tokens
                if _PACKAGE_TOKEN.fullmatch(token) and not token.startswith("-")
            )
        blocks.append((index, block_end, packages))
        index = block_end + 1
    return blocks


def _apt_blocks(lines: list[str]) -> list[tuple[int, int, set[str]]]:
    """Compatibility wrapper retained for callers of the old private helper."""

    return _package_blocks(lines, "apt")


def _render_apt_layer(packages: list[str]) -> list[str]:
    return _render_install_layer("apt", packages)


def _render_install_layer(manager: str, packages: list[str]) -> list[str]:
    if not packages:
        return []
    if manager == "apt":
        rendered = ["RUN apt-get update && apt-get install -y --no-install-recommends \\\n"]
        for package in packages:
            rendered.append(f"    {package} \\\n")
        rendered.append("    && rm -rf /var/lib/apt/lists/*\n")
        return rendered
    if manager == "apk":
        rendered = ["RUN apk add --no-cache \\\n"]
        for position, package in enumerate(packages):
            suffix = " \\\n" if position < len(packages) - 1 else "\n"
            rendered.append(f"    {package}{suffix}")
        return rendered
    if manager == "dnf":
        rendered = ["RUN dnf install -y \\\n"]
        for package in packages:
            rendered.append(f"    {package} \\\n")
        rendered.append("    && dnf clean all\n")
        return rendered
    return []


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
    return _inject_package_layer(lines, packages, "apt")


def _inject_package_layer(
    lines: list[str],
    packages: list[str],
    manager: str,
    start: int = 0,
    end: int | None = None,
) -> tuple[list[str], bool]:
    """Replace or add one deterministic manager-specific install layer."""

    if end is None:
        end = len(lines) - 1
    section = lines[start : end + 1]
    blocks = _package_blocks(section, manager)
    existing = set().union(*(block[2] for block in blocks)) if blocks else set()
    combined = sorted({*existing, *packages}, key=lambda value: value.lower())
    if not combined:
        return lines, False
    if blocks:
        removed: list[str] = []
        block_ranges = {index: block_end for index, block_end, _packages in blocks}
        index = 0
        while index < len(section):
            if index in block_ranges:
                index = block_ranges[index] + 1
                continue
            removed.append(section[index])
            index += 1
        section = removed
    anchor = _install_anchor(section)
    section[anchor:anchor] = _render_install_layer(manager, combined)
    return lines[:start] + section + lines[end + 1 :], True


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


def _enforce_appuser(lines: list[str], distro: str | None = None) -> tuple[list[str], bool]:
    if any(re.match(r"\s*USER\s+appuser\b", line, re.IGNORECASE) for line in lines):
        return lines, False
    workdir = "/app"
    for line in lines:
        match = re.match(r"\s*WORKDIR\s+(\S+)", line, re.IGNORECASE)
        if match:
            workdir = match.group(1)
    if distro == "alpine":
        create_user = "adduser -D -u 10001 appuser"
    else:
        create_user = "useradd -m -u 10001 appuser"
    setup = [
        f"RUN {create_user} && chown -R appuser:appuser {workdir}\n",
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
            for directory, dirnames, filenames in os.walk(target, followlinks=False):
                directory_path = Path(directory)
                dirnames[:] = [
                    name
                    for name in dirnames
                    if not (directory_path / name).is_symlink()
                ]
                source_indicators.extend(
                    name.lower()
                    for name in filenames
                    if not (directory_path / name).is_symlink()
                )
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
            r"\b/usr/bin/cc\b|\bgcc\b)",
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
    for directory, dirnames, filenames in os.walk(output, followlinks=False):
        directory_path = Path(directory)
        dirnames[:] = [
            name for name in dirnames if not (directory_path / name).is_symlink()
        ]
        for name in filenames:
            if not name.endswith(".sh"):
                continue
            path = directory_path / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
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
    log_text = (
        log_path.read_text(encoding="utf-8")
        if log_path.is_file() and not log_path.is_symlink()
        else ""
    )
    analysis = analyze_log_hybrid(log_text)
    packages = set(analysis.apt_packages)
    packages.update(_native_and_rust_packages(log_text, before, target))

    lines = before.splitlines(keepends=True)
    lines, base_changed = _pin_base_images(lines)
    stage = _select_package_stage(lines)
    manager = _DISTRO_TO_MANAGER.get(stage.distro) if stage else None
    source_packages = _normalise_packages(packages)
    mapped_packages = _map_packages(source_packages, manager) if manager else []
    package_changed = False
    if stage and manager and mapped_packages:
        lines, package_changed = _inject_package_layer(
            lines,
            mapped_packages,
            manager,
            stage.start,
            stage.end,
        )
    lines, chmod_changed, chmod_refs = _chmod_shell_entrypoints(lines)
    lines, user_changed = _enforce_appuser(lines, stage.distro if stage else None)
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
        changes.append("pin floating base images using runtime-aware defaults")
        security_fixes.append("pinned floating base images without changing runtime family")
    if package_changed and manager:
        changes.append(f"install {manager} packages: {', '.join(mapped_packages)}")
        if manager == "apt":
            security_fixes.append("clean apt package lists in the deterministic install layer")
        else:
            security_fixes.append(
                f"clean {manager} package metadata in the deterministic install layer"
            )
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
        apt_packages=source_packages,
        package_manager=manager,
        packages=mapped_packages,
        install_command=_generic_install_command(manager or "", mapped_packages),
        security_fixes=sorted(set(security_fixes)),
        staged_output_path=str(output),
    )


__all__ = [
    "analyze_log_hybrid",
    "detect_dockerfile_distro",
    "heal_dockerfile",
    "parse_compiler_log",
]
