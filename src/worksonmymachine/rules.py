"""Offline rule-pack metadata used by scanner findings.

Rule packs are deliberately data-only.  The scanner remains the implementation
of each check, while this module gives callers a stable, independently
versioned description of the check that produced a finding.  Keeping the
registry local also means report generation never needs a network lookup.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
import re
from typing import Mapping


_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class FixMode(StrEnum):
    """How a finding can be repaired by the current healer."""

    AUTOMATIC = "automatic"
    STAGED = "staged"
    MANUAL = "manual"


# A descriptive alias is useful to integrations that call this a rule-fix
# mode, while keeping the short name convenient in scanner code.
RuleFixMode = FixMode


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata for one scanner rule."""

    rule_id: str
    pack_name: str
    rule_version: str
    confidence: float = 0.9
    remediation: str | None = None
    fix_mode: FixMode = FixMode.MANUAL

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")
        if not self.pack_name.strip():
            raise ValueError("pack_name must not be empty")
        if not _VERSION.fullmatch(self.rule_version):
            raise ValueError("rule_version must be a semantic version")
        if isinstance(self.confidence, bool) or not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", float(self.confidence))
        if not isinstance(self.fix_mode, FixMode):
            object.__setattr__(self, "fix_mode", FixMode(self.fix_mode))


@dataclass(frozen=True)
class RulePack:
    """An independently named and versioned collection of rules."""

    name: str
    version: str
    rules: tuple[RuleMetadata, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("rule pack name must not be empty")
        if not _VERSION.fullmatch(self.version):
            raise ValueError("rule pack version must be a semantic version")
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError(f"rule pack {self.name!r} contains duplicate rule IDs")
        for rule in self.rules:
            if rule.pack_name != self.name:
                raise ValueError(
                    f"rule {rule.rule_id!r} belongs to {rule.pack_name!r}, "
                    f"not {self.name!r}"
                )

    @property
    def pack_id(self) -> str:
        """Compatibility-friendly name for callers that use pack IDs."""

        return self.name


def _rule(
    rule_id: str,
    pack_name: str,
    *,
    confidence: float = 0.9,
    remediation: str | None = None,
    fix_mode: FixMode = FixMode.MANUAL,
    version: str = "1.0.0",
) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        pack_name=pack_name,
        rule_version=version,
        confidence=confidence,
        remediation=remediation,
        fix_mode=fix_mode,
    )


_PACK_RULES: dict[str, tuple[RuleMetadata, ...]] = {
    "python": (
        _rule("PYTHON-PARSE", "python", confidence=0.99),
        _rule("IMPORT-CASE", "python", confidence=0.99, fix_mode=FixMode.MANUAL),
        _rule("PATH-WINDOWS-DRIVE", "python", confidence=0.98),
        _rule("PATH-HOST-ABSOLUTE", "python", confidence=0.98),
        _rule("PATH-BACKSLASH", "python", confidence=0.96),
        _rule("ENV-MISSING", "python", confidence=0.98),
        _rule("PYPROJECT-UNPINNED", "python", confidence=0.99, fix_mode=FixMode.AUTOMATIC),
        _rule("PYPROJECT-LOCK-MISSING", "python", confidence=0.98),
        _rule("PYPROJECT-LOCK-INVALID", "python", confidence=0.98),
        _rule("REQ-UNPINNED", "python", confidence=0.99, fix_mode=FixMode.AUTOMATIC),
    ),
    "docker": (
        _rule("DOCKER-COPY-SHELL-EXEC", "docker", confidence=0.99, fix_mode=FixMode.STAGED),
        _rule("DOCKER-SHELL-EXEC", "docker", confidence=0.99, fix_mode=FixMode.STAGED),
        _rule("DOCKER-BASE-IMAGE", "docker", confidence=0.9),
    ),
    "javascript-typescript": (
        _rule("JS-IMPORT-CASE", "javascript-typescript", confidence=0.99),
        _rule("JS-ENV-MISSING", "javascript-typescript", confidence=0.98),
        _rule("JS-PATH-BACKSLASH", "javascript-typescript", confidence=0.96),
        _rule("JS-UNPINNED-DEPENDENCY", "javascript-typescript", confidence=0.95),
    ),
    "rust-cargo": (
        _rule("RUST-CARGO-LOCK-MISSING", "rust-cargo", confidence=0.98),
        _rule("RUST-CARGO-MANIFEST", "rust-cargo", confidence=0.9),
        _rule("RUST-CARGO-UNPINNED", "rust-cargo", confidence=0.95),
    ),
    "shell": (
        _rule("SHELL-CRLF", "shell", confidence=0.99, fix_mode=FixMode.AUTOMATIC),
        _rule("SHELL-SHEBANG", "shell", confidence=0.99, fix_mode=FixMode.AUTOMATIC),
        _rule("SHELL-NOT-EXECUTABLE", "shell", confidence=0.99, fix_mode=FixMode.MANUAL),
    ),
    "ci": (
        _rule("SECRET-ENV-FILE", "ci", confidence=0.99),
        _rule("SECRET-API-KEY", "ci", confidence=0.99),
        _rule("SECRET-CLOUD-CREDENTIAL", "ci", confidence=0.99),
        _rule("SECRET-PRIVATE-KEY", "ci", confidence=0.99),
        _rule("SECRET-PASSWORD", "ci", confidence=0.99),
        _rule("SECRET-TOKEN", "ci", confidence=0.99),
        _rule("TARGET-REPARSE-POINT", "ci", confidence=1.0),
        _rule("TARGET-NOT-DIRECTORY", "ci", confidence=1.0),
        _rule("CI-CONFIG", "ci", confidence=0.9),
    ),
}


RULE_PACKS: Mapping[str, RulePack] = MappingProxyType(
    {
        name: RulePack(
            name=name,
            version="1.0.0",
            rules=rules,
            description={
                "python": "Python source and packaging portability rules.",
                "docker": "Dockerfile and container build portability rules.",
                "javascript-typescript": "JavaScript and TypeScript portability rules.",
                "rust-cargo": "Rust and Cargo reproducibility rules.",
                "shell": "Shell script portability and execution rules.",
                "ci": "CI configuration and repository safety rules.",
            }[name],
        )
        for name, rules in _PACK_RULES.items()
    }
)

RULE_REGISTRY: Mapping[str, RuleMetadata] = MappingProxyType(
    {rule.rule_id: rule for pack in RULE_PACKS.values() for rule in pack.rules}
)

_PACK_ALIASES = MappingProxyType(
    {
        "javascript": "javascript-typescript",
        "typescript": "javascript-typescript",
        "js": "javascript-typescript",
        "ts": "javascript-typescript",
        "rust": "rust-cargo",
        "cargo": "rust-cargo",
        "python-packaging": "python",
        "shell-scripts": "shell",
        "ci-config": "ci",
    }
)


def available_rule_packs() -> tuple[str, ...]:
    """Return stable, sorted names of the installed local rule packs."""

    return tuple(sorted(RULE_PACKS))


def get_rule_pack(name: str) -> RulePack:
    """Return a named pack or raise a validation-friendly ``ValueError``."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("rule pack name must not be empty")
    normalized = name.strip().lower().replace("_", "-").replace(" ", "-")
    normalized = _PACK_ALIASES.get(normalized, normalized)
    try:
        return RULE_PACKS[normalized]
    except KeyError as exc:
        raise ValueError(
            f"unknown rule pack {name!r}; expected one of {', '.join(available_rule_packs())}"
        ) from exc


def _normalize_pack_name(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-").replace(" ", "-")
    return _PACK_ALIASES.get(normalized, normalized)


def get_rule_metadata(rule_id: str, *, pack_name: str | None = None) -> RuleMetadata:
    """Resolve metadata for a finding, with a safe local fallback.

    A fallback keeps third-party or future scanner rules backward compatible:
    they still receive the metadata fields even before being added to a pack.
    """

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("rule_id must not be empty")
    normalized_pack = _normalize_pack_name(pack_name) if pack_name else None
    metadata = RULE_REGISTRY.get(rule_id.strip())
    if metadata is not None and (normalized_pack is None or metadata.pack_name == normalized_pack):
        return metadata
    selected_pack = normalized_pack or "ci"
    if selected_pack not in RULE_PACKS:
        selected_pack = "ci"
    return RuleMetadata(
        rule_id=rule_id.strip(),
        pack_name=selected_pack,
        rule_version=RULE_PACKS[selected_pack].version,
        confidence=0.9 if normalized_pack else 0.75,
        fix_mode=FixMode.MANUAL,
    )


__all__ = [
    "FixMode",
    "RuleFixMode",
    "RuleMetadata",
    "RulePack",
    "RULE_PACKS",
    "RULE_REGISTRY",
    "available_rule_packs",
    "get_rule_metadata",
    "get_rule_pack",
]
