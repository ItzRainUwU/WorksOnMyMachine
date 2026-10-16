"""Validated repository profiles built on the workspace policy system."""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Mapping

from .config import Policy
from .rules import available_rule_packs


PROFILE_NAMES = (
    "generic",
    "python-service",
    "rust-native-extension",
    "node-app",
    "monorepo",
    "docker-only",
    "ci-validation",
)


@dataclass(frozen=True)
class RepositoryProfile:
    """A named set of repository expectations and policy defaults."""

    name: str
    description: str = ""
    expected_runtimes: tuple[str, ...] = ()
    required_lockfiles: tuple[str, ...] = ()
    expectations: tuple[str, ...] = ()
    enabled_rule_packs: tuple[str, ...] = ()
    policy: Policy = Policy()

    def __post_init__(self) -> None:
        normalized = self.name.strip().lower().replace("_", "-").replace(" ", "-")
        if normalized not in PROFILE_NAMES:
            raise ValueError(
                f"unknown repository profile {self.name!r}; expected one of {', '.join(PROFILE_NAMES)}"
            )
        object.__setattr__(self, "name", normalized)
        for field_name in ("expected_runtimes", "required_lockfiles", "expectations"):
            value = getattr(self, field_name)
            if not isinstance(value, tuple) or any(not isinstance(item, str) or not item.strip() for item in value):
                raise ValueError(f"profile.{field_name} must contain non-empty strings")
            object.__setattr__(self, field_name, tuple(dict.fromkeys(item.strip() for item in value)))
        pack_names = available_rule_packs()
        if not isinstance(self.enabled_rule_packs, tuple):
            raise ValueError("profile.enabled_rule_packs must contain rule-pack names")
        normalized_packs = tuple(
            dict.fromkeys(
                item.strip().lower().replace("_", "-").replace(" ", "-")
                for item in self.enabled_rule_packs
            )
        )
        if any(item not in pack_names for item in normalized_packs):
            raise ValueError("profile.enabled_rule_packs contains an unknown rule pack")
        object.__setattr__(self, "enabled_rule_packs", normalized_packs)
        if not isinstance(self.policy, Policy):
            raise ValueError("profile.policy must be a Policy")

    @property
    def rule_packs(self) -> tuple[str, ...]:
        """Alias used by callers that describe packs as a profile selection."""

        return self.enabled_rule_packs


_ALL_PACKS = available_rule_packs()
PROFILE_REGISTRY: Mapping[str, RepositoryProfile] = MappingProxyType(
    {
        "generic": RepositoryProfile(
            name="generic",
            description="All built-in rules with the workspace policy defaults.",
            enabled_rule_packs=_ALL_PACKS,
        ),
        "python-service": RepositoryProfile(
            name="python-service",
            description="A deployable Python service with locked dependencies.",
            expected_runtimes=("python",),
            required_lockfiles=("requirements.lock", "poetry.lock", "uv.lock", "Pipfile.lock"),
            expectations=("python-runtime", "locked-dependencies", "service-test-command"),
            enabled_rule_packs=("python", "shell", "docker", "ci"),
            policy=Policy(require_lockfiles=True, min_readiness=95.0),
        ),
        "rust-native-extension": RepositoryProfile(
            name="rust-native-extension",
            description="A Rust/Cargo extension, optionally exposed through Python.",
            expected_runtimes=("rust", "cargo"),
            required_lockfiles=("Cargo.lock",),
            expectations=("cargo-lock", "native-build", "extension-runtime"),
            enabled_rule_packs=("rust-cargo", "python", "shell", "docker", "ci"),
            policy=Policy(require_lockfiles=True, min_readiness=95.0),
        ),
        "node-app": RepositoryProfile(
            name="node-app",
            description="A Node.js web application with a committed package lock.",
            expected_runtimes=("node",),
            required_lockfiles=("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
            expectations=("node-runtime", "package-lock", "app-test-command"),
            enabled_rule_packs=("javascript-typescript", "shell", "docker", "ci"),
            policy=Policy(require_lockfiles=True, min_readiness=95.0),
        ),
        "monorepo": RepositoryProfile(
            name="monorepo",
            description="A repository containing multiple independently built projects.",
            expected_runtimes=("python", "node", "rust"),
            required_lockfiles=("requirements.lock", "package-lock.json", "Cargo.lock"),
            expectations=("workspace-boundaries", "per-package-locks", "root-ci"),
            enabled_rule_packs=_ALL_PACKS,
            policy=Policy(require_lockfiles=True, min_readiness=90.0),
        ),
        "docker-only": RepositoryProfile(
            name="docker-only",
            description="A container definition without a language package manifest.",
            expected_runtimes=("docker",),
            expectations=("pinned-base-image", "container-health", "docker-build"),
            enabled_rule_packs=("docker", "ci"),
            policy=Policy(require_lockfiles=False, require_reproducible=False, min_readiness=90.0),
        ),
        "ci-validation": RepositoryProfile(
            name="ci-validation",
            description="A CI-focused validation run across the repository.",
            expected_runtimes=(),
            expectations=("ci-config", "offline-checks", "reproducible-artifacts"),
            enabled_rule_packs=_ALL_PACKS,
            policy=Policy(require_lockfiles=True, require_reproducible=True, min_readiness=95.0),
        ),
    }
)

_PROFILE_ALIASES = MappingProxyType(
    {
        "python": "python-service",
        "python-service-app": "python-service",
        "rust": "rust-native-extension",
        "rust-extension": "rust-native-extension",
        "node": "node-app",
        "node-application": "node-app",
        "docker": "docker-only",
        "ci": "ci-validation",
        "ci-validation-mode": "ci-validation",
    }
)


def available_profiles() -> tuple[str, ...]:
    """Return stable names of profiles available without network access."""

    return PROFILE_NAMES


def get_profile(name: str | RepositoryProfile) -> RepositoryProfile:
    """Resolve and validate one built-in repository profile."""

    if isinstance(name, RepositoryProfile):
        return name
    if not isinstance(name, str) or not name.strip():
        raise ValueError("repository profile name must not be empty")
    normalized = name.strip().lower().replace("_", "-").replace(" ", "-")
    normalized = _PROFILE_ALIASES.get(normalized, normalized)
    try:
        return PROFILE_REGISTRY[normalized]
    except KeyError as exc:
        raise ValueError(
            f"unknown repository profile {name!r}; expected one of {', '.join(PROFILE_NAMES)}"
        ) from exc


def profile_from_mapping(value: object) -> RepositoryProfile:
    """Validate a profile string or a small ``[profile]`` TOML table."""

    if value is None:
        return get_profile("generic")
    if isinstance(value, str):
        return get_profile(value)
    if not isinstance(value, Mapping):
        raise ValueError("profile must be a name or TOML table")
    unknown = sorted(set(value) - {"name", "expectations"})
    if unknown:
        raise ValueError(f"profile contains unsupported field(s): {', '.join(unknown)}")
    profile = get_profile(value.get("name", "generic"))
    expectations = value.get("expectations")
    if expectations is None:
        return profile
    if not isinstance(expectations, list) or any(
        not isinstance(item, str) or not item.strip() for item in expectations
    ):
        raise ValueError("profile.expectations must be an array of non-empty strings")
    return replace(
        profile,
        expectations=tuple(dict.fromkeys((*profile.expectations, *(item.strip() for item in expectations)))),
    )


__all__ = [
    "PROFILE_NAMES",
    "PROFILE_REGISTRY",
    "RepositoryProfile",
    "available_profiles",
    "get_profile",
    "profile_from_mapping",
]
