"""Small, dependency-free configuration loader for local and container runs."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from collections.abc import Mapping


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent.parent
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_SANDBOX_DIR = Path("demo_targets")
DEFAULT_WORKSPACE_CONFIG = PROJECT_ROOT / ".worksonmymachine.toml"

_POLICY_FIELDS = frozenset(
    {
        "fail_on",
        "min_readiness",
        "require_reproducible",
        "allow_floating_docker_tags",
        "require_lockfiles",
    }
)
_POLICY_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Policy:
    """Shared audit gates loaded from the workspace policy table.

    The defaults intentionally match the documented policy example.  Keeping
    the policy as a standalone immutable value lets the CLI, API, and
    integrations consume the same validated object without coupling them to
    TOML parsing details.
    """

    fail_on: str = "high"
    min_readiness: float = 95.0
    require_reproducible: bool = True
    allow_floating_docker_tags: bool = False
    require_lockfiles: bool = True

    def __post_init__(self) -> None:
        """Validate values even when callers construct a policy directly."""

        if not isinstance(self.fail_on, str):
            raise ValueError("policy.fail_on must be one of low, medium, high, critical")
        fail_on = self.fail_on.strip().lower()
        if fail_on not in _POLICY_SEVERITIES:
            raise ValueError("policy.fail_on must be one of low, medium, high, critical")
        object.__setattr__(self, "fail_on", fail_on)

        if isinstance(self.min_readiness, bool) or not isinstance(
            self.min_readiness, (int, float)
        ):
            raise ValueError("policy.min_readiness must be a number between 0 and 100")
        min_readiness = float(self.min_readiness)
        if not 0.0 <= min_readiness <= 100.0:
            raise ValueError("policy.min_readiness must be a number between 0 and 100")
        object.__setattr__(self, "min_readiness", min_readiness)

        for field_name in (
            "require_reproducible",
            "allow_floating_docker_tags",
            "require_lockfiles",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"policy.{field_name} must be true or false")


# A descriptive alias makes the object discoverable for integrations that use
# "workspace policy" terminology while retaining the concise public name.
WorkspacePolicy = Policy


@dataclass(frozen=True)
class WorkspaceConfig:
    """Safe, workspace-relative project instructions for the dashboard."""

    target_paths: tuple[str, ...] = ("workspace",)
    ignore_paths: tuple[str, ...] = ()
    build_command: str | None = None
    test_command: str | None = None
    runtime: str | None = None
    vulnerability_database: str | None = None
    baseline_file: str = ".worksonmymachine-baseline.json"
    suppressions: tuple["SuppressionRule", ...] = ()
    policy: Policy = field(default_factory=Policy)


@dataclass(frozen=True)
class SuppressionRule:
    """One intentional finding suppression with an audit reason."""

    issue_id: str | None = None
    path: str | None = None
    category: str | None = None
    reason: str = ""
    expires: str | None = None


@dataclass(frozen=True)
class Settings:
    """Runtime settings with a project-relative sandbox."""

    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"
    strict_repro_mode: bool = True
    sandbox_dir: Path = DEFAULT_SANDBOX_DIR
    workspace_config_path: Path = DEFAULT_WORKSPACE_CONFIG

    @property
    def sandbox_path(self) -> Path:
        """Return the sandbox resolved from the portable project root."""

        return PROJECT_ROOT / self.sandbox_dir


def _read_dotenv(path: Path) -> dict[str, str]:
    """Read only simple KEY=value lines; shell execution is never attempted."""

    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _relative_sandbox(value: str) -> Path:
    normalized = value.strip()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    candidate = Path(normalized)
    if candidate.is_absolute():
        raise ValueError("SANDBOX_DIR must be a relative path")
    if "\\" in normalized or any(
        part in {"", ".", ".."} for part in normalized.split("/")
    ):
        raise ValueError("SANDBOX_DIR must be a normalized POSIX-relative path")
    return candidate


def _as_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError("STRICT_REPRO_MODE must be true or false")
    return normalized == "true"


def _safe_relative_list(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be an array of relative paths")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must contain only strings")
        normalized = item.strip().replace("\\", "/")
        if normalized in {".", "./"}:
            normalized = "workspace"
        if normalized.startswith("./"):
            normalized = normalized[2:]
        parts = normalized.split("/")
        if (
            not normalized
            or normalized.startswith("/")
            or (len(parts[0]) >= 2 and parts[0][1] == ":")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError(f"{field_name} must contain normalized workspace-relative paths")
        output.append(normalized)
    return tuple(dict.fromkeys(output))


def _load_suppressions(value: object) -> tuple[SuppressionRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("suppressions must be an array of tables")
    rules: list[SuppressionRule] = []
    for raw_rule in value:
        if not isinstance(raw_rule, dict):
            raise ValueError("each suppression must be a TOML table")
        reason = raw_rule.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("each suppression requires a non-empty reason")
        path = raw_rule.get("path")
        if path is not None:
            path = _safe_relative_list([path], "suppression path")[0]
        rules.append(
            SuppressionRule(
                issue_id=str(raw_rule["issue_id"]).strip() if raw_rule.get("issue_id") else None,
                path=path,
                category=str(raw_rule["category"]).strip() if raw_rule.get("category") else None,
                reason=reason.strip(),
                expires=str(raw_rule["expires"]).strip() if raw_rule.get("expires") else None,
            )
        )
    return tuple(rules)


def policy_from_mapping(value: object) -> Policy:
    """Validate and construct a policy from a TOML mapping.

    This small boundary helper is intentionally public so integrations can
    consume policy data from another configuration source while sharing the
    exact workspace validation rules.
    """

    if value is None:
        return Policy()
    if not isinstance(value, Mapping):
        raise ValueError("policy must be a TOML table")
    unknown = sorted(set(value) - _POLICY_FIELDS)
    if unknown:
        names = ", ".join(unknown)
        raise ValueError(f"policy contains unsupported field(s): {names}")
    try:
        return Policy(
            fail_on=value.get("fail_on", "high"),
            min_readiness=value.get("min_readiness", 95.0),
            require_reproducible=value.get("require_reproducible", True),
            allow_floating_docker_tags=value.get("allow_floating_docker_tags", False),
            require_lockfiles=value.get("require_lockfiles", True),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid workspace policy: {exc}") from exc


def _safe_relative_file(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a workspace-relative path")
    return _safe_relative_list([value], field_name)[0]


def load_workspace_config(path: Path | None = None) -> WorkspaceConfig:
    """Load optional workspace instructions without executing any commands."""

    config_path = path or DEFAULT_WORKSPACE_CONFIG
    if not config_path.is_file():
        return WorkspaceConfig()
    try:
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"workspace config is invalid: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("workspace config must contain a TOML table")
    return WorkspaceConfig(
        target_paths=_safe_relative_list(parsed.get("target_paths", ["workspace"]), "target_paths"),
        ignore_paths=_safe_relative_list(parsed.get("ignore_paths", []), "ignore_paths"),
        build_command=parsed.get("build_command") if isinstance(parsed.get("build_command"), str) else None,
        test_command=parsed.get("test_command") if isinstance(parsed.get("test_command"), str) else None,
        runtime=parsed.get("runtime") if isinstance(parsed.get("runtime"), str) else None,
        vulnerability_database=parsed.get("vulnerability_database") if isinstance(parsed.get("vulnerability_database"), str) else None,
        baseline_file=_safe_relative_file(
            parsed.get("baseline_file", ".worksonmymachine-baseline.json"),
            "baseline_file",
        ),
        suppressions=_load_suppressions(parsed.get("suppressions")),
        policy=policy_from_mapping(parsed.get("policy")),
    )


def load_workspace_policy(path: Path | None = None) -> Policy:
    """Load only the shared policy from a workspace TOML file.

    Consumers that do not need target or suppression settings can use this
    helper while preserving one parser and one set of policy defaults.
    """

    return load_workspace_config(path).policy


# Short alias for integrations that refer to this operation simply as loading
# policy; keep the descriptive function above as the canonical API name.
load_policy = load_workspace_policy


def load_settings(
    dotenv_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Load `.env` defaults, then let real environment variables override them."""

    file_values = _read_dotenv(dotenv_path or DEFAULT_ENV_FILE)
    environment = os.environ if environ is None else environ

    def value(name: str, default: str) -> str:
        return environment.get(name, file_values.get(name, default))

    app_port = int(value("APP_PORT", "8000"))
    if not 1 <= app_port <= 65535:
        raise ValueError("APP_PORT must be between 1 and 65535")
    log_level = value("LOG_LEVEL", "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("LOG_LEVEL is not a supported logging level")

    return Settings(
        app_host=value("APP_HOST", "0.0.0.0"),
        app_port=app_port,
        log_level=log_level,
        strict_repro_mode=_as_bool(value("STRICT_REPRO_MODE", "true")),
        sandbox_dir=_relative_sandbox(value("SANDBOX_DIR", "demo_targets")),
        workspace_config_path=_relative_sandbox(value("WORKSPACE_CONFIG", ".worksonmymachine.toml")),
    )


settings = load_settings()
workspace_config = load_workspace_config(PROJECT_ROOT / settings.workspace_config_path)
