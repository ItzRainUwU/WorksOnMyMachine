# Native package recommendations

Compiler diagnostics retain the existing Debian/Ubuntu package vocabulary for
API compatibility. When a Dockerfile is healed, WorksOnMyMachine detects the
supported base-image family and translates those recommendations into the
image's package manager:

| Base image family | Package manager | Example install command |
| --- | --- | --- |
| Debian/Ubuntu | `apt` | `apt-get update && apt-get install -y --no-install-recommends ...` |
| Alpine | `apk` | `apk add --no-cache ...` |
| Fedora/RHEL, UBI, CentOS, Rocky, Alma, Amazon Linux | `dnf` | `dnf install -y ... && dnf clean all` |

For example, `python:3.11-alpine` maps `build-essential` to `build-base` and
`libpq-dev` to `postgresql-dev`. The Dockerfile patch response exposes the
selected `package_manager`, translated `packages`, and `install_command`.

Unknown or ambiguous base images are not guessed: no package layer is injected.
Multi-stage Dockerfiles are only modified when a supported build stage can be
identified from its build tooling.

The raw compiler-log parser remains distro-neutral because a log by itself does
not reliably identify the container distribution.
