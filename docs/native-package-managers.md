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

## Runtime-aware base-image defaults

When healing an official runtime image with an untagged, `latest`, or `stable`
tag, the healer uses the following explicit defaults instead of changing every
Debian-family image to Python:

| Source family | Default pinned image |
| --- | --- |
| Python, including partial version tags such as `python:3.11` | `python:3.11.9-slim` |
| Rust | `rust:1.85-slim-bookworm` |
| Node.js | `node:22-bookworm-slim` |
| Ubuntu | `ubuntu:24.04` |
| Alpine | `alpine:3.20` |

Fully versioned tags and digest references remain unchanged. Runtime variants
such as `python:3.11-alpine3.20` also retain their original Alpine package
manager and are not converted to a Debian image. These defaults are currently
an explicit built-in policy rather than workspace `[docker]` configuration.

The raw compiler-log parser remains distro-neutral because a log by itself does
not reliably identify the container distribution.
