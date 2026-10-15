# WorksOnMyMachine

WorksOnMyMachine is an offline-first cross-platform reproducibility platform
for projects that work on a developer workstation but fail in a clean Linux
environment.

It combines portability scanning, compiler-log diagnosis, Dockerfile repair,
deterministic Merkle hashing, CleanRoom certificates, and a local cyber-
engineering dashboard. The system is designed to inspect and heal a copy of a
target repository without modifying the source fixture.

## What it does

- **Cross-OS landmine scanning** — Finds case-sensitive import mismatches,
  host-specific paths, CRLF shell scripts, missing shebangs, environment drift,
  and unpinned dependencies.
- **Compiler diagnostics** — Parses common Linux failures involving Python
  headers, PostgreSQL, OpenSSL, libffi, GCC, Rust, CMake, XML, audio libraries,
  and shared runtime libraries.
- **Dockerfile auto-healing** — Pins floating base images, injects deterministic
  Debian/Ubuntu apt layers, enables shell-script execution, and enforces a
  non-root runtime user.
- **Deterministic certificates** — Computes normalized SHA-256 file hashes and
  Merkle roots independent of timestamps, ownership, inode values, or directory
  enumeration order.
- **CleanRoom verification** — Combines Linux readiness, dependency-lock
  evidence, Docker hardening, file hashes, and drift metadata into a certificate.
- **Self-contained dashboard** — Serves local HTML, CSS, JavaScript, and custom
  SVG visualizations without CDNs, icon fonts, or external runtime services.

## Architecture

```text
                       +----------------------------------+
                       | CleanRoom Dashboard               |
                       | local SVG / CSS / JavaScript      |
                       +----------------+-----------------+
                                        |
                       +----------------v-----------------+
                       | FastAPI application               |
                       | scan | parse | heal | certify     |
                       | compare | audit                  |
                       +----------------+-----------------+
                                        |
        +-------------------------------+-------------------------------+
        |                               |                               |
+-------v--------+             +--------v---------+             +---------v--------+
| Landmine       |             | Compiler and     |             | Reproducibility  |
| scanner        |             | Docker healer   |             | engine           |
| AST + heuristics|            | offline rules   |             | hashes + certs   |
+----------------+             +------------------+             +------------------+
```

The engine never executes target code during inspection. Auto-healing is
copy-on-write and produces unified diffs for review.

## Requirements

- Python **3.11.9**.
- Docker, optional, for the containerized run.
- A POSIX shell for the commands below. Windows users can use WSL or translate
  the activation command for PowerShell.

The runtime is pinned in `.python-version` and `runtime.txt`. Direct Python
dependencies are pinned in `requirements.txt`; the complete constraints set is
recorded in `requirements.lock`.

## Quick start

```bash
git clone <repository-url> WorksOnMyMachine
cd WorksOnMyMachine
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements.txt
cp .env.example .env
```

The default configuration is safe for local use and requires no API keys. The
optional `LLM_API_KEY` setting only enables enrichment after the deterministic
local parser has run; offline operation remains the default.

## Run the dashboard and API

```bash
. .venv/bin/activate
python -m uvicorn --app-dir src worksonmymachine.app:app \
  --host 0.0.0.0 --port 8000
```

Open <http://127.0.0.1:8000/> for the dashboard or <http://127.0.0.1:8000/docs>
for the interactive OpenAPI reference.

The dashboard automatically loads the `nightmare_ml_service` demonstration
target. Use the target selector to inspect the other fixtures, run a scan, or
run the copy-on-write auto-heal and certification workflow.

## CLI

The CLI is available through the module entry point and the packaged console
script:

```bash
PYTHONPATH=src python -m worksonmymachine --help
PYTHONPATH=src python -m worksonmymachine scan nightmare_ml_service
PYTHONPATH=src python -m worksonmymachine parse-log nightmare_ml_service
PYTHONPATH=src python -m worksonmymachine certify nightmare_ml_service --json
PYTHONPATH=src python -m worksonmymachine heal nightmare_ml_service --json
```

When installed as a package, the equivalent command is:

```bash
worksonmymachine scan nightmare_ml_service
```

## API examples

All target requests use a repository name or a normalized path inside the
workspace. Source targets are never overwritten.

### Scan

```bash
curl --request POST http://127.0.0.1:8000/api/v1/scan \
  --header 'Content-Type: application/json' \
  --data '{"target":"nightmare_ml_service"}'
```

### Parse a build log

```bash
curl --request POST http://127.0.0.1:8000/api/v1/parse-log \
  --header 'Content-Type: application/json' \
  --data '{"target":"rust_crypto_worker"}'
```

Raw compiler output can be submitted instead:

```bash
curl --request POST http://127.0.0.1:8000/api/v1/parse-log \
  --header 'Content-Type: application/json' \
  --data '{"log_text":"fatal error: Python.h: No such file or directory"}'
```

### Audit and certify

```bash
curl --request POST http://127.0.0.1:8000/api/v1/audit \
  --header 'Content-Type: application/json' \
  --data '{"target":"nightmare_ml_service","auto_heal":true}'

curl --request POST http://127.0.0.1:8000/api/v1/certify \
  --header 'Content-Type: application/json' \
  --data '{"target":"nightmare_ml_service"}'
```

### Available endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Serve the local dashboard |
| `GET` | `/health` | Service health check |
| `GET` | `/api/v1/targets` | List available targets |
| `POST` | `/api/v1/scan` | Scan portability landmines |
| `POST` | `/api/v1/parse-log` | Parse a target or raw compiler log |
| `POST` | `/api/v1/heal` | Heal source and configuration files in staging |
| `POST` | `/api/v1/heal-dockerfile` | Harden a staged Dockerfile |
| `POST` | `/api/v1/certify` | Generate a deterministic certificate |
| `POST` | `/api/v1/compare` | Compare certificate drift |
| `POST` | `/api/v1/audit` | Run the unified audit workflow |

## Docker

Build and run the production-style image:

```bash
docker build --tag worksonmymachine:latest .
docker run --rm --publish 8000:8000 worksonmymachine:latest
```

The image uses `python:3.11.9-slim`, installs the locked requirements, copies
the application, static dashboard, and demo targets, and runs as the non-root
`appuser` account.

## Test and development

Run the complete offline suite:

```bash
. .venv/bin/activate
make test
```

Equivalent direct command:

```bash
python -m pytest
```

The suite covers:

- Pydantic contracts and configuration safety.
- Windows/macOS-to-Linux portability detection.
- Compiler-log parsing and apt recommendations.
- Copy-on-write source and Dockerfile healing.
- Merkle determinism and certificate drift comparison.
- CLI behavior and FastAPI integration.
- Dashboard asset delivery, SVG coverage, and zero-CDN guarantees.
- Full end-to-end workflows across all demo targets.
- Rebuildability invariants and source-fixture immutability.

## Demo targets

The `demo_targets/` directory contains intentionally broken, self-contained
fixtures used by the scanner and tests:

- `nightmare_ml_service` — Windows paths, backslash separators, missing
  environment documentation, CRLF shell input, an unpinned Python image, and
  native ML/PostgreSQL/OpenGL failures.
- `case_sensitive_webapp` — Python and JavaScript import casing mismatches,
  unpinned requirements, and a floating Docker base image.
- `rust_crypto_worker` — native libffi/OpenSSL headers, missing Rust toolchain
  evidence, and a hybrid Rust/Python build.

Each fixture contains a simulated `build_error.log`. Healing always uses a
temporary staging directory, so these source fixtures remain unchanged.

## Reproducibility and security model

- Merkle roots use normalized text content and POSIX-relative paths.
- CRLF presence and raw SHA-256 values remain visible in certificate metadata.
- Filesystem timestamps, ownership, inode values, and enumeration order do not
  affect the root hash.
- Target paths are constrained to the workspace by the API and CLI.
- The scanner does not execute target code or install target dependencies.
- Dockerfile healing is deterministic and emits a reviewable unified diff.
- Secrets belong in ignored `.env` files. `.env.example` contains placeholders
  only.

## Project layout

```text
src/worksonmymachine/
├── app.py          FastAPI application and API routes
├── scanner.py      Cross-OS landmine scanner and source healer
├── apt_healer.py  Compiler parser and Dockerfile apt healer
├── repro_hash.py  Merkle hashing, certificates, and audit orchestration
├── cli.py          Click and Rich command-line interface
└── static/         Self-contained dashboard and SVG engine
tests/               Foundation, engine, API, CLI, and UI tests
demo_targets/        Intentionally broken sample repositories
```

## Configuration

Copy `.env.example` to `.env` for local overrides:

```dotenv
APP_HOST=0.0.0.0
APP_PORT=8000
LOG_LEVEL=INFO
STRICT_REPRO_MODE=true
SANDBOX_DIR=./demo_targets
LLM_API_KEY=
LLM_MODEL=gpt-4o-mini
```

The deterministic scanner, parser, healer, certificate engine, dashboard, and
tests work without `LLM_API_KEY` or any network connection.
