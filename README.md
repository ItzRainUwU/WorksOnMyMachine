# WorksOnMyMachine

WorksOnMyMachine is an autonomous Cross-OS (Windows/macOS-to-Linux)
reproducibility platform for the Frontier Buildathon 2026 Developer Tools &
Open Source track. The final Phase 5 build includes a self-contained CleanRoom
cyber-engineering dashboard, deterministic certificate evidence, and three
deliberately broken repositories for repeatable diagnosis.

## Architecture

```text
                        +-----------------------------+
                         | Dashboard + FastAPI API      |
                         | local SVG control plane      |
                        +--------------+--------------+
                                       |
                    +------------------+------------------+
                    |                                     |
          +---------v----------+                +---------v----------+
          | Scanner engine    |                | Evidence engine    |
          | Phase 2            |                | CleanRoom proof    |
          | landmines/logs     |                | Merkle certificates|
          +---------+----------+                +--------------------+
                    |
          +---------v----------+                +--------------------+
          | Docker auto-healer|                | Pydantic contracts |
          | Phase 4           |                | shared API models  |
          +--------------------+                +--------------------+
```

The repository is intentionally split into a `src/` package, local-only tests,
and `demo_targets/` fixtures. The dashboard and engine do not call external APIs
by default or execute untrusted target code. Target paths cross the API boundary
only as normalized POSIX-relative paths.

## Requirements

- Python **3.11.9**, pinned in `.python-version` and `runtime.txt`.
- Docker (optional) for an isolated production-style run.
- A POSIX shell for the commands below. On Windows, use WSL or translate the  
  virtual-environment activation command for PowerShell.

## Setup

```bash
git clone <repository-url> WorksOnMyMachine
cd WorksOnMyMachine
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements.txt
```

The direct dependencies are pinned in `requirements.txt`; the matching
reviewable lock/constraints companion is `requirements.lock`. Copy the safe
configuration template only if you need to override defaults:

```bash
cp .env.example .env
```

No API keys are needed for the service, dashboard, or tests.

The Phase 3 compiler parser is deterministic and offline-first. `LLM_API_KEY`
is optional; when configured, the hybrid analyzer may enrich the local result
through the bounded OpenAI-compatible hook, but package recommendations always
start with the local rule engine.

## Run

Run the API locally from the repository root:

```bash
. .venv/bin/activate
python -m uvicorn --app-dir src worksonmymachine.app:app --host 0.0.0.0 --port 8000
```

Then visit `http://127.0.0.1:8000/health` or
`http://127.0.0.1:8000/api/v1/targets`.

## Scan and heal a target

Phase 2 scans imports, paths, shell metadata, environment drift, and
dependency pins without executing target code. Healing always operates on a
copy in a temporary staging directory and returns unified diffs; the original
fixture is never overwritten.

```bash
curl --request POST http://127.0.0.1:8000/api/v1/scan \
  --header 'Content-Type: application/json' \
  --data '{"target":"nightmare_ml_service"}'

curl --request POST http://127.0.0.1:8000/api/v1/heal \
  --header 'Content-Type: application/json' \
  --data '{"target":"case_sensitive_webapp"}'
```

Parse a captured compiler log and harden a Dockerfile:

```bash
curl --request POST http://127.0.0.1:8000/api/v1/parse-log \
  --header 'Content-Type: application/json' \
  --data '{"target":"rust_crypto_worker"}'

curl --request POST http://127.0.0.1:8000/api/v1/heal-dockerfile \
  --header 'Content-Type: application/json' \
  --data '{"target":"nightmare_ml_service"}'
```

The same workflow is available from the local CLI:

```bash
PYTHONPATH=src python -m worksonmymachine scan nightmare_ml_service
PYTHONPATH=src python -m worksonmymachine parse-log nightmare_ml_service
PYTHONPATH=src python -m worksonmymachine certify nightmare_ml_service --json
PYTHONPATH=src python -m worksonmymachine heal nightmare_ml_service --json
```

The certificate Merkle root contains only normalized file content and relative
POSIX paths. Filesystem timestamps, ownership, inode values, and enumeration
order are deliberately excluded.

## Dashboard

Run the API and open `http://127.0.0.1:8000/`. The dashboard is served from
the local package and has no CDN, icon font, or external JavaScript dependency.
It includes custom inline SVG telemetry, landmine and compiler views, Dockerfile
diffs, Merkle evidence, CleanRoom certificates, target selection, copy actions,
and a live audit telemetry drawer.

## Docker build and run

```bash
docker build --tag worksonmymachine:phase5 .
docker run --rm --publish 8000:8000 worksonmymachine:phase5
```

The image uses `python:3.11.9-slim`, installs the pinned requirements, runs as
the non-root `appuser`, and exposes port `8000`.

## Test

The single offline test command is:

```bash
. .venv/bin/activate
make test
```

Equivalent direct invocation:

```bash
python -m pytest
```

The suite validates public Pydantic schemas, relative-path safety, scanner and
healer behavior, compiler parsing, Merkle determinism, CLI commands, dashboard
assets, API workflows, and demo-target immutability. It does not make network
calls or require external credentials.

## API reference

The FastAPI OpenAPI page is available at `/docs` while the server is running.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Serve the local CleanRoom dashboard |
| `GET` | `/api/v1/targets` | List available target repositories |
| `POST` | `/api/v1/scan` | Scan landmines without modifying a target |
| `POST` | `/api/v1/parse-log` | Parse a target or raw compiler log |
| `POST` | `/api/v1/heal` | Heal source/config files in staging |
| `POST` | `/api/v1/heal-dockerfile` | Harden a staged Dockerfile |
| `POST` | `/api/v1/certify` | Generate a deterministic certificate |
| `POST` | `/api/v1/compare` | Compare certificate file and score drift |
| `POST` | `/api/v1/audit` | Run the unified audit/heal workflow |

## Demo targets

- `demo_targets/nightmare_ml_service/` — Windows paths, a missing model-bucket
  environment variable, CRLF shell input, an unpinned Python image, and native
  ML/PostgreSQL runtime failures.
- `demo_targets/case_sensitive_webapp/` — Python and JavaScript import casing
  that appears to work on case-insensitive filesystems but fails on Linux, plus
  unpinned Python dependencies and a floating Docker base image.
- `demo_targets/rust_crypto_worker/` — native `libffi`/OpenSSL header failures,
  a missing Cargo toolchain scenario, and an intentionally stale lockfile.

Each target contains a simulated `build_error.log`. The fixtures intentionally
remain broken; the scanner and healers operate on copy-on-write staging output
and never overwrite these source repositories.

## Reproducibility policy

All runtime inputs needed to rebuild the service live in this
repository. Paths are resolved from `Path(__file__).resolve().parent` and
project-relative descendants; no workstation-specific absolute path is stored
in the application. Secrets belong in ignored `.env` files and are never
committed.
