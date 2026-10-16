# WorksOnMyMachine Improvement Suggestions

This document records recommended future improvements for WorksOnMyMachine,
prioritized by expected impact on correctness, trust, performance, usability,
and adoption.

## Highest-Priority Improvements

### 1. Make Docker base-image pinning runtime-aware

Preserve the original runtime when replacing floating base images instead of
using one generic fallback for every Debian-family image.

Examples:

- `python:latest` -> `python:3.11.9-slim`
- `rust:latest` -> a pinned Rust Debian image
- `node:latest` -> a pinned Node Debian image
- `ubuntu:latest` -> a pinned Ubuntu release
- `alpine:latest` -> a pinned Alpine release

Add configurable policy values, for example:

```toml
[docker]
python_base = "python:3.11.9-slim"
rust_base = "rust:1.85-slim-bookworm"
node_base = "node:22-bookworm-slim"
```

This makes healing safer for projects that do not use Python.

### 2. Add explicit post-heal verification

Expose a clear before/after healing summary in the API and dashboard:

- Findings before healing
- Findings fixed
- Findings still present
- Files changed
- Readiness score delta
- Dependency score delta
- Certificate status
- Blocking reasons when certification fails

Example:

```json
{
  "before_findings": 12,
  "fixed_findings": 10,
  "remaining_findings": 2,
  "readiness_before": 62,
  "readiness_after": 94,
  "certificate_status": "not_certified",
  "blocking_reasons": [
    "Cargo.lock does not cover openssl",
    "Docker base image is still floating"
  ]
}
```

The product should show why a target was not certified rather than only
displaying a generic failure state.

### 3. Add incremental scanning and caching

Use the existing Merkle hashing as the basis for a cache keyed by:

- File path
- Content hash
- Scanner version
- Rule-set version

Only changed files would need rescanning. This would improve responsiveness on
large repositories while preserving deterministic results.

## Product and Architecture

### 4. Add rule packs

Move portability checks into independently versioned rule packs, such as:

- Python packaging
- Docker
- JavaScript and TypeScript
- Rust and Cargo
- Go modules
- Shell scripts
- CI configuration
- Kubernetes manifests

Every finding should include a rule ID, rule version, confidence, evidence,
remediation, and whether the fix is automatic, staged, or manual.

### 5. Add “Explain this finding” details

For every finding, show:

- Why it was detected
- Exact source lines
- The rule that triggered it
- The likely cross-platform failure scenario
- The proposed fix
- Whether the fix was applied
- How the after-scan verified the result

### 6. Add repository profiles

Provide profiles such as:

- Python service
- Rust native extension
- Node web application
- Monorepo
- Docker-only project
- CI validation mode

Profiles could configure expected runtimes, required lockfiles, allowed base
images, severity thresholds, ignored directories, build commands, and
certification policy.

## Dashboard and User Experience

### 7. Add URL-based navigation

Use URL fragments or query parameters for workspace navigation:

```text
/#dashboard
/#bugs
/#dependency
/#security
```

This enables browser back/forward navigation, bookmarks, reload persistence,
and links directly to an issue or workspace.

### 8. Add a dedicated Run History workspace

Expand report history with:

- Run timestamp
- Target
- Commit SHA
- Readiness score
- Finding count
- Certificate status
- Changed files
- Downloadable artifacts
- Comparison between historical runs

### 9. Improve large finding sets

Add pagination or virtual scrolling, sorting by severity/path/rule/status,
multi-select findings, bulk suppression with a required reason, saved filters,
and CSV export for filtered results.

### 10. Expand accessibility support

Add full keyboard navigation, visible focus states, dialog focus trapping,
screen-reader announcements for scan progress, reduced-motion support,
contrast checks, and accessible textual descriptions for the dependency graph.

## Security and Trust

### 11. Add redacted secret detection

Detect likely API keys, private keys, tokens, passwords, cloud credentials, and
accidentally committed `.env` files without exposing raw values.

Displayed evidence should be redacted, for example:

```text
AWS access key detected: AKIA••••••••••••••
```

Raw secrets must never appear in reports, logs, certificates, or examples.

### 12. Add signed certificates

Build on the Merkle certificate with optional Ed25519, Sigstore, or Cosign
signatures so certificates can be independently verified in CI or on another
machine.

### 13. Harden the staged-copy boundary

Add explicit protections and tests for symlink escapes, Windows junctions and
reparse points, TOCTOU changes during staging, nested output directories,
files changing during a scan, and malicious path names.

## CI and Integrations

### 14. Add GitHub annotations

Enhance the existing SARIF and GitHub Action support with inline pull-request
annotations, workflow summaries, certificate and patch artifacts, readiness
checks, and a default “new findings only” mode.

### 15. Add more CI templates

Provide ready-to-copy examples for GitLab CI, Azure Pipelines, Jenkins,
Buildkite, and generic shell-based CI.

### 16. Add a shared machine-readable policy file

Use one policy engine across the CLI, API, dashboard, GitHub Action, and
pre-commit hook:

```toml
[policy]
fail_on = "high"
min_readiness = 95
require_reproducible = true
allow_floating_docker_tags = false
require_lockfiles = true
```

## Testing and Reliability

### 17. Add Linux and macOS CI

The project promises cross-platform behavior, so CI should cover Windows,
Ubuntu, and macOS for path normalization, CRLF handling, shell executable-bit
behavior, symlinks, Dockerfile parsing, Merkle-root stability, and static asset
delivery.

### 18. Add property-based tests

Good candidates include path normalization, deterministic hashing, diff
generation, malformed parser input, and Docker stage selection. Tests should
prove that paths never escape the target root and ambiguous Docker stages are
never modified.

### 19. Add golden fixtures

Maintain expected JSON, SARIF, certificate, and patch outputs for representative
targets. This will prevent accidental output-format drift.

## Recommended Next Three

If only three improvements are implemented next, prioritize:

1. Runtime-aware Docker base-image policies
2. Explicit post-heal verification and remaining-finding explanations
3. Incremental scan caching using the existing Merkle hashes

Together, these improve correctness, user trust, and performance without
requiring a major architectural rewrite.
