# WorksOnMyMachine Improvement Suggestions

This document records recommended future improvements for WorksOnMyMachine,  
prioritized by expected impact on correctness, trust, performance, usability,  
and adoption.

## Highest-Priority Improvements

### 1. [DONE] Make Docker base-image pinning runtime-aware

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

**Completed 2026-10-16:** Dockerfile healing now uses explicit runtime-aware
defaults for Python, Rust, Node.js, Ubuntu, and Alpine images. Fully pinned tags,
digest references, runtime variants, and package-manager selection are preserved.
See `docs/native-package-managers.md` and the regression coverage in
`tests/test_apt_healer.py`.

### 2. [DONE] Add explicit post-heal verification

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

**Completed 2026-10-16:** Auto-healed audits now expose a typed
`post_heal_summary` with before/fixed/remaining findings, changed files,
readiness and dependency deltas, certificate status, and evidence-derived
blocking reasons. JSON and Markdown exports include the summary.

### 3. [DONE] Add incremental scanning and caching

Use the existing Merkle hashing as the basis for a cache keyed by:

- File path
- Content hash
- Scanner version
- Rule-set version

Only changed files would need rescanning. This would improve responsiveness on  
large repositories while preserving deterministic results.

**Completed 2026-10-16:** `worksonmymachine.incremental` provides a portable
cache keyed by file content, metadata, scanner version, and rule-set version.
Unchanged files reuse validated findings; changed, removed, or invalidated
entries are rescanned safely. The cache is available to callers without
changing the default full-scan behavior.

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

### 5. [DONE] Add “Explain this finding” details

For every finding, show:

- Why it was detected
- Exact source lines
- The rule that triggered it
- The likely cross-platform failure scenario
- The proposed fix
- Whether the fix was applied
- How the after-scan verified the result

**Completed 2026-10-16:** The API and dashboard issue drawer now provide
bounded source context, rule/category/severity, detection rationale,
cross-platform scenario, redacted evidence, remediation, fixed/open status,
and post-heal after-scan verification.

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

### 11. [DONE] Add redacted secret detection

Detect likely API keys, private keys, tokens, passwords, cloud credentials, and  
accidentally committed `.env` files without exposing raw values.

Displayed evidence should be redacted, for example:

```text
AWS access key detected: AKIA••••••••••••••
```

Raw secrets must never appear in reports, logs, certificates, or examples.

**Completed 2026-10-16:** The scanner detects high-confidence credential-shaped
assignments, provider tokens, PEM markers, cloud credentials, passwords, and
committed `.env`-style files while redacting evidence and suppressing
placeholders, documentation examples, lookups, and safe templates.

### 12. Add signed certificates

Build on the Merkle certificate with optional Ed25519, Sigstore, or Cosign  
signatures so certificates can be independently verified in CI or on another  
machine.

### 13. [DONE] Harden the staged-copy boundary

Add explicit protections and tests for symlink escapes, Windows junctions and  
reparse points, TOCTOU changes during staging, nested output directories,  
files changing during a scan, and malicious path names.

**Completed 2026-10-16:** Staging and apply paths now detect and reject
symlink/junction/reparse escapes, unsafe relative names, nested output escapes,
source changes during staging, and stale staged results before writes. Atomic
apply rollback protections remain in place.

## CI and Integrations

### 14. [DONE] Add GitHub annotations

Enhance the existing SARIF and GitHub Action support with inline pull-request  
annotations, workflow summaries, certificate and patch artifacts, readiness  
checks, and a default “new findings only” mode.

**Completed 2026-10-16:** The official action can emit escaped GitHub workflow
annotations and a concise `GITHUB_STEP_SUMMARY`, with opt-out inputs and the
existing report outputs preserved.

### 15. Add more CI templates

Provide ready-to-copy examples for GitLab CI, Azure Pipelines, Jenkins,  
Buildkite, and generic shell-based CI.

### 16. [DONE] Add a shared machine-readable policy file

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

**Completed 2026-10-16:** `.worksonmymachine.toml` now accepts a validated
`[policy]` table with shared defaults for severity gates, readiness,
reproducibility, floating Docker tags, and lockfile requirements. The immutable
policy object and loader helpers are available to CLI, API, and integration
consumers.

## Testing and Reliability

### 17. [DONE] Add Linux and macOS CI

The project promises cross-platform behavior, so CI should cover Windows,  
Ubuntu, and macOS for path normalization, CRLF handling, shell executable-bit  
behavior, symlinks, Dockerfile parsing, Merkle-root stability, and static asset  
delivery.

**Completed 2026-10-16:** `.github/workflows/cross-platform.yml` tests the
pinned Python project on Windows, Ubuntu, and macOS, installs locked
dependencies, runs the offline test command, and conditionally checks tracked
JavaScript syntax without requiring Docker.

### 18. [DONE] Add property-based tests

Good candidates include path normalization, deterministic hashing, diff  
generation, malformed parser input, and Docker stage selection. Tests should  
prove that paths never escape the target root and ambiguous Docker stages are  
never modified.

**Completed 2026-10-16:** Deterministic standard-library generative tests now
exercise path containment, malformed parser inputs, Merkle order independence,
Docker stage ambiguity, and stable diff generation.

### 19. [DONE] Add golden fixtures

Maintain expected JSON, SARIF, certificate, and patch outputs for representative  
targets. This will prevent accidental output-format drift.

**Completed 2026-10-16:** Golden JSON, SARIF, certificate, and unified-patch
fixtures now protect representative serialized outputs with normalization only
for generated timestamps.

## Recommended Next Three

If only three improvements are implemented next, prioritize:

1. Runtime-aware Docker base-image policies
2. Explicit post-heal verification and remaining-finding explanations
3. Incremental scan caching using the existing Merkle hashes

Together, these improve correctness, user trust, and performance without  
requiring a major architectural rewrite.
