# GitHub Action

WorksOnMyMachine ships an official root-level composite action in `action.yml`.
The action installs the checked-out package, runs the read-only `check` command
against the caller repository, and writes a SARIF report for GitHub Code
Scanning. It also emits one GitHub workflow annotation per SARIF finding and a
short `GITHUB_STEP_SUMMARY` by default. The check is read-only: it never passes
`--auto-heal` and needs only repository read access.

```yaml
name: Reproducibility

on: [push, pull_request]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: WorksOnMyMachine
        id: reproducibility
        uses: ./
        with:
          fail-on: high
          min-readiness: '80'
          new-only: 'true'
          baseline: .worksonmymachine-baseline.json
          output: artifacts/worksonmymachine.sarif
```

`target` defaults to `workspace`; `sarif-path` can be used as an alias for
`output`. The action passes the caller checkout explicitly as `--root` so the
CLI does not depend on the action package's installation directory.

## Annotations and job summary

`annotations` and `summary` default to `true`:

- `annotations: true` maps SARIF `error`, `warning`, and `note` results to
  `::error`, `::warning`, and `::notice` workflow commands, including file and
  line information when SARIF provides it.
- `summary: true` appends a compact findings count, result-level counts, and the
  report path to `GITHUB_STEP_SUMMARY`.

Finding messages, paths, and rule IDs are escaped for GitHub workflow-command
delimiters. Input paths are passed as quoted argument-array entries, so spaces,
commas, and shell metacharacters do not change the command. To keep only the
SARIF file and the existing `report-path`/`report` outputs, disable either
publication channel explicitly:

```yaml
with:
  annotations: 'false'
  summary: 'false'
```

The existing `report-path` output (with `report` as its alias) remains
backward-compatible. It contains the selected SARIF path even when the check
exits non-zero, allowing a later `if: always()` step to inspect or upload the
report.

Uploading SARIF to GitHub Code Scanning is optional and requires the additional
workflow permission `security-events: write`. Keep the action itself least
privileged with `contents: read`, then grant that permission only when adding
the upload step:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.reproducibility.outputs.report-path }}
```
