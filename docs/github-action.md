# GitHub Action

WorksOnMyMachine ships an official root-level composite action in `action.yml`.
The action installs the checked-out package, runs the read-only `check` command
against the caller repository, and writes a SARIF report for GitHub Code
Scanning.

```yaml
name: Reproducibility

on: [push, pull_request]

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
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.reproducibility.outputs.report-path }}
```

`target` defaults to `workspace`; `sarif-path` can be used as an alias for
`output`. The action passes the caller checkout explicitly as `--root` so the
CLI does not depend on the action package's installation directory.
