# Pre-commit integration

WorksOnMyMachine publishes a scan-only hook through `.pre-commit-hooks.yaml`.
Add it to a repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/OWNER/WorksOnMyMachine
    rev: v0.1.0
    hooks:
      - id: worksonmymachine-check
        args: [--fail-on, high]
```

The hook runs `worksonmymachine check --root .`, does not pass staged
filenames to the scanner, and runs for every commit because portability issues
can affect files other than the ones currently staged. It never enables
`--auto-heal` or modifies the working tree.

Replace `OWNER/WorksOnMyMachine` and `v0.1.0` with the published repository
and release tag.
