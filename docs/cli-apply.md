# Applying safe repairs from the CLI

Normal scans, audits, the API, the dashboard, and the `check` command do not
modify the source repository. They prepare repairs in a temporary copy and
can emit a unified patch for review.

The CLI can apply those deterministic repairs only when explicitly requested:

```bash
worksonmymachine audit workspace --auto-heal --apply
```

Interactive use asks for confirmation. For an explicitly approved
non-interactive run, add `--yes`:

```bash
worksonmymachine audit workspace --auto-heal --apply --yes
```

`--apply` requires `--auto-heal`, and `--yes` is valid only with `--apply`.
The implementation stages the repair first, refuses to overwrite locally
modified Git files, rejects symlink or deletion replacements, detects source
changes while staging, and writes regular files atomically with rollback on a
write failure.

To apply repairs to a repository other than the installed package workspace,
provide its root explicitly:

```bash
worksonmymachine audit workspace \
  --root /path/to/repository \
  --auto-heal --apply
```
