# Git executable-bit checks

On Windows, NTFS does not provide the POSIX executable bit that Linux uses for
shell entrypoints. WorksOnMyMachine therefore checks Git's index metadata for
tracked `.sh` files instead of trusting the host filesystem mode.

When a tracked script is stored with mode `100644`, the scanner reports an
`SHELL-NOT-EXECUTABLE` finding and recommends:

```bash
git update-index --chmod=+x path/to/entrypoint.sh
```

The check is read-only. It runs only when the target is inside a Git worktree
and safely skips non-Git targets, unavailable Git, failed Git commands, and
deleted working-tree files.
