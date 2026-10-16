# Live watch mode

Run a scan-only polling watcher while developing:

```bash
worksonmymachine watch .
```

The watcher performs an initial scan, polls file metadata, waits for a changed
snapshot to settle, and then reruns the scanner. It reports new, changed, and
resolved findings without modifying the working tree. Stop it with `Ctrl+C`.

Useful options:

```bash
worksonmymachine watch . --interval 0.75 --debounce 0.35
worksonmymachine watch workspace --root /path/to/repository
```

The watcher uses only the Python standard library. Common generated and cache
directories are ignored, along with paths configured in
`.worksonmymachine.toml`. It is intentionally a debounced full rescan rather
than a dependency-aware incremental scanner, so import and Dockerfile changes
are evaluated with the same repository-wide rules as normal scans.
