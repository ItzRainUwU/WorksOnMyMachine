# Node.js native addon diagnostics

The offline compiler-log parser recognizes evidence-backed native build
failures for common Node.js addons:

| Addon or failure | Debian/Ubuntu packages |
| --- | --- |
| `sharp` source/native build | `libvips-dev` |
| `canvas` native build | `libcairo2-dev`, `libpango1.0-dev`, `libgif-dev` |
| `node-gyp` missing Python/toolchain | `python3`, `make`, `g++` |

When a Dockerfile base image is Alpine or Fedora/RHEL-family, the Dockerfile
healer translates these recommendations to `apk` or `dnf` package names using
the same distro-aware package mapping as other native diagnostics.

Ordinary mentions of `sharp`, `canvas`, or `node-gyp` do not produce findings;
the parser requires native-build, missing-tool, or failure evidence. Parsing
remains offline and does not run npm, node-gyp, or a package manager.
