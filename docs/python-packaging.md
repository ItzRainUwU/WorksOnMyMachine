# Modern Python packaging

Python dependency analysis recognizes both legacy and modern local metadata:

- `requirements.txt`, `requirements.in`, and `requirements.lock`
- PEP 621 `project.dependencies` and optional dependencies in `pyproject.toml`
- Poetry dependencies and dependency groups in `pyproject.toml`
- Pipenv `Pipfile` dependencies
- `poetry.lock`, `uv.lock`, and `Pipfile.lock`

The scanner reports unpinned declarations and missing or structurally invalid
lockfiles as local findings. It does not invoke a package manager or access the
network. The reproducibility score validates lockfile structure and checks that
declared package names are covered by the appropriate lockfile.

Valid lockfiles can resolve a range such as `requests>=2.31` to its exact local
locked version. Lockfiles are not generated automatically; regenerate them with
the project's package manager and commit the result.
