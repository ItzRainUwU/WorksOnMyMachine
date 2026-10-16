#!/usr/bin/env bash
# Generic POSIX CI entry point.  Run from the repository root.
set -euo pipefail

test "$(tr -d '\r\n' < .python-version)" = "3.11.9"
python3.11 -m venv .venv
.venv/bin/python -m pip install --requirement requirements.txt --constraint requirements.lock

# Offline test command: pytest does not contact package indexes or services.
.venv/bin/python -m pytest
