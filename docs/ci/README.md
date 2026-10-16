# Copy-ready CI templates

These examples run the same reproducibility checks on CI systems that do not
use GitHub Actions.  They intentionally keep the runtime pinned to the
repository's `.python-version` value (`3.11.9` today), install from the
checked-in `requirements.txt` plus `requirements.lock`, and run `make test`.
The test command itself is offline: it reads only the checked-out source and
the already-installed, locked environment.

Copy the provider-specific file into the conventional location for that CI
system, then adjust only the cache/wheelhouse setup required by your runner.
No signing key is required for an unsigned audit.  Signing is opt-in; inject a
key through the CI secret store and pass it to `worksonmymachine certify` only
when an independently verifiable certificate is required.

| Provider | Template |
| --- | --- |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) |
| Azure Pipelines | [`azure-pipelines.yml`](azure-pipelines.yml) |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) |
| Buildkite | [`buildkite.pipeline.yml`](buildkite.pipeline.yml) |
| Generic shell | [`shell-ci.sh`](shell-ci.sh) |

The examples do not invoke Docker, package managers, or network services
during the test step.
