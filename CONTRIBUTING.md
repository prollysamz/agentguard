# Contributing

Use Python 3.11+, a virtual environment and `python -m pip install -e ".[dev,all,docs]"`.
Run `python -m pytest -q`, `python -m ruff check .`, `python -m build` and
`mkdocs build --strict` before a pull request. User-facing changes need a docs update in
`docs/` and a `CHANGELOG.md` entry under Unreleased.

To release: bump `version` in `pyproject.toml`, move Unreleased entries under the new
version in `CHANGELOG.md`, merge, and wait for CI and Security to pass on the merged commit.
Then publish a GitHub release tagged `vX.Y.Z` on that commit. The release workflow publishes
to PyPI only if CI and Security passed on exactly that commit, the tag matches the version,
and the built wheel passes `scripts/smoke_test_wheel.sh` in clean environments on Linux,
Windows and macOS. Every CI and Security run on that commit counts, including nightly and
weekly runs; a failed run is cleared by re-running it, because the gate reads each run's
latest attempt. If a check was still pending, re-run the release workflow once it passes.
To exercise the gates without publishing, run the workflow manually from the Actions tab.

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), not in issues
or pull requests.

Keep policy, risk, approval, execution, verification and audit separate. Adapters only
translate/dispatch; security decisions belong in the shared Guard pipeline. Add regression
tests that prove a denied action never invokes its tool. Include failure and timeout cases
for new controls. Avoid live network/model dependencies in the default test suite.

Document security assumptions and limitations. Do not describe a working directory,
string matcher or Python wrapper as an OS sandbox. Keep examples free of real credentials
and make simulated external actions explicit. New policy fields must be validated; unknown
fields must not silently relax restrictions.

PRs should describe the problem, resulting behavior, relevant tests and security implications.
Discuss large new integrations before implementing them. The project uses the MIT license.

