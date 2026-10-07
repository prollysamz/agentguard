# Contributing

Use Python 3.11+, a virtual environment and `python -m pip install -e ".[dev,all,docs]"`.
Run `python -m pytest -q`, `python -m ruff check .`, `python -m build` and
`mkdocs build --strict` before a pull request. User-facing changes need a docs update in
`docs/` and a `CHANGELOG.md` entry under Unreleased.

To release: bump `version` in `pyproject.toml`, move Unreleased entries under the new
version in `CHANGELOG.md`, merge, then publish a GitHub release tagged `vX.Y.Z`. The
release workflow builds, checks and publishes to PyPI.

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

