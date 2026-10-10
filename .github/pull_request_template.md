## Problem

<!-- What is wrong or missing, and who is affected? Link the issue if there is one. -->

## Change

<!-- The resulting behavior. Call out any change to decisions, policy fields, the public API or the audit log format. -->

## Tests

<!-- What proves it works, including failure and timeout cases. For a new control, a test that a denied action never invokes its tool. -->

## Security implications

<!-- Could this relax a control, widen what runs without approval, or change what is audited? "None" is a valid answer if you have checked. -->

## Checklist

- [ ] `python -m pytest -q`, `python -m ruff check .` and `python -m ruff format --check .` pass
- [ ] `python -m build` and `mkdocs build --strict` pass
- [ ] Docs in `docs/` updated for user-facing changes
- [ ] `CHANGELOG.md` entry under Unreleased
- [ ] No real credentials, tokens or personal data in code, tests or examples
