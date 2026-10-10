# Stability (proposal for 1.0)

!!! warning "Proposal: not adopted"
    Nothing on this page is a commitment yet. It drafts what AgentGuard would promise at
    1.0, for the maintainer to accept, change or reject. Until it is adopted, 0.x rules
    apply: minor versions may change the API, and only the latest minor release line gets
    security fixes (see [SECURITY.md](https://github.com/prollysamz/agentguard/blob/main/SECURITY.md)).
    Items marked **Decide** need an explicit choice.

## What 1.0 would mean

1.0 is published when the [exit criteria](security-review.md#exit-criteria-for-10) are met
(an independent review, an independently written holdout benchmark, no unmitigated known
weakness) and the commitments below are adopted. From 1.0, versions follow
[Semantic Versioning](https://semver.org/): breaking changes to the stable surface only in
a new major version.

## Proposed stable surface

| Surface | Proposed promise |
| --- | --- |
| Python API in [Public API](api.md) | Names, parameters and documented behavior keep working through 1.x. New optional parameters and new names may be added in minor versions. |
| Policy files with `version: 1` | Every field documented in [Policies](policy.md) keeps its meaning through 1.x, and unknown fields stay errors. A schema change that would alter a valid file's meaning becomes `version: 2`, and 1.x keeps loading `version: 1`. |
| Decision semantics | A matching `deny` rule wins, risk only makes a decision stricter, and approval never overrides a deny. |
| Audit log format | Event stages and fields documented in [Audit log](audit.md) keep their meaning; fields may be added. Logs written by any 1.x version stay verifiable by later 1.x versions. |
| CLI | Commands and options in [CLI](cli.md) keep working; human-readable output may change. |
| Exceptions | `GuardDenied`, `ApprovalPending` and `GuardError` keep their hierarchy and attributes. |

**Decide:** `docs/api.md` lists more public modules than the docstring in
`agentguard/__init__.py`, including `agentguard.bench.judge`, `agentguard.risk.commands`,
`agentguard.dashboard.app` and the audit exporters. Either promote them all to the stable
surface or mark some as provisional before 1.0.

## Proposed exclusions

These would be allowed to change in minor versions:

- **Detection results.** Which commands, paths and secrets are flagged, the risk scores
  they get, and the wording of reasons. Detection is expected to get stricter over time, as
  `core.hooksPath` did in 0.4.1. Changes that make a previously allowed action ask or deny
  would be listed under **Changed** in the changelog, not treated as breaking.
- **Semantic judges.** Prompts, models and their scores.
- **The demo, benchmarks and their datasets.**
- **Dashboard HTML and styling**, but not its HTTP API, login or CSRF behavior.
- **Everything not listed in [Public API](api.md).**

**Decide:** whether a detection change that *relaxes* a check (fixing a false positive)
should also be allowed in a minor version, or only in patch versions with a changelog note.

## Proposed deprecation process

1. Deprecate in a minor version: the old behavior keeps working and emits a
   `DeprecationWarning` naming the replacement, and the changelog lists it under
   **Deprecated**.
2. Keep it for at least one further minor version and at least 6 months.
3. Remove it only in the next major version.

Security fixes are the exception: a change that closes a bypass may break code that relied
on the bypass, and can ship in a patch version with a changelog note.

**Decide:** the minimum deprecation period (6 months is a placeholder).

## Proposed security support

| Line | Security fixes |
| --- | --- |
| Latest 1.x minor | Yes |
| Previous 1.x minor | For 6 months after the next minor ships |
| 0.x | Ends 3 months after 1.0 ships |

**Decide:** both windows (placeholders), and whether fixes are backported or only shipped
in the latest minor.

## Proposed triage

- Vulnerabilities are reported only through
  [private vulnerability reporting](https://github.com/prollysamz/agentguard/security/advisories/new),
  never public issues.
- Triage: the maintainer, @prollysamz. **Decide:** whether to name a second person who can
  triage and publish fixes when the maintainer is unavailable.
- Proposed targets: acknowledge within 7 days; for a confirmed critical or high issue, a
  fixed release or a published mitigation within 30 days. **Decide:** these targets.
- Fixes are prepared in a private advisory, released, then disclosed with a CVE where one
  applies.

## Open decisions

1. Which modules in [Public API](api.md) are stable at 1.0.
2. Whether relaxing a detection rule is allowed in a minor version.
3. The deprecation period.
4. The security support windows and the backport policy.
5. A second person for triage.
6. Response-time targets.
