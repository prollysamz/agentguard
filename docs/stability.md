# Stability (proposal for 1.0)

!!! warning "Proposal: not adopted"
    Nothing on this page is a commitment yet. It describes what AgentGuard would promise at
    1.0. The maintainer chose the direction below on 2026-10-10, but the page has not been
    adopted, and it does not authorize a 1.0 release. Until it is adopted, 0.x rules apply:
    minor versions may change the API, and only the latest minor release line gets security
    fixes (see [SECURITY.md](https://github.com/prollysamz/agentguard/blob/main/SECURITY.md)).

## What 1.0 would mean

1.0 is published when the [exit criteria](security-review.md#exit-criteria-for-10) are met
(an independent review, an independently written holdout benchmark, no unmitigated known
weakness) and this page is adopted. From 1.0, versions follow
[Semantic Versioning](https://semver.org/): breaking changes to the stable surface only in
a new major version.

## Proposed stable surface

Only explicitly designated public APIs and policy fields are stable.
[Public API](api.md) is the list of designated names; the package docstring points to it.

| Surface | Proposed promise |
| --- | --- |
| Python API listed as public in [Public API](api.md) | Names, parameters and documented behavior keep working through 1.x. New optional parameters and new names may be added in minor versions. |
| Policy fields documented in [Policies](policy.md), `version: 1` | Each field keeps its meaning through 1.x, and unknown fields stay errors. A schema change that would alter a valid file's meaning becomes `version: 2`, and 1.x keeps loading `version: 1`. |
| Decision semantics | A matching `deny` rule wins, risk only makes a decision stricter, and approval never overrides a deny. |
| Audit log format | Event stages and fields documented in [Audit log](audit.md) keep their meaning; fields may be added. Logs written by any 1.x version stay verifiable by later 1.x versions. |
| CLI | Commands and options in [CLI](cli.md) keep working; human-readable output may change. |
| Exceptions | `GuardDenied`, `ApprovalPending` and `GuardError` keep their hierarchy and attributes. |

## Provisional and excluded

These may change in minor versions:

- **Provisional modules** listed in [Public API](api.md#provisional-modules): benchmark
  helpers (`agentguard.bench`), command-analysis internals (`agentguard.risk.commands`)
  and dashboard internals (`agentguard.dashboard`). Changes get a changelog note.
- **Detection results:** which commands, paths and secrets are flagged, their risk scores
  and the wording of reasons.
    - *Stricter detection* (an allowed action now asks or is denied) may ship in a minor
      release, listed under **Changed** in the changelog. 0.4.1's `core.hooksPath` check is
      an example.
    - *Narrowly scoped false-positive fixes* may ship in a minor release, each with a
      regression test for the case it stops flagging and a release note.
    - *A change that weakens an intentional security boundary* (for example, no longer
      treating a credential path as sensitive, or letting a class of commands run without
      asking) is not a false-positive fix. It needs a separate review before release,
      whatever version it ships in.
- **Semantic judges:** prompts, models and their scores.
- **The demo, benchmarks and their datasets.**
- **Everything not listed in [Public API](api.md).**

## Proposed deprecation process

1. Deprecate in a minor version: the old behavior keeps working and emits a
   `DeprecationWarning` naming the replacement, and the changelog lists it under
   **Deprecated**.
2. Keep it for at least one further minor release **and** at least six months.
3. Remove it only in the next major version.

Security fixes are the exception: a change that closes a bypass may break code that relied
on the bypass, and can ship in a patch version with a changelog note.

## Proposed security support

| Line | Security fixes |
| --- | --- |
| Latest 1.x minor | Yes |
| Earlier 1.x minors | No; upgrade to the latest minor |
| 0.4.x | For three months after 1.0 ships, then no |

There are no guaranteed backports to unsupported versions. A critical fix may be backported
on a case-by-case basis.

## Proposed triage

- Vulnerabilities are reported only through
  [private vulnerability reporting](https://github.com/prollysamz/agentguard/security/advisories/new),
  never public issues.
- AgentGuard currently has one maintainer, @prollysamz, who triages reports. There is no
  backup maintainer yet.
- Target: acknowledge a report within seven days, on a best-effort basis. There is no fixed
  resolution deadline; the maintainer communicates progress and any mitigations to the
  reporter as the investigation goes on.
- Disclosure is coordinated through a private advisory when a fix or mitigation is
  available.

## Before this can be adopted

- **Find a backup maintainer** who can triage reports and ship a fix when the maintainer is
  unavailable. This is an open task.
- Meet the [1.0 exit criteria](security-review.md#exit-criteria-for-10).
- The maintainer explicitly adopts this page, removes the proposal label and moves the
  commitments into `SECURITY.md`.
