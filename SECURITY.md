# Security policy

AgentGuard is alpha software (0.x). It has not had an independent security review; the
[security review guide](docs/security-review.md) scopes one and lists known weaknesses.
Review [THREAT_MODEL.md](THREAT_MODEL.md) before deployment.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.4.x (latest: 0.4.1) | Yes, released as a new 0.4 patch version |
| Earlier than 0.4 | No; upgrade to the latest release |

Before 1.0, only the latest minor release line receives security fixes. The support policy
proposed for 1.0 is in [docs/stability.md](docs/stability.md) and has not been adopted yet.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting:
<https://github.com/prollysamz/agentguard/security/advisories/new>.

Do not open a public issue, pull request or discussion for a vulnerability. If you are not
sure whether something is a vulnerability, report it privately. Treat these as
vulnerabilities:

- An action runs that policy, risk scoring or approval should have stopped.
- An executor reaches a path, host or command outside what it was configured to allow.
- Dashboard or approval authentication, CSRF or grant scoping can be bypassed.
- An audit log can be altered without `verify-log` detecting it.

Do not include credentials, personal data or a working exploit against a live third-party
system in any report.

A useful report includes the affected version, a minimal local reproduction, expected and
observed enforcement behavior, and whether an unapproved side effect occurred. Use synthetic
credentials and temporary files. Do not test against resources you do not own.

Reports are triaged by the maintainer ([@prollysamz](https://github.com/prollysamz)). Fixes
are coordinated in a private advisory and disclosed with the release that contains them.
