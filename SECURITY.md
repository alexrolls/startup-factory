# Security policy

## Supported versions

During beta, security fixes are made for the most recent published release and
the current `main` branch. Older releases may be asked to upgrade before a fix
is provided. A release is supported only after its tag, package attestations,
and published checksums are available from the official repository.

## Reporting a vulnerability

Do not disclose vulnerability details, proof-of-concept code, credentials, or
affected-user data in a public issue, discussion, or pull request.

The intended intake is GitHub private vulnerability reporting for this
repository. Before announcing a beta, a release owner must verify from the
repository Security settings that private reporting is enabled and complete a
secret-free test of the intake and acknowledgement path. This repository does
not treat documentation, a URL, or an assumption about GitHub defaults as that
proof. Until current verification evidence exists, the automated beta check
reports the private disclosure criterion as not ready.

**Published-beta channel contract: available only after exact-candidate protected verification.**
The intended GitHub private-reporting channel is available for a published beta only
after that exact candidate has passed the protected, secret-free intake and
acknowledgement verification required by the beta-readiness checker.
**Unreleased-candidate status: current channel availability is not asserted.**

If the private-reporting option is unavailable, open a public issue containing
only the words “Security contact requested” and no vulnerability details. A
maintainer will establish a private channel. Do not send secrets until the
recipient and channel have been verified.

Include, where safe: the affected version and component, impact, minimal
reproduction steps, mitigations already attempted, and a way to coordinate.
Remove tokens, customer data, repository credentials, and private logs.

## Response targets

- Acknowledge a report within three business days.
- Complete initial severity and scope triage within seven business days.
- Share a remediation and disclosure plan after triage; timing depends on risk
  and on coordinated downstream fixes.
- Credit reporters who request it, unless doing so would expose sensitive data.

These are response targets, not a guarantee. Active exploitation or credential
exposure should be labelled urgent in the private report.

## Safe harbor

To the extent the maintainers control the systems involved, they will not
initiate legal action against good-faith research that follows this policy,
avoids privacy harm and service disruption, stops after establishing impact,
and gives the project a reasonable opportunity to remediate before disclosure.
Research must be limited to this project's explicitly owned and in-scope
repository artifacts. It does not authorize testing customer or contributor
data, provider infrastructure, third-party services, production deployments,
accounts, credentials, or systems merely referenced by an integration pack.

Denial of service, social engineering, persistence, lateral movement, data
exfiltration, credential use, and accessing more data than is necessary to
demonstrate the issue are outside this safe harbor. If sensitive data or a live
credential is encountered, stop, retain the minimum evidence, do not copy or
share it further, and request a verified private channel using the process
above. This statement cannot bind third parties, waive applicable law, or grant
permission that the maintainers do not possess.

## Disclosure and release process

Maintainers keep a confirmed report private while a fix and regression test are
prepared. The fix must pass the same exact-package validation and security
review as other release candidates. A fixed release or effective mitigation
must be available before, or at the same time as, the advisory is published.
The advisory should include affected and fixed versions, impact, mitigations,
and credit. Exploit-enabling detail is deferred until users have had a
reasonable opportunity to update. Revoked credentials and leaked data are
handled by the relevant service owner; this repository never stores them as
evidence.

No agent, pull request, or automated check has production or release authority.
The human release owner separately decides whether and when to publish. Merging
to `main` does not publish a release. Publication requires a manual exact-commit
workflow dispatch, approval through the protected `release` and `pypi`
environments, and fresh secret-free evidence from the protected
`release-evidence` branch that passes the exact-commit beta-readiness checker.
See `reference/beta-readiness.md` for the auditable transport and branch contract.
