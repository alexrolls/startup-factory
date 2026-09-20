# Beta readiness

Startup Factory is ready for a public beta only when every criterion reported
by `bin/beta-readiness.py` passes for the exact candidate commit. Missing,
stale, malformed, reused, or commit-mismatched evidence is not ready. The
checker does not publish, deploy, merge, authenticate a human, or grant release
authority.

## Documented product criteria

- A security policy defines a private disclosure and coordinated response path.
  It treats the intended channel as available for a published beta only after
  protected verification for that exact candidate; an unreleased candidate
  makes no current-availability claim.
- A concise quickstart and reproducible non-production walkthrough exist.
- The compatibility matrix distinguishes tested, untested, and unsupported use.
- Benchmark and usage measurement methods are reproducible and make no
  unsupported performance or cost claims.

These documents are read from Git blobs in the exact checked-out `HEAD`, not
from mutable working-tree files. `HEAD` is checked again before the result is
returned.

## Required evidence

The evidence envelope and every observation must be no more than 14 days old by
default. Observations cannot postdate the envelope. Every passing entry names a
distinct regular JSON artifact directly below
`.startup-factory/beta-evidence/`, with a unique artifact ID, path, and SHA-256.
Artifacts and every path component must not be symlinks.

All eight operational criteria are required:

- a release owner recorded a secret-free test of GitHub private vulnerability
  intake and acknowledgement;
- the runtime suite, packaging source suite, and packaging built-distribution
  suite exited zero from a clean checkout, each with a positive pass count and
  zero failures;
- two distinctly identified clean builds produced the same canonical release
  set: exact bundle, wheel, and sdist names and SHA-256 values;
- four distinct identities in the Principal Software Architect, Sceptical
  Architect, Senior QA Engineer, and Senior Security Engineer roles approved
  the same exact package;
- stable Python 3.10.x installed-release smoke and stable Python 3.14.x full
  runtime/package validation passed on typed Linux environments for the exact
  candidate and canonical release set;
- one protected execution of the documented, non-production walkthrough binds
  the micro profile decision, exact Markdown pack/plan, authenticated review
  receipts and evidence, completed integration transaction, and explicitly
  disabled and unattempted release/deployment authority;
- at least five successful cold and five successful warm walkthrough runs
  support nearest-rank p50/p95 values, and cold p50 is below 900,000 ms;
- a protected usage recorder attests that every expected agent-runtime run was
  recorded for the exact walkthrough/benchmark fixture and environment
  manifest. Each run records provider and wall time plus per-metric
  token/cache/cost values where exposed, or a non-empty reason for each
  unavailable field. Cost provenance also records pricing date and calculation
  or their explicit unavailable reasons. Unknown never means zero.

The full-validation, review, compatibility, governed-walkthrough, benchmark,
and usage artifacts must contain and bind the same canonical release-set
manifest digest established by the reproducible-package artifact. The
walkthrough and benchmark must also bind exactly the same fixture commit, task
ID, pack ID/digest, and environment-manifest digest. Binding only the bundle is
insufficient: the wheel and sdist are part of the reviewed release set.

## Evidence and artifact contract

The evidence JSON has exactly four top-level keys:

```json
{
  "schemaVersion": 1,
  "candidateCommit": "0123456789abcdef0123456789abcdef01234567",
  "generatedAt": "2026-09-19T12:00:00Z",
  "criteria": []
}
```

Each criterion entry has exactly `id`, `status`, `observedAt`, `evidencePath`,
`evidenceSha256`, and `detail`. Status is `pass`, `fail`, or `unknown`.
All timestamps use UTC `YYYY-MM-DDTHH:MM:SSZ` or, when exact millisecond
duration binding requires it, `YYYY-MM-DDTHH:MM:SS.mmmZ`; other precision and
offsets are rejected.
Non-passing entries use `null` artifact fields. A passing artifact has this
exact common envelope:

```json
{
  "schemaVersion": 1,
  "artifactId": "disclosure-check-20260919",
  "criterionId": "private-disclosure-channel",
  "candidateCommit": "0123456789abcdef0123456789abcdef01234567",
  "observedAt": "2026-09-19T11:55:00Z",
  "producer": {
    "identity": "release-owner@example",
    "role": "release-owner"
  },
  "payload": {
    "channel": "github-private-vulnerability-reporting",
    "intakeVerified": true,
    "acknowledgementVerified": true,
    "secretFreeTest": true
  }
}
```

The expected outer producer roles are `release-owner`, `qa-engineer`,
`integrator`, `review-board-recorder`, `compatibility-tester`,
`walkthrough-operator`, `benchmark-operator`, and `usage-recorder`,
respectively. Payloads are exact and criterion-specific:

- `private-disclosure-channel`: the channel string shown above plus the three
  verification booleans, all `true`.
- `full-validation`: true `cleanCheckout`, `releaseSet`, and exactly three
  canonical `checks` described below.
- `reproducible-package`: `builds`, exactly two objects with distinct `buildId`,
  true `cleanCheckout`, and identical valid `releaseSet` objects.
- `independent-exact-package-review`: `releaseSet` and exactly four `reviews`;
  each review has `role`, distinct `identity`, `decision: "approve"`, and fresh
  `reviewedAt` no later than the artifact observation.
- `exact-candidate-compatibility`: `releaseSet` and exactly two `results`, one
  stable Python 3.10.x `installed-release-smoke` and one stable Python 3.14.x
  `full-runtime-package`. Both use classification `tested`, non-WSL Linux, exact
  candidate/release-set bindings, named OS/architecture/Python/Git/Bash,
  fresh timestamps, zero exit/failure counts, positive passes, non-negative
  skips, and distinct environment-manifest and raw-evidence SHA-256 values.
- `governed-walkthrough-execution`: `releaseSet`, exact `candidateCommit`, and
  typed fixture, `profileDecision`, `selectedPack`, `reviewOutcome`,
  `integrationOutcome`, `authority`, timing, and raw-evidence objects. The
  fixture changes only `README.md`; the profile is `micro` but retains core
  review and exact-package evidence; the selected `tracker-markdown` pack is
  validated/configured with local proof `unknown`; and all release/deployment
  enabled/attempted flags are false. Review binds distinct schema-v2 broker
  receipt digests for the request and three core approvals plus schema-v8
  approval evidence and the review package. Completed integration binds its
  schema-v2 transaction ID/digest, commit, and those same package/approval
  digests.
- `first-governed-delivery-under-15m`: `releaseSet`,
  a fixed `fixture` binding its commit/task ID, pack ID/digest, and environment
  manifest digest; true `allAttemptsRecorded`; `percentileMethod:
  "nearest-rank"`; `targetMs: 900000`; `coldRuns`, `warmRuns`, `failures`; and
  the four calculated `coldP50Ms`, `coldP95Ms`, `warmP50Ms`, `warmP95Ms`
  fields. Every attempt has a globally unique `runId`, exact `cold`/`warm`
  state, ordered fresh UTC start/end, recomputable positive `durationMs`, status,
  bounded retry count, distinct raw-evidence SHA-256, and a null success or
  non-empty failure reason. Its `phaseTimings` are `setup`,
  `implementation-rework`, `review`, `integration`, `total` for success, or a
  non-empty completed prefix plus `total` for failure. Phases are positive,
  bounded, ordered, contiguous, span the run, sum exactly to total, and match
  their timestamps; total also equals the outer run interval and duration.
- `runtime-usage-observability`: `releaseSet`, `coverage`, and `records`.
  `coverage` has true `allAgentRunsRecorded`, the same fixture commit, task,
  pack id/digest, and environment-manifest digest as the walkthrough and
  benchmark, plus a sorted unique `expectedAgentRunIds` list. Records must
  exactly cover that list in order. Each record has a distinct `agentRunId`,
  an `agentId`, `runtime`, `model`, `provider`, `wallTimeMs`,
  `inputTokens`, `outputTokens`, `cacheTokens`, `providerCostMicros`, `currency`,
  `pricingDate`, and `costCalculation`. Numeric observations and text
  observations are exact `{ "value": value-or-null, "unavailableReason":
  string-or-null }` pairs; exactly one member is non-null. Known pricing dates
  use `YYYY-MM-DD` and cannot postdate the observation. Currency is a
  three-letter code only when cost is known. The same logical agent may appear
  in multiple records when it ran in multiple benchmark sessions; completeness
  is over run ids, not display names.

### Canonical release set

Every `releaseSet` has exactly `schemaVersion`, `artifacts`, and `sha256`.
`schemaVersion` is `1`. `artifacts` has exactly three entries in this order:
`bundle`, `wheel`, `sdist`. Each entry has only `kind`, a safe basename in
`name`, and lowercase `sha256`. Bundle names use
`startup-factory-X.Y.Z.tar.gz`; wheels use
`startup_factory-X.Y.Z-py3-none-any.whl`; sdists use
`startup_factory-X.Y.Z.tar.gz`. All three stable numeric versions must match,
and names and hashes are distinct.

The shared artifact version must also equal the static numeric
`project.version` read from `pyproject.toml` in the exact candidate Git tree.
Agreement among three unrelated artifact names is not sufficient.

The release-set `sha256` is calculated from the object containing only
`schemaVersion` and `artifacts`, encoded as ASCII JSON with keys sorted, no
insignificant whitespace, and separators `,` and `:`. It therefore binds the
artifact kinds, names, order, and bytes. The digest field itself is not part of
the hashed object.

### Canonical validation checks

Each full-validation check has exactly `id`, `argv`, `requiredEnvironment`,
integer `exitCode`, `testsPassed`, `testsFailed`, and `testsSkipped`. Exit code
and failures must be zero; passes must be positive; skips are recorded as a
non-negative integer. The three entries and their exact command contracts are:

| `id` | `argv` | required environment names |
| --- | --- | --- |
| `runtime-suite` | `["/bin/bash", "tests/run-all.sh"]` | `[]` |
| `packaging-source-suite` | `["python", "-m", "unittest", "discover", "-s", "tests/packaging", "-p", "test_*.py", "-v"]` | `[]` |
| `packaging-built-distribution-suite` | the same Python unittest argv | `["STARTUP_FACTORY_BUNDLE", "STARTUP_FACTORY_DIST_DIR"]` |

The environment list records required variable names, never their values. The
built-distribution check must run with paths to the exact release-set bundle
and distribution directory in its protected execution environment.

Unknown keys, duplicate keys or IDs, non-finite/non-integer numbers, unsafe or
non-canonical paths, non-regular exact-Git document entries, excessive JSON
size/depth/counts, artifact reuse, wrong producer roles, incomplete validation
commands, wrong calculations, stale/future timestamps, and release-set, digest,
candidate-version or commit mismatches, and recognized secret-like material fail
closed.

## Protected evidence transport and release authorization

Readiness evidence binds an already existing candidate commit, so it cannot be
part of that same commit. Local collection paths are intentionally ignored:
`.startup-factory/beta-readiness-evidence.json` and
`.startup-factory/beta-evidence/` remain transient in a candidate checkout.
They contain no credentials, provider tokens, private vulnerability details, or
raw private logs.

The release workflow transports those exact bytes through a dedicated protected
`release-evidence` branch. Configure that branch before beta release:

1. Make it an orphan/evidence-only branch whose complete tree consists of one
   regular mode-`100644` readiness envelope and exactly the regular JSON
   artifacts referenced by its passing entries at the two paths above. Protect
   it and restrict updates to evidence owners.
2. In a separate clean candidate checkout, collect records from protected
   systems, place only their secret-free normalized JSON at the ignored paths,
   and run this checker against the exact candidate commit. Evidence owners then
   commit those same bytes to the evidence-only branch (ignored paths require an
   intentional force-add in that separate evidence checkout).
3. Record the full current `main` commit and full protected evidence-branch tip.
   A release owner manually dispatches `.github/workflows/release.yml` with
   `release_commit` and `evidence_commit` set to those two hashes, selecting
   `main` as the workflow ref. The requested release hash must also be the exact
   `GITHUB_SHA` from which that dispatch runs.
4. The protected `release` environment requires a human reviewer. The workflow
   proves that the first hash is still `origin/main` and the second is still the
   `release-evidence` tip, reads only allowlisted bounded regular Git blobs, and
   runs this checker before building, attesting, or publishing anything. The
   checker exports the validated canonical release-set digest; after rebuilding
   twice, the workflow recomputes the digest from the actual bundle, wheel, and
   sdist names and bytes and refuses any mismatch before artifact upload.
5. The protected `pypi` environment requires a separate human approval. After
   that approval, the publish job rechecks both `main` and `release-evidence`,
   freshly extracts the same bounded evidence commit, reruns this checker for
   freshness and exact commit/version/release-set identity, and verifies the
   downloaded bundle, checksum sidecar, wheel, and sdist against the authorized
   canonical release-set digest. It then performs one final live check of both
   protected branch tips immediately before trusted publishing. Before invoking
   the trusted publisher, it reconciles the public PyPI version against the
   exact local wheel and sdist. An absent version publishes both files; a
   partial version is resumable only when every existing file has the exact
   approved SHA-256, is not yanked, and carries exactly one PyPI Integrity API
   publish attestation from this repository's `release.yml` workflow and
   protected `pypi` environment. The action then receives a private directory
   containing only the still-missing exact files. A complete exact version
   skips upload. The workflow never enables `skip-existing`, and a mismatch,
   unexpected file, missing/foreign provenance, malformed response, any
   redirect, timeout, or oversized response fails closed. The reconciler treats
   PyPI's HTTPS Integrity API as the remote trust boundary: it validates PyPI's
   Trusted Publisher identity, bounded certificate/transparency material, and
   exact signed statement subject and digest; it does not claim to perform a
   second local Sigstore signature verification. A post-publication check
   retries bounded incomplete publication, temporary API unavailability, and
   Integrity-provenance propagation for up to 18 attempts within the
   publish job's 10-minute timeout, while every deterministic mismatch still
   stops immediately. It then requires the
   complete exact remotely attested set before public installation or the
   GitHub release can proceed. The GitHub release uses those same authorized,
   tested artifact bytes.

The workflow run, environment approvals, protected branch audit, and the two
input hashes form the transport audit trail. Repository administrators must
configure and periodically verify those GitHub protections; YAML cannot create
or attest its own branch/environment settings. A failed or absent protection is
not permission to publish manually.

### Publication recovery

PyPI files are immutable, while the tag and GitHub release intentionally become
public only after PyPI installation succeeds. Recover the same workflow run;
do not compensate with a manual upload, tag, release, deletion, or changed
artifact:

1. If `publish` succeeded and `verify-uvx` or `github-release` failed, choose
   **Re-run failed jobs** for that run. This preserves the successful protected
   publication and reruns only the failed job and its dependants. The GitHub
   release step reconciles an existing draft and re-verifies every asset byte.
2. If `publish` itself failed with an uncertain outcome, use **Re-run failed
   jobs**. The fresh protected job revalidates both authorized branch tips and
   evidence, then classifies PyPI as absent, `partial-exact`, `complete-exact`,
   or conflict. It uploads only exact missing files or skips upload when the set
   is already complete; it never trusts a duplicate-file skip.
3. Any conflict is an andon. Preserve the workflow and PyPI audit evidence and
   investigate it as a release incident. Do not reuse or overwrite that public
   version. If repository owners decide the affected version must be yanked,
   yanking does not make the filename reusable; prepare a new patch version,
   regenerate exact-candidate evidence, and dispatch a new protected release.

A full rerun or fresh dispatch is still subject to current-main, evidence-tip,
freshness, environment-approval, exact-byte, and public-provenance checks, but
**Re-run failed jobs** is the bounded recovery path because it avoids repeating
already successful privileged work.

## Offline authenticity boundary

This checker verifies bytes, consistency, and objective mechanics. A producer
identity inside JSON is asserted metadata, not a signature and not proof that a
person or provider performed the work. The release owner must collect records
from access-controlled CI, review, disclosure, and runtime systems, retain their
native audit links outside this secret-free repository evidence, and separately
decide whether those sources are authentic. Never manufacture a passing JSON
record from a prose assertion. The benchmark producer's
`allAttemptsRecorded: true` and usage recorder's
`allAgentRunsRecorded: true` must likewise be authenticated by the external
evidence system; an offline file cannot prove completeness by itself.

Run a deterministic evaluation at a recorded time:

```bash
python3 bin/beta-readiness.py --project . \
  --evidence .startup-factory/beta-readiness-evidence.json \
  --at 2026-09-19T12:00:00Z --json
```

Exit `0` means structurally ready, `1` means valid but not ready, and `2` means
invalid or unsafe input. Without external evidence, the normal repository
result is intentionally not ready—documentation alone never establishes an
operational criterion. JSON output includes `candidateVersion` and the validated
`releaseSetSha256` (or `null` when no canonical set is present), allowing the
protected release workflow to compare rebuilt artifact names and bytes with the
already approved release set.
