# Delivery benchmark methodology

This document defines how to measure Startup Factory delivery latency and
runtime usage. It contains no benchmark result. A result is valid only when its
raw evidence is bound to the exact candidate commit and canonical bundle,
wheel, and sdist release-set digest.

## Benchmark question

Measure elapsed time from a clean installation command to the first governed,
validated, non-production delivery artifact. Report cold and warm runs
separately. The beta target is a cold p50 below 15 minutes; p95 is reported but
has no target until enough observations exist.

## Fixed fixture

Use clones of one committed disposable Git fixture with the published example
task and one exact reference integration pack. Record the fixture commit, task
ID, pack ID and SHA-256, plus the SHA-256 of an environment manifest that pins
the Startup Factory version/commit, Python, Git, shell, operating-system image,
selected agent runtime and model, adapter, CPU architecture, logical cores,
memory, network class, CI runner image, and the complete expected agent-run
roster with stable run ids. Bind the exact bundle/wheel/sdist release-set
manifest as well. Record the test-runner and governed broker Python paths and
versions separately; they can differ. Never benchmark against production.

## Procedure

1. For a cold run, remove only the disposable fixture and documented caches;
   for a warm run, retain the explicitly named caches.
2. Install the candidate from its verified wheel and bundle; record the complete
   canonical release-set manifest and digest.
3. Run the quickstart without undocumented setup. Stop the clock only when the
   exact output has validation evidence and a review decision.
4. Record a `phaseTimings` array with the exact successful-run order `setup`,
   `implementation-rework`, `review`, `integration`, `total`. Every entry has
   its phase name, UTC start/end in `YYYY-MM-DDTHH:MM:SS[.mmm]Z` form, and a
   positive integer `durationMs`. Give every attempt a distinct ID, `cold` or
   `warm` state, the same outer start/end and total duration, retry count,
   status, and SHA-256 of its raw transcript. Record failures and retries rather
   than deleting them.
5. Complete at least five successful cold and five successful warm runs; retain
   every failure separately rather than replacing it. Report count, min,
   median/p50, p95, max, and failures. Beta evidence uses integer milliseconds
   and the nearest-rank method: sort successful durations and select the value
   at rank `ceil(percentile / 100 * count)` (one-based).

The beta latency criterion passes only when the validated cold p50 is strictly
below 900,000 milliseconds. A single fast run never satisfies the criterion.

### Objective phase boundaries

- `setup` starts with the installation command and ends when install, verify,
  initialization, pack application, and local doctor are ready for the task.
- `implementation-rework` starts when governed task work begins and includes
  planning, implementation, validation before submission, and every rework
  cycle. It ends when the final exact package is submitted for review.
- `review` starts with that final submission and ends only after the request and
  all required approvals have authenticated publication receipts and current
  exact-package evidence.
- `integration` starts after approval and ends when the governed integration
  transaction reaches its completed state.
- `total` spans the complete attempt and must exactly equal the outer run
  timestamps and `durationMs`.

The four non-total phases must be contiguous, strictly ordered, cover the whole
total interval without gaps or overlap, and sum exactly to total. A successful
attempt records all four. A failed attempt records the non-empty completed
prefix in the same order followed by `total`; it never invents a phase that did
not complete. Every phase and total duration is recomputed from its timestamps,
must be positive, and is bounded to 24 hours.

## Usage and cost

Record each expected agent-runtime invocation under its stable run id, agent ID,
runtime, and model. The protected usage recorder attests
`allAgentRunsRecorded: true`; its sorted expected run-id list must exactly equal
the records and bind the same fixture, pack, and environment-manifest digest as
the walkthrough and benchmark. Record provider, wall time, input/output tokens,
cache tokens, provider cost in integer micros,
currency, pricing date, and cost-calculation provenance when exposed. Every
variable observation uses a value-or-reason pair: if a trustworthy value is not
exposed, store `null` plus a specific non-empty unavailability reason. Do not
estimate a missing value or convert absence to zero. Such a field is `unknown`
in summaries, never zero. A known pricing date uses `YYYY-MM-DD`; a known cost
uses a three-letter currency. Infrastructure and third-party service cost
remain separate from provider cost.

## Evidence record

Store each command transcript with secrets redacted, the fixture commit,
candidate commit, canonical release-set manifest/digest, environment manifest,
per-attempt JSON, summary calculation, and SHA-256 of every raw evidence
artifact. The protected benchmark producer must attest `allAttemptsRecorded:
true`; successful runs carry `failureReason: null`, while every failed attempt
has a bounded non-empty reason. The readiness checker requires fresh ordered UTC
timestamps, validates phase order/coverage/contiguity/sum, recomputes each
duration and percentile, rejects reused raw-evidence digests, and validates the
fixed fixture/pack/environment bindings. The benchmark fixture bindings must
exactly match the governed walkthrough artifact. A reviewer must still verify
the protected producer and retained raw records: offline JSON cannot prove that
an attempt was not omitted. Results from a different commit, release set,
changed fixture, or undocumented retry do not satisfy beta readiness.
