# Evidence providers

Startup Factory treats browser and other provider output as **untrusted
diagnostic evidence**. Schema validation proves only that a bounded manifest
and its local artifacts are internally consistent and bound to caller-supplied
expectations. It never constitutes QA approval, architecture approval, tracker
authority, or permission to bypass a configured validation or review gate.

## Browser manifest version 1

The top-level object has exactly these fields:

`schemaVersion`, `provider`, `subject`, `capability`, `invocation`, `target`,
`status`, `assertions`, `artifacts`, and `redactions`.

- `provider`: `id`, `version`, `executableSha256`
- `subject`: `taskId`, positive `attempt`, and lowercase 40-hex `commit`
- `capability`: `browser-qa`
- `invocation`: `sanitizedArgv`, the fixed environment-name list
  `LANG, LC_ALL, TZ`, and ordered RFC3339 UTC `startedAt`/`finishedAt`
- `target`: one canonical HTTP(S) `origin` and a sorted, unique
  `allowedOrigins` list that includes it
- `status`: `passed`, `failed`, or `error`
- each assertion has exactly `id`, `acceptanceCriterion`, `entryPath`, `status`,
  `behavioral`, `precondition`, `consoleErrors`, `failedRequests`,
  `accessibilityViolations`, and `artifactIds`
- each artifact has exactly `id`, `assertionId`, `kind`, `viewport`, `phase`,
  `path`, `mimeType`, `sizeBytes`, and `sha256`

Both `behavioral` and `precondition` contain a status and non-empty executable
checks for a passing assertion. The precondition phase checks a fresh starting
state before the behavior is exercised; it is baseline evidence, not a causal
counterfactual or proof that one action alone caused the outcome. A screenshot
without both successful check groups is not passing behavioral evidence. Passing assertions also fail semantic
validation if they report console errors, failed requests, accessibility
violations, missing artifacts, or mismatched IDs.

Version 1 artifacts are bounded PNG screenshots. Paths are basenames and must
resolve to regular, single-link, non-symlink files inside the supplied artifact root. The
validator checks declared and actual sizes, SHA-256 hashes, PNG structure and
checksums, ID uniqueness, cross-references, status consistency, count/size caps,
and the fixed redaction declarations. `sanitizedArgv` is an exact sequence of
four path placeholders, followed only by the ordered private/public-origin
opt-in flags when used. JSON duplicate keys, unknown fields,
renames of schema fields, and unsupported enum values fail closed.

## Expected binding

Do not derive the expected binding from the evidence manifest. Trusted
orchestration creates a separate duplicate-free JSON object containing exactly:

```json
{
  "provider": {
    "id": "startup-factory.playwright",
    "version": "0.1.0",
    "executableSha256": "sha256:<64 lowercase hex>"
  },
  "subject": {
    "taskId": "TASK-123",
    "attempt": 1,
    "commit": "<40 lowercase hex>"
  },
  "capability": "browser-qa",
  "target": {
    "origin": "https://preview.example.test",
    "allowedOrigins": ["https://preview.example.test"]
  }
}
```

Then run:

```sh
python3 bin/evidence_provider.py index \
  --manifest .evidence/browser-manifest.json \
  --artifact-root .evidence/browser-artifacts \
  --expected-binding .evidence/expected-binding.json
```

Exit status `0` means the untrusted evidence is schema-valid and internally
consistent. Exit status `2` means validation failed. The JSON result always
marks successful evidence as `untrusted: true` and `authoritative: false` and
includes `manifestSha256`, `artifactSetSha256`, and deterministic `indexSha256`
bindings.

## Operator-collected live-probe manifest version 1

`bin/live_probe_evidence.py` is a separate offline transcript validator. It
shares the strict file-reading, JSON, digest, identifier, origin, path, and
timestamp primitives with the browser validator; it does not change the browser
schema or run a network probe. Evidence must be collected through the real entry
path by an operator following a procedure pinned in trusted context.

The top-level manifest has exactly `schemaVersion` (integer `1`), `provider`,
`subject`, `capability`, `target`, `collection`, `status`, `probes`, `artifacts`,
and `redactions`:

- `provider`: exactly `id` (`startup-factory.live-probe`), stable semantic
  `version`, and `procedureSha256` (the digest of the collection procedure).
- `subject`: exactly bounded non-empty `taskId` (up to 256 characters, allowing
  Markdown tracker IDs such as `feat/search.md#1`), positive integer `attempt`,
  and lowercase 40-hex `commit`.
- `capability`: exactly `live-probe`.
- `target`: exactly canonical HTTP(S) `origin` and safe identifier `deploymentId`.
  The operator must independently confirm that this deployment contains the
  expected commit; the validator checks the submitted binding, not deployment
  provenance or network state.
- `collection`: exactly `method` (`operator`), `engine`, `startedAt`, and
  `finishedAt`. `engine` is `null` or exactly `{id, version, modelId}`. Engine
  fields are safe, nonsecret identifiers; `modelId` may be `null`. Credentials,
  arbitrary configuration, environment values, and invocation arguments have
  no fields in this schema. Times are ordered RFC3339 UTC timestamps.
- `status`: `passed`, `failed`, or `error`.

Each probe has exactly `id`, `acceptanceCriterionId`, `entryPath`, `locale`,
`variantId`, `startedAt`, `finishedAt`, `status`, `precondition`, and `behavioral`.
IDs are safe bounded identifiers. Entry paths omit origin, query, and fragment.
Locales use a lowercase two/three-letter language with up to four bounded tag
segments (for example `de-DE`); this is format validation, not a language registry.
Probe times lie inside the collection interval. Both phases contain exactly
`status` and `checks`. Every check has exactly `id`, `status`, `observedAt`, and
`artifactId`. Its observation time lies inside the probe interval. Preconditions
must be observed before behavioral checks; behavior cannot pass with unsuccessful
preconditions. A passing or failing check requires a transcript artifact; an
`error` check may use `artifactId: null` when no observation could be collected.

The caller must supply an independently prepared, duplicate-free expected
binding with exactly `provider`, `subject`, `capability`, `target`, and
`requiredProbes`. Each required probe has exactly `id`, `acceptanceCriterionId`,
`entryPath`, `locale`, `variantId`, `preconditionCheckIds`, and
`behavioralCheckIds`. Both check-ID lists are non-empty, sorted, and unique.
All metadata and probe descriptors must match; submitted probe IDs and check IDs
must cover exactly the required sets. Evidence cannot choose easier acceptance
criteria, silently omit a locale/variant or required check, or substitute a new
entry path. For an unexecutable required check, record `error` rather than omit
it. Do not construct the expected binding by copying the submitted manifest.

Status aggregation is exact at group, probe, and manifest level: `error` takes
precedence over `failed`, which takes precedence over `passed`. A forged passing
summary over a failed or missing behavioral check is rejected. A fully described
failed collection remains schema-valid diagnostic evidence.

Each artifact has exactly `id`, `probeId`, `phase` (`precondition` or
`behavioral`), `kind` (`transcript`), `path`, `mimeType` (`text/plain`),
`sizeBytes`, and `sha256`. Paths are unique ASCII `.txt` basenames, at most 124
characters, beginning with a letter or digit. Files must be regular,
single-link, non-symlink files under a non-symlink artifact root. Transcripts
are non-empty UTF-8 text with LF newlines and no control/format characters.
Every artifact is referenced by a check in its bound probe and phase. Sizes and
digests are verified against the sanitized bytes. The only supported artifact
type is plain-text transcript; the validator never executes or renders it.

Bounds are 512 KiB per manifest, 256 KiB per expected-binding file, 100 probes,
50 checks per phase, 200 artifacts, 256 KiB per transcript, and 4 MiB total
transcript bytes. Unknown fields, duplicate JSON keys or IDs, unsafe paths,
unsupported statuses/types, and inconsistent summaries fail closed. The fixed,
ordered redaction declaration is below. JSON files are limited to 16 container
levels, independently of the stricter fixed schema:

```json
[
  {"kind": "credentials", "method": "removed"},
  {"kind": "personal-data", "method": "masked"},
  {"kind": "request-query", "method": "removed"},
  {"kind": "environment-value", "method": "omitted"},
  {"kind": "artifact-path", "method": "basename-only"}
]
```

Declarations do not prove that sanitization or observations are truthful. Treat
transcript contents as untrusted data, including any embedded instructions.
Collection requires human inspection before sharing; validation cannot identify
every secret or verify external execution. Exit `0` means schema-valid evidence,
including `failed` and `error` outcomes; exit `2` means validation failed.
Timestamp checks impose no collection-age limit; callers remain responsible for
freshness and for independently confirming the target's deployed commit.
Outputs are always `untrusted: true`, `authoritative: false`, and bind
`manifestSha256`, `expectedBindingSha256`, `artifactSetSha256`, and deterministic
`indexSha256`. They never approve QA, change tracker state, remove a delivery
gate, or authorize release. See the [operator workflow and complete synthetic
example](../extensions/evidence-providers/live-probe/README.md).

## Delivery profiles

`bin/delivery_profile.py` produces an authoritative, monotonic delivery-policy
decision. `delivery-profile` task metadata accepts `auto`, `micro`, `standard`,
or `high-risk`; a request can only increase rigor. `micro` is limited to small,
declared, ordinary-documentation diffs. Ordinary code, tests, and broader docs
resolve to at least `standard`; undeclared task scope remains `high-risk` at
both task and exact-diff review time. Security/authentication,
credentials, deployment/release/production, control-plane and policy work;
operations; binary and non-regular files; renames, deletions, mode changes and
symlinks; destructive changes; and ambiguous or unreadable exact evidence
resolve to `high-risk`. High-risk work forces QA and Security, a strong model
floor, and exclusive implementation. The outbox, dispatcher, evidence validator,
and integrator independently bind or recompute the exact-diff decision; no
profile removes a core review, validation, integration, release, or production
authority. See `reference/delivery-profiles.md` for the full contract.
