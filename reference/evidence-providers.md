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

## Delivery profiles

`bin/delivery_profile.py` is likewise diagnostic-only. `delivery-profile` task
metadata accepts `auto`, `micro`, or `standard`; a request can only increase
rigor. `micro` is limited to small ordinary-documentation diffs. Code, control,
test and configuration paths; MDX; ambiguous scope; binary and non-regular files;
renames, deletions, mode changes, symlinks; excessive changes; and strong-risk
language in task text, actual paths, or readable bounded patch content all
resolve to `standard`. Oversized or unreadable patches fail closed. No result
removes a Startup Factory gate.
