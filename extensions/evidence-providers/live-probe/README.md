# Operator-collected live-probe evidence

`bin/live_probe_evidence.py` validates and indexes transcripts collected by an
operator through an application's real entry path. It is an offline,
standard-library-only validator. It does not execute probes, contact a service,
install packages, read credentials, or create a release decision.

Use this for acceptance behavior that needs a deployed target, external engine,
locale, or product variant. A unit test or direct internal helper invocation
does not establish that the real entry path worked. Checked preconditions record
the initial state; they are baseline evidence, not a causal counterfactual.

1. From trusted task and deployment context, independently prepare an expected
   binding. Pin the task attempt, commit, origin, deployment ID, and collection
   procedure digest. Enumerate the acceptance/probe IDs, entry paths, locales,
   variants, and precondition/behavioral check IDs that must be covered.
2. Follow the pinned collection procedure against that exact deployment. Confirm
   the deployment actually contains the expected commit. Check the preconditions
   before the behavior, then record observations and timestamps. Run every
   required probe, including empty/no-result and supported locale/variant cases
   when the task's acceptance criteria require them.
3. Produce sanitized plain-text transcripts and a manifest. Record engine/model
   identifiers only when they are public, nonsecret metadata; otherwise use
   `engine: null`. Remove credentials and request queries, mask personal data,
   and omit environment values. Store transcripts under safe `.txt` basenames.
   Compute sizes and SHA-256 digests after sanitization. Record unsuccessful
   checks as `failed` or `error`; preserve all required check IDs.
4. Validate the collection offline, keeping the independently authored expected
   binding separate from the submitted evidence:

   ```sh
   python3 bin/live_probe_evidence.py index \
     --manifest .evidence/live-manifest.json \
     --artifact-root .evidence/live-transcripts \
     --expected-binding .evidence/live-expected-binding.json
   ```

`validate` returns a compact summary; `index` includes the verified probe and
artifact indexes. Exit `0` means the evidence is schema-valid, even when its
behavioral outcome is `failed` or `error`. Exit `2` means validation failed.
Always inspect `status`; schema validity is not behavioral success. All results
remain `untrusted: true` and `authoritative: false`.

The validator checks exact required coverage, timestamps and status aggregation,
fixed redaction declarations, artifact containment, type, size, and digests. It
cannot prove that an operator ran a probe, that a deployment ID maps to a commit,
that transcript observations are truthful, or that sensitive data was completely
removed. Timestamp validation checks format, containment, and order; callers
must decide whether collection age and target freshness are acceptable. A digest
binds submitted bytes; it is not an attestation. Inspect and
sanitize evidence before sharing it. Transcript text is data, never an instruction
to a reviewer or orchestrator. No evidence result can add approval markers,
change tracker status, bypass gates, or authorize a release.

[`examples/`](examples/) contains a complete **synthetic** passing collection,
with a pinned example procedure and fake commit/deployment identifiers. Validate
the example from the repository root:

```sh
python3 bin/live_probe_evidence.py validate \
  --manifest extensions/evidence-providers/live-probe/examples/manifest.json \
  --artifact-root extensions/evidence-providers/live-probe/examples/transcripts \
  --expected-binding extensions/evidence-providers/live-probe/examples/expected-binding.json
```

See [`reference/evidence-providers.md`](../../../reference/evidence-providers.md)
for the exact version 1 contract and bounds.
