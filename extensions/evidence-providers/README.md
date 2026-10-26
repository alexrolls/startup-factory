# Evidence providers

Evidence providers are optional, project-owned workers that exercise a real
entry path and emit a versioned manifest plus local artifacts. They are outside
Startup Factory's approval boundary: validated evidence remains untrusted and
cannot add review markers, change tracker state, remove gates, or authorize a
release.

The reference provider is [`playwright/`](playwright/README.md). It requires a
consuming project to pin and provision Playwright; the Startup Factory bundle
does not install Node packages or browsers.

[`live-probe/`](live-probe/README.md) adds offline validation of manually collected
transcripts for acceptance behavior through a deployed application's real entry
path. Its separate expected binding pins commit, deployment, required probes and
checks, locales, and variants. It supplies no live runner or credentials.

Validate a manifest offline with the standard-library host validator:

```sh
python3 bin/evidence_provider.py validate \
  --manifest .evidence/browser-manifest.json \
  --artifact-root .evidence/browser-artifacts \
  --expected-binding .evidence/expected-binding.json
```

Use `index` instead of `validate` to return the verified assertion/artifact ID
index. The expected binding must contain exactly `provider`, `subject`,
`capability`, and `target`, copied from trusted orchestration context rather
than from the manifest being checked. See
[`reference/evidence-providers.md`](../../reference/evidence-providers.md) for
the schema and security boundary.

For operator-collected live evidence, use `bin/live_probe_evidence.py` with the
same command flags and its distinct live-probe binding schema. A schema-valid
collection can have `status: failed` or `status: error`; neither validator's
exit status alone establishes behavioral success.
