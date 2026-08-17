# Evidence providers

Evidence providers are optional, project-owned workers that exercise a real
entry path and emit a versioned manifest plus local artifacts. They are outside
Startup Factory's approval boundary: validated evidence remains untrusted and
cannot add review markers, change tracker state, remove gates, or authorize a
release.

The reference provider is [`playwright/`](playwright/README.md). It requires a
consuming project to pin and provision Playwright; the Startup Factory bundle
does not install Node packages or browsers.

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
