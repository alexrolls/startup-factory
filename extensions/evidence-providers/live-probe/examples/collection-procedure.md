# Example collection procedure

This example is synthetic. Adapt the procedure to the task, approve its scope
through the normal delivery workflow, and pin its digest before collecting real
evidence. Do not treat these example observations as a live execution result.

1. Confirm that the trusted target deployment identifies the expected commit.
2. Open the application's real `/search` entry path with locale `de-DE` and the
   `empty-state` variant. Check that the catalog has zero items. Record the
   `empty-catalog` precondition and a sanitized baseline transcript.
3. Submit a search through that same entry path. Check that the expected empty
   response is displayed in the selected locale. Record the `empty-response`
   behavioral check and a sanitized response transcript.
4. Record UTC collection, probe, and observation times. Set each check status to
   `passed`, `failed`, or `error`; report unavailable observations as `error`.
   Preserve all required check IDs. Record only public engine/model identifiers,
   or use no engine metadata. Remove credentials and request queries, mask
   personal data, omit environment values, and use local transcript basenames.
5. Hash and measure the sanitized UTF-8 transcript files, then submit their
   manifest for offline validation against the independently prepared binding.
