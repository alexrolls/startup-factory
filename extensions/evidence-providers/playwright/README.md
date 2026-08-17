# Playwright browser evidence provider (reference)

This optional worker turns an explicit browser journey into a Startup Factory
`browser-qa` evidence manifest. It is project-owned evidence only: it cannot post
review markers, approve work, change lifecycle state, install software, download a
browser, upload artifacts, or use an interactive browser profile.

## Project setup

The consuming project must pin `playwright` to an exact version in its own package
and provision the matching Chromium binary before this worker starts. The journey's
`playwrightVersion` must exactly match that installed version. The worker resolves
Playwright from `--project-root`, verifies the version and binary, and otherwise
fails closed. It never runs `npm`, `npx`, or a Playwright install command.

Run a local test application first, copy `journey.example.json`, replace the subject
and selectors, then execute:

```sh
node extensions/evidence-providers/playwright/provider.mjs \
  --journey ./browser-journey.json \
  --manifest ./.evidence/browser-manifest.json \
  --artifacts ./.evidence/browser-artifacts \
  --project-root .
```

Only loopback and reserved test hostnames are accepted by default. RFC1918/private
targets require `--allow-private-origins`; an isolated public preview requires
`--allow-public-origins`. Link-local and known metadata targets are denied even
with these flags. Opt-in targets must run in a sandbox with egress allowlisting and
DNS controls that prevent rebinding to link-local or metadata addresses. The flags
are not proof that a target is safe. Never point the worker at production. Every
HTTP(S) request and redirect must match an exact member of `allowedOrigins`.
Include required test CDNs or API origins explicitly; an unexpected origin is
aborted and fails the assertion.

## Journey contract

Each assertion has one behavioral phase and one required `precondition` phase that
proves the baseline page state before the behavior is exercised. Both start at
`entryPath` in separate fresh Chromium contexts for each of the three
fixed viewports: desktop 1280x720, tablet 768x1024, and mobile 390x844. Supported
actions are `click`, `fill`, `press`, `check`, `uncheck`, and `select`. Supported
checks are `visible`, `hidden`, `checked`, `unchecked`, `text-contains`, `count`,
and `url-path`.

The worker also records hashed console/page errors, failed or HTTP-error requests
without query strings, a dependency-free accessibility smoke check, and masked
viewport screenshots for both phases. The smoke check covers document language,
main landmark presence, missing image alternatives, unnamed controls, duplicate
IDs, and skipped heading levels. It is useful evidence, not a substitute for a
standards-complete accessibility audit.

## Security boundary

- Use seeded, non-sensitive test data. Journey files must not contain credentials,
  tokens, personal data, or other secrets.
- Environment-backed action values are not supported. Browser subprocesses receive
  only `LANG`, `LC_ALL`, and `TZ`; manifest output includes names, never values.
- Each phase uses `browser.newContext()`. Persistent contexts, ambient cookies,
  extensions, and a user's Chrome profile are never used.
- Console messages and request failures are SHA-256 digests. Request queries and
  fragments are removed. Artifact paths are basenames, and form values are masked
  before screenshots.
- Artifacts remain in the operator-selected local directory. Retention, deletion,
  validation, and any later publication are separate trusted-host responsibilities.
- A passing manifest is evidence about the exact subject commit and journey. It is
  never an approval and grants no lifecycle authority.

The validator-only tests require Node but no Playwright package or browser:

```sh
node --test extensions/evidence-providers/playwright/provider.test.mjs
```
