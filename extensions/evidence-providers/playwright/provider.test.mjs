import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  VIEWPORTS,
  allowedSubresourceUrl,
  allowedTopLevelUrl,
  canonicalOrigin,
  runProvider,
  sanitizeArgv,
  validateJourney,
} from "./provider.mjs";

function journey() {
  return {
    schemaVersion: 1,
    playwrightVersion: "1.55.0",
    subject: { taskId: "TASK-42", attempt: 1, commit: "a".repeat(40) },
    baseUrl: "http://127.0.0.1:3000/",
    allowedOrigins: ["http://127.0.0.1:3000"],
    assertions: [{
      id: "cart-add",
      acceptanceCriterion: "A visitor can add an available item to the cart.",
      entryPath: "/shop",
      behavioral: {
        actions: [{ type: "click", selector: "[data-testid='add-item']" }],
        checks: [{ id: "cart-visible", type: "visible", selector: "[data-testid='cart']" }],
      },
      precondition: {
        actions: [],
        checks: [{ id: "cart-hidden", type: "hidden", selector: "[data-testid='cart']" }],
      },
    }],
  };
}

test("ships exactly the approved three viewport presets", () => {
  assert.deepEqual(VIEWPORTS, [
    { name: "desktop", width: 1280, height: 720 },
    { name: "tablet", width: 768, height: 1024 },
    { name: "mobile", width: 390, height: 844 },
  ]);
});

test("validates a local, pinned journey with a precondition", () => {
  const result = validateJourney(journey());
  assert.equal(result.baseUrl, "http://127.0.0.1:3000/");
  assert.deepEqual(result.allowedOrigins, ["http://127.0.0.1:3000"]);
});

test("rejects public origins unless the operator opts in", () => {
  assert.throws(() => canonicalOrigin("https://preview.example.org"), /explicit/);
  assert.equal(
    canonicalOrigin("https://preview.example.org", { allowPublicOrigins: true }),
    "https://preview.example.org",
  );
});

test("private origins require opt-in and metadata origins are always denied", () => {
  assert.throws(() => canonicalOrigin("http://192.168.10.4"), /allow-private/);
  assert.equal(
    canonicalOrigin("http://192.168.10.4", { allowPrivateOrigins: true }),
    "http://192.168.10.4",
  );
  for (const target of [
    "http://169.254.169.254",
    "http://100.100.100.200",
    "http://metadata.google.internal",
    "http://[fe80::1]",
  ]) {
    assert.throws(
      () => canonicalOrigin(target, { allowPrivateOrigins: true, allowPublicOrigins: true }),
      /always forbidden/,
    );
  }
});

test("top-level pages reject local schemes that subresources may use", () => {
  const allowed = new Set(["http://127.0.0.1:3000"]);
  for (const target of ["about:blank", "data:text/plain,test", "blob:http://127.0.0.1:3000/id"]) {
    assert.equal(allowedTopLevelUrl(target, allowed), false);
  }
  assert.equal(allowedSubresourceUrl("data:image/png;base64,AA==", allowed), true);
  assert.equal(allowedSubresourceUrl("blob:http://127.0.0.1:3000/id", allowed), true);
});

test("rejects redirect helper origins that are not canonical origins", () => {
  assert.throws(() => canonicalOrigin("http://127.0.0.1:3000/redirect"), /canonical/);
  assert.throws(() => canonicalOrigin("http://user:password@127.0.0.1:3000"), /credential-free/);
});

test("rejects missing preconditions and extra input fields", () => {
  const missing = journey();
  delete missing.assertions[0].precondition;
  assert.throws(() => validateJourney(missing), /missing or unsupported/);
  const extra = journey();
  extra.token = "must-not-be-accepted";
  assert.throws(() => validateJourney(extra), /missing or unsupported/);
});

test("rejects environment-backed action values", () => {
  const value = journey();
  value.assertions[0].behavioral.actions[0] = {
    type: "fill",
    selector: "input",
    valueFromEnv: "PASSWORD",
  };
  assert.throws(() => validateJourney(value), /missing or unsupported|environment-backed/);
});

test("rejects an absolute assertion entry URL", () => {
  const value = journey();
  value.assertions[0].entryPath = "https://evil.invalid/path";
  assert.throws(() => validateJourney(value), /origin-relative/);
});

test("rejects query and fragment entry paths", () => {
  for (const entryPath of ["/shop?token=test", "/shop#details"]) {
    const value = journey();
    value.assertions[0].entryPath = entryPath;
    assert.throws(() => validateJourney(value), /query-free/);
  }
});

test("caps journeys at 33 assertions", () => {
  const value = journey();
  value.assertions = Array.from({ length: 34 }, (_, index) => ({
    ...structuredClone(value.assertions[0]),
    id: `assertion-${index}`,
  }));
  assert.throws(() => validateJourney(value), /bounded array/);
});

test("sanitized argv never contains filesystem paths", () => {
  const result = sanitizeArgv({
    journey: "/secret/path/journey.json",
    manifest: "/secret/path/manifest.json",
    artifacts: "/secret/path/artifacts",
    projectRoot: "/secret/project",
    allowPrivateOrigins: true,
    allowPublicOrigins: true,
  });
  assert.equal(result.some((value) => value.includes("/secret")), false);
  assert.deepEqual(result.slice(-2), ["--allow-private-origins", "--allow-public-origins"]);
});

test("emits a manifest accepted by the Python validator without requiring Playwright", async (context) => {
  const value = journey();
  value.assertions[0].behavioral.actions = [];
  value.assertions[0].behavioral.checks = [{ id: "entry", type: "url-path", expected: "/shop" }];
  value.assertions[0].precondition.checks = [{ id: "baseline-entry", type: "url-path", expected: "/shop" }];
  const validated = validateJourney(value);
  const artifactDirectory = await mkdtemp(join(tmpdir(), "startup-factory-playwright-test-"));
  context.after(() => rm(artifactDirectory, { recursive: true, force: true }));
  const validPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  );
  const fakePage = () => {
    let currentUrl = "about:blank";
    return {
      on() {},
      async goto(url) { currentUrl = url; },
      url() { return currentUrl; },
      locator() { throw new Error("this fixture uses URL checks only"); },
      async evaluate() { return []; },
      async addStyleTag() {},
      async screenshot({ path }) { await writeFile(path, validPng); },
    };
  };
  const fakePlaywright = {
    chromium: {
      async launch() {
        return {
          async newContext() {
            return {
              setDefaultTimeout() {},
              async route() {},
              async routeWebSocket() {},
              async newPage() { return fakePage(); },
              async close() {},
            };
          },
          async close() {},
        };
      },
    },
  };
  const manifest = await runProvider(validated, {
    artifacts: artifactDirectory,
    allowPrivateOrigins: false,
    allowPublicOrigins: false,
  }, fakePlaywright);
  assert.deepEqual(Object.keys(manifest).sort(), [
    "artifacts", "assertions", "capability", "invocation", "provider",
    "redactions", "schemaVersion", "status", "subject", "target",
  ]);
  assert.equal(manifest.assertions.length, 3);
  assert.equal(manifest.artifacts.length, 6);
  for (const result of manifest.assertions) {
    assert.deepEqual(Object.keys(result).sort(), [
      "acceptanceCriterion", "accessibilityViolations", "artifactIds", "behavioral",
      "consoleErrors", "entryPath", "failedRequests", "id", "precondition", "status",
    ]);
    assert.equal("viewport" in result, false);
    assert.equal(result.status, "passed");
  }
  const manifestPath = join(artifactDirectory, "manifest.json");
  const bindingPath = join(artifactDirectory, "expected-binding.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
  await writeFile(bindingPath, `${JSON.stringify({
    provider: manifest.provider,
    subject: manifest.subject,
    capability: manifest.capability,
    target: manifest.target,
  })}\n`);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const validation = spawnSync("python3", [
    join(repository, "bin/evidence_provider.py"),
    "validate",
    "--manifest", manifestPath,
    "--artifact-root", artifactDirectory,
    "--expected-binding", bindingPath,
  ], { encoding: "utf8" });
  assert.equal(validation.status, 0, validation.stderr);
  const result = JSON.parse(validation.stdout);
  assert.equal(result.manifestValid, true);
  assert.equal(result.authoritative, false);
  assert.equal(result.assertionCount, 3);
  assert.equal(result.artifactCount, 6);
});
