#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  lstat,
  mkdir,
  readFile,
  rename,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PROVIDER_ID = "startup-factory.playwright";
const PROVIDER_VERSION = "0.1.0";
const MAX_JOURNEY_BYTES = 1024 * 1024;
const MAX_PHASE_EVENTS = 250;
const STATUS = new Set(["passed", "failed", "error"]);
export const VIEWPORTS = Object.freeze([
  Object.freeze({ name: "desktop", width: 1280, height: 720 }),
  Object.freeze({ name: "tablet", width: 768, height: 1024 }),
  Object.freeze({ name: "mobile", width: 390, height: 844 }),
]);

const ACTION_KEYS = Object.freeze({
  click: new Set(["type", "selector"]),
  fill: new Set(["type", "selector", "value"]),
  press: new Set(["type", "selector", "key"]),
  check: new Set(["type", "selector"]),
  uncheck: new Set(["type", "selector"]),
  select: new Set(["type", "selector", "value"]),
});

const CHECK_KEYS = Object.freeze({
  visible: new Set(["id", "type", "selector"]),
  hidden: new Set(["id", "type", "selector"]),
  checked: new Set(["id", "type", "selector"]),
  unchecked: new Set(["id", "type", "selector"]),
  "text-contains": new Set(["id", "type", "selector", "expected"]),
  count: new Set(["id", "type", "selector", "expected"]),
  "url-path": new Set(["id", "type", "expected"]),
});

function providerError(message) {
  const error = new Error(message);
  error.name = "ProviderError";
  return error;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, expected, label) {
  if (!isObject(value)) throw providerError(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw providerError(`${label} has missing or unsupported fields`);
  }
}

function boundedString(value, label, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw providerError(`${label} must be a non-empty bounded string`);
  }
  if ([...value].some((character) => character.charCodeAt(0) < 32)) {
    throw providerError(`${label} must not contain control characters`);
  }
  return value;
}

function identifier(value, label) {
  const result = boundedString(value, label, 100);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) {
    throw providerError(`${label} must be a stable identifier`);
  }
  return result;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function ipv4Octets(hostname) {
  const octets = hostname.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return octets;
}

function isPrivateAddress(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const octets = ipv4Octets(host);
  if (octets) return (
    octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168)
  );
  const firstGroup = Number.parseInt(host.split(":", 1)[0], 16);
  return Number.isInteger(firstGroup) && (firstGroup & 0xfe00) === 0xfc00;
}

function isLoopbackHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const octets = ipv4Octets(host);
  return (
    host === "localhost" ||
    host === "::1" ||
    host.endsWith(".localhost") ||
    (octets !== null && octets[0] === 127)
  );
}

function isReservedTestHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return [".test", ".invalid", ".example"].some((suffix) => host.endsWith(suffix));
}

function isForbiddenMetadataHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  const octets = ipv4Octets(host);
  if (octets && octets[0] === 169 && octets[1] === 254) return true;
  if (["100.100.100.200", "192.0.0.192", "0.0.0.0"].includes(host)) return true;
  const firstGroup = Number.parseInt(host.split(":", 1)[0], 16);
  if (host === "::" || (Number.isInteger(firstGroup) && (firstGroup & 0xffc0) === 0xfe80)) return true;
  return new Set([
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data.ec2.internal",
  ]).has(host) || host === "metadata" || host.startsWith("metadata.");
}

export function canonicalOrigin(
  value,
  { allowPrivateOrigins = false, allowPublicOrigins = false } = {},
) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw providerError("allowed origins must be absolute URLs");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw providerError("allowed origins must be canonical credential-free HTTP(S) origins");
  }
  if (isForbiddenMetadataHost(parsed.hostname)) {
    throw providerError("link-local and metadata origins are always forbidden");
  }
  if (isPrivateAddress(parsed.hostname) && !allowPrivateOrigins) {
    throw providerError("private origins require the explicit --allow-private-origins flag");
  }
  if (
    !isLoopbackHost(parsed.hostname) &&
    !isReservedTestHost(parsed.hostname) &&
    !isPrivateAddress(parsed.hostname) &&
    !allowPublicOrigins
  ) {
    throw providerError("public origins require the explicit --allow-public-origins flag");
  }
  return parsed.origin;
}

function entryUrl(baseUrl, entryPath) {
  const path = boundedString(entryPath, "assertion.entryPath", 1000);
  if (!path.startsWith("/") || path.startsWith("//") || /[\r\n]/.test(path)) {
    throw providerError("assertion.entryPath must be an origin-relative path");
  }
  const result = new URL(path, baseUrl);
  if (result.origin !== new URL(baseUrl).origin || result.username || result.password || result.search || result.hash) {
    throw providerError("assertion.entryPath must be a query-free path on the configured target origin");
  }
  return result;
}

function validateAction(action, label) {
  if (!isObject(action) || typeof action.type !== "string" || !ACTION_KEYS[action.type]) {
    throw providerError(`${label} has an unsupported action type`);
  }
  assertExactKeys(action, ACTION_KEYS[action.type], label);
  boundedString(action.selector, `${label}.selector`, 1000);
  if ("value" in action) boundedString(action.value, `${label}.value`, 2048);
  if ("key" in action) boundedString(action.key, `${label}.key`, 80);
  if ("valueFromEnv" in action) {
    throw providerError(`${label} cannot read environment-backed values`);
  }
}

function validateCheck(check, label) {
  if (!isObject(check) || typeof check.type !== "string" || !CHECK_KEYS[check.type]) {
    throw providerError(`${label} has an unsupported check type`);
  }
  assertExactKeys(check, CHECK_KEYS[check.type], label);
  identifier(check.id, `${label}.id`);
  if ("selector" in check) boundedString(check.selector, `${label}.selector`, 1000);
  if (check.type === "count") {
    if (!Number.isSafeInteger(check.expected) || check.expected < 0) {
      throw providerError(`${label}.expected must be a non-negative integer`);
    }
  } else if ("expected" in check) {
    boundedString(check.expected, `${label}.expected`, 2048);
  }
  if (check.type === "url-path") {
    const expected = check.expected;
    if (!expected.startsWith("/") || expected.startsWith("//")) {
      throw providerError(`${label}.expected must be an origin-relative path`);
    }
  }
}

function validatePhase(phase, label) {
  assertExactKeys(phase, new Set(["actions", "checks"]), label);
  if (!Array.isArray(phase.actions) || phase.actions.length > 50) {
    throw providerError(`${label}.actions must be a bounded array`);
  }
  if (!Array.isArray(phase.checks) || phase.checks.length === 0 || phase.checks.length > 50) {
    throw providerError(`${label}.checks must be a non-empty bounded array`);
  }
  phase.actions.forEach((action, index) => validateAction(action, `${label}.actions[${index}]`));
  phase.checks.forEach((check, index) => validateCheck(check, `${label}.checks[${index}]`));
  const ids = new Set(phase.checks.map((check) => check.id));
  if (ids.size !== phase.checks.length) throw providerError(`${label} check ids must be unique`);
}

export function validateJourney(
  value,
  { allowPrivateOrigins = false, allowPublicOrigins = false } = {},
) {
  assertExactKeys(
    value,
    new Set(["schemaVersion", "playwrightVersion", "subject", "baseUrl", "allowedOrigins", "assertions"]),
    "journey",
  );
  if (value.schemaVersion !== 1) throw providerError("journey.schemaVersion must be 1");
  if (typeof value.playwrightVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(value.playwrightVersion)) {
    throw providerError("journey.playwrightVersion must be an exact stable version");
  }
  assertExactKeys(value.subject, new Set(["taskId", "attempt", "commit"]), "journey.subject");
  identifier(value.subject.taskId, "journey.subject.taskId");
  if (!Number.isSafeInteger(value.subject.attempt) || value.subject.attempt < 1) {
    throw providerError("journey.subject.attempt must be a positive integer");
  }
  if (typeof value.subject.commit !== "string" || !/^[0-9a-f]{40}$/.test(value.subject.commit)) {
    throw providerError("journey.subject.commit must be a full lowercase Git commit");
  }
  if (!Array.isArray(value.allowedOrigins) || value.allowedOrigins.length === 0 || value.allowedOrigins.length > 20) {
    throw providerError("journey.allowedOrigins must be a non-empty bounded array");
  }
  const originOptions = { allowPrivateOrigins, allowPublicOrigins };
  const allowedOrigins = value.allowedOrigins.map((origin) => canonicalOrigin(origin, originOptions));
  if (new Set(allowedOrigins).size !== allowedOrigins.length) {
    throw providerError("journey.allowedOrigins must not contain duplicates");
  }
  const base = new URL(boundedString(value.baseUrl, "journey.baseUrl", 2000));
  if (base.username || base.password || base.search || base.hash) {
    throw providerError("journey.baseUrl must not contain credentials, query, or fragment");
  }
  const baseOrigin = canonicalOrigin(base.origin, originOptions);
  if (!allowedOrigins.includes(baseOrigin)) {
    throw providerError("journey.baseUrl origin must be explicitly allowed");
  }
  if (!Array.isArray(value.assertions) || value.assertions.length === 0 || value.assertions.length > 33) {
    throw providerError("journey.assertions must be a non-empty bounded array");
  }
  for (const [index, assertion] of value.assertions.entries()) {
    const label = `journey.assertions[${index}]`;
    assertExactKeys(
      assertion,
      new Set(["id", "acceptanceCriterion", "entryPath", "behavioral", "precondition"]),
      label,
    );
    identifier(assertion.id, `${label}.id`);
    boundedString(assertion.acceptanceCriterion, `${label}.acceptanceCriterion`, 500);
    entryUrl(value.baseUrl, assertion.entryPath);
    validatePhase(assertion.behavioral, `${label}.behavioral`);
    validatePhase(assertion.precondition, `${label}.precondition`);
  }
  const ids = new Set(value.assertions.map((assertion) => assertion.id));
  if (ids.size !== value.assertions.length) throw providerError("journey assertion ids must be unique");
  return {
    ...value,
    baseUrl: base.href,
    allowedOrigins: [...allowedOrigins].sort(),
  };
}

export function sanitizeArgv(options) {
  const result = [
    "--journey", "<journey-json>",
    "--manifest", "<manifest-json>",
    "--artifacts", "<artifact-directory>",
    "--project-root", "<project-root>",
  ];
  if (options.allowPrivateOrigins) result.push("--allow-private-origins");
  if (options.allowPublicOrigins) result.push("--allow-public-origins");
  return result;
}

function parseArgs(argv) {
  const options = { allowPrivateOrigins: false, allowPublicOrigins: false };
  const values = new Set(["--journey", "--manifest", "--artifacts", "--project-root"]);
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (["--allow-private-origins", "--allow-public-origins"].includes(flag)) {
      const key = flag === "--allow-private-origins" ? "allowPrivateOrigins" : "allowPublicOrigins";
      if (options[key]) throw providerError("duplicate CLI flag");
      options[key] = true;
      continue;
    }
    if (!values.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
      throw providerError("unsupported or incomplete CLI arguments");
    }
    const key = flag.slice(2).replace(/-([a-z])/g, (_, character) => character.toUpperCase());
    if (options[key]) throw providerError("duplicate CLI flag");
    options[key] = argv[index + 1];
    index += 1;
  }
  for (const key of ["journey", "manifest", "artifacts", "projectRoot"]) {
    if (!options[key]) throw providerError("required CLI arguments are missing");
  }
  return options;
}

async function readJourney(path, originOptions) {
  let information;
  try {
    information = await lstat(path);
  } catch {
    throw providerError("journey file is unavailable");
  }
  if (!information.isFile() || information.isSymbolicLink() || information.size > MAX_JOURNEY_BYTES) {
    throw providerError("journey must be a bounded non-symlink regular file");
  }
  let value;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw providerError("journey must contain valid JSON");
  }
  return validateJourney(value, originOptions);
}

async function loadPinnedPlaywright(projectRoot, expectedVersion) {
  const root = resolve(projectRoot);
  const requireFromProject = createRequire(join(root, "package.json"));
  let packagePath;
  let playwright;
  try {
    packagePath = requireFromProject.resolve("playwright/package.json");
    playwright = requireFromProject("playwright");
  } catch {
    throw providerError("the project does not provide Playwright; install nothing from this worker");
  }
  let packageValue;
  try {
    packageValue = JSON.parse(await readFile(packagePath, "utf8"));
  } catch {
    throw providerError("the project Playwright package metadata is unreadable");
  }
  if (packageValue.version !== expectedVersion) {
    throw providerError("the project Playwright version does not match the journey pin");
  }
  if (!playwright?.chromium || typeof playwright.chromium.launch !== "function") {
    throw providerError("the project Playwright package does not expose Chromium");
  }
  let executable;
  try {
    executable = playwright.chromium.executablePath();
    const information = await stat(executable);
    if (!information.isFile()) throw new Error("not a file");
  } catch {
    throw providerError("the pinned Chromium binary is absent; this worker never downloads browsers");
  }
  return playwright;
}

function safeUrlPath(value) {
  try {
    const parsed = new URL(value);
    return parsed.pathname || "/";
  } catch {
    return "/";
  }
}

export function allowedTopLevelUrl(value, allowedOrigins) {
  try {
    const parsed = new URL(value);
    return ["http:", "https:"].includes(parsed.protocol) && allowedOrigins.has(parsed.origin);
  } catch {
    return false;
  }
}

export function allowedSubresourceUrl(value, allowedOrigins) {
  try {
    const parsed = new URL(value);
    if (["data:", "about:"].includes(parsed.protocol)) return true;
    if (parsed.protocol === "blob:") return allowedOrigins.has(parsed.origin);
    if (["ws:", "wss:"].includes(parsed.protocol)) {
      const mapped = `${parsed.protocol === "ws:" ? "http:" : "https:"}//${parsed.host}`;
      return allowedOrigins.has(mapped);
    }
    return allowedTopLevelUrl(value, allowedOrigins);
  } catch {
    return false;
  }
}

async function performAction(page, action) {
  const locator = page.locator(action.selector);
  switch (action.type) {
    case "click": await locator.click(); break;
    case "fill": await locator.fill(action.value); break;
    case "press": await locator.press(action.key); break;
    case "check": await locator.check(); break;
    case "uncheck": await locator.uncheck(); break;
    case "select": await locator.selectOption(action.value); break;
    default: throw providerError("unsupported action reached execution");
  }
}

async function performCheck(page, check) {
  const locator = "selector" in check ? page.locator(check.selector) : null;
  switch (check.type) {
    case "visible": return locator.isVisible();
    case "hidden": return !(await locator.isVisible());
    case "checked": return locator.isChecked();
    case "unchecked": return !(await locator.isChecked());
    case "text-contains": return (await locator.textContent())?.includes(check.expected) === true;
    case "count": return (await locator.count()) === check.expected;
    case "url-path": {
      const current = new URL(page.url());
      return `${current.pathname}${current.search}` === check.expected;
    }
    default: throw providerError("unsupported check reached execution");
  }
}

async function accessibilitySmoke(page, phase) {
  const results = await page.evaluate(() => {
    const violations = [];
    const add = (id, impact, count) => { if (count > 0) violations.push({ id, impact, count }); };
    add("html-lang", "serious", document.documentElement.lang.trim() ? 0 : 1);
    add("main-landmark", "moderate", document.querySelector("main,[role='main']") ? 0 : 1);
    add("image-alt", "critical", [...document.querySelectorAll("img")].filter((node) => !node.hasAttribute("alt")).length);
    const controls = [...document.querySelectorAll("button,input,select,textarea,a[href]")];
    add("control-name", "critical", controls.filter((node) => {
      if (node.getAttribute("aria-label")?.trim() || node.getAttribute("aria-labelledby")?.trim() || node.getAttribute("title")?.trim()) return false;
      if (["BUTTON", "A"].includes(node.tagName) && node.textContent?.trim()) return false;
      if (node.id && document.querySelector(`label[for="${CSS.escape(node.id)}"]`)) return false;
      return !node.closest("label");
    }).length);
    const ids = [...document.querySelectorAll("[id]")].map((node) => node.id).filter(Boolean);
    add("duplicate-id", "serious", ids.length - new Set(ids).size);
    const levels = [...document.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((node) => Number(node.tagName.slice(1)));
    add("heading-order", "moderate", levels.reduce((count, level, index) => count + (index > 0 && level > levels[index - 1] + 1 ? 1 : 0), 0));
    return violations;
  });
  return results.map((violation) => ({ phase, ...violation }));
}

function fileStem(assertionId, viewport, phase) {
  const readable = assertionId.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "assertion";
  const suffix = sha256(`${assertionId}:${viewport}:${phase}`).slice(7, 17);
  return `${readable}-${suffix}-${viewport}-${phase}`;
}

async function captureScreenshot(page, artifactDirectory, assertionId, viewport, phase) {
  await page.addStyleTag({
    content: "input,textarea,select,[contenteditable='true']{color:transparent!important;text-shadow:0 0 8px #000!important;caret-color:transparent!important}",
  });
  const filename = `${fileStem(assertionId, viewport, phase)}.png`;
  const path = join(artifactDirectory, filename);
  await page.screenshot({ path, fullPage: false, animations: "disabled" });
  const bytes = await readFile(path);
  const artifactId = `artifact-${sha256(`${assertionId}:${viewport}:${phase}`).slice(7, 23)}`;
  return {
    id: artifactId,
    assertionId: `${assertionId}@${viewport}`,
    kind: "screenshot",
    viewport,
    phase,
    path: basename(path),
    mimeType: "image/png",
    sizeBytes: bytes.length,
    sha256: sha256(bytes),
  };
}

function combineStatus(statuses) {
  if (statuses.some((status) => status === "error")) return "error";
  if (statuses.some((status) => status === "failed")) return "failed";
  return "passed";
}

async function runPhase(browser, journey, assertion, viewport, phase, artifactDirectory) {
  const consoleErrors = [];
  const failedRequests = [];
  const checks = [];
  let accessibilityViolations = [];
  let artifact = null;
  let operationalError = false;
  const allowedOrigins = new Set(journey.allowedOrigins);
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    acceptDownloads: false,
    serviceWorkers: "block",
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    reducedMotion: "reduce",
  });
  context.setDefaultTimeout(7000);
  await context.route("**/*", async (route) => {
    const request = route.request();
    const allowed = request.resourceType() === "document"
      ? allowedTopLevelUrl(request.url(), allowedOrigins)
      : allowedSubresourceUrl(request.url(), allowedOrigins);
    if (!allowed) {
      if (failedRequests.length < MAX_PHASE_EVENTS) failedRequests.push({
        phase,
        method: request.method(),
        resourceType: request.resourceType(),
        urlPath: safeUrlPath(request.url()),
        failureSha256: sha256("disallowed-origin"),
      });
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
  if (typeof context.routeWebSocket !== "function") {
    await context.close();
    throw providerError("the pinned Playwright version cannot enforce WebSocket origins");
  }
  await context.routeWebSocket("**/*", async (socket) => {
      if (!allowedSubresourceUrl(socket.url(), allowedOrigins)) {
        if (failedRequests.length < MAX_PHASE_EVENTS) failedRequests.push({
          phase,
          method: "GET",
          resourceType: "websocket",
          urlPath: safeUrlPath(socket.url()),
          failureSha256: sha256("disallowed-origin"),
        });
        await socket.close({ code: 1008, reason: "origin blocked" });
        return;
      }
      socket.connectToServer();
  });
  const page = await context.newPage();
  page.on("console", (message) => {
    if (["error", "assert"].includes(message.type())) {
      if (consoleErrors.length < MAX_PHASE_EVENTS) consoleErrors.push({
        phase,
        type: message.type(),
        messageSha256: sha256(message.text()),
        urlPath: safeUrlPath(message.location().url || page.url()),
      });
    }
  });
  page.on("pageerror", (error) => {
    if (consoleErrors.length < MAX_PHASE_EVENTS) consoleErrors.push({
      phase,
      type: "error",
      messageSha256: sha256(error.message || "page-error"),
      urlPath: safeUrlPath(page.url()),
    });
  });
  page.on("requestfailed", (request) => {
    const failure = request.failure()?.errorText || "request-failed";
    if (failure === "net::ERR_BLOCKED_BY_CLIENT") return;
    if (failedRequests.length < MAX_PHASE_EVENTS) failedRequests.push({
      phase,
      method: request.method(),
      resourceType: request.resourceType(),
      urlPath: safeUrlPath(request.url()),
      failureSha256: sha256(failure),
    });
  });
  page.on("response", (response) => {
    const request = response.request();
    const allowed = request.resourceType() === "document"
      ? allowedTopLevelUrl(response.url(), allowedOrigins)
      : allowedSubresourceUrl(response.url(), allowedOrigins);
    if (!allowed) {
      if (failedRequests.length < MAX_PHASE_EVENTS) failedRequests.push({
        phase,
        method: request.method(),
        resourceType: request.resourceType(),
        urlPath: safeUrlPath(response.url()),
        failureSha256: sha256("disallowed-response-origin"),
      });
      return;
    }
    if (response.status() >= 400) {
      if (failedRequests.length < MAX_PHASE_EVENTS) failedRequests.push({
        phase,
        method: request.method(),
        resourceType: request.resourceType(),
        urlPath: safeUrlPath(response.url()),
        failureSha256: sha256(`http-${response.status()}`),
      });
    }
  });

  try {
    await page.goto(entryUrl(journey.baseUrl, assertion.entryPath).href, { waitUntil: "domcontentloaded" });
    if (!allowedTopLevelUrl(page.url(), allowedOrigins)) throw providerError("redirect left allowed origins");
    for (const action of assertion[phase === "behavioral" ? "behavioral" : "precondition"].actions) {
      await performAction(page, action);
      if (!allowedTopLevelUrl(page.url(), allowedOrigins)) throw providerError("page navigated outside allowed origins");
    }
    for (const check of assertion[phase === "behavioral" ? "behavioral" : "precondition"].checks) {
      try {
        checks.push({ id: check.id, type: check.type, status: (await performCheck(page, check)) ? "passed" : "failed" });
      } catch {
        checks.push({ id: check.id, type: check.type, status: "error" });
      }
    }
    if (!allowedTopLevelUrl(page.url(), allowedOrigins)) throw providerError("final URL left allowed origins");
    accessibilityViolations = await accessibilitySmoke(page, phase);
    artifact = await captureScreenshot(page, artifactDirectory, assertion.id, viewport.name, phase);
  } catch {
    operationalError = true;
    for (const check of assertion[phase === "behavioral" ? "behavioral" : "precondition"].checks) {
      if (!checks.some((result) => result.id === check.id)) checks.push({ id: check.id, type: check.type, status: "error" });
    }
    try {
      artifact = await captureScreenshot(page, artifactDirectory, assertion.id, viewport.name, phase);
    } catch {
      artifact = null;
    }
  } finally {
    await context.close();
  }
  const groupStatus = operationalError || !artifact || checks.some((check) => check.status === "error")
    ? "error"
    : checks.some((check) => check.status === "failed")
      ? "failed"
      : "passed";
  const phaseStatus = groupStatus === "error"
    ? "error"
    : groupStatus === "failed" || consoleErrors.length || failedRequests.length || accessibilityViolations.length
      ? "failed"
      : "passed";
  return {
    status: phaseStatus,
    groupStatus,
    checks,
    consoleErrors,
    failedRequests,
    accessibilityViolations,
    artifact,
  };
}

export async function runProvider(journey, options, playwright) {
  const startedAt = new Date().toISOString();
  await mkdir(options.artifacts, { recursive: true, mode: 0o700 });
  let browser;
  const assertions = [];
  const artifacts = [];
  try {
    browser = await playwright.chromium.launch({
      headless: true,
      env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TZ: "UTC" },
    });
    for (const assertion of journey.assertions) {
      for (const viewport of VIEWPORTS) {
        const behavioral = await runPhase(browser, journey, assertion, viewport, "behavioral", options.artifacts);
        const precondition = await runPhase(browser, journey, assertion, viewport, "precondition", options.artifacts);
        const currentArtifacts = [behavioral.artifact, precondition.artifact].filter(Boolean);
        artifacts.push(...currentArtifacts);
        assertions.push({
          id: `${assertion.id}@${viewport.name}`,
          acceptanceCriterion: assertion.acceptanceCriterion,
          entryPath: new URL(assertion.entryPath, journey.baseUrl).pathname,
          status: combineStatus([behavioral.status, precondition.status]),
          behavioral: { status: behavioral.groupStatus, checks: behavioral.checks },
          precondition: { status: precondition.groupStatus, checks: precondition.checks },
          consoleErrors: [...behavioral.consoleErrors, ...precondition.consoleErrors],
          failedRequests: [...behavioral.failedRequests, ...precondition.failedRequests],
          accessibilityViolations: [...behavioral.accessibilityViolations, ...precondition.accessibilityViolations],
          artifactIds: currentArtifacts.map((artifact) => artifact.id),
        });
      }
    }
  } finally {
    if (browser) await browser.close();
  }
  const executableBytes = await readFile(new URL(import.meta.url));
  const finishedAt = new Date().toISOString();
  const manifest = {
    schemaVersion: 1,
    provider: {
      id: PROVIDER_ID,
      version: PROVIDER_VERSION,
      executableSha256: sha256(executableBytes),
    },
    subject: journey.subject,
    capability: "browser-qa",
    invocation: {
      sanitizedArgv: sanitizeArgv(options),
      environmentNames: ["LANG", "LC_ALL", "TZ"],
      startedAt,
      finishedAt,
    },
    target: {
      origin: new URL(journey.baseUrl).origin,
      allowedOrigins: journey.allowedOrigins,
    },
    status: combineStatus(assertions.map((assertion) => assertion.status)),
    assertions,
    artifacts,
    redactions: [
      { kind: "console-message", method: "sha256" },
      { kind: "request-query", method: "removed" },
      { kind: "form-value", method: "masked" },
      { kind: "artifact-path", method: "basename-only" },
      { kind: "environment-value", method: "omitted" },
    ],
  };
  if (!STATUS.has(manifest.status)) throw providerError("internal status error");
  return manifest;
}

async function writeManifest(path, manifest) {
  const parent = dirname(resolve(path));
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const temporary = join(parent, `.${basename(path)}.${process.pid}.tmp`);
  await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  await rename(temporary, resolve(path));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  options.artifacts = resolve(options.artifacts);
  const journey = await readJourney(resolve(options.journey), {
    allowPrivateOrigins: options.allowPrivateOrigins,
    allowPublicOrigins: options.allowPublicOrigins,
  });
  const playwright = await loadPinnedPlaywright(options.projectRoot, journey.playwrightVersion);
  const manifest = await runProvider(journey, options, playwright);
  await writeManifest(options.manifest, manifest);
  process.stdout.write(`${resolve(options.manifest)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`playwright-provider: ${error?.message || "execution failed"}\n`);
    process.exitCode = 1;
  });
}
