#!/usr/bin/env python3
"""Authoritative, monotonic delivery-profile assessment.

The decision separates latency and model-routing choices from authority.
Profiles may increase rigor, but they never remove the core review board,
exact-package evidence, independent validation, immutable denies, integration
authority, or credential-separated release and production authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
from task_metadata import contains_strong_risk, normalize_risk_text, parse_task_metadata  # noqa: E402


SCHEMA_VERSION = 2
PROFILE_LEVELS = {"micro": 0, "standard": 1, "high-risk": 2}
MAX_MICRO_FILES = 3
MAX_MICRO_CHANGED_LINES = 200
MAX_GIT_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_GIT_ERROR_BYTES = 64 * 1024
MAX_GIT_RUNTIME_SECONDS = 15.0
MAX_PATCH_BYTES = 512 * 1024
MAX_REVIEW_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_REVIEW_PACKAGE_RUNTIME_SECONDS = 30.0
DOC_SUFFIXES = {".adoc", ".md", ".rst", ".txt"}
ROOT_DOC_STEMS = {"changelog", "contributing", "license", "notice", "readme"}
CONTROL_COMPONENTS = {
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".github",
    ".gitlab",
    ".mvn",
    ".openai",
    ".teamwork",
    "adapters",
    "app",
    "apps",
    "bin",
    "config",
    "configs",
    "deploy",
    "deployment",
    "extensions",
    "infra",
    "infrastructure",
    "lib",
    "packages",
    "packaging",
    "plans",
    "policies",
    "policy",
    "reference",
    "roles",
    "runbooks",
    "scripts",
    "src",
    "superpowers",
    "teams",
    "test",
    "tests",
    "workflows",
}
CONTROL_NAMES = {
    ".gitattributes",
    ".gitmodules",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "agents.md",
    "claude.md",
    "codeowners",
    "dockerfile",
    "makefile",
    "skill.md",
}
HIGH_RISK_COMPONENTS = {
    ".agents",
    ".buildkite",
    ".ci",
    ".claude",
    ".circleci",
    ".codex",
    ".cursor",
    ".devcontainer",
    ".direnv",
    ".drone",
    ".github",
    ".gitlab",
    ".mvn",
    ".openai",
    ".teamwork",
    "adapters",
    "ansible",
    "alembic",
    "argocd",
    "bin",
    "charts",
    "ci",
    "cd",
    "cloudformation",
    "config",
    "configs",
    "deployments",
    "deploy",
    "deployment",
    "docker",
    "ecs",
    "flyway",
    "flux",
    "helm",
    "iac",
    "infra",
    "infrastructure",
    "k8s",
    "kubernetes",
    "kustomize",
    "liquibase",
    "manifests",
    "migrate",
    "migration",
    "migrations",
    "nomad",
    "operations",
    "openshift",
    "ops",
    "packer",
    "packaging",
    "policies",
    "policy",
    "pulumi",
    "requirements",
    "roles",
    "runbooks",
    "scripts",
    "serverless",
    "systemd",
    "teams",
    "terraform",
    "terragrunt",
    "third-party",
    "third_party",
    "pipelines",
    "vendor",
    "vendors",
    "workflows",
}
SECURITY_PATH_TOKENS = {
    "admin",
    "admins",
    "administrator",
    "administrators",
    "acl",
    "auth",
    "authentication",
    "authorization",
    "authn",
    "authz",
    "cert",
    "certificate",
    "certificates",
    "certs",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "crypto",
    "csrf",
    "decrypt",
    "decryption",
    "encrypt",
    "encryption",
    "entitlement",
    "entitlements",
    "iam",
    "hmac",
    "identity",
    "jwt",
    "keyring",
    "keystore",
    "login",
    "logout",
    "migration",
    "migrations",
    "mfa",
    "oauth",
    "oauth2",
    "oidc",
    "passwd",
    "password",
    "passwords",
    "permission",
    "permissions",
    "rbac",
    "saml",
    "secret",
    "secrets",
    "security",
    "signature",
    "signatures",
    "signing",
    "session",
    "sessions",
    "schema",
    "schemas",
    "sso",
    "tls",
    "xss",
}
SECURITY_COMPOUND_EXTRA_ROOTS = {"token", "tokens"}
SECURITY_COMPOUND_ROOTS = tuple(
    sorted(
        SECURITY_PATH_TOKENS | SECURITY_COMPOUND_EXTRA_ROOTS,
        key=lambda value: (-len(value), value),
    )
)
SECURITY_COMPONENT_SUFFIXES = (
    "checker",
    "check",
    "client",
    "controller",
    "engine",
    "filter",
    "guard",
    "handler",
    "hash",
    "issuer",
    "manager",
    "middleware",
    "policy",
    "provider",
    "repository",
    "reset",
    "server",
    "service",
    "store",
    "validator",
    "verifier",
)
SECURITY_KEY_QUALIFIERS = (
    "api",
    "encryption",
    "hmac",
    "private",
    "public",
    "secret",
    "signing",
)
SECURITY_COMPOUND_SUBJECT_PREFIXES = (
    "account",
    "customer",
    "internal",
    "member",
    "my",
    "payment",
    "payments",
    "tenant",
    "user",
)
SECURITY_EMBEDDABLE_ROOTS = (
    "authentication",
    "authorization",
    "credential",
    "decryption",
    "encryption",
    "permission",
    "signature",
    "security",
    "password",
    "keyring",
    "keystore",
    "identity",
    "crypto",
    "cookie",
    "decrypt",
    "encrypt",
    "oauth2",
    "login",
    "logout",
    "secret",
    "token",
    "authn",
    "authz",
    "oauth",
    "oidc",
    "passwd",
    "rbac",
    "saml",
    "auth",
    "csrf",
    "hmac",
    "jwt",
    "mfa",
    "xss",
    # Keep plural roots explicit: do not derive these mechanically because
    # ambiguous roots such as session, signing, cert, and migration must never
    # become eligible after an arbitrary domain prefix.
    "credentials",
    "permissions",
    "signatures",
    "identities",
    "passwords",
    "cookies",
    "secrets",
    "tokens",
)
# These plural nouns are security-bearing even when a product/domain prefix is
# fused directly to the noun and no component suffix follows (for example,
# ``orgsecrets`` or ``platformcredentials``).  Keep this list deliberately
# narrower than ``SECURITY_EMBEDDABLE_ROOTS``: ambiguous roots such as session,
# signing, cert, migration, and schema still require an exact boundary or the
# established component grammar below.
SECURITY_TERMINAL_PLURAL_ROOTS = (
    "credentials",
    "permissions",
    "signatures",
    "identities",
    "passwords",
    "cookies",
    "secrets",
)
# ``token`` is intentionally not a generally embeddable terminal noun.  It is
# common product/design language, so a fused terminal ``tokens`` must carry an
# explicit security qualifier.  This preserves ordinary ``designTokens`` and
# ``designtokens`` names while covering ``apitokens`` and ``refreshTokens``.
SECURITY_TERMINAL_TOKEN_QUALIFIERS = (
    "authentication",
    "credential",
    "session",
    "access",
    "bearer",
    "refresh",
    "secret",
    "signing",
    "auth",
    "oauth",
    "api",
    "jwt",
)
# An auth module can be named for its subject without a conventional component
# suffix (``userauth.py``).  Only explicit, high-confidence subject prefixes
# qualify here: an arbitrary prefix would turn ordinary words such as
# ``authorship`` into a security match.
SECURITY_TERMINAL_AUTH_SUBJECTS = (
    "account",
    "app",
    "client",
    "customer",
    "internal",
    "member",
    "org",
    "service",
    "tenant",
    "user",
)
SECURITY_TERMINAL_ROLE_SUBJECTS = (
    "account",
    "admin",
    "member",
    "tenant",
    "user",
)
SECURITY_COMPOUND_TOKEN_RE = re.compile(
    rf"(?:(?:{'|'.join(map(re.escape, SECURITY_COMPOUND_SUBJECT_PREFIXES))}))?"
    r"(?:"
    rf"(?:{'|'.join(map(re.escape, SECURITY_COMPOUND_ROOTS))})"
    rf"(?:{'|'.join(map(re.escape, SECURITY_COMPONENT_SUFFIXES))})s?"
    r"|"
    rf"(?:{'|'.join(map(re.escape, SECURITY_KEY_QUALIFIERS))})keys?"
    rf"(?:(?:{'|'.join(map(re.escape, SECURITY_COMPONENT_SUFFIXES))})s?)?"
    r"|access(?:controller|control(?:engine|guard|manager|policy|service|validator)?)s?"
    r"|passwordless(?:auth|authentication|login|provider|service)?"
    r"|authenticators?|authori[sz]ers?"
    r")"
    r"(?:v[0-9]+)?",
    re.I,
)
SECURITY_EMBEDDED_COMPOUND_TOKEN_RE = re.compile(
    r"[a-z0-9]+"
    r"(?:"
    rf"(?:{'|'.join(map(re.escape, SECURITY_EMBEDDABLE_ROOTS))})"
    rf"(?:{'|'.join(map(re.escape, SECURITY_COMPONENT_SUFFIXES))})s?"
    r"|"
    rf"(?:{'|'.join(map(re.escape, SECURITY_KEY_QUALIFIERS))})keys?"
    rf"(?:(?:{'|'.join(map(re.escape, SECURITY_COMPONENT_SUFFIXES))})s?)?"
    r"|access(?:controller|control(?:engine|guard|manager|policy|service|validator)?)s?"
    r"|passwordless(?:auth|authentication|login|provider|service)?"
    r")"
    r"(?:v[0-9]+)?",
    re.I,
)
SECURITY_TERMINAL_COMPOUND_TOKEN_RE = re.compile(
    r"(?:"
    rf"[a-z0-9]+(?:{'|'.join(map(re.escape, SECURITY_TERMINAL_PLURAL_ROOTS))})"
    r"|"
    rf"[a-z0-9]*(?:{'|'.join(map(re.escape, SECURITY_TERMINAL_TOKEN_QUALIFIERS))})tokens"
    r"|"
    rf"(?:{'|'.join(map(re.escape, SECURITY_TERMINAL_AUTH_SUBJECTS))})auth(?:n|z)?"
    r"|"
    rf"(?:{'|'.join(map(re.escape, SECURITY_TERMINAL_ROLE_SUBJECTS))})roles?"
    r"|role(?:guard|policy|validator)"
    r")"
    r"(?:v[0-9]+)?",
    re.I,
)
SECURITY_ROTATION_STEM_RE = re.compile(
    r"(?:(?:access|api|auth|encryption|hmac|private|refresh|secret|signing))?"
    r"(?:key|token)rotation(?:v[0-9]+)?(?:\.(?:test|spec))?",
    re.I,
)
SECURITY_ROLE_STEM_RE = re.compile(
    rf"(?:(?:{'|'.join(map(re.escape, SECURITY_TERMINAL_ROLE_SUBJECTS))})roles?"
    r"|role(?:guard|policy|validator))"
    r"(?:v[0-9]+)?(?:\.(?:test|spec))?",
    re.I,
)
DEPENDENCY_MANIFEST_NAMES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "conda-lock.yaml",
    "conda-lock.yml",
    "conanfile.py",
    "conanfile.txt",
    "cartfile",
    "cartfile.resolved",
    "deno.lock",
    "deps.edn",
    "directory.packages.props",
    "environment.yaml",
    "environment.yml",
    "flake.lock",
    "flake.nix",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "global.json",
    "gradle.lockfile",
    "mix.exs",
    "mix.lock",
    "module.bazel",
    "npm-shrinkwrap.json",
    "nuget.config",
    "package-lock.json",
    "package.json",
    "packages.lock.json",
    "package.resolved",
    "package.swift",
    "pdm.lock",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "podfile",
    "podfile.lock",
    "project.clj",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "renovate.json",
    "renovate.json5",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "uv.lock",
    "vcpkg.json",
    "workspace",
    "workspace.bazel",
    "yarn.lock",
    ".nvmrc",
    ".python-version",
    ".ruby-version",
    ".tool-versions",
    "gradle-wrapper.properties",
    "maven-wrapper.properties",
    "alembic.ini",
}
DEPLOYMENT_FILE_NAMES = {
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".travis.yml",
    "appspec.yml",
    "appspec.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "cdk.json",
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "chart.yaml",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
    "fly.toml",
    "heroku.yml",
    "heroku.yaml",
    "jenkinsfile",
    "kustomization.yaml",
    "kustomization.yml",
    "netlify.toml",
    "railway.json",
    "render.yaml",
    "render.yml",
    "samconfig.toml",
    "skaffold.yaml",
    "skaffold.yml",
    "serverless.yaml",
    "serverless.yml",
    "vercel.json",
    "werf.yaml",
    "werf.yml",
    "tiltfile",
}
SECURITY_CONFIG_NAMES = {
    ".env",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "authorized_keys",
    "known_hosts",
}
HIGH_RISK_REASONS = {
    "binary-content",
    "declared-files-mismatch",
    "diff-accounting-mismatch",
    "duplicate-declared-files",
    "duplicate-diff-path",
    "empty-diff",
    "file-mode-change",
    "files-not-declared",
    "invalid-declared-files",
    "invalid-numstat",
    "malformed-task-fields",
    "malformed-task-metadata",
    "non-regular-file-mode",
    "operations-work-kind",
    "strong-risk-diff-content",
    "strong-risk-diff-path",
    "strong-risk-language",
    "unreadable-or-oversized-patch",
    "unrecognized-numstat",
    "unrecognized-raw-diff",
    "unsafe-declared-path",
    "unsafe-diff-path",
    "unreadable-exact-diff",
}


class DeliveryProfileError(ValueError):
    """Raised for malformed assessor inputs or an unusable Git repository."""


def _resolve_git_executable() -> str:
    """Resolve Git once from the platform's controlled system search path."""
    candidate = shutil.which("git", path=os.defpath)
    if candidate is None:
        raise DeliveryProfileError("git is unavailable on the controlled system path")
    resolved = Path(candidate).resolve()
    if not resolved.is_absolute() or not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise DeliveryProfileError("git executable is not a usable absolute regular file")
    return str(resolved)


GIT_EXECUTABLE = _resolve_git_executable()


def _safe_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    if value.startswith("/") or value.endswith("/"):
        return None
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return None
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or str(parsed) != value:
        return None
    return value


def _path_tokens(path: PurePosixPath) -> set[str]:
    return {
        token.casefold()
        for part in path.parts
        for token in re.findall(r"[A-Za-z0-9]+", normalize_risk_text(part))
    }


def _is_dependency_manifest(name: str) -> bool:
    if name in DEPENDENCY_MANIFEST_NAMES:
        return True
    if name == "lockfile" or name.endswith(".lock"):
        return True
    if re.fullmatch(r"requirements(?:[-_.][a-z0-9]+)*\.(?:in|txt)", name):
        return True
    return bool(
        re.fullmatch(r"build\.gradle(?:\.kts)?", name)
        or re.fullmatch(r"libs\.versions\.toml", name)
    )


def _is_deployment_or_iac_file(path: PurePosixPath) -> bool:
    name = path.name.casefold()
    if name in DEPLOYMENT_FILE_NAMES:
        return True
    if re.fullmatch(r"procfile(?:[._-].+)?", name):
        return True
    if len(path.parts) == 1 and name in {"app.yaml", "app.yml"}:
        return True
    if re.fullmatch(r"dockerfile(?:[._-].+)?", name):
        return True
    if re.fullmatch(
        r"(?:release|publish|promote)(?:[-_.][a-z0-9_-]+)*\.(?:bat|cmd|ps1|py|rb|sh)",
        name,
    ):
        return True
    if re.fullmatch(r"pulumi(?:\.[a-z0-9_-]+)?\.ya?ml", name):
        return True
    return bool(
        name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json", ".hcl"))
    )


def _is_security_surface(path: PurePosixPath) -> bool:
    lowered_parts = tuple(part.casefold() for part in path.parts)
    name = lowered_parts[-1]
    tokens = _path_tokens(path)
    # Key/token rotation is a security operation even without another security
    # qualifier. Match the whole stem, not an arbitrary suffix of words such
    # as ``keyboardRotation`` or ``tokenrotationgame``.
    compact_stem = re.sub(r"[-_]", "", PurePosixPath(name).stem)
    if (
        SECURITY_ROTATION_STEM_RE.fullmatch(compact_stem)
        or SECURITY_ROLE_STEM_RE.fullmatch(compact_stem)
    ):
        return True
    # A directory literally named ``session`` is conventionally an auth state
    # boundary.  A compound identifier such as ``workshopSessionCard`` is not;
    # it needs another security term before it can raise the risk floor.
    session_tokens = tokens & {"session", "sessions"}
    unconditional_tokens = SECURITY_PATH_TOKENS - {"session", "sessions"}
    if tokens & unconditional_tokens:
        return True
    # Lowercase compound filenames have no case/separator boundary for the
    # generic tokenizer to expose.  Ambiguous roots (for example ``session``,
    # ``cert``, ``migration``, and ``signing``) are accepted only at the start
    # or after one allowlisted subject prefix.  A smaller, high-confidence root
    # set may follow an arbitrary alphanumeric domain prefix, but only when it
    # terminates in a conventional security component and optional numeric
    # ``vN`` version.  A narrow terminal-noun grammar also recognizes fused,
    # high-confidence plural nouns (``orgsecrets``) and explicitly qualified
    # plural tokens (``apitokens``), without treating generic ``designtokens``
    # as security.  Full matching rejects free-form tails such as
    # ``authorship``, ``credentialstory``, and ``oauthclientele``.
    if any(
        SECURITY_COMPOUND_TOKEN_RE.fullmatch(token)
        or SECURITY_EMBEDDED_COMPOUND_TOKEN_RE.fullmatch(token)
        or SECURITY_TERMINAL_COMPOUND_TOKEN_RE.fullmatch(token)
        for token in tokens
    ):
        return True
    if any(part in {"session", "sessions"} for part in lowered_parts):
        return True
    if re.fullmatch(r"sessions?(?:\.[a-z0-9]+)+", name):
        return True
    if session_tokens and tokens & {
        "auth",
        "authentication",
        "cookie",
        "credential",
        "expiry",
        "expiration",
        "fixation",
        "hijack",
        "login",
        "logout",
        "security",
        "store",
        "timeout",
        "token",
    }:
        return True
    if {"access", "control"} <= tokens:
        return True
    if tokens & {"token", "tokens"} and tokens & {
        "access",
        "api",
        "auth",
        "authentication",
        "bearer",
        "credential",
        "jwt",
        "oauth",
        "refresh",
        "secret",
        "session",
    }:
        return True
    if tokens & {"key", "keys"} and tokens & {
        "api",
        "encryption",
        "private",
        "public",
        "secret",
        "signing",
    }:
        return True
    if "policy" in tokens and tokens & {
        "access",
        "auth",
        "authorization",
        "permission",
        "rbac",
        "role",
        "security",
    }:
        return True
    return (
        name in SECURITY_CONFIG_NAMES
        or name.startswith((".env.", ".envrc."))
        or name.endswith((".cer", ".crt", ".jks", ".key", ".p12", ".pem", ".pfx"))
    )


def _contains_strong_surface(value: object) -> bool:
    return contains_strong_risk(value)


def is_ordinary_documentation_path(value: object) -> bool:
    """Return true only for allowlisted, non-control documentation paths."""
    path = _safe_relative_path(value)
    if path is None:
        return False
    parsed = PurePosixPath(path)
    lowered_parts = tuple(part.casefold() for part in parsed.parts)
    if any(part.startswith(".") or part in CONTROL_COMPONENTS for part in lowered_parts):
        return False
    name = lowered_parts[-1]
    if name in CONTROL_NAMES:
        return False
    suffix = parsed.suffix.casefold()
    stem = parsed.stem.casefold()
    if len(parsed.parts) == 1:
        return stem in ROOT_DOC_STEMS and suffix in DOC_SUFFIXES | {""}
    return lowered_parts[0] in {"doc", "docs", "documentation"} and suffix in DOC_SUFFIXES


def is_control_plane_path(value: object) -> bool:
    """Return true for control, security, dependency, deploy, or IaC surfaces."""
    path = _safe_relative_path(value)
    if path is None:
        return False
    parsed = PurePosixPath(path)
    lowered_parts = tuple(part.casefold() for part in parsed.parts)
    name = lowered_parts[-1]
    return (
        any(part in HIGH_RISK_COMPONENTS for part in lowered_parts)
        or name in CONTROL_NAMES
        or _is_dependency_manifest(name)
        or _is_deployment_or_iac_file(parsed)
        or _is_security_surface(parsed)
    )


def _reason_is_high_risk(reason: str) -> bool:
    return reason in HIGH_RISK_REASONS or reason.startswith(
        ("control-plane-path:", "unsupported-change-status:")
    )


def _authority(profile: str) -> dict:
    forced_gates = ["qa", "security"] if profile == "high-risk" else []
    return {
        "coreReviewRoles": [
            "team-lead",
            "principal-architect",
            "sceptical-architect",
        ],
        "distinctCoreReviewDecisionsRequired": 3,
        "productScopeDecisionRequired": True,
        "principalDesignDecisionRequired": True,
        "scepticalDesignDecisionRequired": True,
        "profileForcedReviewGates": forced_gates,
        "reviewGatePolicy": "monotonic-union-task-preset-risk-profile",
        "exactPackageEvidenceRequired": True,
        "independentValidationRequired": True,
        "integratorAuthorityRequired": True,
        "immutableDenyRulesEnforced": True,
        "releaseAuthority": "credential-separated-external",
        "productionAuthority": "credential-separated-external",
        "profileMayReduceCoreReviewModel": False,
    }


def _delivery_policy(profile: str) -> dict:
    return {
        "micro": {
            "modelProfileFloor": "fast",
            "implementationConcurrency": "declared-parallel-safe-only",
        },
        "standard": {
            "modelProfileFloor": "standard",
            "implementationConcurrency": "declared-parallel-safe-only",
        },
        "high-risk": {
            "modelProfileFloor": "strong",
            "implementationConcurrency": "exclusive",
        },
    }[profile]


def _decision(
    *,
    phase: str,
    requested: str,
    inferred: str,
    reasons: list[str],
    files: list[str],
    changed_lines: int | None,
    base_commit: str | None = None,
    head_commit: str | None = None,
) -> dict:
    requested_level = PROFILE_LEVELS.get(requested, -1)
    effective = max(
        (inferred, requested if requested in PROFILE_LEVELS else inferred),
        key=PROFILE_LEVELS.__getitem__,
    )
    ordered_reasons = list(dict.fromkeys(reasons))
    if requested in PROFILE_LEVELS and requested_level > PROFILE_LEVELS[inferred]:
        ordered_reasons.insert(0, f"{requested}-requested")
    elif requested in PROFILE_LEVELS and requested_level < PROFILE_LEVELS[inferred]:
        ordered_reasons.append(f"{requested}-request-cannot-lower-{inferred}")
    if not ordered_reasons:
        ordered_reasons = [
            "bounded-ordinary-documentation-diff"
            if phase == "diff"
            else "bounded-ordinary-documentation"
        ]
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "phase": phase,
        "requestedProfile": requested,
        "inferredProfile": inferred,
        "effectiveProfile": effective,
        "files": sorted(files),
        "changedLines": changed_lines,
        "reasons": ordered_reasons,
        "authority": _authority(effective),
        "deliveryPolicy": _delivery_policy(effective),
        "authoritative": True,
        "diagnosticOnly": False,
    }
    if phase == "diff":
        result["baseCommit"] = base_commit
        result["headCommit"] = head_commit
    return result


def _task_shape(task: dict, metadata: dict) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    files = metadata.get("files") or []
    if not isinstance(files, list) or any(not isinstance(path, str) for path in files):
        return [], ["invalid-declared-files"]
    if any(not isinstance(task.get(name), (str, type(None))) for name in ("title", "description")):
        reasons.append("malformed-task-fields")
    if metadata.get("resources"):
        reasons.append("declared-shared-resources")
    if not files:
        reasons.append("files-not-declared")
    elif len(files) > MAX_MICRO_FILES:
        reasons.append("too-many-files")
    if len(files) != len(set(files)):
        reasons.append("duplicate-declared-files")
    if any(_safe_relative_path(path) is None for path in files):
        reasons.append("unsafe-declared-path")
    for path in files:
        if is_control_plane_path(path):
            reasons.append(f"control-plane-path:{path}")
    if files and not all(is_ordinary_documentation_path(path) for path in files):
        reasons.append("non-ordinary-documentation-path")
    if metadata.get("workKind") == "operations":
        reasons.append("operations-work-kind")
    if files and _contains_strong_surface("\n".join(files)):
        reasons.append("strong-risk-diff-path")
    if _contains_strong_surface(
        "%s\n%s" % (task.get("title") or "", task.get("description") or "")
    ):
        reasons.append("strong-risk-language")
    return sorted(files), list(dict.fromkeys(reasons))


def assess_task(task: dict, metadata: dict | None = None) -> dict:
    """Assess declared scope; absent, malformed, or unsafe input is high-risk."""
    if not isinstance(task, dict):
        raise DeliveryProfileError("task must be an object")
    if metadata is None:
        try:
            metadata = parse_task_metadata(task.get("description"), task.get("title"))
        except ValueError:
            return _decision(
                phase="task",
                requested="auto",
                inferred="high-risk",
                reasons=["malformed-task-metadata"],
                files=[],
                changed_lines=None,
            )
    if not isinstance(metadata, dict):
        return _decision(
            phase="task",
            requested="auto",
            inferred="high-risk",
            reasons=["malformed-task-metadata"],
            files=[],
            changed_lines=None,
        )
    requested = metadata.get("deliveryProfile", "auto")
    if requested not in {"auto", *PROFILE_LEVELS}:
        return _decision(
            phase="task",
            requested="auto",
            inferred="high-risk",
            reasons=["malformed-task-metadata"],
            files=[],
            changed_lines=None,
        )
    files, reasons = _task_shape(task, metadata)
    if any(_reason_is_high_risk(reason) for reason in reasons):
        inferred = "high-risk"
    elif not reasons:
        inferred = "micro"
    else:
        inferred = "standard"
    return _decision(
        phase="task",
        requested=requested,
        inferred=inferred,
        reasons=reasons,
        files=files,
        changed_lines=None,
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill and reap Git plus any child process it may have started."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()


def _git(
    repo: Path,
    *arguments: str,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    timeout_seconds: float = MAX_GIT_RUNTIME_SECONDS,
    input_bytes: bytes | None = None,
    object_directory: Path | None = None,
    index_file: Path | None = None,
) -> bytes:
    """Run Git with preventive stdout/stderr byte caps and a wall deadline."""
    if max_output_bytes <= 0 or timeout_seconds <= 0:
        raise DeliveryProfileError("git resource limits must be positive")
    # The caller environment is not an authority source.  Use an absolute Git
    # resolved once from the controlled system path and construct the complete
    # child environment here: repository/object/config/credential/protocol
    # variables must not redirect or extend an evidence-classification command.
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if object_directory is not None:
        try:
            object_path = object_directory.resolve(strict=True)
            object_mode = object_path.lstat().st_mode
        except OSError as exc:
            raise DeliveryProfileError("Git object directory is unavailable") from exc
        if object_path.is_symlink() or not stat.S_ISDIR(object_mode):
            raise DeliveryProfileError("Git object directory must be a real directory")
        environment["GIT_OBJECT_DIRECTORY"] = str(object_path)
    if index_file is not None:
        index_path = index_file.absolute()
        if not index_path.parent.is_dir() or index_path.parent.is_symlink():
            raise DeliveryProfileError("temporary Git index directory is unsafe")
        environment["GIT_INDEX_FILE"] = str(index_path)
    command = [
        GIT_EXECUTABLE,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.abbrev=7",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.pager=",
        "-c",
        "core.quotePath=true",
        "-c",
        "credential.helper=",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "diff.algorithm=myers",
        "-c",
        "diff.indentHeuristic=false",
        "-c",
        "diff.ignoreSubmodules=none",
        "-c",
        "diff.interHunkContext=0",
        "-c",
        "diff.mnemonicPrefix=false",
        "-c",
        "diff.noprefix=false",
        "-c",
        "diff.renameLimit=32767",
        "-c",
        "diff.renames=true",
        "-c",
        "diff.srcPrefix=a/",
        "-c",
        "diff.dstPrefix=b/",
        "-c",
        "diff.statGraphWidth=50",
        "-c",
        "diff.statNameWidth=50",
        "-c",
        "diff.statWidth=80",
        "-c",
        "diff.submodule=short",
        "-c",
        "diff.suppressBlankEmpty=false",
        "-c",
        "i18n.commitEncoding=UTF-8",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        "-c",
        "log.decorate=false",
        "-c",
        "log.showSignature=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "merge.default=text",
        "-c",
        "merge.renormalize=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "rerere.autoupdate=false",
        "-c",
        "rerere.enabled=false",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(repo),
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        raise DeliveryProfileError("git could not be executed") from exc

    assert process.stdout is not None and process.stderr is not None
    streams = {
        "output": (process.stdout, max_output_bytes),
        "error output": (process.stderr, MAX_GIT_ERROR_BYTES),
    }
    buffers = {name: bytearray() for name in streams}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    input_offset = 0
    try:
        for name, (stream, limit) in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, limit))
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            if input_bytes:
                selector.register(process.stdin, selectors.EVENT_WRITE, ("input", None))
            else:
                process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeliveryProfileError("git command timed out")
            for key, _ in selector.select(min(remaining, 0.1)):
                name, limit = key.data
                if name == "input":
                    assert input_bytes is not None and process.stdin is not None
                    try:
                        written = os.write(key.fd, input_bytes[input_offset : input_offset + 64 * 1024])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                    input_offset += written
                    if written == 0 or input_offset == len(input_bytes):
                        selector.unregister(key.fileobj)
                        process.stdin.close()
                    continue
                assert limit is not None
                try:
                    chunk = os.read(
                        key.fd,
                        min(64 * 1024, limit + 1 - len(buffers[name])),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > limit:
                    raise DeliveryProfileError(
                        "git %s exceeds the safety cap" % name
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeliveryProfileError("git command timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise DeliveryProfileError("git command timed out") from exc
    except DeliveryProfileError:
        _terminate_process_group(process)
        raise
    except OSError as exc:
        _terminate_process_group(process)
        raise DeliveryProfileError("git output could not be read") from exc
    finally:
        selector.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()

    output = bytes(buffers["output"])
    error_output = bytes(buffers["error output"])
    if return_code:
        message = error_output.decode("utf-8", "replace").strip()
        raise DeliveryProfileError("git command failed: %s" % (message or return_code))
    return output


def _patch_risk(repo: Path, base: str, head: str) -> list[str]:
    try:
        patch = _git(
            repo,
            "diff",
            "--patch",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            base,
            head,
            "--",
            max_output_bytes=MAX_PATCH_BYTES,
        )
        text = patch.decode("utf-8", "strict")
    except (DeliveryProfileError, UnicodeError):
        return ["unreadable-or-oversized-patch"]
    return ["strong-risk-diff-content"] if _contains_strong_surface(text) else []


def _blob_risk(repo: Path, head: str, files: list[str]) -> list[str]:
    """Inspect target blobs independently of attacker-controlled diff attributes."""
    reasons: list[str] = []
    for path in files:
        try:
            body = _git(
                repo,
                "cat-file",
                "blob",
                f"{head}:{path}",
                max_output_bytes=MAX_PATCH_BYTES,
                timeout_seconds=MAX_GIT_RUNTIME_SECONDS,
            )
        except DeliveryProfileError:
            reasons.append("unreadable-or-oversized-patch")
            continue
        if b"\0" in body:
            reasons.append("binary-content")
    return list(dict.fromkeys(reasons))


def _repository_root(repo: Path) -> Path:
    if repo.is_symlink() or not repo.is_dir():
        raise DeliveryProfileError("repository must be a non-symlink directory")
    resolved = repo.resolve()
    reported = _git(resolved, "rev-parse", "--show-toplevel")
    try:
        root = Path(reported.rstrip(b"\n").decode("utf-8", "strict")).resolve()
    except UnicodeError as exc:
        raise DeliveryProfileError("repository root is not UTF-8") from exc
    if root != resolved:
        raise DeliveryProfileError("repository path must be the Git top level")
    return resolved


def repository_root(path: str | os.PathLike[str]) -> Path:
    """Resolve a contained workspace path to its exact Git top level."""
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_dir():
        raise DeliveryProfileError("repository lookup path must be a non-symlink directory")
    reported = _git(candidate.resolve(), "rev-parse", "--show-toplevel")
    try:
        root = Path(reported.rstrip(b"\n").decode("utf-8", "strict")).resolve()
    except UnicodeError as exc:
        raise DeliveryProfileError("repository root is not UTF-8") from exc
    return _repository_root(root)


def _resolve_commit(repo: Path, reference: str) -> str:
    if not isinstance(reference, str) or not reference or "\x00" in reference:
        raise DeliveryProfileError("revision must be a non-empty string")
    output = _git(repo, "rev-parse", "--verify", "--end-of-options", reference + "^{commit}")
    value = output.strip().decode("ascii", "strict")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise DeliveryProfileError("revision did not resolve to a commit")
    return value.lower()


def _decode_git_output(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeliveryProfileError(f"{label} is not UTF-8") from exc


def _git_common_directory(repo: Path) -> Path:
    raw = _decode_git_output(
        _git(repo, "rev-parse", "--git-common-dir"), "Git common directory"
    ).strip()
    if not raw:
        raise DeliveryProfileError("Git common directory is empty")
    path = Path(raw)
    return (path if path.is_absolute() else repo / path).resolve()


def _reject_external_checkout_filters(repo: Path) -> None:
    """Reject repository-local commands that checkout/read-tree could execute."""
    raw = _git(
        repo,
        "config",
        "--local",
        "--includes",
        "--null",
        "--name-only",
        "--list",
        max_output_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    try:
        keys = [
            item.decode("utf-8", "strict").casefold()
            for item in raw.split(b"\0")
            if item
        ]
    except UnicodeError as exc:
        raise DeliveryProfileError(
            "repository-local Git configuration is not UTF-8"
        ) from exc
    unsafe = sorted(
        key
        for key in keys
        if re.fullmatch(r"filter\..+\.(?:clean|smudge|process)", key)
    )
    if unsafe:
        raise DeliveryProfileError(
            "repository-local external checkout filters are forbidden during governed integration: "
            + ", ".join(unsafe)
        )


def canonical_merge_tree(
    repo: str | os.PathLike[str],
    base: str,
    head: str,
    merge_base: str | None = None,
) -> tuple[str, str, str, str]:
    """Build the deterministic disjoint-overlay integration tree.

    Stable v1 deliberately refuses overlapping feature/task edits. Reviewed
    paths are copied by mode+object id onto the exact integration base through
    a private index. No content merge, attribute driver, filter, hook, caller
    ``PATH``, or repository-local merge command participates. An overlap must
    be rebased and reviewed again instead of relying on ambient merge policy.
    """
    root = _repository_root(Path(repo))
    resolved_base = _resolve_commit(root, base)
    resolved_head = _resolve_commit(root, head)
    observed_raw = _git(root, "merge-base", resolved_base, resolved_head).strip()
    try:
        observed_merge_base = observed_raw.decode("ascii", "strict").lower()
    except UnicodeError as exc:
        raise DeliveryProfileError("merge base is not an ASCII commit id") from exc
    if not re.fullmatch(r"[0-9a-f]{40,64}", observed_merge_base):
        raise DeliveryProfileError("merge base is not a canonical commit id")
    if merge_base is not None:
        resolved_merge_base = _resolve_commit(root, merge_base)
        if resolved_merge_base != observed_merge_base:
            raise DeliveryProfileError(
                "declared review base is not the exact merge base"
            )
    _reject_external_checkout_filters(root)

    def changes(old: str, new: str) -> dict[bytes, tuple[str | None, str | None]]:
        raw = _git(
            root,
            "diff",
            "--raw",
            "-z",
            "--full-index",
            "--abbrev=64",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            old,
            new,
            "--",
            max_output_bytes=MAX_REVIEW_PACKAGE_BYTES,
            timeout_seconds=30.0,
        ).split(b"\0")
        if raw and raw[-1] == b"":
            raw.pop()
        result: dict[bytes, tuple[str | None, str | None]] = {}
        index = 0
        while index < len(raw):
            fields = raw[index].split()
            index += 1
            if len(fields) != 5 or not fields[0].startswith(b":") or index >= len(raw):
                raise DeliveryProfileError("canonical overlay received malformed raw diff")
            old_mode = fields[0][1:].decode("ascii", "strict")
            new_mode = fields[1].decode("ascii", "strict")
            old_oid = fields[2].decode("ascii", "strict").lower()
            new_oid = fields[3].decode("ascii", "strict").lower()
            status = fields[4].decode("ascii", "strict")
            path = raw[index]
            index += 1
            if not path or path in result or status not in {"A", "D", "M", "T"}:
                raise DeliveryProfileError("canonical overlay received an unsupported change")
            try:
                path.decode("utf-8", "strict")
            except UnicodeError as exc:
                raise DeliveryProfileError("canonical overlay path is not UTF-8") from exc
            oid_width = len(resolved_base)
            if (
                not re.fullmatch(r"[0-7]{6}", old_mode)
                or not re.fullmatch(r"[0-7]{6}", new_mode)
                or not re.fullmatch(rf"[0-9a-f]{{{oid_width}}}", old_oid)
                or not re.fullmatch(rf"[0-9a-f]{{{oid_width}}}", new_oid)
            ):
                raise DeliveryProfileError("canonical overlay diff entry is malformed")
            if status == "D":
                result[path] = (None, None)
            elif new_mode == "000000" or set(new_oid) == {"0"}:
                raise DeliveryProfileError("canonical overlay change lacks a target object")
            else:
                result[path] = (new_mode, new_oid)
        return result

    reviewed = changes(observed_merge_base, resolved_head)
    if not reviewed:
        raise DeliveryProfileError("canonical overlay has no reviewed changes")
    concurrent = changes(observed_merge_base, resolved_base)

    def overlaps(left: bytes, right: bytes) -> bool:
        return (
            left == right
            or left.startswith(right + b"/")
            or right.startswith(left + b"/")
        )

    collisions = sorted(
        left.decode("utf-8", "strict")
        for left in reviewed
        if any(overlaps(left, right) for right in concurrent)
    )
    if collisions:
        raise DeliveryProfileError(
            "integration base overlaps reviewed paths; rebase and re-review required: "
            + ", ".join(collisions)
        )
    with tempfile.TemporaryDirectory(prefix="startup-factory-index-") as temporary:
        index_path = Path(temporary) / "index"
        _git(
            root,
            "read-tree",
            resolved_base,
            max_output_bytes=64 * 1024,
            timeout_seconds=30.0,
            index_file=index_path,
        )
        zero_oid = "0" * len(resolved_base)
        updates = bytearray()
        for path in sorted(reviewed):
            mode, oid = reviewed[path]
            if mode is None or oid is None:
                updates.extend(f"0 {zero_oid}\t".encode("ascii") + path + b"\0")
            else:
                updates.extend(f"{mode} {oid}\t".encode("ascii") + path + b"\0")
        _git(
            root,
            "update-index",
            "-z",
            "--index-info",
            input_bytes=bytes(updates),
            max_output_bytes=64 * 1024,
            timeout_seconds=30.0,
            index_file=index_path,
        )
        result = _git(
            root,
            "write-tree",
            max_output_bytes=64 * 1024,
            timeout_seconds=30.0,
            index_file=index_path,
        )
    try:
        tree = result.strip().decode("ascii", "strict").lower()
    except UnicodeError as exc:
        raise DeliveryProfileError("canonical merge tree is not ASCII") from exc
    if not re.fullmatch(r"[0-9a-f]{40,64}", tree):
        raise DeliveryProfileError(
            "canonical merge did not produce exactly one tree id"
        )
    _git(root, "cat-file", "-e", tree + "^{tree}", max_output_bytes=64 * 1024)
    return tree, resolved_base, resolved_head, observed_merge_base


def _atomic_write(directory: Path, name: str, body: bytes, mode: int = 0o600) -> Path:
    """Write one bounded artifact without following a destination symlink."""
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise DeliveryProfileError("artifact filename is unsafe")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        directory_mode = directory.lstat().st_mode
    except OSError as exc:
        raise DeliveryProfileError("artifact directory is unavailable") from exc
    if directory.is_symlink() or not stat.S_ISDIR(directory_mode):
        raise DeliveryProfileError("artifact directory must be a non-symlink directory")
    directory_flags = os.O_RDONLY
    for flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
        directory_flags |= getattr(os, flag, 0)
    try:
        directory_fd = os.open(directory, directory_flags)
    except OSError as exc:
        raise DeliveryProfileError("artifact directory cannot be securely opened") from exc
    temporary = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for flag in ("O_CLOEXEC", "O_NOFOLLOW"):
            flags |= getattr(os, flag, 0)
        descriptor = os.open(temporary, flags, mode, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        raise DeliveryProfileError("review artifact could not be written atomically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
    return directory / name


def build_review_package(
    repo: str | os.PathLike[str],
    task_id: str,
    base: str,
    head: str,
) -> tuple[bytes, str, str]:
    """Build the canonical exact-diff reviewer package with bounded safe Git.

    The returned commit ids are the canonical immutable objects used for every
    command. Repository-local diff helpers, text conversion, replacement refs,
    lazy fetch, credentials, and transport protocols cannot affect the bytes.
    """
    if (
        not isinstance(task_id, str)
        or not task_id
        or len(task_id) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in task_id)
    ):
        raise DeliveryProfileError("task id is invalid for a review package")
    root = _repository_root(Path(repo))
    resolved_base = _resolve_commit(root, base)
    resolved_head = _resolve_commit(root, head)
    revision_range = f"{resolved_base}..{resolved_head}"
    common = (
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--default-prefix",
        "--no-relative",
        "--submodule=short",
        "--find-renames=50%",
        "-O/dev/null",
    )
    commits = _git(
        root,
        "log",
        "--oneline",
        "--no-decorate",
        "--no-notes",
        "--no-show-signature",
        revision_range,
        "--",
        max_output_bytes=MAX_REVIEW_PACKAGE_BYTES,
        timeout_seconds=MAX_REVIEW_PACKAGE_RUNTIME_SECONDS,
    ).rstrip(b"\n")
    statistics = _git(
        root,
        "diff",
        "--stat=80,50",
        *common,
        revision_range,
        "--",
        max_output_bytes=MAX_REVIEW_PACKAGE_BYTES,
        timeout_seconds=MAX_REVIEW_PACKAGE_RUNTIME_SECONDS,
    ).rstrip(b"\n")
    patch = _git(
        root,
        "diff",
        "-U10",
        "--inter-hunk-context=0",
        "--binary",
        "--full-index",
        *common,
        revision_range,
        "--",
        max_output_bytes=MAX_REVIEW_PACKAGE_BYTES,
        timeout_seconds=MAX_REVIEW_PACKAGE_RUNTIME_SECONDS,
    ).rstrip(b"\n")
    if b"\0" in patch:
        raise DeliveryProfileError(
            "review diff contains raw NUL bytes; remove attributes that force binary blobs to text"
        )
    body = b"\n".join(
        (
            f"# Review package: {task_id}".encode("utf-8"),
            b"",
            f"Base: {resolved_base}".encode("ascii"),
            f"Head: {resolved_head}".encode("ascii"),
            b"",
            b"## Commits",
            commits,
            b"",
            b"## Files changed",
            statistics,
            b"",
            b"## Diff",
            patch,
        )
    ) + b"\n"
    if len(body) > MAX_REVIEW_PACKAGE_BYTES:
        raise DeliveryProfileError("review package exceeds the safety cap")
    return body, resolved_base, resolved_head


def create_review_package(
    repo: str | os.PathLike[str],
    worktree: str | os.PathLike[str],
    base_ref: str,
    head_ref: str,
    task_id: str,
    output_directory: str | os.PathLike[str],
) -> Path:
    """Create a clean-worktree review package and its immutable binding record."""
    root = _repository_root(Path(repo))
    worktree_root = _repository_root(Path(worktree))
    if _git_common_directory(root) != _git_common_directory(worktree_root):
        raise DeliveryProfileError("review worktree belongs to a different Git repository")
    expected_head_ref = head_ref if head_ref.startswith("refs/") else f"refs/heads/{head_ref}"
    current_head_ref = _decode_git_output(
        _git(worktree_root, "symbolic-ref", "--quiet", "HEAD"),
        "review worktree branch",
    ).strip()
    if current_head_ref != expected_head_ref:
        raise DeliveryProfileError("review worktree is not on its bound task branch")
    if _git(
        worktree_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        max_output_bytes=MAX_GIT_OUTPUT_BYTES,
    ):
        raise DeliveryProfileError(
            f"{task_id} has uncommitted changes; worker must create task-branch checkpoint commits first"
        )
    base_tip = _resolve_commit(root, base_ref)
    head = _resolve_commit(root, head_ref)
    base_raw = _git(root, "merge-base", base_tip, head).strip()
    try:
        base = base_raw.decode("ascii", "strict").lower()
    except UnicodeError as exc:
        raise DeliveryProfileError("review merge base is not an ASCII commit id") from exc
    if not re.fullmatch(r"[0-9a-f]{40,64}", base):
        raise DeliveryProfileError("review merge base is not a canonical commit id")
    package, base, head = build_review_package(root, task_id, base, head)
    base_short = _decode_git_output(
        _git(root, "rev-parse", "--short", base), "short review base"
    ).strip()
    head_short = _decode_git_output(
        _git(root, "rev-parse", "--short", head), "short review head"
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{4,64}", base_short) or not re.fullmatch(
        r"[0-9a-f]{4,64}", head_short
    ):
        raise DeliveryProfileError("short review commit id is malformed")
    directory = Path(output_directory)
    destination = _atomic_write(
        directory, f"review-{base_short}..{head_short}.diff", package
    )
    binding = {
        "schemaVersion": 1,
        "reviewBaseCommit": base,
        "taskBranchHead": head,
        "reviewPackagePath": str(destination),
        "reviewPackageSha256": "sha256:" + hashlib.sha256(package).hexdigest(),
    }
    _atomic_write(
        directory,
        f"review-{base_short}..{head_short}.bindings.json",
        (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return destination


def _decode_path(value: bytes) -> str:
    try:
        return value.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeliveryProfileError("diff contains a non-UTF-8 path") from exc


def _raw_diff(repo: Path, base: str, head: str) -> tuple[list[str], list[str]]:
    tokens = _git(
        repo,
        "diff",
        "--raw",
        "-z",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--find-renames=50%",
        base,
        head,
        "--",
    ).split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    files: list[str] = []
    reasons: list[str] = []
    index = 0
    while index < len(tokens):
        header = tokens[index]
        index += 1
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(b":"):
            return [], ["unrecognized-raw-diff"]
        old_mode = fields[0][1:].decode("ascii", "replace")
        new_mode = fields[1].decode("ascii", "replace")
        status = fields[4].decode("ascii", "replace")
        if index >= len(tokens):
            return [], ["unrecognized-raw-diff"]
        first_path = _decode_path(tokens[index])
        index += 1
        path = first_path
        if status.startswith(("R", "C")):
            if index >= len(tokens):
                return [], ["unrecognized-raw-diff"]
            path = _decode_path(tokens[index])
            index += 1
        files.append(path)
        if status not in {"A", "M"}:
            reasons.append("unsupported-change-status:%s" % (status or "unknown"))
        if old_mode != new_mode and old_mode != "000000":
            reasons.append("file-mode-change")
        if new_mode != "100644":
            reasons.append("non-regular-file-mode")
    if len(files) != len(set(files)):
        reasons.append("duplicate-diff-path")
    return files, reasons


def _numstat_diff(repo: Path, base: str, head: str) -> tuple[dict[str, int], list[str]]:
    tokens = _git(
        repo,
        "diff",
        "--numstat",
        "-z",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--find-renames=50%",
        base,
        head,
        "--",
    ).split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    counts: dict[str, int] = {}
    reasons: list[str] = []
    index = 0
    while index < len(tokens):
        fields = tokens[index].split(b"\t", 2)
        index += 1
        if len(fields) != 3:
            return {}, ["unrecognized-numstat"]
        added, deleted, raw_path = fields
        # Rename/copy numstat encodes an empty path followed by old and new paths.
        if raw_path == b"":
            if index + 1 >= len(tokens):
                return {}, ["unrecognized-numstat"]
            index += 1
            raw_path = tokens[index]
            index += 1
        path = _decode_path(raw_path)
        if added == b"-" or deleted == b"-":
            reasons.append("binary-content")
            continue
        try:
            changed = int(added) + int(deleted)
        except ValueError:
            return {}, ["unrecognized-numstat"]
        if changed < 0 or path in counts:
            reasons.append("invalid-numstat")
        else:
            counts[path] = changed
    return counts, reasons


def assess_diff(
    repo: str | os.PathLike[str],
    base: str,
    head: str,
    task: dict,
    metadata: dict | None = None,
) -> dict:
    """Assess the exact committed Git diff with a monotonic risk floor."""
    if not isinstance(task, dict):
        raise DeliveryProfileError("task must be an object")
    metadata_error = False
    if metadata is None:
        try:
            metadata = parse_task_metadata(task.get("description"), task.get("title"))
        except ValueError:
            metadata_error = True
            metadata = {
                "deliveryProfile": "auto",
                "files": [],
                "resources": [],
                "workKind": None,
            }
    elif not isinstance(metadata, dict):
        metadata_error = True
        metadata = {
            "deliveryProfile": "auto",
            "files": [],
            "resources": [],
            "workKind": None,
        }
    requested = metadata.get("deliveryProfile", "auto")
    if requested not in {"auto", *PROFILE_LEVELS}:
        metadata_error = True
        requested = "auto"
    root = _repository_root(Path(repo))
    resolved_base = _resolve_commit(root, base)
    resolved_head = _resolve_commit(root, head)
    files, reasons = _raw_diff(root, resolved_base, resolved_head)
    declared, task_reasons = _task_shape(task, metadata)
    reasons.extend(task_reasons)
    if metadata_error:
        reasons.append("malformed-task-metadata")
    counts, numstat_reasons = _numstat_diff(root, resolved_base, resolved_head)
    reasons.extend(numstat_reasons)
    if not files:
        reasons.append("empty-diff")
    if len(files) > MAX_MICRO_FILES:
        reasons.append("too-many-files")
    if set(files) != set(counts):
        reasons.append("diff-accounting-mismatch")
    if any(_safe_relative_path(path) is None for path in files):
        reasons.append("unsafe-diff-path")
    for path in files:
        if is_control_plane_path(path):
            reasons.append(f"control-plane-path:{path}")
    if files and not all(is_ordinary_documentation_path(path) for path in files):
        reasons.append("non-ordinary-documentation-path")
    if files and _contains_strong_surface("\n".join(files)):
        reasons.append("strong-risk-diff-path")
    reasons.extend(_patch_risk(root, resolved_base, resolved_head))
    reasons.extend(_blob_risk(root, resolved_head, files))
    changed_lines = sum(counts.values())
    if changed_lines > MAX_MICRO_CHANGED_LINES:
        reasons.append("too-many-changed-lines")
    if declared and set(declared) != set(files):
        reasons.append("declared-files-mismatch")
    reasons = list(dict.fromkeys(reasons))
    if any(_reason_is_high_risk(reason) for reason in reasons):
        inferred = "high-risk"
    elif not reasons:
        inferred = "micro"
    else:
        inferred = "standard"
    return _decision(
        phase="diff",
        requested=requested,
        inferred=inferred,
        reasons=reasons,
        files=files,
        changed_lines=changed_lines,
        base_commit=resolved_base,
        head_commit=resolved_head,
    )


def assess_review_diff(
    repo: str | os.PathLike[str],
    base: object,
    head: object,
    task: dict,
) -> dict:
    """Assess bound review commits, converting every ambiguity to high-risk.

    The review boundary must remain routable when a binding, Git object, path,
    or task field is malformed.  It therefore returns a high-risk decision
    instead of allowing an exception to skip QA or Security.
    """
    try:
        return assess_diff(repo, base, head, task)  # type: ignore[arg-type]
    except (DeliveryProfileError, OSError, TypeError, ValueError, UnicodeError):
        requested = "auto"
        if isinstance(task, dict):
            try:
                candidate = parse_task_metadata(
                    task.get("description"), task.get("title")
                ).get("deliveryProfile", "auto")
                if candidate in PROFILE_LEVELS:
                    requested = candidate
            except (TypeError, ValueError):
                pass
        return _decision(
            phase="diff",
            requested=requested,
            inferred="high-risk",
            reasons=["unreadable-exact-diff"],
            files=[],
            changed_lines=None,
            base_commit=base if isinstance(base, str) else None,
            head_commit=head if isinstance(head, str) else None,
        )


def _read_task(path: str) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeliveryProfileError("task file must contain valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise DeliveryProfileError("task file must contain an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    task = subparsers.add_parser("task", help="assess declared task scope")
    task.add_argument("--task", required=True, help="task JSON file")
    diff = subparsers.add_parser("diff", help="assess an actual committed Git diff")
    diff.add_argument("--repo", required=True)
    diff.add_argument("--base", required=True)
    diff.add_argument("--head", required=True)
    diff.add_argument("--task", required=True, help="task JSON file")
    root = subparsers.add_parser("repo-root", help="resolve a controlled Git top level")
    root.add_argument("--path", required=True)
    subparsers.add_parser(
        "git-executable", help="print the absolute controlled Git executable"
    )
    package = subparsers.add_parser(
        "review-package", help="create one canonical bounded exact-diff package"
    )
    package.add_argument("--repo", required=True)
    package.add_argument("--worktree", required=True)
    package.add_argument("--base-ref", required=True)
    package.add_argument("--head-ref", required=True)
    package.add_argument("--task", required=True)
    package.add_argument("--output-directory", required=True)
    merge_tree = subparsers.add_parser(
        "merge-tree", help="compute one isolated canonical integration tree"
    )
    merge_tree.add_argument("--repo", required=True)
    merge_tree.add_argument("--base", required=True)
    merge_tree.add_argument("--head", required=True)
    merge_tree.add_argument("--merge-base", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "git-executable":
            print(GIT_EXECUTABLE)
            return 0
        if args.command == "repo-root":
            print(repository_root(args.path))
            return 0
        if args.command == "review-package":
            print(
                create_review_package(
                    args.repo,
                    args.worktree,
                    args.base_ref,
                    args.head_ref,
                    args.task,
                    args.output_directory,
                )
            )
            return 0
        if args.command == "merge-tree":
            tree, _, _, _ = canonical_merge_tree(
                args.repo, args.base, args.head, args.merge_base
            )
            print(tree)
            return 0
        task = _read_task(args.task)
        result = assess_task(task) if args.command == "task" else assess_diff(
            args.repo, args.base, args.head, task
        )
    except DeliveryProfileError as exc:
        print("delivery-profile: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
