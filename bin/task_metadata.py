#!/usr/bin/env python3
"""Shared parsing and conservative policy helpers for task metadata."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


METADATA_RE = re.compile(
    r"^\s*(track|parallel-safe|files|resources|model-profile|delivery-profile|work-kind|review-gates)\s*:(.*)$",
    re.I,
)
FRONTEND_RE = re.compile(r"\b(frontend|client|browser|component|css|ui)\b", re.I)
OBVIOUS_FAST_RE = re.compile(
    r"\b(docs?|documentation|readme|comments?|typos?|spelling|lint|format(?:ting)?)\b",
    re.I,
)
STRUCTURAL_FAST_RE = re.compile(r"\b(rename|copy|config(?:uration)?|constants?|test-only|tests? only)\b", re.I)
DOC_SUFFIXES = {".adoc", ".md", ".rst", ".txt"}
DOC_NAMES = {"changelog", "contributing", "license", "readme"}
SUPPORTED_REVIEW_GATES = ("qa", "security")
STRONG_RISK_RE = re.compile(
    r"\b(?:access[ -]?control|acl|auth|authentication|authorization|authn|authz|"
    r"oauth2?|sso|mfa|csrf|xss|cors|same[ -]?site|cookies?|identity|iam|rbac|"
    r"admins?|administrat(?:or|ive|ion)|entitlements?|"
    r"login|logout|jwt|oidc|saml|certificates?|tls|ssl|security|permissions?|"
    r"privileges?|tenants?|migrations?|schemas?|concurren\w*|races?|crypt\w*|"
    r"public[ -]?api|secrets?|credentials?|passwords?|deploy\w*|production|"
    r"guardrails?|sandbox|control[ -]?plane|broker|destructive|data[ -]?loss|"
    r"supply[ -]?chain|dependenc(?:y|ies)|lockfiles?|serverless|kubernetes|k8s|helm|terraform|"
    r"terragrunt|pulumi|ansible|cloudformation|infrastructure[ -]?as[ -]?code|iac)\b",
    re.I,
)
AUTH_OPERATION_RE = re.compile(
    r"\b(?:(?:un)?authenticat(?:e[sd]?|ing|ion|ors?)|"
    r"(?:un)?authori[sz](?:e[sd]?|ers?|ing|ation))\b",
    re.I,
)
SENSITIVE_TOKEN_RE = re.compile(
    r"\b(?:(?:access|refresh|bearer|api|auth|authentication|session|credential|"
    r"secret|oauth|jwt)[ -]+tokens?|tokens?[ -]+(?:rotation|validation|verification|"
    r"expiry|expiration|revocation|scope))\b",
    re.I,
)
SENSITIVE_SESSION_RE = re.compile(
    r"\b(?:(?:login|user|auth|authentication|browser|cookie|server)[ -]+sessions?|"
    r"sessions?[ -]+(?:cookie|store|expiry|expiration|timeout|fixation|hijack|"
    r"authentication))\b",
    re.I,
)
RELEASE_OPERATION_RE = re.compile(
    r"\b(?:(?:deploy|publish|promote|ship|cut|prepare|automate)\w*[ -]+"
    r"(?:the[ -]+|a[ -]+)?release|release[ -]+(?:pipeline|workflow|process|artifact|"
    r"package|automation|promotion|deployment|candidate|build|version|v?\d[\w.-]*|"
    r"to[ -]+(?:production|staging|pypi|npm|an?[ -]+app[ -]+store))|"
    r"publish\w*[ -]+(?:package|artifact|image|build|wheel|sdist)|"
    r"promot\w*[ -]+(?:a[ -]+|the[ -]+)?(?:build|artifact|release)[ -]+"
    r"(?:to[ -]+)?(?:production|staging))\b",
    re.I,
)
POLICY_CONTROL_RE = re.compile(
    r"\b(?:(?:security|access|authorization|deployment|production|release|sandbox|"
    r"guardrail)[ -]+polic(?:y|ies)|polic(?:y|ies)[ -]+(?:engine|enforcement|"
    r"guardrail|authorization|access[ -]+control))\b",
    re.I,
)
DESTRUCTIVE_OPERATION_RE = re.compile(
    r"\b(?:delete|drop|truncate|erase|purge)\w*[ -]+(?:\w+[ -]+){0,2}"
    r"(?:table|database|schema|data|records?|files?|storage|bucket|cluster|production)\b",
    re.I,
)
CONTROL_HOOK_RE = re.compile(
    r"\b(?:git|pre[ -]?commit|post[ -]?receive|deployment|security)[ -]+hooks?\b",
    re.I,
)
PUBLIC_CONTRACT_RE = re.compile(
    r"\b(?:public|external|api)[ -]+contracts?\b",
    re.I,
)
SIGNATURE_SECURITY_RE = re.compile(
    r"\b(?:(?:verify|validate|check|enforce)\w*[ -]+(?:a[ -]+|the[ -]+)?"
    r"(?:request|payload|message|webhook|token)?[ -]*signatures?|"
    r"(?:request|payload|message|webhook|token)[ -]+signature(?:s)?(?:[ -]+verification)?|"
    r"signature[ -]+(?:verification|validation|bypass|forgery))\b",
    re.I,
)
INJECTION_SECURITY_RE = re.compile(
    r"\b(?:(?:sql|command|shell|template|header|query|prompt|code)[ -]+injection|"
    r"inject(?:ed|ing)?[ -]+(?:sql|commands?|shell|headers?|queries?|prompts?|code))\b",
    re.I,
)


def normalize_risk_text(value: object) -> str:
    """Expose identifier boundaries without turning harmless prefixes into risk.

    Security-sensitive code commonly uses camelCase or acronym-prefixed names
    (``csrfProtection``, ``JWTVerifier``).  Splitting those boundaries lets the
    exact terms match while keeping ``author`` distinct from ``auth``.
    """
    text = str(value or "")
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    return text.replace("_", "-")


def contains_strong_risk(value: object) -> bool:
    text = normalize_risk_text(value)
    return any(
        pattern.search(text)
        for pattern in (
            STRONG_RISK_RE,
            AUTH_OPERATION_RE,
            SENSITIVE_TOKEN_RE,
            SENSITIVE_SESSION_RE,
            RELEASE_OPERATION_RE,
            POLICY_CONTROL_RE,
            DESTRUCTIVE_OPERATION_RE,
            CONTROL_HOOK_RE,
            PUBLIC_CONTRACT_RE,
            SIGNATURE_SECURITY_RE,
            INJECTION_SECURITY_RE,
        )
    )


def requires_strong_model(task: dict) -> bool:
    text = "%s\n%s" % (task.get("title") or "", task.get("description") or "")
    return contains_strong_risk(text)


def normalize_review_gates(values: list[str] | tuple[str, ...]) -> list[str]:
    normalized = [str(item).strip().lower() for item in values if str(item).strip()]
    if len(normalized) != len(set(normalized)):
        raise ValueError("review gates must not contain duplicates")
    unsupported = sorted(set(normalized) - set(SUPPORTED_REVIEW_GATES))
    if unsupported:
        raise ValueError(
            "review-gates supports only qa and security; got: "
            + ", ".join(unsupported)
        )
    return [gate for gate in SUPPORTED_REVIEW_GATES if gate in normalized]


def required_review_gates(preset_text: object = "") -> list[str]:
    matches = re.findall(
        r"^REQUIRED_REVIEW_GATES=([^\r\n]+)$", str(preset_text or ""), re.M
    )
    if len(matches) > 1:
        raise ValueError("team preset must not duplicate REQUIRED_REVIEW_GATES")
    if not matches or matches[0].strip().lower() == "null":
        return []
    return normalize_review_gates(tuple(matches[0].split(",")))


def profile_forced_review_gates(delivery_profile: object = None) -> list[str]:
    """Return the gates forced by an authoritative delivery-profile decision.

    Callers must never trust a decision object's embedded gate list.  The
    effective profile is the only input, and an unrecognised or malformed
    supplied decision fails closed to both supported specialist gates.
    ``None`` preserves compatibility for callers that have not classified a
    task yet.
    """
    if delivery_profile is None:
        return []
    if isinstance(delivery_profile, dict):
        profile = delivery_profile.get("effectiveProfile")
    else:
        profile = delivery_profile
    if profile == "high-risk":
        return list(SUPPORTED_REVIEW_GATES)
    if profile in {"micro", "standard"}:
        return []
    return list(SUPPORTED_REVIEW_GATES)


def effective_review_gates(
    metadata: dict,
    preset_text: object = "",
    delivery_profile: object = None,
) -> list[str]:
    combined = set(metadata.get("reviewGates") or ()) | set(
        required_review_gates(preset_text)
    ) | set(profile_forced_review_gates(delivery_profile))
    return [gate for gate in SUPPORTED_REVIEW_GATES if gate in combined]


def parse_task_metadata(description: object, title: object = "") -> dict:
    text = str(description or "")
    result = {
        "parallelSafe": False,
        "files": [],
        "resources": [],
        "track": None,
        "modelProfile": None,
        "deliveryProfile": "auto",
        "workKind": None,
        "reviewGates": [],
    }
    aliases = {
        "track": "track",
        "parallel-safe": "parallelSafe",
        "files": "files",
        "resources": "resources",
        "model-profile": "modelProfile",
        "delivery-profile": "deliveryProfile",
        "work-kind": "workKind",
        "review-gates": "reviewGates",
    }
    seen_fields: set[str] = set()
    for line in text.splitlines():
        match = METADATA_RE.match(line)
        if not match:
            continue
        key = aliases[match.group(1).lower()]
        value = match.group(2).strip()
        if not value:
            raise ValueError(f"{match.group(1).lower()} must have a value")
        if key in seen_fields:
            raise ValueError(
                f"{match.group(1).lower()} must not be declared more than once"
            )
        seen_fields.add(key)
        if key == "parallelSafe":
            result[key] = value.lower() in {"true", "yes", "1"}
        elif key in {"files", "resources", "reviewGates"}:
            result[key] = [item.strip() for item in value.split(",") if item.strip()]
            if key == "reviewGates":
                result[key] = normalize_review_gates(tuple(result[key]))
        elif key == "workKind":
            result[key] = value.lower()
            if result[key] not in {"defect", "change", "research", "operations"}:
                raise ValueError(
                    "work-kind must be defect, change, research, or operations"
                )
        elif key == "deliveryProfile":
            result[key] = value.lower()
            if result[key] not in {"auto", "micro", "standard", "high-risk"}:
                raise ValueError(
                    "delivery-profile must be auto, micro, standard, or high-risk"
                )
        elif key == "modelProfile":
            result[key] = value.lower()
            if result[key] not in {"fast", "standard", "strong"}:
                raise ValueError(
                    "model-profile must be fast, standard, or strong"
                )
        else:
            result[key] = value.lower()
    if not result["track"]:
        haystack = "%s\n%s" % (title or "", text)
        result["track"] = "frontend" if FRONTEND_RE.search(haystack) else "backend"
    return result


def _is_documentation_file(path: str) -> bool:
    normalized = path.lower().replace("\\", "/")
    parsed = PurePosixPath(normalized)
    stem = parsed.stem.lower()
    return parsed.suffix.lower() in DOC_SUFFIXES or stem in DOC_NAMES


def _is_test_file(path: str) -> bool:
    normalized = path.lower().replace("\\", "/")
    name = PurePosixPath(normalized).name
    wrapped = "/%s/" % normalized.strip("/")
    return (
        "/test/" in wrapped
        or "/tests/" in wrapped
        or name.startswith("test_")
        or ".test." in name
        or ".spec." in name
    )


def is_fast_task(task: dict, metadata: dict) -> bool:
    """Return true only for clearly bounded, low-risk task shapes."""
    text = "%s\n%s" % (task.get("title") or "", task.get("description") or "")
    files = metadata.get("files") or []
    if metadata.get("resources") or len(files) > 3:
        return False
    if files and all(_is_documentation_file(path) for path in files):
        return True
    if metadata.get("parallelSafe") and files and all(_is_test_file(path) for path in files):
        return True
    if OBVIOUS_FAST_RE.search(text) and not files:
        return True
    return bool(
        metadata.get("parallelSafe")
        and len(files) <= 2
        and STRUCTURAL_FAST_RE.search(text)
    )
