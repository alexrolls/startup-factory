"""Dependency-free detection and redaction of high-confidence secret material.

The patterns in this module intentionally target provider-assigned token shapes,
private-key material, authenticated URLs, JWTs, and explicit secret assignments.
They are not a general entropy scanner: ordinary identifiers and CI check names
must remain usable.  Callers should still avoid reflecting untrusted text even
after it passes this defense-in-depth detector.
"""

from __future__ import annotations

import re


REDACTION_MARKER = "[REDACTED SECRET]"

_PEM_HEADER_SOURCE = r"-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|CERTIFICATE)-----"
_BENIGN_ASSIGNMENT_VALUE_SOURCE = (
    r"(?:required|documented|configured|missing|present|enabled|disabled|"
    r"available|unavailable|redacted|masked|unset|none|null|true|false|"
    r"validation|check|bearer)\b"
)


# Keep the alternatives bounded and free of nested quantifiers.  Inputs are
# attacker-controlled on both integration-pack and beta-evidence surfaces.
_SECRET_PATTERN_SOURCES = (
    # Preserve the earlier fail-closed treatment of private-key and certificate
    # blocks. A BEGIN marker is sufficient even when the body is unterminated or
    # unusually large.
    _PEM_HEADER_SOURCE,
    # AWS long-lived and temporary access-key identifiers.
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    # GitHub personal, OAuth, user-to-server, server-to-server, and fine-grained
    # personal access tokens.
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
    # GitLab personal/deploy/runner/job/feed/service-account token families.
    r"(?<![A-Za-z0-9_])(?:glpat|gldt|glrt|glcbt|glptt|glft|glsoat|glagent)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_])",
    # npm automation/granular access tokens.
    r"\bnpm_[A-Za-z0-9]{36,}\b",
    # Stripe secret/restricted keys (live and test are both credentials) and
    # webhook-signing secrets. Publishable pk_* keys are intentionally omitted.
    r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
    r"\bwhsec_[A-Za-z0-9]{16,}\b",
    # OpenAI and compatible service keys. Retain the pre-centralization minimum
    # so this hardening does not silently narrow established coverage.
    r"(?<![A-Za-z0-9_])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_])",
    # Slack tokens.
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    # Google API keys.
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    # PyPI upload tokens.
    r"(?<![A-Za-z0-9_])pypi-[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_])",
    # SendGrid API keys.
    r"(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_])",
    # Hugging Face user and organization access tokens.
    r"\bhf_[A-Za-z0-9]{20,}\b",
    # Shopify access/application/shared-secret token families.
    r"\b(?:shpat|shpca|shppa|shpss)_[A-Fa-f0-9]{32}\b",
    # DigitalOcean personal access tokens.
    r"\bdop_v1_[A-Fa-f0-9]{64}\b",
    # Linear personal API keys and OAuth access tokens.  These stable prefixes
    # are also covered when they appear outside an Authorization header.
    r"(?<![A-Za-z0-9_])lin_(?:api|oauth)_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_])",
    # Signed JSON Web Tokens.
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    # Credentials embedded in a URI authority component.
    # Bound the scheme so an attacker-controlled long alphabetic string cannot
    # make the search retry a greedy scheme match at every character.
    r"[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/@:\s]+:[^/@\s]+@",
    # HTTP Authorization credentials with a real scheme and bounded value.
    r"(?i:\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,})",
    # Explicit assignments remain a useful catch-all when a provider does not
    # publish a stable prefix. The key name and assignment operator are required
    # so ordinary uses of words such as "token" are not rejected. Common
    # declarative placeholders are excluded; provider-shaped values are caught
    # independently above.
    rf"(?i:(?:password|passwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|private[_-]?key|client[_-]?secret|secret[_-]?access[_-]?key|access[_-]?key|account[_-]?key|authorization|connection[_-]?string)\s*[:=]\s*(?!\[?{_BENIGN_ASSIGNMENT_VALUE_SOURCE})[^\s,;}}]{{6,}})",
)


SECRET_MATERIAL_RE = re.compile(
    "(?:" + ")|(?:".join(_SECRET_PATTERN_SOURCES) + ")"
)
_PEM_HEADER_RE = re.compile(_PEM_HEADER_SOURCE)


def contains_secret_like(value: str) -> bool:
    """Return whether ``value`` contains a high-confidence secret shape."""

    return bool(SECRET_MATERIAL_RE.search(value))


def redact_secret_like(value: str, marker: str = REDACTION_MARKER) -> str:
    """Replace every recognized secret span without exposing matched bytes."""

    pem_header = _PEM_HEADER_RE.search(value)
    if pem_header is not None:
        # An untrusted PEM body may be unterminated or arbitrarily large. Keep
        # any safe prefix, redact secrets in it, and discard the complete suffix
        # instead of attempting to locate a potentially forged END marker.
        return SECRET_MATERIAL_RE.sub(marker, value[: pem_header.start()]) + marker
    return SECRET_MATERIAL_RE.sub(marker, value)


__all__ = [
    "REDACTION_MARKER",
    "SECRET_MATERIAL_RE",
    "contains_secret_like",
    "redact_secret_like",
]
