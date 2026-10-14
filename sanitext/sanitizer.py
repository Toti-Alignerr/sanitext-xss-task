"""HTML sanitiser for user-generated content."""

from __future__ import annotations

import re

from .policy import DEFAULT_POLICY, Policy

_DANGEROUS_BLOCK = re.compile(r"<(script|style)\b.*?>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_EVENT_HANDLER = re.compile(r"""\s+on\w+\s*=\s*("[^"]*"|'[^']*')""", re.IGNORECASE)
_JAVASCRIPT = re.compile(r"javascript\s*:", re.IGNORECASE)
_TAG = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>")


def sanitize(html: str, policy: Policy = DEFAULT_POLICY) -> str:
    """Returns ``html`` with everything not allowed by ``policy`` removed."""
    html = _DANGEROUS_BLOCK.sub("", html)
    html = _EVENT_HANDLER.sub("", html)
    html = _JAVASCRIPT.sub("", html)

    def keep_allowed(match: re.Match[str]) -> str:
        return match.group(0) if match.group(1).lower() in policy.allowed_tags else ""

    return _TAG.sub(keep_allowed, html)
