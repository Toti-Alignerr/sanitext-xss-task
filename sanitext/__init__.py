"""sanitext: allowlist-based HTML sanitising for user-generated content."""

from .policy import DEFAULT_POLICY, POLICIES, STRICT_POLICY, Policy
from .sanitizer import sanitize

__all__ = ["DEFAULT_POLICY", "POLICIES", "STRICT_POLICY", "Policy", "sanitize"]
__version__ = "2.1.0"
