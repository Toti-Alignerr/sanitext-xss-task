"""Sanitisation policies: which tags, attributes and URL schemes survive."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    """What a sanitised document may contain.

    ``allowed_attributes`` maps a tag name to the attribute names allowed on
    it; the key ``"*"`` lists attributes allowed on every allowed tag.
    ``url_attributes`` are attributes whose values are URLs and are checked
    against ``allowed_schemes``.
    """

    allowed_tags: frozenset[str]
    allowed_attributes: dict[str, frozenset[str]] = field(default_factory=dict)
    url_attributes: frozenset[str] = frozenset({"href", "src"})
    allowed_schemes: frozenset[str] = frozenset({"http", "https", "mailto"})

    def attribute_allowed(self, tag: str, name: str) -> bool:
        return name in self.allowed_attributes.get(tag, frozenset()) or name in self.allowed_attributes.get(
            "*", frozenset()
        )


#: Default policy for forum comments.
DEFAULT_POLICY = Policy(
    allowed_tags=frozenset(
        {"a", "b", "strong", "i", "em", "u", "s", "p", "br", "ul", "ol", "li", "blockquote", "code", "pre", "img"}
    ),
    allowed_attributes={
        "a": frozenset({"href", "title"}),
        "img": frozenset({"src", "alt", "title"}),
        "*": frozenset(),
    },
)

#: Plain formatting only: no links or images.
STRICT_POLICY = Policy(
    allowed_tags=frozenset({"b", "strong", "i", "em", "u", "s", "p", "br", "code"}),
    allowed_attributes={},
)

POLICIES = {"default": DEFAULT_POLICY, "strict": STRICT_POLICY}
