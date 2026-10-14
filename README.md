# sanitext

Sanitises untrusted HTML (forum comments, profile bios) before it is stored
and rendered. Everything that is not explicitly allowed by a `Policy` is
removed. Standard library only; Python 3.11+ (developed on 3.14).

```python
from sanitext import sanitize, STRICT_POLICY
sanitize('<p onclick="x()">Hi <a href="https://example.com">there</a></p>')
# '<p>Hi <a href="https://example.com">there</a></p>'
sanitize("<b>bold</b> <a href='https://x'>link</a>", STRICT_POLICY)
```

```sh
python3 -m sanitext comment.html > safe.html
python3 -m sanitext --policy strict < comment.html
```

## Policies

* `DEFAULT_POLICY`: basic formatting, lists, quotes, code, links (`href`,
  `title`) and images (`src`, `alt`, `title`); URL schemes `http`, `https`,
  `mailto`.
* `STRICT_POLICY`: inline formatting and paragraphs only.
* Custom: `Policy(allowed_tags=..., allowed_attributes={"a": frozenset({"href"}), "*": frozenset({"title"})}, ...)`.

## Development

```sh
python3 -m unittest discover -s tests -t .
```
