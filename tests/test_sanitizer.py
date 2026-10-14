import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sanitext import DEFAULT_POLICY, STRICT_POLICY, Policy, sanitize

ROOT = Path(__file__).parent.parent


class SanitizeTests(unittest.TestCase):
    def test_keeps_allowed_markup(self):
        self.assertEqual(sanitize("<p>Hello <b>world</b></p>"), "<p>Hello <b>world</b></p>")
        self.assertEqual(sanitize("<ul><li>one</li><li>two</li></ul>"), "<ul><li>one</li><li>two</li></ul>")
        self.assertEqual(sanitize("<blockquote><em>quoted</em></blockquote>"), "<blockquote><em>quoted</em></blockquote>")

    def test_keeps_safe_links_and_images(self):
        html = '<a href="https://example.com/page" title="Example">link</a>'
        self.assertEqual(sanitize(html), html)
        img = '<img src="https://example.com/a.png" alt="A">'
        self.assertEqual(sanitize(img), img)
        self.assertEqual(sanitize("line<br>break"), "line<br>break")

    def test_removes_script_and_style_blocks(self):
        self.assertEqual(sanitize("<script>alert(1)</script><p>ok</p>"), "<p>ok</p>")
        self.assertEqual(sanitize("<STYLE>p { color: red }</STYLE>text"), "text")

    def test_removes_quoted_event_handlers(self):
        self.assertEqual(sanitize('<p onclick="steal()">hi</p>'), "<p>hi</p>")
        self.assertEqual(sanitize("<b onmouseover='x()'>bold</b>"), "<b>bold</b>")

    def test_drops_disallowed_tags_but_keeps_text(self):
        self.assertEqual(sanitize("<div><span>text</span></div>"), "text")
        self.assertEqual(sanitize("<h1>Title</h1>"), "Title")

    def test_strict_policy(self):
        self.assertEqual(sanitize('<a href="https://x.example/">x</a><b>y</b>', STRICT_POLICY), "x<b>y</b>")
        self.assertEqual(sanitize('<img src="https://x.example/i.png">ok', STRICT_POLICY), "ok")

    def test_custom_policy(self):
        policy = Policy(allowed_tags=frozenset({"span"}))
        self.assertEqual(sanitize("<span>a</span><b>b</b>", policy), "<span>a</span>b")
        self.assertTrue(DEFAULT_POLICY.attribute_allowed("a", "href"))
        self.assertFalse(DEFAULT_POLICY.attribute_allowed("p", "href"))

    def test_plain_text_is_unchanged(self):
        self.assertEqual(sanitize("just some words"), "just some words")
        self.assertEqual(sanitize(""), "")


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=""):
        return subprocess.run([sys.executable, "-m", "sanitext", *args], input=stdin, cwd=ROOT,
                              capture_output=True, text=True, check=False)

    def test_stdin_to_stdout(self):
        result = self.run_cli(stdin="<p>hi</p><script>x</script>")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "<p>hi</p>")

    def test_file_and_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "in.html"
            path.write_text('<a href="https://x.example/">x</a>', encoding="utf-8")
            self.assertEqual(self.run_cli(str(path)).stdout, '<a href="https://x.example/">x</a>')
            self.assertEqual(self.run_cli("--policy", "strict", str(path)).stdout, "x")

    def test_errors(self):
        self.assertEqual(self.run_cli("missing.html").returncode, 1)
        self.assertEqual(self.run_cli("--policy", "nope").returncode, 2)


if __name__ == "__main__":
    unittest.main()
