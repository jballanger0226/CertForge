"""The seal (shown when a certificate is issued) and the logo mark."""
import re
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

APP = Path(__file__).resolve().parent.parent / "app"
ENV = Environment(loader=FileSystemLoader(APP / "templates"), autoescape=select_autoescape(["html"]))


def render(org: str) -> str:
    return ENV.from_string('{% from "_seal.html" import seal %}{{ seal(org) }}').render(org=org)


class Seal(unittest.TestCase):
    def test_the_ring_text_is_the_cas_own_name(self):
        self.assertIn(">Home Lab Certificate Authority<", render("Home Lab"))
        self.assertIn(">Acme Widgets Certificate Authority<", render("Acme Widgets"))
        long = "A Very Long Organisation Name Indeed"
        self.assertIn(f">{long}<", render(long))                  # too long to add "Certificate Authority"

    def test_names_cannot_inject_markup(self):
        out = render('<script>alert(1)</script>"><svg onload=x>')
        self.assertNotIn("<script", out)
        self.assertNotIn("<svg onload", out)
        self.assertIn("&lt;script&gt;", out)

    def test_it_works_under_our_content_security_policy(self):
        out = render("Home Lab")
        self.assertNotRegex(out, r"\sstyle\s*=")                  # style-src 'self' would block it
        self.assertNotRegex(out, r"(?i)<style|<script|javascript:|\son\w+\s*=")
        ids = re.findall(r'\bid="([^"]+)"', out)
        self.assertEqual(len(ids), len(set(ids)))
        for target in set(re.findall(r'(?:href="#|url\(#)([A-Za-z0-9_-]+)', out)):
            self.assertIn(target, ids, f"{target} is referenced but not defined")

    def test_the_header_mark_and_favicon_use_the_same_drawing(self):
        base = (APP / "templates" / "base.html").read_text()
        fav = (APP / "static" / "favicon.svg").read_text()
        self.assertIn('<symbol id="mark"', base)
        self.assertNotRegex(base, r"<symbol[^>]*>[^<]*<g[^>]*style=")
        self.assertNotIn("style=", fav)
        self.assertIn('color="#4a3fb0"', fav)
        # the favicon is a standalone file, so every reference in it must resolve inside it
        ids = set(re.findall(r'\bid="([^"]+)"', fav))
        for target in set(re.findall(r"url\(#([A-Za-z0-9_-]+)\)", fav)):
            self.assertIn(target, ids)


if __name__ == "__main__":
    unittest.main()
