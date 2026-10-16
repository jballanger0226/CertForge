"""Looks for a newer CertForge release. It only ever reads; installing is done on the host, by an administrator.

Off unless an administrator turns it on (CERTFORGE_UPDATE_CHECK=1 or the switch on the CA page). One check is a
single HTTPS request to the GitHub releases API for the project's repository, about once a day; it sends nothing
but the program name and version, though GitHub sees this server's address.
"""
from __future__ import annotations

import json
import re
from datetime import timedelta
import urllib.error
import urllib.request

from . import version as V
from .store import iso, parse_iso, utcnow

DEFAULT_REPO = "jballanger0226/CertForge"
CHECK_EVERY_HOURS = 20
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")


class CheckError(Exception):
    """The check couldn't be completed. The message is safe to show."""


def fetch_latest(repo: str, build: V.Build, timeout: float = 8.0, opener=urllib.request.urlopen) -> dict | None:
    """The newest published release as {"version", "tag", "url", "published"}, or None if there isn't one yet."""
    if not _REPO.match(repo or ""):
        raise CheckError(f"'{repo}' isn't a GitHub repository name like owner/name.")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"CertForge/{build.version}",
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener(req, timeout=timeout) as r:
            data = json.loads(r.read(1_000_000))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None                                   # no releases yet (or the repository isn't public)
        raise CheckError(f"GitHub answered {e.code}" + (" (rate limited; it will try again later)" if e.code in (403, 429) else "")) from None
    except (OSError, ValueError) as e:
        raise CheckError(f"Couldn't reach GitHub: {getattr(e, 'reason', None) or e}") from None
    tag = str(data.get("tag_name", ""))
    if not V.parse(tag):
        raise CheckError(f"The newest release is called '{tag}', which isn't a version number.")
    return {"version": tag.lstrip("v"), "tag": tag, "url": str(data.get("html_url", "")),
            "published": str(data.get("published_at", ""))[:10]}


class Updates:
    def __init__(self, store, cfg, build: V.Build, fetch=fetch_latest):
        self.store, self.cfg, self.build, self.fetch = store, cfg, build, fetch

    def _state(self) -> dict:
        return self.store.get("updates", {}) or {}

    def enabled(self) -> bool:
        v = self._state().get("enabled")
        return self.cfg.update_check if v is None else bool(v)

    def set_enabled(self, enabled: bool) -> None:
        self.store.set("updates", {**self._state(), "enabled": bool(enabled)})

    def due(self) -> bool:
        st = self._state()
        if not self.enabled():
            return False
        if not st.get("checked"):
            return True
        return utcnow() - parse_iso(st["checked"]) > timedelta(hours=CHECK_EVERY_HOURS)

    def check(self) -> dict:
        """Ask GitHub now and remember the answer. Returns status(). Failures are remembered, not raised."""
        st = self._state()
        try:
            latest, error = self.fetch(self.cfg.update_repo, self.build), ""
        except CheckError as e:
            latest, error = st.get("latest"), str(e)          # keep what we knew
        self.store.set("updates", {**st, "checked": iso(utcnow()), "latest": latest, "error": error})
        return self.status()

    def status(self) -> dict:
        st = self._state()
        latest = st.get("latest")
        newer = V.is_newer(latest["version"], self.build.version) if latest else None
        return {
            "enabled": self.enabled(), "checked": st.get("checked"), "error": st.get("error", ""), "latest": latest,
            "repo": self.cfg.update_repo,
            "available": bool(latest) and newer is True,
            # a development build can't be compared with a release, so say that instead of guessing
            "uncomparable": bool(latest) and newer is None,
            "current": bool(latest) and newer is False,
            "command": V.update_command(self.build.deploy),
        }
