"""Which version is running, recording changes, and the optional look for a newer release."""
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from app import ca as C
from app import version as V
from app.config import Config
from app.service import Service
from app.store import Store
from app.updates import CheckError, Updates, fetch_latest


class Parsing(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(V.parse("1.2.3"), (1, 2, 3, ""))
        self.assertEqual(V.parse("v10.0.1-rc.2"), (10, 0, 1, "rc.2"))
        self.assertEqual(V.parse("1.2.3+build5"), (1, 2, 3, ""))
        for bad in ("dev", "1.2", "latest", "", "1.2.3.4", "v", "1.x.3"):
            self.assertIsNone(V.parse(bad), bad)

    def test_ordering(self):
        newer = [("1.2.4", "1.2.3"), ("1.10.0", "1.9.9"), ("2.0.0", "1.99.99"), ("1.2.0", "1.2.0-rc1"), ("1.2.0-rc2", "1.2.0-rc1"), ("v1.3.0", "1.2.0")]
        for a, b in newer:
            self.assertTrue(V.is_newer(a, b), (a, b))
            self.assertFalse(V.is_newer(b, a), (b, a))
        self.assertFalse(V.is_newer("1.2.3", "1.2.3"))
        self.assertIsNone(V.is_newer("1.2.3", "dev"))                  # can't compare with a development build
        self.assertIsNone(V.is_newer("1.2.3", "0.0.0-abc1234") if False else V.is_newer("nonsense", "1.0.0"))

    def test_unreleased_builds_are_not_releases(self):
        self.assertTrue(V.Build("1.2.0", "abc1234", "").released)
        for v in ("dev", "0.0.0-abc1234", "1.2.0-rc1", ""):
            self.assertFalse(V.Build(v, "", "").released, v)
        self.assertEqual(V.Build("1.2.0", "abc1234", "").label, "1.2.0 (abc1234)")
        self.assertEqual(V.Build("dev", "", "").label, "dev")


class Identity(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cf-ver-"))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_defaults_to_dev(self):
        self.assertEqual(V.current(env={}, root=self.d), V.Build("dev", "", ""))

    def test_files(self):
        (self.d / "VERSION").write_text("v1.4.2\n")
        (self.d / "REVISION").write_text("0123456789abcdef0123\n")
        b = V.current(env={"CERTFORGE_DEPLOY": "Host"}, root=self.d)
        self.assertEqual((b.version, b.revision, b.deploy), ("1.4.2", "0123456789ab", "host"))

    def test_environment_wins_over_files(self):
        (self.d / "VERSION").write_text("1.0.0\n")
        b = V.current(env={"CERTFORGE_VERSION": "2.0.0", "CERTFORGE_REVISION": "feedbee"}, root=self.d)
        self.assertEqual((b.version, b.revision), ("2.0.0", "feedbee"))

    def test_an_unreleased_build_keeps_its_label(self):
        (self.d / "VERSION").write_text("0.0.0-abc1234\n")
        self.assertEqual(V.current(env={}, root=self.d).version, "0.0.0-abc1234")

    def test_this_checkout_reports_a_revision_from_git(self):
        self.assertRegex(V.current(env={}).revision, r"^[0-9a-f]{7}$")

    def test_what_to_type_on_the_host(self):
        self.assertIn("docker compose pull", V.update_command("docker"))
        self.assertEqual(V.update_command("host"), "sudo certforge-update")
        self.assertIn("README", V.update_command(""))


def opener_returning(body=None, error=None):
    def opener(req, timeout=0):
        self_seen.append((req.full_url, dict(req.header_items()), timeout))
        if error:
            raise error
        return io.BytesIO(json.dumps(body).encode())
    return opener


self_seen: list = []


class Fetching(unittest.TestCase):
    build = V.Build("1.0.0", "abc1234", "host")

    def setUp(self):
        self_seen.clear()

    def test_reads_the_latest_release(self):
        r = fetch_latest("octo/repo", self.build, opener=opener_returning(
            {"tag_name": "v1.3.0", "html_url": "https://github.com/octo/repo/releases/tag/v1.3.0", "published_at": "2026-10-01T12:00:00Z"}))
        self.assertEqual(r, {"version": "1.3.0", "tag": "v1.3.0", "url": "https://github.com/octo/repo/releases/tag/v1.3.0", "published": "2026-10-01"})
        url, headers, timeout = self_seen[0]
        self.assertEqual(url, "https://api.github.com/repos/octo/repo/releases/latest")
        self.assertEqual(headers["User-agent"], "CertForge/1.0.0")             # and nothing that identifies this server
        self.assertNotIn("Authorization", headers)
        self.assertLessEqual(timeout, 10)

    def test_failures_are_explained(self):
        def http(code):
            return urllib.error.HTTPError("u", code, "x", {}, None)
        self.assertIsNone(fetch_latest("a/b", self.build, opener=opener_returning(error=http(404))))
        with self.assertRaisesRegex(CheckError, "rate limited"):
            fetch_latest("a/b", self.build, opener=opener_returning(error=http(403)))
        with self.assertRaisesRegex(CheckError, "answered 500"):
            fetch_latest("a/b", self.build, opener=opener_returning(error=http(500)))
        with self.assertRaisesRegex(CheckError, "Couldn't reach GitHub"):
            fetch_latest("a/b", self.build, opener=opener_returning(error=OSError("no route")))
        with self.assertRaisesRegex(CheckError, "isn't a version"):
            fetch_latest("a/b", self.build, opener=opener_returning({"tag_name": "nightly"}))
        with self.assertRaisesRegex(CheckError, "isn't a GitHub repository"):
            fetch_latest("../etc/passwd", self.build, opener=opener_returning({}))
        for bad in ("", "a", "a/b/c", "a b/c", "a/b?x=1"):
            with self.assertRaises(CheckError, msg=bad):
                fetch_latest(bad, self.build, opener=opener_returning({}))


class Watching(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cf-upd-"))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.store = Store(self.d / "x.db")
        self.answer = {"version": "1.5.0", "tag": "v1.5.0", "url": "https://example/r", "published": "2026-10-01"}
        self.calls = 0

    def make(self, build="1.2.0", enabled=False) -> Updates:
        cfg = Config(data=self.d, bind="x", https_port=1, http_port=0, hostnames="", setup_token=None, update_check=enabled)

        def fetch(repo, b):
            self.calls += 1
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        return Updates(self.store, cfg, V.Build(build, "abc1234", "host"), fetch)

    def test_off_unless_asked(self):
        u = self.make()
        self.assertFalse(u.enabled())
        self.assertFalse(u.due())
        self.assertFalse(u.status()["available"])
        self.assertEqual(self.calls, 0)

    def test_the_environment_turns_it_on_and_the_page_can_override_it(self):
        u = self.make(enabled=True)
        self.assertTrue(u.enabled() and u.due())
        u.set_enabled(False)                                           # an explicit choice wins over the default
        self.assertFalse(self.make(enabled=True).enabled())
        u.set_enabled(True)
        self.assertTrue(self.make(enabled=False).enabled())

    def test_a_newer_release_is_reported_with_the_command_to_run(self):
        u = self.make(enabled=True)
        st = u.check()
        self.assertTrue(st["available"])
        self.assertEqual((st["latest"]["version"], st["command"]), ("1.5.0", "sudo certforge-update"))
        self.assertFalse(u.due())                                      # not again for about a day

    def test_current_and_older_and_none(self):
        for build, want in (("1.5.0", "current"), ("1.6.0", "current"), ("1.5.0-rc1", "available")):
            st = self.make(build, enabled=True).check()
            self.assertTrue(st[want], (build, st))
        self.answer = None
        st = self.make(enabled=True).check()
        self.assertEqual((st["latest"], st["available"], st["error"]), (None, False, ""))

    def test_a_development_build_is_not_compared(self):
        st = self.make("0.0.0-abc1234", enabled=True).check()
        self.assertTrue(st["available"])                               # 0.0.0-x is a valid version, older than any release
        st = self.make("dev", enabled=True).check()
        self.assertEqual((st["available"], st["uncomparable"]), (False, True))

    def test_a_failed_check_keeps_the_last_answer_and_says_why(self):
        u = self.make(enabled=True)
        u.check()
        self.answer = CheckError("Couldn't reach GitHub: offline")
        st = u.check()
        self.assertEqual(st["error"], "Couldn't reach GitHub: offline")
        self.assertEqual(st["latest"]["version"], "1.5.0")
        self.answer = dict(self.answer if isinstance(self.answer, dict) else {}, version="1.5.0") if False else {"version": "1.5.0", "tag": "v1.5.0", "url": "", "published": ""}
        self.assertEqual(u.check()["error"], "")

    def test_due_again_after_a_day(self):
        from datetime import timedelta
        from app.store import iso, utcnow
        u = self.make(enabled=True)
        u.check()
        st = self.store.get("updates")
        self.store.set("updates", {**st, "checked": iso(utcnow() - timedelta(hours=25))})
        self.assertTrue(u.due())


class InTheService(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cf-svc-ver-"))        # fresh data folder per test: state must not leak between them
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def boot(self, **env) -> Service:
        with mock.patch.dict(os.environ, env):
            return Service(Config(data=self.tmp, bind="127.0.0.1", https_port=8443, http_port=0, hostnames="", setup_token=None))

    def test_changes_are_recorded_in_the_activity_log_and_only_changes(self):
        svc = self.boot(CERTFORGE_VERSION="1.0.0", CERTFORGE_REVISION="aaaaaaa")
        self.assertEqual(svc.store.get("build")["version"], "1.0.0")
        self.assertEqual([a for a in svc.store.recent_audit() if a["action"] == "update"], [])      # the first start isn't an update
        self.boot(CERTFORGE_VERSION="1.0.0", CERTFORGE_REVISION="aaaaaaa")                          # a plain restart isn't either
        svc = self.boot(CERTFORGE_VERSION="1.1.0", CERTFORGE_REVISION="bbbbbbb")
        entries = [a for a in svc.store.recent_audit() if a["action"] == "update"]
        self.assertEqual([e["detail"] for e in entries], ["CertForge changed from 1.0.0 (aaaaaaa) to 1.1.0 (bbbbbbb)"])
        self.assertEqual(svc.store.get("previous_build")["version"], "1.0.0")
        about = svc.about()
        self.assertEqual((about["version"], about["revision"], about["previous"]["version"]), ("1.1.0", "bbbbbbb", "1.0.0"))
        svc = self.boot(CERTFORGE_VERSION="1.0.0", CERTFORGE_REVISION="aaaaaaa")                    # going back is recorded too
        self.assertEqual(len([a for a in svc.store.recent_audit() if a["action"] == "update"]), 2)

    def test_what_the_update_tool_wrote_is_shown(self):
        svc = self.boot(CERTFORGE_VERSION="1.2.0")
        self.assertEqual(svc.about()["last_update"], {})
        (self.tmp / "last-update.json").write_text(json.dumps({"from_version": "1.1.0 (aaa)", "to_version": "1.2.0 (bbb)",
                                                              "when": "2026-10-16T01:02:03Z", "backup": "/var/backups/x.tar.gz"}))
        self.assertEqual(svc.about()["last_update"]["backup"], "/var/backups/x.tar.gz")
        (self.tmp / "last-update.json").write_text("{not json")
        self.assertEqual(svc.about()["last_update"], {})

    def test_the_alert_and_the_daily_check(self):
        svc = self.boot(CERTFORGE_VERSION="1.0.0", CERTFORGE_DEPLOY="host")
        svc.setup(token=svc.setup_token(), org="Ver Lab", admin_password="an-admin-password-123", admin_password2="an-admin-password-123",
                  passphrase="ca-passphrase-for-tests-456", key_type="ec-p384", root_years=10, int_years=5, seal=False,
                  permitted="", ui_names="ca.lab.test", public_host="ca.lab.test")
        calls = []
        svc.updates.fetch = lambda repo, b: calls.append(repo) or {"version": "1.1.0", "tag": "v1.1.0", "url": "u", "published": ""}
        svc.maintain()
        self.assertEqual(calls, [])                                    # off by default: nothing is asked
        self.assertFalse(any("is available" in a["text"] for a in svc.alerts()))
        svc.updates.set_enabled(True)
        svc.maintain()
        self.assertEqual(calls, ["jballanger0226/CertForge"])
        svc.maintain()
        self.assertEqual(len(calls), 1)                                # once a day, not every pass
        alert = [a for a in svc.alerts() if "is available" in a["text"]]
        self.assertEqual(len(alert), 1)
        self.assertIn("sudo certforge-update", alert[0]["text"])
        self.assertIn("1.1.0", alert[0]["text"])

    def test_a_broken_check_never_breaks_housekeeping(self):
        svc = self.boot(CERTFORGE_VERSION="1.0.0")
        svc.updates.set_enabled(True)
        svc.updates.fetch = lambda repo, b: 1 / 0
        svc.maintain()                                                 # must not raise


if __name__ == "__main__":
    unittest.main()
