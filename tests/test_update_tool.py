"""deploy/certforge-update, with the network, systemd and pip replaced by fakes."""
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "deploy" / "certforge-update"
loader = SourceFileLoader("certforge_update", str(PATH))
U = module_from_spec(spec_from_loader("certforge_update", loader))
loader.exec_module(U)


def make_tar(path: Path, version: str, wrap: str = "", extra=(), reqs="cryptography==1\n") -> bytes:
    with tarfile.open(path, "w:gz") as tf:
        def add(name, data: bytes):
            ti = tarfile.TarInfo((wrap + "/" if wrap else "") + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        add("app/server.py", f"# {version}\n".encode())
        add("requirements.txt", reqs.encode())
        add("VERSION", f"{version}\n".encode())
        add("REVISION", b"abcdef1234567\n")
        for name, data in extra:
            add(name, data)
    return path.read_bytes()


class Harness(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cf-upd-tool-"))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.prefix, self.data, self.backups = self.d / "opt", self.d / "var", self.d / "bak"
        (self.prefix / "app").mkdir(parents=True)
        (self.prefix / "venv").mkdir()
        (self.prefix / "app" / "server.py").write_text("# old\n")
        (self.prefix / "requirements.txt").write_text("cryptography==1\n")
        (self.prefix / "VERSION").write_text("1.0.0\n")
        (self.prefix / "REVISION").write_text("1111111\n")
        self.data.mkdir()
        (self.data / "certforge.db").write_text("data-v1")
        self.commands, self.healthy, self.web = [], [True], {}
        self.venvs, self.requests = [], []

    def tool(self, **kw) -> "U.Updater":
        def run(cmd):
            self.commands.append(" ".join(cmd))
            return 0

        def http(url, limit=0, accept=""):
            self.requests.append((url, accept))
            if url not in self.web:
                raise U.NotFound(f"GitHub answered 404 for {url}")
            return self.web[url]

        def health(timeout=0):
            return self.healthy.pop(0) if len(self.healthy) > 1 else self.healthy[0]

        def build_venv(venv, req):
            self.venvs.append(req.read_text())
            venv.mkdir()
        args = dict(prefix=self.prefix, data=self.data, backups=self.backups, repo="o/r", http=http, run=run, health=health,
                    build_venv=build_venv, is_root=lambda: True)
        args.update(kw)
        return U.Updater(**args)

    def publish(self, version="1.1.0", tarball=None, sums=None, tag=None, **mk):
        tb = self.d / f"certforge-{version}.tar.gz"
        raw = make_tar(tb, version, **mk) if tarball is None else tarball
        digest = hashlib.sha256(raw).hexdigest()
        base = f"https://dl/{version}"
        release = {"tag_name": tag or f"v{version}", "assets": [
            {"name": f"certforge-{version}.tar.gz", "browser_download_url": f"{base}/t"},
            {"name": "SHA256SUMS", "browser_download_url": f"{base}/s"}]}
        self.web["https://api.github.com/repos/o/r/releases/latest"] = json.dumps(release).encode()
        self.web[f"https://api.github.com/repos/o/r/releases/tags/v{version}"] = json.dumps(release).encode()
        self.web[f"{base}/t"] = raw
        self.web[f"{base}/s"] = (sums if sums is not None else f"{digest}  certforge-{version}.tar.gz\n").encode()
        return raw


class Updating(Harness):
    def test_installs_the_newest_release_and_records_it(self):
        self.publish("1.1.0")
        self.assertEqual(self.tool().install(), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.1.0")
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# 1.1.0\n")
        note = json.loads((self.data / "last-update.json").read_text())
        self.assertEqual((note["from_version"], note["to_version"]), ("1.0.0 (1111111)", "1.1.0 (abcdef1)"))
        self.assertTrue(Path(note["backup"]).is_file())
        self.assertLess(self.commands.index("systemctl stop certforge"), self.commands.index("systemctl start certforge"))
        self.assertEqual(self.venvs, [])                                  # same requirements: the environment is reused

    def test_new_dependencies_get_a_new_environment(self):
        self.publish("1.1.0", reqs="cryptography==2\n")
        self.tool().install()
        self.assertEqual(self.venvs, ["cryptography==2\n"])
        self.assertTrue((self.prefix / "venv").is_dir())
        self.assertFalse((self.prefix / "venv.old").exists() or (self.prefix / "venv.new").exists())

    def test_a_wrapping_folder_is_fine(self):
        self.publish("1.1.0", wrap="certforge-1.1.0")
        self.assertEqual(self.tool().install(), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.1.0")

    def test_already_current_does_nothing(self):
        self.publish("1.0.0")
        self.assertEqual(self.tool().install(), 0)
        self.assertEqual(self.commands, [])

    def test_a_chosen_version_can_be_older(self):
        self.publish("0.9.0")
        self.assertEqual(self.tool().install(version="0.9.0"), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "0.9.0")

    def test_check_changes_nothing(self):
        self.publish("1.1.0")
        self.assertEqual(self.tool().check(), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual(self.commands, [])

    def test_the_stale_backups_are_pruned(self):
        import itertools
        n = itertools.count(1)
        for i in range(5):
            self.publish(f"1.{i + 1}.0")
            self.tool(now=lambda i=i: U.datetime(2026, 1, 1 + i, tzinfo=U.timezone.utc)).install()
        self.assertEqual(len(list(self.backups.glob("certforge-*.tar.gz"))), U.KEEP_BACKUPS)
        self.assertEqual(oct(self.backups.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct(next(self.backups.glob("*.gz")).stat().st_mode & 0o777), "0o600")
        next(n)


class Refusing(Harness):
    def assertUntouched(self):
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# old\n")
        self.assertNotIn("systemctl stop certforge", self.commands)

    def test_not_root(self):
        self.publish()
        with self.assertRaisesRegex(U.Fail, "as root"):
            self.tool(is_root=lambda: False).install()
        with self.assertRaisesRegex(U.Fail, "as root"):
            self.tool(is_root=lambda: False).rollback()
        self.assertUntouched()

    def test_checksum_mismatch(self):
        self.publish(sums=f"{'0' * 64}  certforge-1.1.0.tar.gz\n")
        with self.assertRaisesRegex(U.Fail, "checksum doesn't match"):
            self.tool().install()
        self.assertUntouched()

    def test_missing_or_malformed_checksum_entry(self):
        for sums in ("", "nothex  certforge-1.1.0.tar.gz\n", f"{'a' * 64}  other.tar.gz\n"):
            self.publish(sums=sums)
            with self.assertRaisesRegex(U.Fail, "no entry"):
                self.tool().install()
        self.assertUntouched()

    def test_archive_that_lies_about_its_version(self):
        self.publish("1.1.0", tarball=make_tar(self.d / "x.tar.gz", "9.9.9"))
        with self.assertRaisesRegex(U.Fail, "says it is 9.9.9"):
            self.tool().install()
        self.assertUntouched()

    def test_unsafe_archives(self):
        cases = {"traversal": [("../evil", b"x")], "absolute": [("/etc/evil", b"x")], "stranger": [("evil.sh", b"x")],
                 "deep traversal": [("app/../../evil", b"x")]}
        for label, extra in cases.items():
            self.publish("1.1.0", tarball=make_tar(self.d / "u.tar.gz", "1.1.0", extra=extra))
            with self.assertRaises(U.Fail, msg=label):
                self.tool().install()
        self.assertUntouched()
        self.assertFalse((self.d / "evil").exists() or (self.prefix.parent / "evil").exists())

    def test_links_are_refused(self):
        tb = self.d / "l.tar.gz"
        with tarfile.open(tb, "w:gz") as tf:
            ti = tarfile.TarInfo("app")
            ti.type, ti.linkname = tarfile.SYMTYPE, "/etc"
            tf.addfile(ti)
        self.publish("1.1.0", tarball=tb.read_bytes())
        with self.assertRaisesRegex(U.Fail, "plain file"):
            self.tool().install()
        self.assertUntouched()

    def test_not_a_release(self):
        tb = self.d / "n.tar.gz"
        with tarfile.open(tb, "w:gz") as tf:
            ti = tarfile.TarInfo("VERSION")
            ti.size = 2
            tf.addfile(ti, io.BytesIO(b"1\n"))
        self.publish("1.1.0", tarball=tb.read_bytes())
        with self.assertRaisesRegex(U.Fail, "missing app/server.py"):
            self.tool().install()
        self.publish("1.1.0", tarball=b"not an archive")
        with self.assertRaisesRegex(U.Fail, "couldn't be unpacked"):
            self.tool().install()
        self.assertUntouched()

    def test_release_without_assets_and_odd_tags(self):
        self.web["https://api.github.com/repos/o/r/releases/latest"] = json.dumps({"tag_name": "v1.1.0", "assets": []}).encode()
        with self.assertRaisesRegex(U.Fail, "no certforge-1.1.0.tar.gz"):
            self.tool().install()
        self.web["https://api.github.com/repos/o/r/releases/latest"] = json.dumps({"tag_name": "nightly"}).encode()
        with self.assertRaisesRegex(U.Fail, "isn't a version"):
            self.tool().install()
        self.assertUntouched()

    def test_dependency_build_failure_changes_nothing(self):
        self.publish("1.1.0", reqs="other==1\n")

        def boom(venv, req):
            raise OSError("pip exploded")
        with self.assertRaisesRegex(U.Fail, "Nothing was changed"):
            self.tool(build_venv=boom).install()
        self.assertUntouched()
        self.assertFalse((self.prefix / "venv.new").exists())


class WhenTheNewVersionIsBroken(Harness):
    def test_everything_is_put_back(self):
        self.publish("1.1.0", reqs="cryptography==2\n")
        self.healthy = [False, True]                                     # new one fails, the restored one answers

        class Tamper(U.Updater):
            def _service(self, verb):
                if verb == "start" and (self.prefix / "VERSION").read_text().strip() == "1.1.0":
                    (self.data / "certforge.db").write_text("half-migrated")     # the new version got as far as touching data
                super()._service(verb)
        t = self.tool()
        t.__class__ = Tamper
        with self.assertRaisesRegex(U.Fail, "Rolled back"):
            t.install()
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# old\n")
        self.assertEqual((self.data / "certforge.db").read_text(), "data-v1")
        self.assertTrue((self.prefix / "venv").is_dir())
        self.assertFalse((self.prefix / "venv.old").exists())
        self.assertFalse((self.data / "last-update.json").exists())       # nothing claims an update that didn't stay
        self.assertEqual(self.commands[-1], "systemctl start certforge")

    def test_a_failed_restart_also_rolls_back(self):
        self.publish("1.1.0")
        calls = {"n": 0}

        def run(cmd):
            self.commands.append(" ".join(cmd))
            if cmd[1] == "start":
                calls["n"] += 1
                return 1 if calls["n"] == 1 else 0
            return 0
        self.healthy = [True]
        with self.assertRaises(U.Fail):
            self.tool(run=run).install()
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")


class RollingBack(Harness):
    def test_restores_the_program_and_leaves_the_data(self):
        self.publish("1.1.0")
        self.tool().install()
        (self.data / "certforge.db").write_text("data-v2")
        self.assertEqual(self.tool().rollback(), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual((self.data / "certforge.db").read_text(), "data-v2")
        note = json.loads((self.data / "last-update.json").read_text())
        self.assertEqual((note["from_version"], note["to_version"]), ("1.1.0 (abcdef1)", "1.0.0 (1111111)"))

    def test_nothing_to_go_back_to(self):
        with self.assertRaisesRegex(U.Fail, "no saved copy"):
            self.tool().rollback()


class FromAFile(Harness):
    def test_with_and_without_a_checksum(self):
        raw = make_tar(self.d / "mine.tar.gz", "1.2.0")
        with self.assertRaisesRegex(U.Fail, "checksum"):
            self.tool().install(file=self.d / "mine.tar.gz", sha256="0" * 64)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual(self.tool().install(file=self.d / "mine.tar.gz", sha256=hashlib.sha256(raw).hexdigest()), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.2.0")

    def test_missing_file_and_cli(self):
        with self.assertRaisesRegex(U.Fail, "doesn't exist"):
            self.tool().install(file=self.d / "nope.tar.gz")
        self.assertEqual(U.main(["--repo", "../x"]), 2)


SHA = "9f8e7d6c5b4a39281706f5e4d3c2b1a099887766"


def make_source(path: Path, sha: str = SHA, owner="o-r", extra=(), reqs="cryptography==1\n", symlink=False) -> bytes:
    """What GitHub serves for a branch or tag: the whole repository in a folder named owner-repo-<sha7>."""
    w = f"{owner}-{sha[:7]}"
    with tarfile.open(path, "w:gz") as tf:
        def add(name, data: bytes):
            ti = tarfile.TarInfo(f"{w}/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        d = tarfile.TarInfo(w)
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        add("app/server.py", b"# from source\n")
        add("requirements.txt", reqs.encode())
        add("deploy/certforge-update", b"#!/bin/sh\n")
        add("tests/test_x.py", b"x")
        add("README.md", b"readme")
        for name, data in extra:
            add(name, data)
        if symlink:
            ln = tarfile.TarInfo(f"{w}/docs/link")
            ln.type = tarfile.SYMTYPE
            ln.linkname = "/etc/passwd"
            tf.addfile(ln)
    return path.read_bytes()


class FromABranch(Harness):
    def serve(self, ref="main", sha=SHA, **kw):
        self.web[f"https://api.github.com/repos/o/r/commits/{ref}"] = sha.encode()
        self.web[f"https://api.github.com/repos/o/r/tarball/{sha}"] = make_source(self.d / "src.tar.gz", sha, **kw)

    def test_installs_a_branch_as_an_unreleased_build(self):
        self.serve()
        self.assertEqual(self.tool().install(ref="main"), 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "0.0.0-9f8e7d6")
        self.assertEqual((self.prefix / "REVISION").read_text().strip(), SHA)
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# from source\n")
        self.assertFalse((self.prefix / "tests").exists())             # only what the system runs is taken
        self.assertFalse((self.prefix / "README.md").exists())
        note = json.loads((self.data / "last-update.json").read_text())
        self.assertEqual((note["from_version"], note["to_version"], note["source"]), ("1.0.0 (1111111)", "0.0.0-9f8e7d6 (9f8e7d6)", "main @ 9f8e7d6"))
        self.assertTrue(Path(note["backup"]).is_file())
        self.assertIn("systemctl start certforge", self.commands)

    def test_it_downloads_the_commit_it_resolved_not_the_moving_name(self):
        self.serve()
        self.tool().install(ref="main")
        urls = [u for u, _ in self.requests]
        self.assertIn(f"https://api.github.com/repos/o/r/tarball/{SHA}", urls)
        self.assertNotIn("https://api.github.com/repos/o/r/tarball/main", urls)

    def test_a_version_tag_is_installed_under_its_number(self):
        self.serve("v1.2.0")
        self.tool().install(ref="v1.2.0")
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.2.0")
        self.assertEqual((self.prefix / "REVISION").read_text().strip(), SHA)

    def test_slashes_in_a_branch_name(self):
        self.serve("feature/x")
        self.assertEqual(self.tool().install(ref="feature/x"), 0)

    def test_the_same_commit_is_a_no_op_unless_forced(self):
        self.serve()
        (self.prefix / "REVISION").write_text(SHA[:7] + "\n")
        self.assertEqual(self.tool().install(ref="main"), 0)
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# old\n")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.tool().install(ref="main", force=True), 0)
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# from source\n")

    def test_unknown_branch(self):
        with self.assertRaisesRegex(U.Fail, "no branch or tag called 'nope'"):
            self.tool().install(ref="nope")
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")

    def test_bad_names_never_reach_the_network(self):
        for bad in ("../x", "a..b", "-rf", "a b", "x;y", "a//b", "", "x" * 300, "main.lock"):
            with self.assertRaises(U.Fail, msg=bad):
                self.tool().resolve(bad)
        self.assertEqual(self.requests, [])

    def test_a_download_for_a_different_commit_is_refused(self):
        self.web["https://api.github.com/repos/o/r/commits/main"] = SHA.encode()
        self.web[f"https://api.github.com/repos/o/r/tarball/{SHA}"] = make_source(self.d / "s.tar.gz", "0" * 40)
        with self.assertRaisesRegex(U.Fail, "isn't the commit"):
            self.tool().install(ref="main")
        self.assertEqual((self.prefix / "app" / "server.py").read_text(), "# old\n")
        self.assertEqual(self.commands, [])

    def test_a_non_commit_answer_is_refused(self):
        self.web["https://api.github.com/repos/o/r/commits/main"] = b"<html>captive portal</html>"
        with self.assertRaisesRegex(U.Fail, "commit id"):
            self.tool().install(ref="main")

    def test_links_and_odd_items_outside_the_parts_taken_do_not_matter_but_inside_they_do(self):
        self.serve(symlink=True)                        # docs/link is skipped: docs/ is never installed
        self.assertEqual(self.tool().install(ref="main"), 0)
        self.serve(extra=[], symlink=False)
        w = f"o-r-{SHA[:7]}"
        with tarfile.open(self.d / "bad.tar.gz", "w:gz") as tf:
            ln = tarfile.TarInfo(f"{w}/app/evil")
            ln.type = tarfile.SYMTYPE
            ln.linkname = "/etc/shadow"
            tf.addfile(ln)
        with self.assertRaisesRegex(U.Fail, "isn't a plain file"):
            U.Updater.unpack(self.d / "bad.tar.gz", self.d / "out", source=True)

    def test_two_wrapping_folders_and_loose_files_are_refused(self):
        with tarfile.open(self.d / "two.tar.gz", "w:gz") as tf:
            for n in ("a/app/server.py", "b/app/server.py"):
                ti = tarfile.TarInfo(n)
                ti.size = 1
                tf.addfile(ti, io.BytesIO(b"x"))
        with self.assertRaisesRegex(U.Fail, "layout"):
            U.Updater.unpack(self.d / "two.tar.gz", self.d / "o1", source=True)
        with tarfile.open(self.d / "loose.tar.gz", "w:gz") as tf:
            ti = tarfile.TarInfo("loose.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        with self.assertRaisesRegex(U.Fail, "layout"):
            U.Updater.unpack(self.d / "loose.tar.gz", self.d / "o2", source=True)

    def test_a_source_that_is_not_certforge(self):
        self.serve(reqs="x")
        w = f"o-r-{SHA[:7]}"
        with tarfile.open(self.d / "e.tar.gz", "w:gz") as tf:
            ti = tarfile.TarInfo(f"{w}/README.md")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        self.web[f"https://api.github.com/repos/o/r/tarball/{SHA}"] = (self.d / "e.tar.gz").read_bytes()
        with self.assertRaisesRegex(U.Fail, "doesn't look like CertForge"):
            self.tool().install(ref="main")

    def test_a_broken_branch_build_is_rolled_back(self):
        self.serve()
        self.healthy[:] = [False, True]
        with self.assertRaisesRegex(U.Fail, "Rolled back"):
            self.tool().install(ref="main")
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual((self.data / "certforge.db").read_text(), "data-v1")

    def test_only_root(self):
        self.serve()
        with self.assertRaisesRegex(U.Fail, "as root"):
            self.tool(is_root=lambda: False).install(ref="main")
        self.assertEqual(self.requests, [])

    def test_check_with_a_ref_changes_nothing(self):
        self.serve()
        self.assertEqual(self.tool().check(ref="main"), 0)
        self.assertEqual(self.commands, [])
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.0.0")

    def test_with_no_release_the_error_points_at_branches(self):
        with self.assertRaisesRegex(U.Fail, "certforge-update main"):
            self.tool().install()


class TheCommandLine(Harness):
    def run_main(self, argv, env=None, conf=None, **kw):
        envfile = self.d / "update.env"
        if conf is not None:
            envfile.write_text(conf)
            envfile.chmod(0o600)
        saved = {k: __import__("os").environ.pop(k, None) for k in ("CERTFORGE_UPDATE_REPO", "GITHUB_TOKEN")}
        try:
            seen = {}
            real = U.Updater

            class Spy(real):
                def __init__(s, **a):
                    seen.update(a)
                    super().__init__(**{**a, **self_args})
            self_args = dict(prefix=self.prefix, data=self.data, backups=self.backups, http=self.tool().http, run=lambda c: 0,
                             health=lambda timeout=0: True, build_venv=lambda v, r: v.mkdir(), is_root=lambda: True)
            U.Updater = Spy
            try:
                rc = U.main(argv, env_file=envfile)
            finally:
                U.Updater = real
            return rc, seen
        finally:
            for k, v in saved.items():
                if v is not None:
                    __import__("os").environ[k] = v

    def test_the_ref_conflicts_with_the_other_modes(self):
        self.assertEqual(self.run_main(["main", "--version", "1.0.0"])[0], 2)
        self.assertEqual(self.run_main(["main", "--rollback"])[0], 2)
        self.assertEqual(self.run_main(["--", "../x"])[0], 2)

    def test_the_settings_file_supplies_the_default_ref_repo_and_token(self):
        self.web["https://api.github.com/repos/a/b/commits/dev"] = SHA.encode()
        self.web[f"https://api.github.com/repos/a/b/tarball/{SHA}"] = make_source(self.d / "s.tar.gz")
        rc, seen = self.run_main([], conf="# comment\nCERTFORGE_REF=dev\nCERTFORGE_UPDATE_REPO=a/b\nGITHUB_TOKEN='tok'\n")
        self.assertEqual((rc, seen["repo"], seen["token"]), (0, "a/b", "tok"))
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "0.0.0-9f8e7d6")

    def test_an_explicit_choice_beats_the_settings_file(self):
        self.publish("1.1.0")
        self.web["https://api.github.com/repos/o/r/releases/latest"] = self.web["https://api.github.com/repos/o/r/releases/latest"]
        rc, _ = self.run_main(["--release", "--repo", "o/r"], conf="CERTFORGE_REF=dev\n")
        self.assertEqual(rc, 0)
        self.assertEqual((self.prefix / "VERSION").read_text().strip(), "1.1.0")

    def test_a_settings_file_anyone_could_have_written_is_ignored(self):
        envfile = self.d / "bad.env"
        envfile.write_text("CERTFORGE_UPDATE_REPO=evil/repo\n")
        envfile.chmod(0o666)
        self.assertEqual(U.trusted_env(envfile), {})
        envfile.chmod(0o600)
        self.assertEqual(U.trusted_env(envfile), {"CERTFORGE_UPDATE_REPO": "evil/repo"})
        self.assertEqual(U.trusted_env(self.d / "missing"), {})

    def test_the_token_goes_only_to_the_github_api(self):
        sent = []

        class Resp:
            def __init__(s, body=b"ok"):
                s.body = body

            def read(s, n=-1):
                return s.body

            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False
        real = U.urllib.request.build_opener

        class Opener:
            def open(s, req, timeout=0):
                sent.append((req.full_url, req.get_header("Authorization")))
                return Resp()
        U.urllib.request.build_opener = lambda *h: Opener()
        try:
            t = U.Updater(token="sekrit", repo="o/r")
            t._http("https://api.github.com/repos/o/r/commits/main", 100)
            t._http("https://github.com/o/r/releases/download/v1/x.tar.gz", 100)
        finally:
            U.urllib.request.build_opener = real
        self.assertEqual(sent, [("https://api.github.com/repos/o/r/commits/main", "Bearer sekrit"),
                                ("https://github.com/o/r/releases/download/v1/x.tar.gz", None)])

    def test_a_redirect_to_a_foreign_or_plain_http_host_loses_the_token_or_is_refused(self):
        import urllib.request as ur
        h = U._KeepTokenOnGitHub()
        req = ur.Request("https://api.github.com/x", headers={"Authorization": "Bearer t"})
        gh = h.redirect_request(req, None, 302, "Found", {}, "https://codeload.github.com/o/r/tar.gz/abc")
        self.assertEqual(gh.get_header("Authorization"), "Bearer t")
        other = h.redirect_request(req, None, 302, "Found", {}, "https://evil.example/x")
        self.assertIsNone(other.get_header("Authorization"))
        with self.assertRaises(U.urllib.error.HTTPError):
            h.redirect_request(req, None, 302, "Found", {}, "http://codeload.github.com/x")


class Versions(unittest.TestCase):
    def test_order(self):
        self.assertTrue(U.newer("1.10.0", "1.9.0"))
        self.assertTrue(U.newer("1.2.0", "1.2.0-rc1"))
        self.assertFalse(U.newer("1.2.0", "1.2.0"))
        self.assertIsNone(U.newer("dev", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
