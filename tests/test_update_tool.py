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
        self.venvs = []

    def tool(self, **kw) -> "U.Updater":
        def run(cmd):
            self.commands.append(" ".join(cmd))
            return 0

        def http(url, limit=0):
            if url not in self.web:
                raise U.Fail(f"GitHub answered 404 for {url}")
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


class Versions(unittest.TestCase):
    def test_order(self):
        self.assertTrue(U.newer("1.10.0", "1.9.0"))
        self.assertTrue(U.newer("1.2.0", "1.2.0-rc1"))
        self.assertFalse(U.newer("1.2.0", "1.2.0"))
        self.assertIsNone(U.newer("dev", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
