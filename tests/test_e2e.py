"""End-to-end tests: start the real server, drive it over real HTTPS, judge results with OpenSSL.

Run (needs permission to bind ports 443 and 80, e.g. as root):
    python -m unittest tests.test_e2e -v

Nothing here turns TLS verification off: before the CA exists we verify against the server's own
bootstrap certificate, and after setup against the root CA that the app just created.
"""
import html
import io
import os
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# `requests` lets these environment variables override Session.verify, which would silently check
# our server against some other CA bundle. These tests pin the CA they mean to trust, so drop them.
for _var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
    os.environ.pop(_var, None)

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "an-admin-password-123"
PASS = "ca-passphrase-for-tests-456"
NAMES = "localhost\n127.0.0.1\nca.lab.test"


def sh(*args, input=None, check=True):
    p = subprocess.run(args, input=input, capture_output=True)
    if check and p.returncode != 0:
        raise AssertionError(f"{' '.join(map(str, args))}\n{p.stdout.decode()}\n{p.stderr.decode()}")
    return p


def C_sans(cert) -> list[str]:
    from app import ca
    return ca.sans_of(cert)


def json_setting(data: Path, key: str):
    """A value from the CA's meta.json (e.g. public_host)."""
    import json
    return json.loads((data / "ca" / "meta.json").read_text()).get(key)


def csrf_of(page: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def T(r) -> str:
    """Page text with HTML entities decoded (Jinja writes isn't as isn&#39;t)."""
    return html.unescape(r.text)


class Server:
    def __init__(self, data: Path, https_port=443, http_port=80, token="e2e-setup-token", env=None):
        self.data, self.https, self.http, self.token = data, https_port, http_port, token
        self.extra_env = env or {}
        self.proc = None
        self.log_path = data.parent / f"server-{https_port}.log"

    def start(self):
        env = {**os.environ, "CERTFORGE_DATA": str(self.data), "CERTFORGE_HOSTNAMES": NAMES.replace("\n", ","),
               "CERTFORGE_HTTPS_PORT": str(self.https), "CERTFORGE_HTTP_PORT": str(self.http)}
        env.update(self.extra_env)
        if self.token:
            env["CERTFORGE_SETUP_TOKEN"] = self.token
        else:
            env.pop("CERTFORGE_SETUP_TOKEN", None)
        self.log = open(self.log_path, "ab")
        self.proc = subprocess.Popen([sys.executable, "-m", "app.server"], cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if not self.log.closed:
            self.log.close()

    def wait(self, verify, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise AssertionError("server exited:\n" + self.log_path.read_text()[-2000:])
            try:
                if requests.get(f"https://localhost:{self.https}/healthz", verify=str(verify), timeout=3).text == "ok":
                    return
            except OSError:      # connection refused, or the CA file isn't written yet (RequestException is an OSError)
                time.sleep(0.2)
        raise AssertionError("server didn't come up:\n" + self.log_path.read_text()[-2000:])


def do_setup(base: str, verify, token: str, *, seal=False, org="Test Lab", **over) -> requests.Response:
    s = requests.Session(); s.verify = str(verify)
    tok = csrf_of(s.get(f"{base}/setup").text)
    data = dict(csrf_token=tok, token=token, org=org, admin_password=ADMIN, admin_password2=ADMIN, passphrase=PASS,
                key_type="ec-p384", root_years="20", int_years="10", permitted="", public_host="ca.lab.test", ui_names=NAMES)
    if seal:
        data["seal"] = "1"
    data.update(over)
    r = s.post(f"{base}/setup", data=data)
    r.session = s
    return r


class Base(unittest.TestCase):
    base: str
    root: Path
    srv: Server

    @classmethod
    def boot(cls, https=443, http=80, token="e2e-setup-token", seal=False, env=None, verify_with_root=False):
        cls.tmp = Path(tempfile.mkdtemp(prefix="certforge-e2e-"))
        cls.data = cls.tmp / "data"
        cls.srv = Server(cls.data, https, http, token, env)
        cls.srv.start()
        cls.addClassCleanup(cls.srv.stop)          # even if setUpClass fails below, never orphan the server
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.base = f"https://localhost{'' if https == 443 else f':{https}'}"
        cls.root = cls.data / "ca" / "root.crt"
        cls.srv.wait(cls.root if verify_with_root else cls.data / "ui" / "bootstrap.crt")

    @classmethod
    def wait_for_ca_cert(cls, timeout=15):
        """The web cert is swapped in place shortly after setup; wait until it verifies against our root."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                if requests.get(f"{cls.base}/healthz", verify=str(cls.root), timeout=3).text == "ok":
                    return
            except OSError:
                time.sleep(0.2)
        raise AssertionError("web certificate never switched to the CA-issued one")

    def login(self, password=ADMIN) -> requests.Session:
        s = requests.Session(); s.verify = str(self.root)
        tok = csrf_of(s.get(f"{self.base}/login").text)
        r = s.post(f"{self.base}/login", data=dict(csrf_token=tok, password=password, next="/"), allow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text[:300])
        s.csrf = csrf_of(s.get(f"{self.base}/issue").text)
        return s

    def post(self, s, path, **kw):
        data = kw.pop("data", {})
        data["csrf_token"] = s.csrf
        return s.post(f"{self.base}{path}", data=data, allow_redirects=False, **kw)

    def tmpfile(self, name, data: bytes) -> str:
        p = self.tmp / name
        p.write_bytes(data)
        return str(p)

    def issue(self, s, names="app.lab.test", **over) -> str:
        data = dict(names=names, days="90", purpose="both", key_type="ec-p256", p12="compat", password="")
        data.update(over)
        r = self.post(s, "/issue", data=data)
        self.assertEqual(r.status_code, 303, r.text[:500])
        return re.search(r"/certs/([0-9A-F]+)\?new=1", r.headers["Location"]).group(1)


# ==========================================================================================

class TestMain(Base):
    @classmethod
    def setUpClass(cls):
        cls.boot()
        r = do_setup(cls.base, cls.data / "ui" / "bootstrap.crt", "e2e-setup-token")
        assert r.status_code == 200 and "Your CA is ready" in r.text, r.text[:1500]
        cls.wait_for_ca_cert()
        cls.pid = cls.srv.proc.pid

    # ---- the web UI's own certificate -------------------------------------------------------
    def test_01_web_cert_chains_to_our_root_on_the_standard_port(self):
        ctx = ssl.create_default_context(cafile=str(self.root))
        for name in ("localhost", "ca.lab.test", "127.0.0.1"):
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=name) as tls:
                self.assertIn(tls.version(), ("TLSv1.2", "TLSv1.3"), name)
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
                ctx.wrap_socket(raw, server_hostname="evil.example")
        out = sh("openssl", "s_client", "-connect", "127.0.0.1:443", "-servername", "ca.lab.test", "-CAfile", str(self.root),
                 "-verify_return_error", "-verify_hostname", "ca.lab.test", "-brief", input=b"")
        out = (out.stdout + out.stderr).decode()
        self.assertIn("Verification: OK", out)
        self.assertIn("ca.lab.test", out.split("Verified peer", 1)[1].splitlines()[0])

    def test_01b_old_tls_versions_are_refused(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # only probing the protocol version here
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            self.skipTest("this OpenSSL build can't even attempt TLS 1.1")
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
                ctx.wrap_socket(raw, server_hostname="localhost")

    # ---- access control ---------------------------------------------------------------------
    def test_02_everything_private_requires_login(self):
        s = requests.Session(); s.verify = str(self.root)
        for path in ("/", "/issue", "/issue/csr", "/issue/csr/abc", "/certs", "/certs/AB", "/certs/AB/download/p12", "/ca"):
            r = s.get(self.base + path, allow_redirects=False)
            self.assertEqual(r.status_code, 303, path)
            self.assertTrue(r.headers["Location"].startswith("/login"), path)
        for path in ("/issue", "/certs/AB/revoke", "/ca/unlock", "/ca/root-key/export", "/ca/root-key/remove", "/ca/ui-names", "/account/password", "/logout"):
            r = s.post(self.base + path, data={"x": "y"}, allow_redirects=False)
            if r.status_code == 303:                      # not signed in: sent to the login page before anything else
                self.assertTrue(r.headers["Location"].startswith("/login"), path)
            else:
                self.assertEqual(r.status_code, 403, path)    # no session, no CSRF token
        for path in ("/trust", "/login", "/healthz", "/pki/root.crt", "/static/app.css"):
            self.assertEqual(s.get(self.base + path).status_code, 200, path)
        self.assertEqual(s.get(self.base + "/setup", allow_redirects=False).status_code, 303)   # setup is locked after use

    def test_03_login_rules(self):
        s = requests.Session(); s.verify = str(self.root)
        tok = csrf_of(s.get(f"{self.base}/login").text)
        r = s.post(f"{self.base}/login", data=dict(csrf_token=tok, password="wrong password!"), allow_redirects=False)
        self.assertEqual(r.status_code, 401)
        self.assertIn("isn't right", T(r))
        for nxt, want in (("//evil.example", "/"), ("https://evil.example/", "/"), ("/\\evil.example", "/"), ("/certs", "/certs")):
            s = requests.Session(); s.verify = str(self.root)       # signing in rotates the session, so start fresh each time
            tok = csrf_of(s.get(f"{self.base}/login").text)
            r = s.post(f"{self.base}/login", data=dict(csrf_token=tok, password=ADMIN, next=nxt), allow_redirects=False)
            self.assertEqual((r.status_code, r.headers.get("Location")), (303, want), nxt)

    def test_04_every_page_renders(self):
        s = self.login()
        for path, marker in (("/", "Make a certificate"), ("/issue", "New certificate"), ("/issue/csr", "Sign a certificate request"),
                             ("/certs", "Certificates"), ("/ca", "Chain of trust"), ("/trust", "Download root certificate")):
            r = s.get(self.base + path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn(marker, r.text, path)
            self.assertNotIn("Traceback", r.text)
        r = s.get(self.base + "/certs/DEADBEEF")
        self.assertEqual(r.status_code, 404)

    # ---- generate flow ------------------------------------------------------------------------
    def test_05_generate_certificate_end_to_end(self):
        s = self.login()
        serial = self.issue(s, "app.lab.test, 10.9.8.7, *.apps.lab.test")
        page = s.get(f"{self.base}/certs/{serial}?new=1").text
        self.assertIn("Certificate created", page)
        self.assertIn("app.lab.test", page)
        pw = re.search(r'id="p12pw">([^<]+)<', page).group(1)
        self.assertGreaterEqual(len(pw), 16)

        # p12: key + leaf + intermediate, opens with the shown password, validates strictly
        r = s.get(f"{self.base}/certs/{serial}/download/p12")
        self.assertEqual(r.status_code, 200)
        self.assertIn(".p12", r.headers["Content-Disposition"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        p12 = self.tmpfile("a.p12", r.content)
        leaf = sh("openssl", "pkcs12", "-in", p12, "-passin", f"pass:{pw}", "-clcerts", "-nokeys").stdout
        chain = sh("openssl", "pkcs12", "-in", p12, "-passin", f"pass:{pw}", "-cacerts", "-nokeys").stdout
        key = sh("openssl", "pkcs12", "-in", p12, "-passin", f"pass:{pw}", "-nocerts", "-nodes").stdout
        self.assertEqual(chain.count(b"BEGIN CERTIFICATE"), 1)
        leaf_path, chain_path = self.tmpfile("leaf.pem", leaf), self.tmpfile("ch.pem", chain)
        base_args = ["openssl", "verify", "-CAfile", str(self.root), "-untrusted", chain_path, "-x509_strict", "-purpose", "sslserver"]
        sh(*base_args, "-verify_hostname", "app.lab.test", "-verify_ip", "10.9.8.7", leaf_path)
        sh(*base_args, "-verify_hostname", "anything.apps.lab.test", leaf_path)          # the wildcard
        self.assertNotEqual(sh(*base_args, "-verify_hostname", "other.lab.test", leaf_path, check=False).returncode, 0)
        pub_cert = sh("openssl", "x509", "-in", self.tmpfile("l2.pem", leaf), "-pubkey", "-noout").stdout
        pub_key = sh("openssl", "pkey", "-in", self.tmpfile("k.pem", key), "-pubout").stdout
        self.assertEqual(pub_cert, pub_key)

        # zip bundle
        z = zipfile.ZipFile(io.BytesIO(s.get(f"{self.base}/certs/{serial}/download/zip").content))
        names = {n.split("/")[-1] for n in z.namelist()}
        self.assertTrue({"README.txt", "ca-chain.pem"} <= names and any(n.endswith(".key") for n in names))

        # public formats
        for fmt, marker in (("cer", b"BEGIN CERTIFICATE"), ("fullchain", b"BEGIN CERTIFICATE"), ("p7b", b"BEGIN PKCS7")):
            self.assertIn(marker, s.get(f"{self.base}/certs/{serial}/download/{fmt}").content, fmt)
        self.assertEqual(x509.load_der_x509_certificate(s.get(f"{self.base}/certs/{serial}/download/der").content).serial_number, int(serial, 16))

        # another session can't get the key
        other = self.login()
        self.assertEqual(other.get(f"{self.base}/certs/{serial}/download/p12").status_code, 404)
        # the private key can be wiped, after which the download is gone for good
        self.assertEqual(self.post(s, f"/certs/{serial}/discard-key").status_code, 303)
        self.assertEqual(s.get(f"{self.base}/certs/{serial}/download/p12").status_code, 404)
        self.assertEqual(s.get(f"{self.base}/certs/{serial}/download/cer").status_code, 200)   # public stuff stays

        # it is in the inventory and searchable
        self.assertIn(serial, s.get(f"{self.base}/certs?q=apps.lab").text)
        self.assertNotIn(serial, s.get(f"{self.base}/certs?q=nothing-like-this").text)
        self.__class__.good_serial = serial

    def test_05b_bad_input_is_rejected_with_a_helpful_message(self):
        s = self.login()
        for names, days, why in (("bad_name!", "30", "characters"), ("", "30", "Enter at least one"), ("a.test", "9999", "between 1 and"),
                                 ("a.test", "soon", "whole number")):
            r = self.post(s, "/issue", data=dict(names=names, days=days, purpose="both", key_type="ec-p256", p12="compat", password=""))
            self.assertEqual(r.status_code, 400, (names, days))
            self.assertIn(why, r.text)
        r = self.post(s, "/issue", data=dict(names="a.test", days="30", purpose="both", key_type="ec-p256", p12="compat", password="short"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("at least 8", r.text)

    def test_05c_custom_password_and_modern_p12(self):
        s = self.login()
        serial = self.issue(s, "modern.lab.test", password="my-own-password-1", p12="modern", key_type="rsa-2048")
        p12 = self.tmpfile("m.p12", s.get(f"{self.base}/certs/{serial}/download/p12").content)
        info = sh("openssl", "pkcs12", "-in", p12, "-passin", "pass:my-own-password-1", "-info", "-nokeys").stderr.decode()
        self.assertIn("AES-256-CBC", info)
        self.assertIn("my-own-password-1", s.get(f"{self.base}/certs/{serial}").text)

    # ---- CSR flow -------------------------------------------------------------------------------
    def test_06_csr_flow(self):
        s = self.login()
        key, csr = self.tmp / "c.key", self.tmp / "c.csr"
        sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=files.lab.test",
           "-addext", "subjectAltName=DNS:files.lab.test,DNS:nas,IP:192.168.1.9")
        # paste
        r = self.post(s, "/issue/csr", data=dict(csr_text=csr.read_text()))
        self.assertEqual(r.status_code, 303)
        review = s.get(self.base + r.headers["Location"]).text
        for want in ("files.lab.test", "nas", "192.168.1.9", "RSA 2048"):
            self.assertIn(want, review)
        r2 = self.post(s, r.headers["Location"], data=dict(names="files.lab.test\nnas\n192.168.1.9", days="200", purpose="server"))
        self.assertEqual(r2.status_code, 303, r2.text[:400])
        serial = re.search(r"/certs/([0-9A-F]+)", r2.headers["Location"]).group(1)
        self.assertIn("Certificate signed", s.get(self.base + r2.headers["Location"]).text)
        cer = self.tmpfile("f.cer", s.get(f"{self.base}/certs/{serial}/download/cer").content)
        full = self.tmpfile("full.pem", s.get(f"{self.base}/certs/{serial}/download/fullchain").content)
        sh("openssl", "verify", "-CAfile", str(self.root), "-untrusted", full, "-x509_strict", "-purpose", "sslserver", "-verify_hostname", "nas", cer)
        # the issued cert carries the CSR's key, and we never saw the private key
        self.assertEqual(sh("openssl", "x509", "-in", cer, "-pubkey", "-noout").stdout, sh("openssl", "req", "-in", str(csr), "-pubkey", "-noout").stdout)
        # the review link can't be reused
        self.assertEqual(self.post(s, r.headers["Location"], data=dict(names="a.test", days="5", purpose="server")).status_code, 303)
        self.assertTrue(s.get(f"{self.base}/certs/{serial}").text.count("Download .p12") == 0)    # no key offered for CSR certs
        # upload variant, DER-encoded
        der = sh("openssl", "req", "-in", str(csr), "-outform", "DER").stdout
        r = s.post(f"{self.base}/issue/csr", data=dict(csrf_token=s.csrf), files={"csr_file": ("req.der", der)}, allow_redirects=False)
        self.assertEqual(r.status_code, 303)
        # another session can't peek at someone else's pending request
        other = self.login()
        self.assertEqual(other.get(self.base + r.headers["Location"], allow_redirects=False).status_code, 303)

    def test_06b_bad_csrs(self):
        s = self.login()
        r = self.post(s, "/issue/csr", data=dict(csr_text="hello world"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("doesn't look like a certificate request", T(r))
        r = self.post(s, "/issue/csr", data=dict(csr_text="x" * 70000))
        self.assertEqual(r.status_code, 400)
        r = s.post(f"{self.base}/issue/csr", data=dict(csrf_token=s.csrf), files={"csr_file": ("x.csr", b"\x00" * 100000)}, allow_redirects=False)
        self.assertEqual(r.status_code, 400)

    # ---- revocation ----------------------------------------------------------------------------------
    def test_07_revoke_publishes_a_crl_that_openssl_enforces(self):
        s = self.login()
        keep, kill = self.issue(s, "keep.lab.test"), self.issue(s, "kill.lab.test")
        leafs = {}
        for name, serial in (("keep", keep), ("kill", kill)):
            leafs[name] = self.tmpfile(f"{name}.pem", s.get(f"{self.base}/certs/{serial}/download/cer").content)
        self.assertEqual(self.post(s, f"/certs/{kill}/revoke", data=dict(reason="keyCompromise")).status_code, 303)
        self.assertIn("Revoked", s.get(f"{self.base}/certs/{kill}").text)
        self.assertNotEqual(self.post(s, f"/certs/{kill}/revoke", data=dict(reason="keyCompromise")).status_code, 500)

        # the CRL is public on both ports, as a real client would fetch it (from the URL inside the cert)
        crl_der = requests.get("http://localhost/pki/intermediate.crl", timeout=5)
        self.assertEqual(crl_der.status_code, 200)
        self.assertEqual(crl_der.headers["Content-Type"], "application/pkix-crl")
        self.assertEqual(requests.get(f"{self.base}/pki/intermediate.crl", verify=str(self.root)).content, crl_der.content)
        crl_pem = self.tmpfile("crl.pem", sh("openssl", "crl", "-inform", "DER", "-outform", "PEM", input=crl_der.content).stdout)
        inter = self.tmpfile("int.pem", requests.get("http://localhost/pki/intermediate.crt").content)
        txt = sh("openssl", "crl", "-in", crl_pem, "-noout", "-text").stdout.decode()
        self.assertIn(kill, txt); self.assertNotIn(keep, txt)
        self.assertIn("Key Compromise", txt)
        flags = ["-CAfile", str(self.root), "-untrusted", inter, "-crl_check", "-CRLfile", crl_pem]
        sh("openssl", "verify", *flags, leafs["keep"])
        bad = sh("openssl", "verify", *flags, leafs["kill"], check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("revoked", (bad.stdout + bad.stderr).decode())
        # the cert tells clients where to look
        info = sh("openssl", "x509", "-in", leafs["keep"], "-noout", "-text").stdout.decode()
        self.assertIn("http://ca.lab.test/pki/intermediate.crl", info)
        self.assertIn("http://ca.lab.test/pki/intermediate.cer", info)
        # the CRL is also what the AIA URL serves: DER cert
        self.assertEqual(x509.load_der_x509_certificate(requests.get("http://localhost/pki/intermediate.cer").content).serial_number,
                         x509.load_pem_x509_certificate(requests.get("http://localhost/pki/intermediate.crt").content).serial_number)

    def test_07b_cannot_revoke_the_web_ui_cert(self):
        s = self.login()
        row = re.search(r'href="/certs/([0-9A-F]+)"[^>]*>localhost', s.get(f"{self.base}/certs").text)
        self.assertIsNotNone(row)
        self.post(s, f"/certs/{row.group(1)}/revoke", data=dict(reason="unspecified"))
        self.assertNotIn("Revoked", re.search(r'<dl class="facts">.*?</dl>', s.get(f"{self.base}/certs/{row.group(1)}").text, re.S).group(0))

    # ---- public trust material ----------------------------------------------------------------------------
    def test_08_public_downloads(self):
        root_pem = requests.get("http://localhost/pki/root.crt", timeout=5)      # plain HTTP, no login
        root = x509.load_pem_x509_certificate(root_pem.content)
        self.assertEqual(root.subject.rfc4514_string().count("Test Lab Root CA"), 1)
        self.assertEqual(x509.load_der_x509_certificate(requests.get("http://localhost/pki/root.cer").content), root)
        self.assertEqual(root_pem.content, self.root.read_bytes())
        chain = requests.get("http://localhost/pki/chain.pem").content
        self.assertEqual(chain.count(b"BEGIN CERTIFICATE"), 2)
        p7 = sh("openssl", "pkcs7", "-inform", "PEM", "-print_certs", "-noout", input=requests.get("http://localhost/pki/chain.p7b").content).stdout.decode()
        self.assertEqual(p7.count("subject="), 2)
        prof = plistlib.loads(requests.get("http://localhost/pki/root.mobileconfig").content)
        payload = prof["PayloadContent"][0]
        self.assertEqual(payload["PayloadType"], "com.apple.security.root")
        self.assertEqual(x509.load_der_x509_certificate(payload["PayloadContent"]), root)
        self.assertEqual(requests.get("http://localhost/pki/nope.crt").status_code, 404)
        # trust page shows the same fingerprint the root really has
        fp = ":".join(f"{b:02X}" for b in root.fingerprint(hashes.SHA256()))
        page = requests.get(f"{self.base}/trust", verify=str(self.root)).text
        for line in [fp[i:i + 23] for i in range(0, len(fp), 24)]:
            self.assertIn(line, page)
        self.assertIn(f'"{fp}"', page)    # the Linux one-liner pins it

    def test_08b_port_80_only_redirects_and_never_to_a_forged_host(self):
        r = requests.get("http://localhost/certs?status=valid", allow_redirects=False, timeout=5)
        self.assertEqual((r.status_code, r.headers["Location"]), (307, "https://localhost/certs?status=valid"))
        r = requests.get("http://localhost/", headers={"Host": "evil.example"}, allow_redirects=False, timeout=5)
        self.assertNotIn("evil.example", r.headers["Location"])
        self.assertEqual(requests.post("http://localhost/login", data={"a": "b"}, timeout=5).status_code, 405)

    # ---- headers, cookies, limits -----------------------------------------------------------------------------
    def test_09_headers_cookies_and_limits(self):
        s = self.login()
        r = s.get(self.base + "/")
        csp = r.headers["Content-Security-Policy"]
        for want in ("default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "form-action 'self'"):
            self.assertIn(want, csp)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertNotIn("Server", r.headers)
        raw = requests.get(f"{self.base}/login", verify=str(self.root)).headers["Set-Cookie"].lower()
        for flag in ("secure", "httponly", "samesite=strict"):
            self.assertIn(flag, raw)
        # no inline script or style anywhere, which the CSP would block anyway
        for path in ("/", "/issue", "/ca", "/trust", "/certs"):
            html = s.get(self.base + path).text
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)")
            self.assertNotIn(" style=", html, path)
            self.assertNotRegex(html, r"\son(click|load|submit)=")
        # CSRF: a valid session but a wrong token is refused
        r = s.post(f"{self.base}/issue", data=dict(csrf_token="nope", names="a.test"), allow_redirects=False)
        self.assertEqual(r.status_code, 403)
        # big bodies are refused, with and without Content-Length, and the server stays healthy
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        for body in (b"x" * 2_000_000, (b"x" * 100_000 for _ in range(30))):
            try:     # either a 413, or the server hangs up on us mid-upload; both mean "refused"
                self.assertEqual(requests.post(f"{self.base}/login", data=body, headers=hdr, verify=str(self.root)).status_code, 413)
            except requests.RequestException:
                pass
        self.assertEqual(requests.get(f"{self.base}/healthz", verify=str(self.root)).text, "ok")

    # ---- CA page actions ----------------------------------------------------------------------------------------
    def test_10_root_key_custody_and_intermediate_renewal(self):
        s = self.login()
        page = s.get(self.base + "/ca").text
        self.assertIn("The root key is on this server", page)
        # removal is refused until a backup has been downloaded
        self.post(s, "/ca/root-key/remove", data=dict(confirm="remove root key"))
        self.assertTrue((self.data / "ca" / "root.key").exists())
        # wrong passphrase gets no key; right one gets a standard encrypted PKCS#8 that OpenSSL can open
        r = self.post(s, "/ca/root-key/export", data=dict(passphrase="not the passphrase"))
        self.assertEqual(r.status_code, 303)
        r = self.post(s, "/ca/root-key/export", data=dict(passphrase=PASS))
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", r.content)
        backup = r.content
        sh("openssl", "pkey", "-in", self.tmpfile("root.key.enc", backup), "-passin", f"pass:{PASS}", "-noout")
        # must type the confirmation exactly
        self.post(s, "/ca/root-key/remove", data=dict(confirm="yes"))
        self.assertTrue((self.data / "ca" / "root.key").exists())
        self.post(s, "/ca/root-key/remove", data=dict(confirm="remove root key"))
        self.assertFalse((self.data / "ca" / "root.key").exists())
        self.assertIn("not on this server", s.get(self.base + "/ca").text)
        # renew without the key fails; with the uploaded backup it works, and old certs still verify
        self.post(s, "/ca/intermediate/renew", data=dict(passphrase=PASS, years="5"), files={"root_key": ("", b"")})
        self.assertIn("isn't on this server", T(s.get(self.base + "/ca")))
        before = requests.get("http://localhost/pki/intermediate.crt").content
        r = s.post(f"{self.base}/ca/intermediate/renew", data=dict(csrf_token=s.csrf, passphrase="wrong wrong wrong", years="5"),
                   files={"root_key": ("root.key.enc", backup)}, allow_redirects=False)
        self.assertEqual(requests.get("http://localhost/pki/intermediate.crt").content, before)
        self.assertIn("didn't unlock", T(s.get(self.base + "/ca")))
        r = s.post(f"{self.base}/ca/intermediate/renew", data=dict(csrf_token=s.csrf, passphrase=PASS, years="5"),
                   files={"root_key": ("root.key.enc", backup)}, allow_redirects=False)
        self.assertEqual(r.status_code, 303)
        after = requests.get("http://localhost/pki/intermediate.crt").content
        self.assertNotEqual(after, before)
        old_leaf = self.tmpfile("old.pem", s.get(f"{self.base}/certs/{self.good_serial}/download/cer").content)
        sh("openssl", "verify", "-CAfile", str(self.root), "-untrusted", self.tmpfile("new-int.pem", after), old_leaf)
        sh("openssl", "verify", "-CAfile", str(self.root), "-untrusted", self.tmpfile("new-int2.pem", after),
           self.tmpfile("fresh.pem", s.get(f"{self.base}/certs/{self.issue(s, 'after-renew.lab.test')}/download/cer").content))

    def test_11_web_names_change_takes_effect_without_a_restart(self):
        s = self.login()
        # refuses to lock you out
        self.post(s, "/ca/ui-names", data=dict(names="ca.lab.test\nextra.lab.test"))
        self.assertIn("Keep localhost in the list", s.get(self.base + "/ca").text)
        ctx = ssl.create_default_context(cafile=str(self.root))
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
                ctx.wrap_socket(raw, server_hostname="extra.lab.test")
        self.assertEqual(self.post(s, "/ca/ui-names", data=dict(names="localhost\n127.0.0.1\nca.lab.test\nextra.lab.test")).status_code, 303)
        end = time.time() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname="extra.lab.test"):
                    break
            except ssl.SSLCertVerificationError:
                self.assertLess(time.time(), end, "new name never appeared in the live certificate")
                time.sleep(0.2)
        self.assertEqual(self.srv.proc.pid, self.pid)            # same process: switched in place
        self.assertIsNone(self.srv.proc.poll())
        self.assertEqual(s.get(self.base + "/").status_code, 200)

    def test_12_password_change_signs_everyone_else_out(self):
        a, b = self.login(), self.login()
        r = self.post(a, "/account/password", data=dict(current="wrong", new="x" * 14, new2="x" * 14))
        self.assertIn("isn't right", T(a.get(self.base + "/ca")))
        self.post(a, "/account/password", data=dict(current=ADMIN, new="a-new-password-9876", new2="a-new-password-9876"))
        self.assertEqual(a.get(self.base + "/ca", allow_redirects=False).status_code, 200)        # this session stays valid
        self.assertEqual(b.get(self.base + "/ca", allow_redirects=False).status_code, 303)        # the other one is out
        c = requests.Session(); c.verify = str(self.root)
        tok = csrf_of(c.get(f"{self.base}/login").text)
        self.assertEqual(c.post(f"{self.base}/login", data=dict(csrf_token=tok, password=ADMIN), allow_redirects=False).status_code, 401)
        self.post(a, "/account/password", data=dict(current="a-new-password-9876", new=ADMIN, new2=ADMIN))   # put it back
        self.login()    # proves the original password works again, and clears the failed-login count for the rate-limit test

    def test_13_the_version_is_shown_and_updating_is_not_offered_in_the_browser(self):
        anon = requests.get(self.base + "/login", verify=str(self.root))
        self.assertNotIn("CertForge dev", anon.text)                    # the build isn't shown to people who aren't signed in
        s = self.login()
        page = s.get(self.base + "/ca").text
        self.assertIn('id="software"', page)
        self.assertRegex(page, r"CertForge (dev|\d+\.\d+\.\d+\S*)")        # also in the footer on every page
        self.assertRegex(s.get(self.base + "/").text, r"<footer>\s*<div class=\"wrap\">\s*<span>CertForge ")
        self.assertIn("never from this page", page)
        # there is nothing to POST to that would install anything
        for path in ("/ca/update", "/update", "/ca/updates/install", "/ca/updates/apply"):
            self.assertIn(self.post(s, path).status_code, (404, 405), path)
        self.assertEqual(s.get(self.base + "/ca/updates").status_code, 405)
        # the check is opt-in, and switching it on and off is a logged action
        self.assertNotIn("checked", re.search(r'<input[^>]*name="enabled"[^>]*>', page).group(0))
        self.assertEqual(self.post(s, "/ca/updates", data={"enabled": "1"}).status_code, 303)
        self.assertIn("checked", re.search(r'<input[^>]*name="enabled"[^>]*>', s.get(self.base + "/ca").text).group(0))
        self.assertEqual(self.post(s, "/ca/updates").status_code, 303)
        self.assertNotIn("checked", re.search(r'<input[^>]*name="enabled"[^>]*>', s.get(self.base + "/ca").text).group(0))
        self.assertIn("Update check turned on", s.get(self.base + "/ca").text)
        for path in ("/ca/updates", "/ca/updates/check"):                 # needs the CSRF token and a session
            r = requests.post(self.base + path, verify=str(self.root), allow_redirects=False)
            self.assertIn(r.status_code, (303, 400, 401, 403), path)

    def test_zz_login_is_rate_limited(self):
        s = requests.Session(); s.verify = str(self.root)
        tok = csrf_of(s.get(f"{self.base}/login").text)
        codes = [s.post(f"{self.base}/login", data=dict(csrf_token=tok, password=f"wrong-{i}"), allow_redirects=False).status_code for i in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5:], [429, 429])
        r = s.post(f"{self.base}/login", data=dict(csrf_token=tok, password=ADMIN), allow_redirects=False)   # even the right password waits
        self.assertEqual(r.status_code, 429)
        self.assertIn("Too many", r.text)


# ==========================================================================================

class TestSealedAndSetupRules(Base):
    """Separate server on other ports: wrong-setup attempts, a generated setup code, and 'ask for the passphrase after restart'."""

    PORT = 8443

    @classmethod
    def setUpClass(cls):
        cls.boot(https=cls.PORT, http=0, token=None)
        cls.boot_bootstrap = cls.data / "ui" / "bootstrap.crt"

    def setup_token_from_log(self) -> str:
        log = self.srv.log_path.read_text()
        return re.search(r"enter this setup code:\n\s+(\S+)", log).group(1)

    def test_1_setup_rules_then_sealed_flow(self):
        token = self.setup_token_from_log()
        self.assertEqual((self.data / "setup.token").read_text().strip(), token)
        self.assertEqual(oct((self.data / "setup.token").stat().st_mode & 0o777), "0o600")
        boot = self.boot_bootstrap
        # wrong code, mismatched passwords, short passwords, same passphrase as password, bad names: all refused, nothing created
        for over, why in ((dict(token="guess"), "setup code isn't right"), (dict(admin_password2="different-password-1"), "don't match"),
                          (dict(admin_password="short", admin_password2="short"), "at least 12"), (dict(passphrase=ADMIN), "different passphrase"),
                          (dict(passphrase="short"), "passphrase must be"), (dict(org="bad/org"), "CA name"),
                          (dict(ui_names="bad_name!"), "characters"), (dict(root_years="x"), "whole number")):
            over = dict(over)
            r = do_setup(self.base, boot, over.pop("token", token), seal=True, **over)
            self.assertEqual(r.status_code, 400, over)
            self.assertIn(why, T(r), over)
        self.assertFalse((self.data / "ca" / "root.crt").exists())
        # and the passwords the person typed are never echoed back into the page
        echoed = do_setup(self.base, boot, "guess", seal=True)
        self.assertEqual(echoed.status_code, 400)
        self.assertNotIn(ADMIN, echoed.text)
        self.assertNotIn(PASS, echoed.text)

        r = do_setup(self.base, boot, token, seal=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Your CA is ready", r.text)
        self.assertFalse((self.data / "setup.token").exists())      # single use
        self.assertIn(b"ENCRYPTED PRIVATE KEY", (self.data / "ca" / "intermediate.key").read_bytes())
        self.wait_for_ca_cert()
        s = self.login()
        serial = self.issue(s, "first.lab.test")                    # usable right after setup: you just typed the passphrase
        self.assertTrue(serial)
        # setup can't be run again, even with the right code
        s2 = requests.Session(); s2.verify = str(self.root)
        tok = csrf_of(s2.get(f"{self.base}/login").text)
        r = s2.post(f"{self.base}/setup", data=dict(csrf_token=tok, token=token, org="Hijack", admin_password="x" * 14, admin_password2="x" * 14,
                                                   passphrase="y" * 14, key_type="ec-p384", ui_names="evil.test"), allow_redirects=False)
        self.assertEqual((r.status_code, r.headers["Location"]), (303, "/"))
        self.assertIn("Test Lab Root CA", requests.get(f"{self.base}/trust", verify=str(self.root)).text)

        # ---- restart the process: the CA must come back locked, but the web UI keeps its CA-issued cert
        self.srv.stop()
        self.srv.start()
        self.srv.wait(self.root)
        s = self.login()
        self.assertIn("The CA is locked", s.get(self.base + "/").text)
        r = self.post(s, "/issue", data=dict(names="second.lab.test", days="30", purpose="both", key_type="ec-p256", p12="compat", password=""))
        self.assertEqual(r.status_code, 423)
        self.assertIn("locked", T(r))
        self.assertEqual(self.post(s, "/certs/" + serial + "/revoke", data=dict(reason="unspecified")).status_code, 303)
        self.assertNotIn("Revoked", re.search(r'<dl class="facts">.*?</dl>', s.get(f"{self.base}/certs/{serial}").text, re.S).group(0))
        self.post(s, "/ca/unlock", data=dict(passphrase="wrong wrong wrong"))
        self.assertIn("didn't unlock", T(s.get(self.base + "/ca")))
        self.assertEqual(self.post(s, "/issue", data=dict(names="second.lab.test", days="30", purpose="both", key_type="ec-p256", p12="compat", password="")).status_code, 423)
        self.post(s, "/ca/unlock", data=dict(passphrase=PASS))
        self.assertNotIn("The CA is locked", s.get(self.base + "/").text)
        self.assertTrue(self.issue(s, "second.lab.test"))
        # revoking works now
        self.assertEqual(self.post(s, f"/certs/{serial}/revoke", data=dict(reason="superseded")).status_code, 303)
        self.assertIn("Revoked", s.get(f"{self.base}/certs/{serial}").text)


class TestBlankFieldsUseDetectedSettings(Base):
    """Setup with only the code and the two secrets: org, names and public address come from the network."""

    @classmethod
    def setUpClass(cls):
        cls.boot(https=8444, http=0)

    def test_setup_form_is_prefilled_and_blank_fields_are_filled_in(self):
        s = requests.Session(); s.verify = str(self.data / "ui" / "bootstrap.crt")
        page = T(s.get(f"{self.base}/setup"))
        self.assertIn("looked at the network", page)
        self.assertIn("ca.lab.test", page)                         # names from CERTFORGE_HOSTNAMES are shown
        self.assertNotIn(" required", re.search(r'<textarea id="ui_names"[^>]*>', page).group(0))
        r = do_setup(self.base, self.data / "ui" / "bootstrap.crt", "e2e-setup-token", org="", ui_names="", public_host="")
        self.assertEqual(r.status_code, 200, T(r)[:400])
        self.wait_for_ca_cert()
        ca = T(requests.get(f"{self.base}/trust", verify=str(self.root)))
        self.assertRegex(ca, r"Trust .+ on this device")           # a non-empty organization was chosen
        cert = x509.load_pem_x509_certificate((self.data / "ui" / "ui.crt").read_bytes())
        self.assertEqual(set(C_sans(cert)), {"localhost", "127.0.0.1", "ca.lab.test"})
        self.assertEqual(json_setting(self.data, "public_host"), "localhost")


class TestHeadlessSetup(Base):
    """CERTFORGE_ADMIN_PASSWORD + CERTFORGE_CA_PASSPHRASE: the CA exists before the first request."""

    @classmethod
    def setUpClass(cls):
        secretdir = Path(tempfile.mkdtemp(prefix="certforge-secrets-"))
        cls.addClassCleanup(shutil.rmtree, secretdir, ignore_errors=True)
        (secretdir / "ca").write_text(PASS + "\n")
        cls.boot(https=8445, http=0, token=None, verify_with_root=True, env={
            "CERTFORGE_ADMIN_PASSWORD": ADMIN, "CERTFORGE_CA_PASSPHRASE_FILE": str(secretdir / "ca"),
            "CERTFORGE_ORG": "Auto Lab", "CERTFORGE_SEAL": "true", "CERTFORGE_PUBLIC_HOST": "pki.lab.test"})

    def test_ca_is_ready_and_nothing_secret_is_logged(self):
        log = self.srv.log_path.read_text()
        self.assertIn("set up automatically", log)
        self.assertNotIn(ADMIN, log)
        self.assertNotIn(PASS, log)
        self.assertFalse((self.data / "setup.token").exists())
        s = requests.Session(); s.verify = str(self.root)
        self.assertEqual(s.get(f"{self.base}/setup", allow_redirects=False).status_code, 303)    # no setup page to hijack
        self.assertIn("Auto Lab Root CA", s.get(f"{self.base}/trust").text)
        self.assertEqual(json_setting(self.data, "public_host"), "pki.lab.test")
        s = self.login()
        self.assertIn("Certificate authority", s.get(f"{self.base}/ca").text)

    def test_sealed_after_restart_and_unlocks_with_the_passphrase(self):
        self.srv.stop(); self.srv.start(); self.srv.wait(self.root)
        s = self.login()
        self.assertIn("The CA is locked", s.get(self.base + "/").text)
        self.post(s, "/ca/unlock", data=dict(passphrase=PASS))
        self.assertNotIn("The CA is locked", s.get(self.base + "/").text)


class TestBadHeadlessSettingsFailLoudly(unittest.TestCase):
    def test_short_secrets_stop_the_server_with_a_reason(self):
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "CERTFORGE_DATA": d, "CERTFORGE_HTTPS_PORT": "8446", "CERTFORGE_HTTP_PORT": "0",
                   "CERTFORGE_ADMIN_PASSWORD": "short", "CERTFORGE_CA_PASSPHRASE": "short"}
            p = subprocess.run([sys.executable, "-m", "app.server"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Automatic setup failed", p.stderr + p.stdout)


class TestAcmeOverHttps(Base):
    """The ACME server on the real HTTPS listener, with a real port-80 challenge server and a real client."""

    PORT = 8447

    @classmethod
    def setUpClass(cls):
        from app import netinfo
        ips = netinfo.local_ips()
        if not ips:
            raise unittest.SkipTest("no non-loopback address to validate against")
        cls.ip = ips[0]
        cls.boot(https=cls.PORT, http=0, token=None, verify_with_root=True, env={
            "CERTFORGE_ADMIN_PASSWORD": ADMIN, "CERTFORGE_CA_PASSPHRASE": PASS, "CERTFORGE_ORG": "Acme Lab",
            "CERTFORGE_ACME_NETWORKS": f"{cls.ip}/32", "CERTFORGE_ACME_DAYS": "45"})

    def challenge_server(self, client):
        """Serves the key authorization for any token on port 80 of our address, like certbot --standalone does."""
        from http.server import BaseHTTPRequestHandler, HTTPServer

        seen = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.path.rsplit("/", 1)[-1]
                seen.append((self.path, self.headers.get("Host")))
                body = client.key_authorization(token).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def log_message(self, *a):
                pass
        import threading
        srv = HTTPServer((self.ip, 80), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return seen

    def new_client(self):
        from tests.acme_client import Client, Http
        s = requests.Session(); s.verify = str(self.root)
        c = Client(Http(s), self.base, "ES256")
        self.assertEqual(c.new_account(["mailto:ops@lab.test"]).status, 201)
        return c, s

    def test_zero_touch_turned_acme_on_and_the_directory_is_public(self):
        d = requests.get(f"{self.base}/acme/directory", verify=str(self.root))
        self.assertEqual(d.status_code, 200)
        self.assertEqual(d.json()["newOrder"], f"{self.base}/acme/new-order")
        self.assertEqual(d.headers["Cache-Control"], "no-store")
        for h, want in (("evil.example", 400), ("localhost", 200)):
            r = requests.get(f"{self.base}/acme/directory", verify=str(self.root), headers={"Host": h})
            self.assertEqual(r.status_code, want, h)
        r = requests.post(f"{self.base}/acme/new-order", data=b"{}", verify=str(self.root), headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 415)
        self.assertEqual(requests.get(f"{self.base}/acme/new-order", verify=str(self.root)).status_code, 405)

    def test_certificate_for_an_ip_then_revoke_then_manage_in_the_web_page(self):
        from tests.acme_client import make_csr
        c, s = self.new_client()
        seen = self.challenge_server(c)
        r = c.new_order([{"type": "ip", "value": self.ip}])
        self.assertEqual(r.status, 201, r.body)
        url = r.headers["location"]
        order = c.poll(url).json()
        z = c.poll(order["authorizations"][0]).json()
        self.assertEqual(c.poke(z["challenges"][0]["url"]).status, 200)
        end = time.time() + 15
        while time.time() < end and c.poll(url).json()["status"] not in ("ready", "invalid"):
            time.sleep(0.2)
        order = c.poll(url).json()
        self.assertEqual(order["status"], "ready", order)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], f"/.well-known/acme-challenge/{z['challenges'][0]['token']}")
        self.assertEqual(seen[0][1], self.ip)

        csr, key = make_csr([self.ip])
        order = c.finalize(order, csr).json()
        self.assertEqual(order["status"], "valid")
        chain = c.post(order["certificate"], None).body
        certs = x509.load_pem_x509_certificates(chain)
        self.assertEqual(len(certs), 2)
        leaf = certs[0]
        self.assertTrue(44 <= (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 46)     # CERTFORGE_ACME_DAYS=45
        inter = self.tmpfile("inter.pem", certs[1].public_bytes(serialization.Encoding.PEM))
        leaf_pem = self.tmpfile("leaf.pem", certs[0].public_bytes(serialization.Encoding.PEM))
        sh("openssl", "verify", "-CAfile", str(self.root), "-untrusted", inter, "-purpose", "sslserver", "-verify_ip", self.ip, leaf_pem)

        # the web page lists it and shows the ACME page
        w = self.login()
        listing = T(w.get(f"{self.base}/certs"))
        self.assertIn("ACME client", listing)
        page = T(w.get(f"{self.base}/acme"))
        self.assertIn(f"{self.base}/acme/directory", page)
        self.assertIn(self.ip, page)
        self.assertIn("Issued", page)
        self.assertEqual(w.get(f"{self.base}/acme/directory").status_code, 200)

        # revoke over ACME; the web page agrees
        self.assertEqual(c.revoke(certs[0].public_bytes(serialization.Encoding.DER), reason=4).status, 200)
        serial = f"{leaf.serial_number:X}"
        serial = serial if len(serial) % 2 == 0 else "0" + serial
        self.assertIn("Revoked", re.search(r'<dl class="facts">.*?</dl>', w.get(f"{self.base}/certs/{serial}").text, re.S).group(0))

    def test_admin_page_actions(self):
        w = self.login()
        self.assertEqual(w.get(f"{self.base}/acme", allow_redirects=False).status_code, 200)
        anon = requests.get(f"{self.base}/acme", verify=str(self.root), allow_redirects=False)
        self.assertEqual((anon.status_code, anon.headers["Location"].startswith("/login")), (303, True))
        anon = requests.post(f"{self.base}/acme/settings", data={"enabled": "1"}, verify=str(self.root), allow_redirects=False)
        self.assertEqual(anon.status_code, 303)

        # bad settings are explained, nothing changes
        r = self.post(w, "/acme/settings", data=dict(enabled="1", domains="*.lab.test", networks="", days="30"))
        self.assertIn("wildcards", T(w.get(f"{self.base}/acme")))
        # require an account key; registering without one fails, with one works
        self.post(w, "/acme/settings", data=dict(enabled="1", domains="lab.test", networks=f"{self.ip}/32", days="45", require_eab="1"))
        from tests.acme_client import Client, Http
        sess = requests.Session(); sess.verify = str(self.root)
        c = Client(Http(sess), self.base)
        self.assertEqual(c.new_account().problem, "externalAccountRequired")
        self.post(w, "/acme/eab", data=dict(label="e2e laptop"))
        flash = T(w.get(f"{self.base}/acme"))
        m = re.search(r"Key id: (\S+)\s+HMAC key: (\S+)", flash)
        self.assertTrue(m, flash[:2000])
        kid, key = m.group(1), m.group(2)
        self.assertEqual(c.new_account(eab=(kid, key)).status, 201)
        page = T(w.get(f"{self.base}/acme"))
        self.assertIn("e2e laptop", page)
        self.assertIn("Used", page)
        # deactivate the account from the page
        acct_id = c.kid.rsplit("/", 1)[1]
        self.assertEqual(self.post(w, f"/acme/accounts/{acct_id}/deactivate", data={}).status_code, 303)
        self.assertEqual(c.new_order([{"type": "ip", "value": self.ip}]).status, 403)
        # a revoked key can't be used
        self.post(w, f"/acme/eab/{kid}/revoke", data={})
        # switch it all off again
        self.post(w, "/acme/settings", data=dict(domains="lab.test", networks=f"{self.ip}/32", days="45"))
        self.assertEqual(requests.get(f"{self.base}/acme/directory", verify=str(self.root)).status_code, 404)
        self.post(w, "/acme/settings", data=dict(enabled="1", domains="lab.test", networks=f"{self.ip}/32", days="45"))
        self.assertEqual(requests.get(f"{self.base}/acme/directory", verify=str(self.root)).status_code, 200)


class AcmeCaBase(Base):
    """Shared plumbing for the ACME issuing CA tests: a zero-touch server with ACME on, and a real client."""

    PORT = 0
    new_client = TestAcmeOverHttps.new_client

    def serving(self, client):
        """Port 80 on this machine's address answers ACME challenges until the block ends."""
        import contextlib
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = client.key_authorization(self.path.rsplit("/", 1)[-1]).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def log_message(self, *a):
                pass

        @contextlib.contextmanager
        def run():
            srv = HTTPServer((self.ip, 80), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                yield
            finally:
                srv.shutdown()
                srv.server_close()
        return run()

    @classmethod
    def setUpClass(cls):
        from app import netinfo
        ips = netinfo.local_ips()
        if not ips:
            raise unittest.SkipTest("no non-loopback address to validate against")
        cls.ip = ips[0]
        cls.boot(https=cls.PORT, http=0, token=None, verify_with_root=True, env={
            "CERTFORGE_ADMIN_PASSWORD": ADMIN, "CERTFORGE_CA_PASSPHRASE": PASS, "CERTFORGE_ORG": "Split Lab",
            "CERTFORGE_SEAL": "true", "CERTFORGE_ACME_NETWORKS": f"{cls.ip}/32"})

    def restart(self, **env):
        self.srv.stop()
        self.srv.extra_env = {k: v for k, v in {**self.srv.extra_env, **env}.items() if v is not None}
        self.srv.start()
        self.srv.wait(self.root)

    def order_certificate(self):
        """A full ACME order for this machine's address. Returns (client, [leaf, issuing CA])."""
        from tests.acme_client import make_csr
        c, _ = self.new_client()
        r = c.new_order([{"type": "ip", "value": self.ip}])
        self.assertEqual(r.status, 201, r.body)
        url = r.headers["location"]
        z = c.poll(c.poll(url).json()["authorizations"][0]).json()
        with self.serving(c):
            self.assertEqual(c.poke(z["challenges"][0]["url"]).status, 200)
            end = time.time() + 15
            while time.time() < end and c.poll(url).json()["status"] not in ("ready", "invalid"):
                time.sleep(0.2)
        order = c.poll(url).json()
        self.assertEqual(order["status"], "ready", order)
        order = c.finalize(order, make_csr([self.ip])[0]).json()
        self.assertEqual(order["status"], "valid", order)
        return c, x509.load_pem_x509_certificates(c.post(order["certificate"], None).body)

    def verify_chain(self, certs, root_path):
        inter = self.tmpfile("acme-inter.pem", certs[1].public_bytes(serialization.Encoding.PEM))
        leaf = self.tmpfile("acme-leaf.pem", certs[0].public_bytes(serialization.Encoding.PEM))
        return sh("openssl", "verify", "-CAfile", str(root_path), "-untrusted", inter, "-purpose", "sslserver",
                  "-verify_ip", self.ip, leaf, check=False)

    def create_form(self, **over):
        data = dict(mode="under-main", main_passphrase=PASS, passphrase="acme-issuing-passphrase-1", passphrase2="acme-issuing-passphrase-1",
                    hold="secret", years="3", key_type="ec-p384", permitted=f"{self.ip}/32")
        data.update(over)
        return data


class TestAcmeCaSignedByTheMainRoot(AcmeCaBase):
    PORT = 8448
    ACME_PASS = "acme-issuing-passphrase-1"

    def test_1_the_page_offers_both_ways_and_acme_uses_the_main_ca_for_now(self):
        w = self.login()
        page = T(w.get(f"{self.base}/acme/ca"))
        self.assertIn("Signed by your existing root", page)
        self.assertIn("Give ACME its own root", page)
        self.assertIn("Your main intermediate CA", T(w.get(f"{self.base}/acme")))
        self.assertIn("separate ACME issuing CA", T(w.get(f"{self.base}/")))         # the dashboard nudges
        anon = requests.get(f"{self.base}/acme/ca", verify=str(self.root), allow_redirects=False)
        self.assertEqual((anon.status_code, anon.headers["Location"].startswith("/login")), (303, True))
        anon = requests.post(f"{self.base}/acme/ca/create", data={"mode": "under-main"}, verify=str(self.root), allow_redirects=False)
        self.assertEqual(anon.status_code, 303)

    def test_2_mistakes_are_explained_and_nothing_is_created(self):
        w = self.login()
        for over, why in ((dict(main_passphrase="not the ca passphrase"), "didn't unlock"),
                          (dict(passphrase2="something else entirely"), "don't match"),
                          (dict(passphrase=PASS, passphrase2=PASS), "different passphrase"),
                          (dict(passphrase=ADMIN, passphrase2=ADMIN), "admin login"),
                          (dict(mode="sideways"), "Choose how"),
                          (dict(years="soon"), "whole number")):
            r = self.post(w, "/acme/ca/create", data=self.create_form(**over))
            self.assertEqual(r.status_code, 400, (over, r.text[:300]))
            self.assertIn(why, T(r), over)
            if over.get("main_passphrase"):
                self.assertNotIn(over["main_passphrase"], r.text)          # secrets are never echoed back
        self.assertFalse((self.data / "acme-ca").exists())

    def test_3_create_it_and_get_a_certificate_from_it(self):
        w = self.login()
        r = self.post(w, "/acme/ca/create", data=self.create_form())
        self.assertEqual((r.status_code, r.headers["Location"]), (303, "/acme/ca"), r.text[:300])
        page = T(w.get(f"{self.base}/acme/ca"))
        self.assertIn("Unlocked.", page)
        self.assertIn("Signed by your existing root", page)
        self.assertNotIn("Download the new root", page)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", (self.data / "acme-ca" / "issuing.key").read_bytes())
        self.assertEqual((self.data / "acme-ca").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.data / "acme-ca" / "issuing.key").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("Your main intermediate CA", T(w.get(f"{self.base}/acme")))

        _, certs = self.order_certificate()
        r = self.verify_chain(certs, self.root)                 # it chains to the very same root as everything else
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        self.assertEqual(certs[1].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value, "Split Lab ACME Issuing CA")
        self.assertNotEqual(certs[1].fingerprint(hashes.SHA256()),
                            x509.load_pem_x509_certificate((self.data / "ca" / "intermediate.crt").read_bytes()).fingerprint(hashes.SHA256()))
        self.assertIn("ACME client", T(w.get(f"{self.base}/certs")))

        crl = requests.get(f"{self.base}/pki/acme-intermediate.crl", verify=str(self.root))
        self.assertEqual((crl.status_code, crl.headers["Content-Type"]), (200, "application/pkix-crl"))
        x509.load_der_x509_crl(crl.content)
        self.assertEqual(requests.get(f"{self.base}/pki/acme-root.crt", verify=str(self.root)).status_code, 200)

    def test_4_after_a_restart_it_unlocks_from_the_secret_or_by_hand(self):
        self.restart()                                         # no secret given
        w = self.login()
        self.assertIn("The ACME issuing CA is locked", T(w.get(f"{self.base}/")))
        self.assertIn("The issuing key is locked", T(w.get(f"{self.base}/acme/ca")))
        c, _ = self.new_client()
        self.assertEqual(c.new_order([{"type": "ip", "value": self.ip}]).status, 503)
        self.post(w, "/acme/ca/unlock", data=dict(passphrase="wrong passphrase here"))
        self.assertIn("didn't unlock", T(w.get(f"{self.base}/acme/ca")))
        self.post(w, "/acme/ca/unlock", data=dict(passphrase=self.ACME_PASS))
        self.assertIn("Unlocked.", T(w.get(f"{self.base}/acme/ca")))
        self.assertEqual(len(self.order_certificate()[1]), 2)

        self.restart(CERTFORGE_ACME_CA_PASSPHRASE=self.ACME_PASS)          # now give the server the secret
        self.assertIn("ACME issuing CA is unlocked", self.srv.log_path.read_text())
        self.assertNotIn(self.ACME_PASS, self.srv.log_path.read_text())
        w = self.login()
        self.assertNotIn("ACME issuing CA is locked", T(w.get(f"{self.base}/")))
        self.assertEqual(len(self.order_certificate()[1]), 2)

    def test_5_the_main_ca_can_stay_locked_while_acme_works(self):
        self.restart(CERTFORGE_ACME_CA_PASSPHRASE=self.ACME_PASS, CERTFORGE_ADMIN_PASSWORD=None, CERTFORGE_CA_PASSPHRASE=None)
        w = self.login()
        self.assertIn("The CA is locked", T(w.get(f"{self.base}/")))       # the main CA needs its passphrase...
        self.assertEqual(len(self.order_certificate()[1]), 2)               # ...and ACME doesn't care

    def test_6_renew_and_retire(self):
        w = self.login()
        self.post(w, "/acme/ca/renew", data=dict(passphrase="wrong wrong wrong", years="4"))
        self.assertIn("didn't unlock", T(w.get(f"{self.base}/acme/ca")))
        before = x509.load_pem_x509_certificate((self.data / "acme-ca" / "issuing.crt").read_bytes())
        self.post(w, "/acme/ca/renew", data=dict(passphrase=PASS, years="4"))
        self.assertIn("has been renewed", T(w.get(f"{self.base}/acme/ca")))
        after = x509.load_pem_x509_certificate((self.data / "acme-ca" / "issuing.crt").read_bytes())
        self.assertGreater(after.not_valid_after_utc, before.not_valid_after_utc)
        self.assertEqual(after.public_key().public_numbers(), before.public_key().public_numbers())

        self.post(w, "/acme/ca/retire", data=dict(confirm="nope"))
        self.assertIn("Type retire acme ca", T(w.get(f"{self.base}/acme/ca")))
        self.assertTrue((self.data / "acme-ca").exists())
        self.post(w, "/acme/ca/retire", data=dict(confirm="retire acme ca"))
        page = T(w.get(f"{self.base}/acme/ca"))
        self.assertIn("ACME is turned off", page)
        self.assertIn("Signed by your existing root", page)                  # and a new one can be made
        self.assertFalse((self.data / "acme-ca").exists())
        self.assertTrue(list((self.data / "acme-ca-retired").glob("*/issuing.key")))
        self.assertEqual(requests.get(f"{self.base}/acme/directory", verify=str(self.root)).status_code, 404)


class TestAcmeCaWithItsOwnRoot(AcmeCaBase):
    PORT = 8449
    ROOT_PASS = "acme-root-passphrase-xyz"
    ACME_PASS = "acme-issuing-passphrase-2"

    def own_form(self, **over):
        data = dict(mode="own-root", org="Edge Lab", root_passphrase=self.ROOT_PASS, passphrase=self.ACME_PASS,
                    passphrase2=self.ACME_PASS, hold="manual", root_years="15", years="4", key_type="ec-p384",
                    permitted=f"{self.ip}/32")
        data.update(over)
        return data

    def test_1_rules(self):
        w = self.login()
        for over, why in ((dict(passphrase=self.ROOT_PASS, passphrase2=self.ROOT_PASS), "different passphrase"),
                          (dict(root_years="3"), "root lifetime"), (dict(org="<b>"), "CA name"),
                          (dict(root_passphrase="short"), "at least")):
            r = self.post(w, "/acme/ca/create", data=self.own_form(**over))
            self.assertEqual(r.status_code, 400, (over, r.text[:200]))
            self.assertIn(why, T(r), over)
        self.assertFalse((self.data / "acme-ca").exists())

    def test_2_create_download_the_root_key_once_and_trust_the_new_root(self):
        w = self.login()
        r = self.post(w, "/acme/ca/create", data=self.own_form())
        self.assertEqual(r.status_code, 303, r.text[:300])
        m = re.fullmatch(r"/acme/ca\?backup=([\w-]+)", r.headers["Location"])
        self.assertTrue(m, r.headers["Location"])
        page = T(w.get(f"{self.base}{r.headers['Location']}"))
        self.assertIn("Download encrypted root key", page)
        self.assertIn("Its own separate root", page)
        self.assertFalse((self.data / "acme-ca" / "root.key").exists())      # the server holds no copy

        dl = w.get(f"{self.base}/acme/ca/root-key/download/{m.group(1)}")
        self.assertEqual(dl.status_code, 200)
        self.assertIn('filename="edge_lab-acme-root-ca.key.enc"', dl.headers["Content-Disposition"])
        self.assertIn(b"ENCRYPTED PRIVATE KEY", dl.content)
        key = serialization.load_pem_private_key(dl.content, self.ROOT_PASS.encode())
        acme_root = x509.load_pem_x509_certificate((self.data / "acme-ca" / "root.crt").read_bytes())
        self.assertEqual(key.public_key().public_numbers(), acme_root.public_key().public_numbers())
        again = w.get(f"{self.base}/acme/ca/root-key/download/{m.group(1)}", allow_redirects=True)
        self.assertIn("expired or was already used", T(again))
        self.__class__.root_backup = dl.content

        # nobody else can fetch a backup token
        other = self.login()
        self.assertEqual(other.get(f"{self.base}/acme/ca/root-key/download/not-a-token", allow_redirects=False).status_code, 303)

        # the trust page and the downloads carry the new root, distinct from the main one
        trust = T(requests.get(f"{self.base}/trust", verify=str(self.root)))
        self.assertIn("For machines that use ACME", trust)
        self.assertIn("Edge Lab ACME Root CA", trust)
        got = requests.get(f"{self.base}/pki/acme-root.crt", verify=str(self.root))
        self.assertEqual(x509.load_pem_x509_certificate(got.content).subject, acme_root.subject)
        self.assertNotEqual(got.content, requests.get(f"{self.base}/pki/root.crt", verify=str(self.root)).content)
        self.assertEqual(requests.get(f"{self.base}/pki/acme-root.mobileconfig", verify=str(self.root)).status_code, 200)

    def test_3_certificates_verify_against_the_new_root_and_not_the_main_one(self):
        self.restart()
        w = self.login()
        self.post(w, "/acme/ca/unlock", data=dict(passphrase=self.ACME_PASS))       # hold=manual: by hand
        _, certs = self.order_certificate()
        new_root = self.data / "acme-ca" / "root.crt"
        ok = self.verify_chain(certs, new_root)
        self.assertEqual(ok.returncode, 0, ok.stdout.decode() + ok.stderr.decode())
        self.assertNotEqual(self.verify_chain(certs, self.root).returncode, 0)
        self.assertIn("Edge Lab ACME Issuing CA", certs[0].issuer.rfc4514_string())

    def test_4_renewing_needs_the_root_key_backup(self):
        w = self.login()
        self.post(w, "/acme/ca/renew", data=dict(passphrase=self.ROOT_PASS, years="6"))
        self.assertIn("root key isn't on this server", T(w.get(f"{self.base}/acme/ca")))
        before = x509.load_pem_x509_certificate((self.data / "acme-ca" / "issuing.crt").read_bytes())
        self.post(w, "/acme/ca/renew", data=dict(passphrase=self.ROOT_PASS, years="6"),
                  files={"root_key": ("root.key.enc", self.root_backup)})
        self.assertIn("has been renewed", T(w.get(f"{self.base}/acme/ca")))
        after = x509.load_pem_x509_certificate((self.data / "acme-ca" / "issuing.crt").read_bytes())
        self.assertGreater(after.not_valid_after_utc, before.not_valid_after_utc)
        after.verify_directly_issued_by(x509.load_pem_x509_certificate((self.data / "acme-ca" / "root.crt").read_bytes()))
        # a different key is refused
        other_key = C_encrypt(self.ROOT_PASS)
        self.post(w, "/acme/ca/renew", data=dict(passphrase=self.ROOT_PASS, years="6"), files={"root_key": ("x.enc", other_key)})
        self.assertIn("isn't the key for this", T(w.get(f"{self.base}/acme/ca")))


class TestZeroTouchAcmeCa(AcmeCaBase):
    """CERTFORGE_ACME_CA=...: the issuing CA exists before the first request, and unlocks itself on every start."""

    PORT = 8450
    SECRET = "acme-issuing-passphrase-3"

    @classmethod
    def setUpClass(cls):
        from app import netinfo
        ips = netinfo.local_ips()
        if not ips:
            raise unittest.SkipTest("no non-loopback address to validate against")
        cls.ip = ips[0]
        secretdir = Path(tempfile.mkdtemp(prefix="certforge-secrets-"))
        cls.addClassCleanup(shutil.rmtree, secretdir, ignore_errors=True)
        (secretdir / "acme").write_text(cls.SECRET + "\n")
        cls.boot(https=cls.PORT, http=0, token=None, verify_with_root=True, env={
            "CERTFORGE_ADMIN_PASSWORD": ADMIN, "CERTFORGE_CA_PASSPHRASE": PASS, "CERTFORGE_ORG": "Auto Split",
            "CERTFORGE_SEAL": "true", "CERTFORGE_ACME_NETWORKS": f"{cls.ip}/32", "CERTFORGE_ACME_CA": "intermediate",
            "CERTFORGE_ACME_CA_PASSPHRASE_FILE": str(secretdir / "acme"), "CERTFORGE_ACME_CA_PERMITTED": f"{cls.ip}/32"})

    def test_1_created_at_start_and_issuing(self):
        log = self.srv.log_path.read_text()
        self.assertIn("ACME issuing CA was created", log)
        self.assertIn("ACME issuing CA is unlocked", log)
        self.assertNotIn(self.SECRET, log)
        self.assertNotIn(PASS, log)
        c, certs = self.order_certificate()
        self.assertEqual(self.verify_chain(certs, self.root).returncode, 0)
        self.assertIn("Auto Split ACME Issuing CA", certs[0].issuer.rfc4514_string())

    def test_2_every_restart_unlocks_it_without_anyone_there(self):
        self.restart(CERTFORGE_ADMIN_PASSWORD=None, CERTFORGE_CA_PASSPHRASE=None)     # main CA now sealed, as in real life
        self.assertEqual(len(self.order_certificate()[1]), 2)
        w = self.login()
        page = T(w.get(f"{self.base}/acme/ca"))
        self.assertIn("so it unlocks itself at start", page)
        self.assertIn("Unlocked.", page)


class TestBadAcmeCaSettingsFailLoudly(unittest.TestCase):
    def run_server(self, **env):
        with tempfile.TemporaryDirectory() as d:
            e = {**os.environ, "CERTFORGE_DATA": d, "CERTFORGE_HTTPS_PORT": "8451", "CERTFORGE_HTTP_PORT": "0",
                 "CERTFORGE_ADMIN_PASSWORD": ADMIN, "CERTFORGE_CA_PASSPHRASE": PASS, **env}
            return subprocess.run([sys.executable, "-m", "app.server"], cwd=ROOT, env=e, capture_output=True, text=True, timeout=90)

    def test_a_weak_or_reused_passphrase_stops_the_server_with_a_reason(self):
        p = self.run_server(CERTFORGE_ACME_CA="intermediate", CERTFORGE_ACME_CA_PASSPHRASE="short")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Automatic ACME CA setup failed", p.stderr + p.stdout)
        self.assertIn("at least", p.stderr + p.stdout)
        p = self.run_server(CERTFORGE_ACME_CA="intermediate", CERTFORGE_ACME_CA_PASSPHRASE=PASS)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("different passphrase", p.stderr + p.stdout)

    def test_a_missing_piece_is_named(self):
        p = self.run_server(CERTFORGE_ACME_CA="root", CERTFORGE_ACME_CA_PASSPHRASE="a-long-enough-passphrase")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("CERTFORGE_ACME_ROOT_PASSPHRASE", p.stderr + p.stdout)


def C_encrypt(passphrase: str) -> bytes:
    from app import ca
    return ca.encrypt_key(ca.generate_key("ec-p384"), passphrase)


if __name__ == "__main__":
    unittest.main(verbosity=2)
