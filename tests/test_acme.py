"""ACME server: the protocol, driven in-process by a real signing client. Needs the openssl CLI (the CA uses it)."""
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app import acme as A
from app.config import Config
from app.service import Service
from tests.acme_client import Client, InProcess, b64d, b64e, make_csr

BASE = "https://ca.lab.test"
ADMIN = "an-admin-password-123"
PASS = "ca-passphrase-for-tests-456"


class FakeNet:
    """Stands in for DNS and for the client's port-80 web server."""

    def __init__(self):
        self.dns: dict[str, list[str]] = {}
        self.calls: list[tuple] = []
        self.handler = lambda addr, host, path: (404, b"")

    def resolve(self, name):
        return list(self.dns.get(name, []))

    def fetch(self, addr, host, path, **kw):
        self.calls.append((addr, host, path))
        return self.handler(addr, host, path)


def make_service(permitted: str = "") -> tuple[Path, Service]:
    tmp = Path(tempfile.mkdtemp(prefix="certforge-acme-"))
    svc = Service(Config(data=tmp, bind="127.0.0.1", https_port=8443, http_port=0, hostnames="", setup_token=None))
    svc.setup(token=svc.setup_token(), org="ACME Test", admin_password=ADMIN, admin_password2=ADMIN, passphrase=PASS,
              key_type="ec-p384", root_years=10, int_years=5, seal=False, permitted=permitted,
              ui_names="ca.lab.test", public_host="ca.lab.test")
    return tmp, svc


_shared: dict = {}


def shared_service() -> tuple[Path, Service]:
    """Creating a CA takes a couple of seconds, so every unconstrained test class shares one."""
    if "svc" not in _shared:
        _shared["tmp"], _shared["svc"] = make_service()
    return _shared["tmp"], _shared["svc"]


def tearDownModule():
    if "tmp" in _shared:
        shutil.rmtree(_shared["tmp"], ignore_errors=True)


class Base(unittest.TestCase):
    permitted = ""

    @classmethod
    def setUpClass(cls):
        if cls.permitted:
            cls.tmp, cls.svc = make_service(cls.permitted)
            cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        else:
            cls.tmp, cls.svc = shared_service()
        cls.acme = cls.svc.acme
        cls.root = cls.tmp / "ca" / "root.crt"

    def setUp(self):
        self.net = FakeNet()
        self.acme.fetch, self.acme.resolve = self.net.fetch, self.net.resolve
        self.acme.account_gate, self.acme.order_gate = A.RateGate(20, 3600), A.RateGate(60, 3600)    # fresh limits per test
        self.configure()
        self.http = InProcess(self.acme, BASE)

    def configure(self, **over):
        s = dict(enabled=True, domains_raw="lab.test", networks_raw="192.168.7.0/24", days=90, require_eab=False)
        s.update(over)
        self.acme.save_settings("test", **s)

    def client(self, alg="ES256") -> Client:
        c = Client(self.http, BASE, alg)
        r = c.new_account(["mailto:ops@lab.test"])
        self.assertEqual(r.status, 201, r.body)
        return c

    def serve_challenges(self, c: Client):
        self.net.handler = lambda addr, host, path: (200, c.key_authorization(path.rsplit("/", 1)[1]).encode())

    def wait(self, c: Client, url: str, want: tuple, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            o = c.poll(url).json()
            if o["status"] in want:
                return o
            time.sleep(0.05)
        self.fail(f"{url} stayed {o['status']}")

    def run_challenges(self, c: Client, order_url: str) -> dict:
        order = c.poll(order_url).json()
        for authz_url in order["authorizations"]:
            z = c.poll(authz_url).json()
            self.assertEqual(z["challenges"][0]["type"], "http-01")
            self.assertEqual(c.poke(z["challenges"][0]["url"]).status, 200)
        return self.wait(c, order_url, ("ready", "invalid"))

    def get_cert(self, c: Client, names: list[str], key=None):
        ids = [{"type": "ip" if n[0].isdigit() else "dns", "value": n} for n in names]
        r = c.new_order(ids)
        self.assertEqual(r.status, 201, r.body)
        url = r.headers["location"]
        self.serve_challenges(c)
        order = self.run_challenges(c, url)
        self.assertEqual(order["status"], "ready", order)
        csr, key = make_csr(names, key)
        r = c.finalize(order, csr)
        self.assertEqual(r.status, 200, r.body)
        order = r.json()
        self.assertEqual(order["status"], "valid")
        chain = c.post(order["certificate"], None)
        self.assertEqual(chain.status, 200)
        self.assertEqual(chain.headers["content-type"], "application/pem-certificate-chain")
        return chain.body, key, url


class Basics(Base):
    def test_directory_and_nonce(self):
        c = Client(self.http, BASE)
        d = c.directory()
        self.assertEqual(d["newAccount"], f"{BASE}/acme/new-account")
        self.assertEqual(set(d) - {"meta"}, {"newNonce", "newAccount", "newOrder", "revokeCert"})
        self.assertFalse(d["meta"]["externalAccountRequired"])
        head = self.http("HEAD", f"{BASE}/acme/new-nonce", None, {})
        self.assertEqual(head.status, 200)
        get = self.http("GET", f"{BASE}/acme/new-nonce", None, {})
        self.assertEqual(get.status, 204)
        self.assertNotEqual(head.headers["replay-nonce"], get.headers["replay-nonce"])
        self.assertEqual(get.headers["cache-control"], "no-store")
        self.assertIn('rel="index"', get.headers["link"])

    def test_off_means_404(self):
        self.configure(enabled=False)
        r = self.http("GET", f"{BASE}/acme/directory", None, {})
        self.assertEqual(r.status, 404)
        self.configure()

    def test_settings_validation(self):
        for over, why in ((dict(domains_raw="*.lab.test"), "wildcards"), (dict(domains_raw="10.0.0.1"), "isn't a domain"),
                          (dict(domains_raw="", networks_raw=""), "at least one"), (dict(networks_raw="nope"), "IP range"),
                          (dict(days=0), "between 1 and"), (dict(days=9999), "between 1 and")):
            with self.assertRaises(Exception) as cm:
                self.configure(**over)
            self.assertIn(why, str(cm.exception), over)
        self.configure(enabled=False, domains_raw="", networks_raw="")      # turning it off needs no names


class Accounts(Base):
    def test_create_find_and_all_key_types(self):
        for alg in ("ES256", "ES384", "RS256"):
            c = Client(self.http, BASE, alg)
            r = c.new_account(["mailto:a@lab.test"])
            self.assertEqual(r.status, 201, (alg, r.body))
            self.assertEqual(r.json()["status"], "valid")
            self.assertTrue(r.json()["orders"].startswith(BASE + "/acme/acct/"))
            again = Client(self.http, BASE, alg, key=c.key)
            r2 = again.new_account()
            self.assertEqual((r2.status, r2.headers["location"]), (200, r.headers["location"]))

    def test_only_return_existing(self):
        r = Client(self.http, BASE).new_account(only_existing=True)
        self.assertEqual((r.status, r.problem), (400, "accountDoesNotExist"))

    def test_contacts(self):
        self.assertEqual(Client(self.http, BASE).new_account(["tel:+1555"]).problem, "unsupportedContact")
        self.assertEqual(Client(self.http, BASE).new_account(["mailto:" + "x" * 300]).problem, "invalidContact")

    def test_update_and_deactivate(self):
        c = self.client()
        r = c.post(c.kid, {"contact": ["mailto:new@lab.test"]})
        self.assertEqual(r.json()["contact"], ["mailto:new@lab.test"])
        other = self.client()
        self.assertEqual((other.post(c.kid, None).status, other.post(c.kid, None).problem), (403, "unauthorized"))
        self.assertEqual(c.post(c.kid, {"status": "deactivated"}).json()["status"], "deactivated")
        r = c.new_order([{"type": "dns", "value": "a.lab.test"}])
        self.assertEqual(r.status, 403)

    def test_admin_deactivation(self):
        c = self.client()
        self.acme.deactivate_account("test", c.kid.rsplit("/", 1)[1])
        self.assertEqual(c.new_order([{"type": "dns", "value": "a.lab.test"}]).status, 403)
        self.assertEqual(Client(self.http, BASE, key=c.key).new_account().status, 403)


class RequestChecks(Base):
    def test_bad_requests(self):
        c = self.client()
        url = f"{BASE}/acme/new-order"
        ids = {"identifiers": [{"type": "dns", "value": "a.lab.test"}]}
        # nonce reuse -> badNonce, and the error carries a fresh nonce to retry with
        n = c.get_nonce()
        self.assertEqual(c.post(url, ids, nonce=n).status, 201)
        r = c.post(url, ids, nonce=n)
        self.assertEqual((r.status, r.problem), (400, "badNonce"))
        self.assertTrue(r.headers["replay-nonce"])
        self.assertEqual(c.post(url, ids, nonce="made-up").problem, "badNonce")
        # wrong url inside the signature, tampered signature, wrong algorithm, wrong content type, junk body
        self.assertEqual(c.post(url, ids, protected_extra={"url": url + "x"}).problem, "malformed")
        self.assertEqual(c.post(url, ids, tamper=True).problem, "malformed")
        r = c.post(url, ids, protected_extra={"alg": "HS256"})
        self.assertEqual((r.problem, r.json()["algorithms"]), ("badSignatureAlgorithm", list(A.JWS_ALGS)))
        self.assertEqual(c.post(url, ids, alg="none", raw=None).problem, "badSignatureAlgorithm")
        self.assertEqual(c.post(url, ids, content_type="application/json").status, 415)
        self.assertEqual(c.post(url, None, raw=b"not json").problem, "malformed")
        self.assertEqual(c.post(url, None, raw=json.dumps({"protected": "x"}).encode()).problem, "malformed")
        # both or neither of jwk/kid; jwk where a kid is required; unknown or foreign kid
        self.assertEqual(c.post(url, ids, kid=False).problem, "malformed")
        self.assertEqual(c.post(url, ids, protected_extra={"jwk": c.jwk}).problem, "malformed")
        stranger = Client(self.http, BASE)
        stranger.kid = f"{BASE}/acme/acct/nope"
        self.assertEqual(stranger.post(url, ids).problem, "accountDoesNotExist")
        stranger.kid = "https://evil.example/acme/acct/x"
        self.assertEqual(stranger.post(url, ids).problem, "malformed")
        # a signature made by a different key than the account's
        impostor = Client(self.http, BASE)
        impostor.kid = c.kid
        self.assertEqual(impostor.post(url, ids).problem, "malformed")
        # kid on new-account is refused
        self.assertEqual(c.post(f"{BASE}/acme/new-account", {}, kid=True).problem, "malformed")

    def test_methods(self):
        self.assertEqual(self.http("POST", f"{BASE}/acme/directory", b"", {}).status, 405)
        self.assertEqual(self.http("GET", f"{BASE}/acme/new-order", None, {}).status, 405)

    def test_weak_account_keys(self):
        c = Client(self.http, BASE, "RS256", key=rsa.generate_private_key(65537, 2048))
        jwk = dict(c.jwk, n=b64e((2 ** 1500 + 1).to_bytes(188, "big")))
        r = c.post(f"{BASE}/acme/new-account", {}, kid=False, protected_extra={"jwk": jwk})
        self.assertEqual(r.problem, "badPublicKey")
        r = c.post(f"{BASE}/acme/new-account", {}, kid=False, protected_extra={"jwk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}})
        self.assertEqual(r.problem, "badPublicKey")


class Policy(Base):
    def order(self, c, ids):
        return c.new_order(ids)

    def test_identifier_rules(self):
        c = self.client()
        dns = lambda v: {"type": "dns", "value": v}   # noqa: E731
        for ids, kind, hint in (
            ([dns("evil.example")], "rejectedIdentifier", "isn't one of the names"),
            ([dns("lab.test.evil.example")], "rejectedIdentifier", "isn't one of the names"),
            ([dns("notlab.test")], "rejectedIdentifier", "isn't one of the names"),
            ([dns("*.lab.test")], "rejectedIdentifier", "Wildcard"),
            ([dns("a.lab.test"), dns("evil.example")], "rejectedIdentifier", "evil.example"),
            ([{"type": "ip", "value": "10.1.1.1"}], "rejectedIdentifier", "isn't one of the names"),
            ([{"type": "ip", "value": "not-an-ip"}], "rejectedIdentifier", ""),
            ([{"type": "dns", "value": "192.168.7.5"}], "rejectedIdentifier", "isn't a DNS name"),
            ([{"type": "email", "value": "a@lab.test"}], "unsupportedIdentifier", ""),
            ([{"type": "dns"}], "unsupportedIdentifier", ""),
            ([], "malformed", ""),
        ):
            r = c.new_order(ids)
            self.assertEqual((r.status, r.problem), (400, kind), ids)
            self.assertIn(hint, r.json()["detail"], ids)
        self.assertEqual(c.new_order([dns(f"h{i}.lab.test") for i in range(21)]).problem, "malformed")

    def test_accepts_names_inside_the_allow_list_and_dedupes(self):
        c = self.client()
        r = c.new_order([{"type": "dns", "value": "A.Lab.Test."}, {"type": "dns", "value": "a.lab.test"},
                         {"type": "dns", "value": "lab.test"}, {"type": "ip", "value": "192.168.7.9"}])
        self.assertEqual(r.status, 201, r.body)
        self.assertEqual([i["value"] for i in r.json()["identifiers"]], ["a.lab.test", "lab.test", "192.168.7.9"])
        self.assertEqual(len(r.json()["authorizations"]), 3)

    def test_orders_are_private_to_their_account(self):
        a, b = self.client(), self.client()
        r = a.new_order([{"type": "dns", "value": "x.lab.test"}])
        order = r.json()
        for url in (r.headers["location"], order["authorizations"][0], order["finalize"]):
            self.assertEqual((b.post(url, None).status, b.post(url, None).problem), (403, "unauthorized"), url)
        self.assertEqual(b.post(a.kid + "/orders", None).status, 403)
        self.assertEqual(a.post(a.kid + "/orders", None).json()["orders"], [r.headers["location"]])

    def test_pending_order_cap(self):
        c = self.client()
        for i in range(50):
            self.assertEqual(c.new_order([{"type": "dns", "value": f"p{i}.lab.test"}]).status, 201)
        r = c.new_order([{"type": "dns", "value": "one-too-many.lab.test"}])
        self.assertEqual((r.status, r.problem), (429, "rateLimited"))

    def test_locked_ca_refuses_politely(self):
        c = self.client()
        real = self.svc.ca.sealed
        self.svc.ca.sealed = lambda: True
        try:
            r = c.new_order([{"type": "dns", "value": "a.lab.test"}])
        finally:
            self.svc.ca.sealed = real
        self.assertEqual((r.status, r.problem), (503, "serverInternal"))
        self.assertIn("locked", r.json()["detail"])


class ConstrainedCA(Base):
    permitted = "lab.test"

    def test_ca_name_limits_still_apply_on_top(self):
        self.configure(domains_raw="lab.test, other.example")
        c = self.client()
        r = c.new_order([{"type": "dns", "value": "x.other.example"}])
        self.assertEqual((r.status, r.problem), (400, "rejectedIdentifier"))
        self.assertIn("limited to", r.json()["detail"])


class Issuing(Base):
    def verify(self, chain_pem: bytes, names: list[str], days=90):
        certs = x509.load_pem_x509_certificates(chain_pem)
        self.assertEqual(len(certs), 2, "leaf + intermediate, no root")
        leaf, inter = certs
        d = Path(tempfile.mkdtemp(dir=self.tmp))
        (d / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (d / "inter.pem").write_bytes(inter.public_bytes(serialization.Encoding.PEM))
        for flag in ("-verify_hostname", "-verify_ip"):
            for n in names:
                if flag == ("-verify_ip" if n[0].isdigit() else "-verify_hostname"):
                    p = subprocess.run(["openssl", "verify", "-CAfile", str(self.root), "-untrusted", str(d / "inter.pem"),
                                        "-purpose", "sslserver", flag, n, str(d / "leaf.pem")], capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        got = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
        self.assertEqual(sorted(got), sorted(names))
        life = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
        self.assertTrue(days <= life <= days + 1, life)
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertEqual([o.dotted_string for o in eku], ["1.3.6.1.5.5.7.3.1"])        # server auth only
        return leaf

    def test_dns_certificate_end_to_end(self):
        self.net.dns["app.lab.test"] = ["192.168.7.20"]
        c = self.client()
        chain, key, order_url = self.get_cert(c, ["app.lab.test"])
        leaf = self.verify(chain, ["app.lab.test"])
        self.assertEqual(self.net.calls[0][0:2], ("192.168.7.20", "app.lab.test"))     # connected to the resolved address, Host set
        self.assertTrue(self.net.calls[0][2].startswith("/.well-known/acme-challenge/"))
        row = self.svc.store.get_cert(f"{leaf.serial_number:X}".rjust(len(f"{leaf.serial_number:X}") + len(f"{leaf.serial_number:X}") % 2, "0"))
        self.assertEqual((row["source"], row["issued_by"].startswith("acme:")), ("acme", True))
        self.assertEqual(c.poll(order_url).json()["status"], "valid")

    def test_ip_and_multiple_names_with_rsa_and_ec_keys(self):
        self.net.dns.update({"a.lab.test": ["192.168.7.21"], "b.lab.test": ["192.168.7.22"]})
        c = self.client("RS256")
        names = ["a.lab.test", "b.lab.test", "192.168.7.30"]
        chain, _, _ = self.get_cert(c, names, key=rsa.generate_private_key(65537, 2048))
        self.verify(chain, names)
        addrs = {call[0] for call in self.net.calls}
        self.assertEqual(addrs, {"192.168.7.21", "192.168.7.22", "192.168.7.30"})

    def test_lifetime_setting(self):
        self.configure(days=30)
        self.net.dns["l.lab.test"] = ["192.168.7.5"]
        chain, _, _ = self.get_cert(self.client(), ["l.lab.test"])
        self.verify(chain, ["l.lab.test"], days=30)
        self.configure()

    def test_failed_validation_leaves_order_invalid(self):
        self.net.dns["f.lab.test"] = ["192.168.7.6"]
        c = self.client()
        r = c.new_order([{"type": "dns", "value": "f.lab.test"}])
        url = r.headers["location"]
        for body, status, hint in ((b"wrong", 200, "expected key authorization"), (b"", 404, "HTTP 404"), (b"", 302, "redirects")):
            self.net.handler = lambda addr, host, path, b=body, s=status: (s, b)
            r = c.new_order([{"type": "dns", "value": "f.lab.test"}])
            url = r.headers["location"]
            order = self.run_challenges(c, url)
            self.assertEqual(order["status"], "invalid")
            self.assertIn(hint, order["error"]["detail"])
            z = c.poll(order["authorizations"][0]).json()
            self.assertEqual((z["status"], z["challenges"][0]["status"]), ("invalid", "invalid"))
            self.assertIn("error", z["challenges"][0])
            fin = c.finalize(order, make_csr(["f.lab.test"])[0])
            self.assertEqual((fin.status, fin.problem), (403, "orderNotReady"))

    def test_connection_problems(self):
        c = self.client()
        r = c.new_order([{"type": "dns", "value": "nodns.lab.test"}])
        order = self.run_challenges(c, r.headers["location"])
        self.assertIn("Couldn't find an address", order["error"]["detail"])

        def refuse(addr, host, path):
            raise ConnectionRefusedError("refused")
        self.net.dns["down.lab.test"] = ["192.168.7.8"]
        self.net.handler = refuse
        order = self.run_challenges(c, c.new_order([{"type": "dns", "value": "down.lab.test"}]).headers["location"])
        self.assertIn("Couldn't connect", order["error"]["detail"])

    def test_poking_a_challenge_twice_validates_once(self):
        self.net.dns["t.lab.test"] = ["192.168.7.9"]
        c = self.client()
        self.serve_challenges(c)
        url = c.new_order([{"type": "dns", "value": "t.lab.test"}]).headers["location"]
        z = c.poll(c.poll(url).json()["authorizations"][0]).json()
        for _ in range(3):
            c.poke(z["challenges"][0]["url"])
        self.wait(c, url, ("ready",))
        self.assertEqual(len([x for x in self.net.calls if x[1] == "t.lab.test"]), 1)

    def test_never_connects_to_addresses_that_cannot_be_hosts(self):
        c = self.client()
        for name, addrs in (("lo.lab.test", ["127.0.0.1"]), ("meta.lab.test", ["169.254.169.254"]), ("v6lo.lab.test", ["::1"]),
                            ("mapped.lab.test", ["::ffff:127.0.0.1"]), ("zero.lab.test", ["0.0.0.0"]), ("mc.lab.test", ["224.0.0.1"])):
            self.net.dns[name] = addrs
            self.net.calls.clear()
            order = self.run_challenges(c, c.new_order([{"type": "dns", "value": name}]).headers["location"])
            self.assertEqual(order["status"], "invalid", name)
            self.assertIn("won't connect", order["error"]["detail"], name)
            self.assertEqual(self.net.calls, [], name)
        # a name with one bad and one good address uses the good one
        self.net.dns["mixed.lab.test"] = ["127.0.0.1", "192.168.7.44"]
        self.serve_challenges(c)
        order = self.run_challenges(c, c.new_order([{"type": "dns", "value": "mixed.lab.test"}]).headers["location"])
        self.assertEqual((order["status"], self.net.calls[-1][0]), ("ready", "192.168.7.44"))

    def test_csr_rules(self):
        self.net.dns.update({"c1.lab.test": ["192.168.7.51"], "c2.lab.test": ["192.168.7.52"]})
        c = self.client()
        self.serve_challenges(c)
        url = c.new_order([{"type": "dns", "value": "c1.lab.test"}, {"type": "dns", "value": "c2.lab.test"}]).headers["location"]
        order = self.run_challenges(c, url)
        self.assertEqual(order["status"], "ready")
        ec_ = ec.generate_private_key(ec.SECP256R1())
        for names, key, kind in ((["c1.lab.test"], ec_, "badCSR"), (["c1.lab.test", "c2.lab.test", "extra.lab.test"], ec_, "badCSR"),
                                 (["c1.lab.test", "c2.lab.test"], ec.generate_private_key(ec.SECP224R1()), "badPublicKey")):
            r = c.finalize(order, make_csr(names, key)[0])
            self.assertEqual((r.status, r.problem), (400, kind), names)
        self.assertEqual(c.finalize(order, b"junk").problem, "badCSR")
        self.assertEqual(c.post(order["finalize"], {}).problem, "malformed")
        # the CSR can ask for whatever it likes; only its names and key are used
        from cryptography import x509 as X
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (X.CertificateSigningRequestBuilder().subject_name(X.Name([X.NameAttribute(NameOID.COMMON_NAME, "c1.lab.test")]))
               .add_extension(X.SubjectAlternativeName([X.DNSName("c1.lab.test"), X.DNSName("c2.lab.test")]), False)
               .add_extension(X.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        r = c.finalize(order, csr.public_bytes(serialization.Encoding.DER))
        self.assertEqual(r.status, 200, r.body)
        cert = x509.load_pem_x509_certificates(c.post(r.json()["certificate"], None).body)[0]
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        # finalizing twice
        self.assertEqual(c.finalize(order, csr.public_bytes(serialization.Encoding.DER)).problem, "orderNotReady")

    def test_interrupted_validations_fail_on_restart(self):
        c = self.client()
        r = c.new_order([{"type": "dns", "value": "r.lab.test"}])
        authz_id = r.json()["authorizations"][0].rsplit("/", 1)[1]
        self.svc.store._x("UPDATE acme_authz SET chall_status='processing' WHERE id=?", (authz_id,))
        A.Acme(self.svc)
        z = c.poll(r.json()["authorizations"][0]).json()
        self.assertEqual(z["status"], "invalid")
        self.assertEqual(c.poll(r.headers["location"]).json()["status"], "invalid")


class Revocation(Base):
    def issue(self, name="rv.lab.test"):
        self.net.dns[name] = ["192.168.7.60"]
        c = self.client()
        chain, key, _ = self.get_cert(c, [name])
        return c, x509.load_pem_x509_certificates(chain)[0], key

    def revoked_serials(self):
        self.svc.refresh_crl(force=True)
        return {r.serial_number for r in self.svc.ca.crl()}

    def test_revoke_with_the_account(self):
        c, cert, _ = self.issue()
        der = cert.public_bytes(serialization.Encoding.DER)
        other = self.client()
        r = other.revoke(der)
        self.assertEqual((r.status, r.problem), (403, "unauthorized"))
        self.assertEqual(c.revoke(der, reason=9).problem, "badRevocationReason")
        self.assertEqual(c.revoke(der, reason=1).status, 200)
        self.assertIn(cert.serial_number, self.revoked_serials())
        row = self.svc.store.get_cert(f"{cert.serial_number:X}".rjust(40, "0")[-len(f"{cert.serial_number:X}") - len(f"{cert.serial_number:X}") % 2:])
        self.assertEqual(row["revoke_reason"], "keyCompromise")
        self.assertEqual(c.revoke(der).problem, "alreadyRevoked")

    def test_revoke_by_signing_with_the_certificate_key(self):
        c, cert, key = self.issue("rk.lab.test")
        holder = Client(self.http, BASE, "ES256", key=key)            # no account at all
        r = holder.revoke(cert.public_bytes(serialization.Encoding.DER), kid=False)
        self.assertEqual(r.status, 200, r.body)
        self.assertIn(cert.serial_number, self.revoked_serials())
        c2, cert2, _ = self.issue("rk2.lab.test")
        stranger = Client(self.http, BASE)
        self.assertEqual(stranger.revoke(cert2.public_bytes(serialization.Encoding.DER), kid=False).status, 403)

    def test_only_acme_certificates_can_be_revoked_this_way(self):
        c = self.client()
        issued = self.svc.ca.sign_csr(x509.load_der_x509_csr(make_csr(["manual.lab.test"])[0]), A.C.parse_names(["manual.lab.test"]), 30, "server")
        self.svc._record(issued.cert, "server", "csr", "admin")
        r = c.revoke(issued.cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual((r.status, r.problem), (404, "malformed"))
        self.assertEqual(c.post(f"{BASE}/acme/revoke-cert", {"certificate": "AAAA"}).problem, "malformed")


class AccountKeys(Base):
    def setUp(self):
        super().setUp()
        self.configure(require_eab=True)

    def tearDown(self):
        self.configure()

    def test_registration_needs_a_valid_unused_key(self):
        self.assertTrue(Client(self.http, BASE).directory()["meta"]["externalAccountRequired"])
        r = Client(self.http, BASE).new_account()
        self.assertEqual((r.status, r.problem), (403, "externalAccountRequired"))

        kid, key = self.acme.new_eab("test", "laptop")
        c = Client(self.http, BASE)
        self.assertEqual(c.new_account(eab=(kid, key)).status, 201)
        # the same key can't register a second account...
        r = Client(self.http, BASE).new_account(eab=(kid, key))
        self.assertEqual((r.status, r.problem), (403, "unauthorized"))
        # ...but the existing account can look itself up again
        self.assertEqual(Client(self.http, BASE, key=c.key).new_account(eab=(kid, key)).status, 200)

    def test_wrong_secrets_and_bindings(self):
        kid, key = self.acme.new_eab("test", "x")
        other_kid, other_key = self.acme.new_eab("test", "y")
        c = Client(self.http, BASE)
        wrong_mac = (kid, other_key)
        self.assertEqual(c.new_account(eab=wrong_mac).json()["detail"], "The account key's signature is wrong.")
        self.assertIn("Unknown", Client(self.http, BASE).new_account(eab=("nope", key)).json()["detail"])
        a, b = Client(self.http, BASE), Client(self.http, BASE)
        binding = a.eab_binding(kid, key)                                   # bound to a's key, presented by b
        r = b.post(f"{BASE}/acme/new-account", {"externalAccountBinding": binding}, kid=False)
        self.assertEqual(r.status, 403)
        r = a.post(f"{BASE}/acme/new-account", {"externalAccountBinding": a.eab_binding(kid, key, url=BASE + "/acme/new-order")}, kid=False)
        self.assertEqual(r.status, 403)
        self.acme.revoke_eab("test", other_kid)
        self.assertIn("revoked", Client(self.http, BASE).new_account(eab=(other_kid, other_key)).json()["detail"])
        self.assertEqual(Client(self.http, BASE).new_account(eab=(kid, key)).status, 201)       # the good key still works

    def test_keys_are_optional_when_not_required(self):
        self.configure(require_eab=False)
        self.assertEqual(Client(self.http, BASE).new_account().status, 201)
        kid, key = self.acme.new_eab("test", "z")
        self.assertEqual(Client(self.http, BASE).new_account(eab=(kid, "AAAA")).status, 403)    # given, so it must be right


class Pieces(unittest.TestCase):
    def test_unsafe_addresses(self):
        for a in ("127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1", "240.0.0.1"):
            self.assertTrue(A.unsafe_address(a), a)
        for a in ("192.168.1.1", "10.0.0.5", "172.16.0.9", "100.64.1.1", "2001:db8::1", "fd00::5", "8.8.8.8"):
            self.assertFalse(A.unsafe_address(a), a)

    def test_rate_gate_and_nonces(self):
        g = A.RateGate(2, 60)
        self.assertEqual([g.allow("a"), g.allow("a"), g.allow("a"), g.allow("b")], [True, True, False, True])
        n = A.Nonces(ttl=60, cap=3)
        first = n.new()
        for _ in range(3):
            n.new()
        self.assertFalse(n.use(first))                    # evicted: the cap keeps memory bounded
        last = n.new()
        self.assertTrue(n.use(last))
        self.assertFalse(n.use(last))                     # single use
        self.assertFalse(A.Nonces(ttl=-1).use(A.Nonces(ttl=-1).new()))

    def test_thumbprint_matches_rfc7638_example(self):
        jwk = {"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
               "e": "AQAB"}
        self.assertEqual(A.jwk_thumbprint(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_http_fetch_never_follows_redirects_and_caps_the_body(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/redir"):
                    self.send_response(302); self.send_header("Location", "http://169.254.169.254/"); self.end_headers()
                else:
                    self.send_response(200); self.end_headers(); self.wfile.write(b"x" * 100000)

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        self.assertEqual(A.http_fetch("127.0.0.1", "h", "/redir", port=port)[0], 302)
        status, body = A.http_fetch("127.0.0.1", "h", "/big", port=port)
        self.assertEqual((status, len(body)), (200, 2049))


if __name__ == "__main__":
    unittest.main()
