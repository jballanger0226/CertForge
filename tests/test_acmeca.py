"""The ACME issuing CA: the authority on its own, then the whole flow through the ACME protocol."""
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import ca as C
from app.acmeca import AcmeAuthority
from app.config import Config
from app.service import Service
from app.store import Store
from tests import test_acme as T

MAIN_PASS = "main-ca-passphrase-123"
ACME_PASS = "acme-issuing-passphrase-456"
ROOT_PASS = "acme-root-passphrase-789"


def mini_ca(tmp: Path, permitted: str = "") -> C.CertAuthority:
    ca = C.CertAuthority(tmp)
    ca.create(org="Unit Lab", key_type="ec-p384", passphrase=MAIN_PASS, root_years=10, int_years=5, permitted=permitted,
              public_host="ca.lab.test")
    return ca


def names(*n) -> C.Names:
    return C.parse_names(list(n))


def csr_for(*n):
    from tests.acme_client import make_csr
    der, key = make_csr(list(n))
    return x509.load_der_x509_csr(der), key


def openssl_verify(root_pem: bytes, chain: list[x509.Certificate], leaf: x509.Certificate, host: str) -> subprocess.CompletedProcess:
    d = Path(tempfile.mkdtemp(prefix="cf-verify-"))
    try:
        (d / "root.pem").write_bytes(root_pem)
        (d / "mid.pem").write_bytes(C.chain_pem(chain))
        (d / "leaf.pem").write_bytes(C.pem(leaf))
        return subprocess.run(["openssl", "verify", "-CAfile", str(d / "root.pem"), "-untrusted", str(d / "mid.pem"),
                               "-purpose", "sslserver", "-verify_hostname", host, str(d / "leaf.pem")],
                              capture_output=True, text=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class UnderMain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="cf-acmeca-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.main = mini_ca(cls.tmp)
        cls.ac = AcmeAuthority(cls.tmp)
        cls.ac.create_under_main(cls.main, main_passphrase=MAIN_PASS, root_key_pem=None, passphrase=ACME_PASS,
                                 key_type="ec-p384", years=3, permitted="lab.test 192.168.7.0/24", hold="secret")

    def test_it_is_a_constrained_issuing_ca_under_the_main_root(self):
        ac = self.ac
        ac.issuing.verify_directly_issued_by(self.main.root)
        self.assertEqual(ac.root.fingerprint(C.hashes.SHA256()), self.main.root.fingerprint(C.hashes.SHA256()))
        bc = ac.issuing.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc.value.ca)
        self.assertEqual(bc.value.path_length, 0)
        self.assertEqual(C.describe_cert(ac.issuing)["subject"], "Unit Lab ACME Issuing CA")
        self.assertEqual(sorted(C.describe_cert(ac.issuing)["permitted"]), ["192.168.7.0/24", "lab.test"])
        self.assertNotEqual(C.fingerprint(ac.issuing), C.fingerprint(self.main.intermediate))

    def test_the_key_is_encrypted_at_rest_and_needs_unlocking_after_a_restart(self):
        self.assertIn(b"ENCRYPTED PRIVATE KEY", (self.ac.dir / "issuing.key").read_bytes())
        fresh = AcmeAuthority(self.tmp)
        fresh.load()
        self.assertTrue(fresh.sealed())
        with self.assertRaises(C.CASealed):
            fresh.sign_csr(csr_for("a.lab.test")[0], names("a.lab.test"), 30, "server", "ca.lab.test")
        with self.assertRaisesRegex(C.CAError, "didn't unlock"):
            fresh.unlock("not the passphrase at all")
        self.assertTrue(fresh.sealed())
        fresh.unlock(ACME_PASS)
        self.assertFalse(fresh.sealed())
        fresh.lock_now()
        self.assertTrue(fresh.sealed())

    def test_leaf_certificates_chain_to_the_main_root_and_point_at_the_acme_downloads(self):
        csr, _ = csr_for("web.lab.test", "192.168.7.20")
        issued = self.ac.sign_csr(csr, names("web.lab.test", "192.168.7.20"), 60, "server", "ca.lab.test")
        leaf = issued.cert
        r = openssl_verify(C.pem(self.main.root), [self.ac.issuing], leaf, "web.lab.test")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value[0].access_location.value
        crl = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value
        self.assertEqual((aia, crl), ("http://ca.lab.test/pki/acme-intermediate.cer", "http://ca.lab.test/pki/acme-intermediate.crl"))

    def test_the_issuing_cas_own_limits_apply(self):
        csr, _ = csr_for("evil.example.com")
        with self.assertRaisesRegex(C.CAError, "outside the domains"):
            self.ac.sign_csr(csr, names("evil.example.com"), 30, "server", None)
        with self.assertRaisesRegex(C.CAError, "outside the IP ranges"):
            self.ac.sign_csr(csr, names("10.9.9.9"), 30, "server", None)

    def test_a_revocation_list_of_its_own(self):
        csr, _ = csr_for("gone.lab.test")
        leaf = self.ac.sign_csr(csr, names("gone.lab.test"), 30, "server", None).cert
        crl = self.ac.make_crl([(leaf.serial_number, C._now(), "keyCompromise")])
        self.assertTrue(crl.is_signature_valid(self.ac.issuing.public_key()))
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(leaf.serial_number))
        self.assertEqual(self.ac.crl().issuer, self.ac.issuing.subject)
        self.assertEqual(self.ac.meta["crl_number"], 1)

    def test_renewal_keeps_the_same_key_and_name(self):
        before, serial = self.ac.issuing, self.ac.issuing.serial_number
        new = self.ac.renew(self.main.load_root_key(MAIN_PASS), 5)
        self.assertEqual(C.describe_cert(new)["subject"], C.describe_cert(before)["subject"])
        self.assertEqual(new.public_key().public_numbers(), before.public_key().public_numbers())
        self.assertNotEqual(new.serial_number, serial)
        self.assertGreater(new.not_valid_after_utc, before.not_valid_after_utc)
        self.assertTrue(list((self.ac.dir / "archive").glob("issuing-*.crt")))
        self.assertEqual(sorted(C.describe_cert(new)["permitted"]), ["192.168.7.0/24", "lab.test"])


class UnderMainRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="cf-acmeca-rules-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.main = mini_ca(cls.tmp, permitted="lab.test")
        cls.root_backup = (cls.main.dir / "root.key").read_bytes()

    def fresh(self) -> AcmeAuthority:
        d = Path(tempfile.mkdtemp(prefix="cf-acmeca-x-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return AcmeAuthority(d)

    def make(self, ac, **over):
        args = dict(main_passphrase=MAIN_PASS, root_key_pem=self.root_backup, passphrase=ACME_PASS, key_type="ec-p384",
                    years=3, permitted="", hold="secret")
        args.update(over)
        ac.create_under_main(self.main, **args)

    def test_blank_limits_inherit_the_main_cas(self):
        ac = self.fresh()
        self.make(ac)
        self.assertEqual(ac.meta["permitted_dns"], ["lab.test"])

    def test_refuses_the_same_passphrase_as_the_main_ca(self):
        with self.assertRaisesRegex(C.CAError, "different passphrase"):
            self.make(self.fresh(), passphrase=MAIN_PASS)

    def test_needs_the_right_main_passphrase_and_a_root_key(self):
        with self.assertRaisesRegex(C.CAError, "didn't unlock"):
            self.make(self.fresh(), main_passphrase="wrong-passphrase-here")
        self.main.remove_root_key()
        with self.assertRaisesRegex(C.CAError, "root key isn't on this server"):
            self.make(self.fresh(), root_key_pem=None)

    def test_bad_input(self):
        for over, why in ((dict(passphrase="short"), "at least"), (dict(hold="never"), "how the issuing key"),
                          (dict(key_type="ec-p256"), "P-384 or RSA 4096"), (dict(years=0), "lifetime"), (dict(years=40), "lifetime")):
            with self.assertRaisesRegex(C.CAError, why, msg=str(over)):
                self.make(self.fresh(), **over)

    def test_only_one_at_a_time_and_retiring_keeps_everything(self):
        ac = self.fresh()
        self.make(ac)
        with self.assertRaisesRegex(C.CAError, "already exists"):
            self.make(ac)
        dest = ac.retire()
        self.assertFalse(ac.loaded())
        self.assertTrue((dest / "issuing.key").exists() and (dest / "issuing.crt").exists())
        self.make(ac)                              # and a new one can follow
        self.assertTrue(ac.loaded())


class OwnRoot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="cf-acmeca-own-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.main = mini_ca(cls.tmp)
        cls.ac = AcmeAuthority(cls.tmp)
        cls.blob = cls.ac.create_own_root(org="Edge Lab", key_type="ec-p384", root_passphrase=ROOT_PASS, passphrase=ACME_PASS,
                                          root_years=15, years=4, permitted="edge.test", hold="manual", keep_root_key=False)

    def test_a_separate_root_with_its_own_name_and_no_link_to_the_main_ca(self):
        ac = self.ac
        ac.root.verify_directly_issued_by(ac.root)                         # self-signed
        ac.issuing.verify_directly_issued_by(ac.root)
        self.assertEqual(C.describe_cert(ac.root)["subject"], "Edge Lab ACME Root CA")
        self.assertEqual(C.describe_cert(ac.issuing)["subject"], "Edge Lab ACME Issuing CA")
        self.assertNotEqual(C.fingerprint(ac.root), C.fingerprint(self.main.root))
        with self.assertRaises(Exception):
            ac.issuing.verify_directly_issued_by(self.main.root)
        self.assertEqual(ac.mode, "own-root")

    def test_the_root_key_is_not_kept_on_the_server_unless_asked(self):
        self.assertFalse(self.ac.root_key_present())
        self.assertFalse((self.ac.dir / "root.key").exists())
        self.assertIn(b"ENCRYPTED PRIVATE KEY", self.blob)
        key = C.load_encrypted_key(self.blob, ROOT_PASS)                   # the backup is what proves the passphrase
        self.assertTrue(C.same_key(key, self.ac.root))
        with self.assertRaises(C.CAError):
            C.load_encrypted_key(self.blob, "not the root passphrase")

    def test_leaf_certificates_verify_against_the_new_root_only(self):
        csr, _ = csr_for("edge1.edge.test")
        leaf = self.ac.sign_csr(csr, names("edge1.edge.test"), 30, "server", "edge.lab.test").cert
        ok = openssl_verify(C.pem(self.ac.root), [self.ac.issuing], leaf, "edge1.edge.test")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        bad = openssl_verify(C.pem(self.main.root), [self.ac.issuing], leaf, "edge1.edge.test")
        self.assertNotEqual(bad.returncode, 0)

    def test_does_not_inherit_the_main_cas_limits_and_applies_its_own(self):
        self.assertEqual(self.ac.meta["permitted_dns"], ["edge.test"])
        with self.assertRaisesRegex(C.CAError, "outside the domains"):
            self.ac.sign_csr(csr_for("x.other.test")[0], names("x.other.test"), 30, "server", None)

    def test_renewal_needs_the_root_key_backup(self):
        with self.assertRaisesRegex(C.CAError, "isn't on this server"):
            self.ac.load_root_key(ROOT_PASS)
        with self.assertRaisesRegex(C.CAError, "didn't unlock"):
            self.ac.load_root_key("wrong wrong wrong wrong", self.blob)
        other = C.encrypt_key(C.generate_key("ec-p384"), ROOT_PASS)
        with self.assertRaisesRegex(C.CAError, "isn't the key for this"):
            self.ac.load_root_key(ROOT_PASS, other)
        before = self.ac.issuing
        new = self.ac.renew(self.ac.load_root_key(ROOT_PASS, self.blob), 6)
        self.assertGreater(new.not_valid_after_utc, before.not_valid_after_utc)
        new.verify_directly_issued_by(self.ac.root)

    def test_rules(self):
        d = Path(tempfile.mkdtemp(prefix="cf-acmeca-own2-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ac = AcmeAuthority(d)
        base = dict(org="Rules Lab", key_type="ec-p384", root_passphrase=ROOT_PASS, passphrase=ACME_PASS, root_years=15,
                    years=4, permitted="", hold="secret", keep_root_key=False)
        for over, why in ((dict(passphrase=ROOT_PASS), "different passphrase"), (dict(org="!!"), "CA name"),
                          (dict(root_years=3), "Pick a root lifetime"), (dict(years=8, root_years=6), "Pick a root lifetime"),
                          (dict(root_passphrase="short"), "at least")):
            with self.assertRaisesRegex(C.CAError, why, msg=str(over)):
                ac.create_own_root(**{**base, **over})
        self.assertFalse(ac.initialized())
        ac.create_own_root(**{**base, "keep_root_key": True})
        self.assertTrue(ac.root_key_present())
        ac.mark_root_key_exported()
        ac.remove_root_key()
        self.assertFalse(ac.root_key_present())

    def test_limits_report(self):
        self.assertEqual(self.ac.covers(["edge.test", "a.edge.test", "other.test"], []), ["other.test"])
        self.assertEqual(self.ac.covers(["edge.test"], ["10.0.0.0/8"]), [])       # only DNS names are limited here


class Migration(unittest.TestCase):
    def test_old_databases_gain_the_issuer_column(self):
        d = Path(tempfile.mkdtemp(prefix="cf-mig-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        db = d / "old.db"
        c = sqlite3.connect(db)
        c.executescript("""CREATE TABLE certs(serial TEXT PRIMARY KEY, cn TEXT NOT NULL, sans TEXT NOT NULL, purpose TEXT NOT NULL,
            key_desc TEXT NOT NULL, source TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL, issued_at TEXT NOT NULL,
            issued_by TEXT NOT NULL, sha256 TEXT NOT NULL, pem TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT);
            INSERT INTO certs VALUES('AA','old','[]','server','k','csr','2020-01-01T00:00:00Z','2030-01-01T00:00:00Z',
            '2020-01-01T00:00:00Z','admin','x','p','2021-01-01T00:00:00Z','unspecified');""")
        c.commit()
        c.close()
        store = Store(db)
        self.assertEqual(store.get_cert("AA")["issuer"], "main")
        self.assertEqual([r[0] for r in store.revoked()], [0xAA])
        self.assertEqual(store.revoked("acme"), [])
        Store(db)                                                           # opening it again is harmless


# ---- through the protocol ------------------------------------------------------------------------------
class Flow(T.Base):
    """ACME clients against a service with a dedicated ACME CA. Every class makes its own service."""
    mode = "under-main"
    hold = "secret"

    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.svc = T.make_service()
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        cls.acme = cls.svc.acme
        cls.token = cls.svc.acme_ca_create(
            "test", "owner", mode=cls.mode, passphrase=ACME_PASS, passphrase2=ACME_PASS, hold=cls.hold, years=3,
            permitted="lab.test 192.168.7.0/24", main_passphrase=T.PASS, org="Flow Lab", root_passphrase=ROOT_PASS,
            keep_root_key=False)
        cls.root = cls.tmp / "acme-ca" / "root.crt"

    def setUp(self):
        super().setUp()
        self.acme.resolve = lambda name: ["192.168.7.20"]          # every name the tests use lives on the lab network

    def verify(self, chain_pem: bytes, host: str):
        certs = x509.load_pem_x509_certificates(chain_pem)
        r = openssl_verify(self.root.read_bytes(), certs[1:], certs[0], host)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return certs

    def test_certificates_come_from_the_acme_ca_and_the_main_ca_is_not_needed(self):
        key, self.svc.ca._key = self.svc.ca._key, None         # seal the main CA: ACME carries on regardless
        try:
            self.assertTrue(self.svc.ca.sealed())
            c = self.client()
            chain, _, _ = self.get_cert(c, ["web.lab.test"])
        finally:
            self.svc.ca._key = key
        leaf, issuing = self.verify(chain, "web.lab.test")
        self.assertEqual(len(x509.load_pem_x509_certificates(chain)), 2)    # the leaf and the issuing CA; clients hold the root
        self.assertEqual(issuing.fingerprint(C.hashes.SHA256()), self.svc.acme_ca.issuing.fingerprint(C.hashes.SHA256()))
        row = self.svc.store.get_cert(C.serial_hex(leaf.serial_number))
        self.assertEqual((row["issuer"], row["source"]), ("acme", "acme"))
        self.assertEqual(C.describe_cert(leaf)["issuer"], self.svc.acme_ca.meta["org"] + " ACME Issuing CA")

    def test_a_locked_acme_ca_refuses_even_though_the_main_ca_is_open(self):
        self.svc.acme_ca.lock_now()
        try:
            c = self.client()
            r = c.new_order([{"type": "dns", "value": "locked.lab.test"}])
            self.assertEqual(r.status, 503, r.body)
        finally:
            self.svc.acme_ca_unlock("test", ACME_PASS)
        self.assertEqual(self.client().new_order([{"type": "dns", "value": "open.lab.test"}]).status, 201)

    def test_the_cas_own_limits_refuse_names_the_settings_allow(self):
        self.configure(domains_raw="lab.test other.example")
        try:
            r = self.client().new_order([{"type": "dns", "value": "x.other.example"}])
            self.assertEqual((r.status, r.problem), (400, "rejectedIdentifier"))
            self.assertIn("outside the domains", r.json()["detail"])
            self.assertEqual(self.svc.acme_ca_summary()["uncovered"], ["other.example"])
            self.assertTrue(any("other.example" in a["text"] for a in self.svc.alerts()))
        finally:
            self.configure()

    def test_revocation_goes_on_the_acme_crl_and_not_the_main_one(self):
        c = self.client()
        chain, key, _ = self.get_cert(c, ["revoke-me.lab.test"])
        leaf = x509.load_pem_x509_certificates(chain)[0]
        r = c.revoke(leaf.public_bytes(serialization.Encoding.DER), reason=1)
        self.assertEqual(r.status, 200, r.body)
        self.svc.refresh_crl()
        acme_crl = self.svc.acme_ca.crl()
        self.assertIsNotNone(acme_crl.get_revoked_certificate_by_serial_number(leaf.serial_number))
        self.assertTrue(acme_crl.is_signature_valid(self.svc.acme_ca.issuing.public_key()))
        self.assertIsNone(self.svc.ca.crl().get_revoked_certificate_by_serial_number(leaf.serial_number))
        self.assertEqual([s for s, *_ in self.svc.store.revoked("main")], [])
        # and it is served where the certificate says to look
        data, mime, _ = self.svc.pki("acme-intermediate.crl")
        self.assertEqual(mime, "application/pkix-crl")
        self.assertIsNotNone(x509.load_der_x509_crl(data).get_revoked_certificate_by_serial_number(leaf.serial_number))

    def test_trust_downloads(self):
        pki = self.svc.pki
        self.assertEqual(x509.load_pem_x509_certificate(pki("acme-root.crt")[0]).fingerprint(C.hashes.SHA256()),
                         self.svc.acme_ca.root.fingerprint(C.hashes.SHA256()))
        self.assertEqual(len(x509.load_pem_x509_certificates(pki("acme-chain.pem")[0])), 2)
        self.assertEqual(x509.load_der_x509_certificate(pki("acme-intermediate.cer")[0]).subject, self.svc.acme_ca.issuing.subject)
        self.assertIn(b"com.apple.security.root", pki("acme-root.mobileconfig")[0])
        self.assertIsNotNone(pki("root.crt"))                  # the main CA's downloads are unaffected
        self.assertIsNone(pki("acme-nonsense.crt"))

    def test_downloads_for_an_acme_certificate_use_its_own_chain(self):
        c = self.client()
        chain, _, _ = self.get_cert(c, ["dl.lab.test"])
        row = self.svc.store.get_cert(C.serial_hex(x509.load_pem_x509_certificates(chain)[0].serial_number))
        files = self.svc.cert_files(row)
        full = x509.load_pem_x509_certificates(files["fullchain"][2])
        self.assertEqual(full[1].subject, self.svc.acme_ca.issuing.subject)

    def test_retiring_turns_acme_off_instead_of_falling_back_quietly(self):
        # a throwaway service so the shared one keeps its CA
        tmp, svc = T.make_service()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        svc.acme_ca_create("t", "o", mode="under-main", passphrase=ACME_PASS, main_passphrase=T.PASS, hold="secret")
        svc.acme.save_settings("t", enabled=True, domains_raw="lab.test", networks_raw="", days=90, require_eab=False)
        svc.acme_ca_retire("t")
        self.assertFalse(svc.acme_ca.loaded())
        self.assertFalse(svc.acme.settings().enabled)
        self.assertEqual(svc.acme_issuer()[0], "main")
        self.assertTrue(list((tmp / "acme-ca-retired").iterdir()))


class FlowOwnRoot(Flow):
    mode = "own-root"
    hold = "manual"

    def test_the_root_key_backup_downloads_once_for_the_right_person(self):
        self.assertIsNone(self.svc.acme_ca_root_download("someone else", self.token))
        blob, name = self.svc.acme_ca_root_download("owner", self.token)
        self.assertTrue(name.endswith("acme-root-ca.key.enc"))
        self.assertTrue(C.same_key(C.load_encrypted_key(blob, ROOT_PASS), self.svc.acme_ca.root))
        self.assertIsNone(self.svc.acme_ca_root_download("owner", self.token))             # gone after one download
        self.assertTrue(self.svc.acme_ca.meta["root_key_exported"])
        self.assertFalse(self.svc.acme_ca.root_key_present())

    def test_the_new_root_is_not_the_main_root(self):
        self.assertNotEqual(self.svc.acme_ca.root.fingerprint(C.hashes.SHA256()), self.svc.ca.root.fingerprint(C.hashes.SHA256()))
        self.assertEqual(C.describe_cert(self.svc.acme_ca.root)["subject"], "Flow Lab ACME Root CA")


class StartUp(unittest.TestCase):
    """Unlocking from a secret at start, and creating the ACME CA from the environment."""

    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.svc = T.make_service()
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)

    def restart(self, **cfg) -> Service:
        base = Config(data=self.tmp, bind="127.0.0.1", https_port=8443, http_port=0, hostnames="", setup_token=None, **cfg)
        return Service(base)

    def test_secret_hold_unlocks_at_start_with_the_right_secret_only(self):
        self.svc.acme_ca_create("t", "o", mode="under-main", passphrase=ACME_PASS, main_passphrase=T.PASS, hold="secret")
        self.addCleanup(self.svc.acme_ca_retire, "t")
        self.assertTrue(self.restart().acme_ca.sealed())                                     # no secret: locked
        self.assertTrue(self.restart(acme_ca_passphrase="a-wrong-secret-here").acme_ca.sealed())
        self.assertFalse(self.restart(acme_ca_passphrase=ACME_PASS).acme_ca.sealed())

    def test_manual_hold_ignores_the_secret(self):
        tmp, other = T.make_service()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        other.acme_ca_create("t", "o", mode="under-main", passphrase=ACME_PASS, main_passphrase=T.PASS, hold="manual")
        again = Service(Config(data=tmp, bind="127.0.0.1", https_port=8443, http_port=0, hostnames="", setup_token=None,
                               acme_ca_passphrase=ACME_PASS))
        self.assertTrue(again.acme_ca.sealed())
        again.acme_ca_unlock("t", ACME_PASS)
        self.assertFalse(again.acme_ca.sealed())

    def test_environment_settings(self):
        env = {"CERTFORGE_ADMIN_PASSWORD": T.ADMIN, "CERTFORGE_CA_PASSPHRASE": T.PASS, "CERTFORGE_ORG": "Env Lab",
               "CERTFORGE_PUBLIC_HOST": "ca.lab.test", "CERTFORGE_HOSTNAMES": "ca.lab.test",
               "CERTFORGE_ACME_CA": "root", "CERTFORGE_ACME_CA_PASSPHRASE": ACME_PASS,
               "CERTFORGE_ACME_ROOT_PASSPHRASE": ROOT_PASS, "CERTFORGE_ACME_DOMAINS": "lab.test",
               "CERTFORGE_ACME_CA_PERMITTED": "lab.test", "CERTFORGE_ACME_CA_YEARS": "2"}
        d = Path(tempfile.mkdtemp(prefix="cf-env-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        cfg = Config.from_env({**env, "CERTFORGE_DATA": str(d), "CERTFORGE_HTTP_PORT": "0", "CERTFORGE_HTTPS_PORT": "8443"})
        svc = Service(cfg)
        self.assertTrue(svc.auto_setup())
        self.assertTrue(svc.auto_acme_ca())
        self.assertFalse(svc.auto_acme_ca())                                                 # once only
        ac = svc.acme_ca
        self.assertEqual((ac.mode, ac.hold, ac.sealed()), ("own-root", "secret", False))
        self.assertTrue(ac.root_key_present())                                               # nobody was there to download it
        self.assertEqual(svc.root_backups._items, {})
        self.assertEqual(C.describe_cert(ac.root)["subject"], "Env Lab ACME Root CA")
        self.assertEqual(Service(cfg).acme_ca.sealed(), False)                               # and a restart unlocks it from the secret

    def test_environment_mistakes_fail_loudly(self):
        for env, why in (({"CERTFORGE_ACME_CA": "sideways"}, "must be"),
                         ({"CERTFORGE_ACME_CA": "intermediate", "CERTFORGE_ACME_CA_HOLD": "maybe"}, "HOLD")):
            with self.assertRaises(SystemExit, msg=str(env)) as cm:
                Config.from_env(env)
            self.assertIn(why, str(cm.exception))
        self.assertIsNone(Config.from_env({"CERTFORGE_ACME_CA": "off"}).acme_ca_auto)

    def test_missing_pieces_are_named_when_the_ca_is_to_be_created(self):
        main = {"CERTFORGE_ADMIN_PASSWORD": T.ADMIN, "CERTFORGE_CA_PASSPHRASE": T.PASS, "CERTFORGE_ORG": "Env Lab",
                "CERTFORGE_PUBLIC_HOST": "ca.lab.test", "CERTFORGE_HOSTNAMES": "ca.lab.test"}
        for extra, why in (({"CERTFORGE_ACME_CA": "intermediate"}, "ACME_CA_PASSPHRASE"),
                           ({"CERTFORGE_ACME_CA": "root", "CERTFORGE_ACME_CA_PASSPHRASE": ACME_PASS}, "ACME_ROOT_PASSPHRASE")):
            d = Path(tempfile.mkdtemp(prefix="cf-env2-"))
            self.addCleanup(shutil.rmtree, d, ignore_errors=True)
            svc = Service(Config.from_env({**main, **extra, "CERTFORGE_DATA": str(d)}))
            svc.auto_setup()
            with self.assertRaisesRegex(C.CAError, why):
                svc.auto_acme_ca()
            self.assertFalse(svc.acme_ca.initialized())

    def test_once_it_exists_the_main_passphrase_is_not_needed_again(self):
        main = {"CERTFORGE_ADMIN_PASSWORD": T.ADMIN, "CERTFORGE_CA_PASSPHRASE": T.PASS, "CERTFORGE_ORG": "Env Lab",
                "CERTFORGE_PUBLIC_HOST": "ca.lab.test", "CERTFORGE_HOSTNAMES": "ca.lab.test"}
        acme = {"CERTFORGE_ACME_CA": "intermediate", "CERTFORGE_ACME_CA_PASSPHRASE": ACME_PASS}
        d = Path(tempfile.mkdtemp(prefix="cf-env3-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        svc = Service(Config.from_env({**main, **acme, "CERTFORGE_DATA": str(d)}))
        svc.auto_setup()
        self.assertTrue(svc.auto_acme_ca())
        later = Service(Config.from_env({**acme, "CERTFORGE_DATA": str(d)}))        # the admin and CA passphrases are gone
        self.assertFalse(later.auto_acme_ca())
        self.assertFalse(later.acme_ca.sealed())


if __name__ == "__main__":
    unittest.main()
