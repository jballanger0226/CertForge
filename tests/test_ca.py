"""CA engine tests. The OpenSSL command line is the independent judge: if `openssl verify`
accepts (or rejects) what we built, that's the ground truth, not our own code.

Run:  python -m unittest tests.test_ca -v      (from the project root)
"""
import datetime as dt
import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
import io
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import ca as C

PASS = "correct horse battery staple"


def sh(*args, input=None, check=True):
    p = subprocess.run(args, input=input, capture_output=True)
    if check and p.returncode != 0:
        raise AssertionError(f"{' '.join(args)}\n{p.stdout.decode()}\n{p.stderr.decode()}")
    return p


class Base(unittest.TestCase):
    ca: C.CertAuthority
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def make_ca(cls, **kw):
        cls.tmp = tempfile.TemporaryDirectory()
        os.umask(0o077)
        cls.ca = C.CertAuthority(cls.tmp.name)
        args = dict(org="Test Lab", key_type="ec-p384", passphrase=PASS, public_host="ca.lab.test")
        args.update(kw)
        cls.ca.create(**args)
        cls.root_path = cls.ca.dir / "root.crt"
        cls.int_path = cls.ca.dir / "intermediate.crt"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def write(self, name, data):
        p = Path(self.tmp.name) / name
        p.write_bytes(data)
        return str(p)

    def verify(self, cert, *extra, check=True):
        leaf = self.write("leaf.pem", C.pem(cert))
        return sh("openssl", "verify", "-CAfile", str(self.root_path), "-untrusted", str(self.int_path),
                  *extra, leaf, check=check)


class TestSerialFormat(unittest.TestCase):
    def test_whole_bytes_uppercase(self):
        for n, want in ((0x7F, "7F"), (0x80, "80"), (0x123, "0123"), (0xABC, "0ABC"), (0xFF00, "FF00")):
            self.assertEqual(C.serial_hex(n), want, hex(n))

    def test_matches_what_openssl_prints(self):
        """Ground truth is OpenSSL's own `x509 -text`, which shows the serial's magnitude bytes
        (no DER padding byte), including for serials whose first byte has the top bit set."""
        import re
        with tempfile.TemporaryDirectory() as d:
            ca = C.CertAuthority(d)
            ca.create(org="Serials", key_type="ec-p384", passphrase=PASS)
            for _ in range(300):
                cert = ca.issue_generated(C.parse_names("s.test"), 1, "server", "ec-p256").cert
                p = Path(d) / "c.pem"; p.write_bytes(C.pem(cert))
                text = sh("openssl", "x509", "-in", str(p), "-noout", "-text").stdout.decode()
                shown = re.search(r"Serial Number:\s*([0-9a-fA-F:\s]+?)\n\s*Signature Algorithm", text, re.S).group(1)
                self.assertEqual(C.serial_hex(cert.serial_number), re.sub(r"[^0-9a-fA-F]", "", shown).upper())


class TestNames(unittest.TestCase):
    def test_mixed(self):
        n = C.parse_names("Web.Example.LAN, *.apps.example.lan\n10.0.0.5  ::1 [fd00::1]. web.example.lan")
        self.assertEqual(n.dns, ["web.example.lan", "*.apps.example.lan"])
        self.assertEqual(n.ips, ["10.0.0.5", "::1", "fd00::1"])
        self.assertEqual(n.cn(), "web.example.lan")

    def test_idna(self):
        self.assertEqual(C.parse_names("bücher.lan").dns, ["xn--bcher-kva.lan"])

    def test_single_label_ok(self):
        self.assertEqual(C.parse_names("nas").dns, ["nas"])

    def test_rejects(self):
        for bad in ["", "   ", "foo_bar.lan", "a*.lan", "*", "foo..lan", "-x.lan", "exa mple".replace(" ", "!")]:
            with self.assertRaises(C.CAError, msg=bad):
                C.parse_names(bad)

    def test_too_many(self):
        with self.assertRaises(C.CAError):
            C.parse_names(" ".join(f"h{i}.lan" for i in range(101)))

    def test_constraints_parse(self):
        self.assertEqual(C.parse_constraints("Home.arpa, .lan *.corp.example 10.0.0.0/8"),
                         (["home.arpa", "lan", "corp.example"], ["10.0.0.0/8"]))
        with self.assertRaises(C.CAError):
            C.parse_constraints("10.0.0.5/8")  # host bits set


class TestIssuing(Base):
    @classmethod
    def setUpClass(cls):
        cls.make_ca(permitted="lab.test, 10.0.0.0/8")

    def test_file_permissions(self):
        d = self.ca.dir
        self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
        for f in ("root.key", "intermediate.key"):
            self.assertEqual(stat.S_IMODE((d / f).stat().st_mode), 0o600, f)

    def test_root_key_is_strongly_encrypted_standard_pkcs8(self):
        p = str(self.ca.dir / "root.key")
        sh("openssl", "pkey", "-in", p, "-passin", f"pass:{PASS}", "-noout")
        r = sh("openssl", "pkey", "-in", p, "-passin", "pass:wrong wrong wrong", "-noout", check=False)
        self.assertNotEqual(r.returncode, 0)
        asn = sh("openssl", "asn1parse", "-in", p).stdout.decode()
        self.assertIn("PBES2", asn)
        self.assertIn("0927C0", asn)  # 600,000 iterations

    def test_ca_certs_are_correct(self):
        r = sh("openssl", "x509", "-in", str(self.root_path), "-noout", "-text").stdout.decode()
        self.assertIn("pathlen:1", r)
        self.assertIn("Certificate Sign, CRL Sign", r)
        i = sh("openssl", "x509", "-in", str(self.int_path), "-noout", "-text").stdout.decode()
        self.assertIn("pathlen:0", i)
        self.assertIn("Name Constraints: critical", i)
        self.assertIn("DNS:lab.test", i)
        self.assertIn("IP:10.0.0.0/255.0.0.0", i)

    def test_generated_ec_cert_verifies_strictly(self):
        names = C.parse_names("app.lab.test, 10.1.2.3")
        iss = self.ca.issue_generated(names, 365, "both", "ec-p256")
        self.assertIsNotNone(iss.key)
        self.verify(iss.cert, "-x509_strict", "-purpose", "sslserver", "-verify_hostname", "app.lab.test",
                    "-verify_ip", "10.1.2.3")
        self.verify(iss.cert, "-purpose", "sslclient")
        txt = sh("openssl", "x509", "-in", self.write("l.pem", C.pem(iss.cert)), "-noout", "-text").stdout.decode()
        for want in ("CA:FALSE", "TLS Web Server Authentication", "TLS Web Client Authentication",
                     "DNS:app.lab.test", "IP Address:10.1.2.3", "http://ca.lab.test/pki/intermediate.cer",
                     "http://ca.lab.test/pki/intermediate.crl", "Digital Signature"):
            self.assertIn(want, txt)
        self.assertNotIn("Key Encipherment", txt)  # EC keys don't use it

    def test_generated_rsa_cert_has_key_encipherment(self):
        iss = self.ca.issue_generated(C.parse_names("rsa.lab.test"), 90, "server", "rsa-2048")
        self.verify(iss.cert, "-x509_strict", "-purpose", "sslserver")
        txt = sh("openssl", "x509", "-in", self.write("l.pem", C.pem(iss.cert)), "-noout", "-text").stdout.decode()
        self.assertIn("Key Encipherment", txt)
        self.assertNotIn("TLS Web Client Authentication", txt)

    def test_server_only_cert_fails_client_purpose(self):
        iss = self.ca.issue_generated(C.parse_names("s.lab.test"), 30, "server", "ec-p256")
        self.verify(iss.cert, "-purpose", "sslserver")
        self.assertNotEqual(self.verify(iss.cert, "-purpose", "sslclient", check=False).returncode, 0)

    def test_policy_rejects_out_of_scope(self):
        for bad in ("evil.com", "x.lab.test.evil.com", "notlab.test", "192.168.1.1"):
            with self.assertRaises(C.CAError, msg=bad):
                self.ca.issue_generated(C.parse_names(bad), 30, "server", "ec-p256")
        # subdomains and the domain itself are fine, so is a wildcard under it
        self.ca.issue_generated(C.parse_names("lab.test, a.b.lab.test, *.lab.test"), 30, "server", "ec-p256")

    def test_openssl_itself_enforces_name_constraints(self):
        """Even if our policy check were bypassed, the constraint inside the intermediate stops clients."""
        saved = dict(self.ca.meta)
        self.ca.meta["permitted_dns"], self.ca.meta["permitted_ips"] = [], []
        try:
            iss = self.ca.issue_generated(C.parse_names("evil.example.com"), 30, "server", "ec-p256")
        finally:
            self.ca.meta.clear(); self.ca.meta.update(saved)
        r = self.verify(iss.cert, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("permitted subtree violation", (r.stdout + r.stderr).decode())

    def test_validity_limits(self):
        for days in (0, C.MAX_LEAF_DAYS + 1):
            with self.assertRaises(C.CAError):
                self.ca.issue_generated(C.parse_names("v.lab.test"), days, "server", "ec-p256")

    def test_serials_unique_and_large(self):
        s = {self.ca.issue_generated(C.parse_names("u.lab.test"), 1, "server", "ec-p256").cert.serial_number for _ in range(5)}
        self.assertEqual(len(s), 5)
        self.assertTrue(all(n.bit_length() > 100 for n in s))

    def test_pkcs12_modern_and_legacy_open_in_openssl(self):
        iss = self.ca.issue_generated(C.parse_names("p12.lab.test"), 30, "server", "rsa-2048")
        for legacy, marker in ((False, "AES-256-CBC"), (True, "TripleDES")):
            blob = C.make_pkcs12(iss.key, iss.cert, [self.ca.intermediate], "S3cret-pass-1234", "p12.lab.test", legacy=legacy)
            p = self.write("t.p12", blob)
            info = sh("openssl", "pkcs12", "-in", p, "-passin", "pass:S3cret-pass-1234", "-info", "-nodes").stderr.decode()
            self.assertIn(marker, info)
            pem_out = sh("openssl", "pkcs12", "-in", p, "-passin", "pass:S3cret-pass-1234", "-nodes").stdout.decode()
            self.assertEqual(pem_out.count("BEGIN CERTIFICATE"), 2)  # leaf + intermediate
            self.assertEqual(pem_out.count("BEGIN PRIVATE KEY"), 1)
            self.assertNotEqual(sh("openssl", "pkcs12", "-in", p, "-passin", "pass:nope", "-nodes", check=False).returncode, 0)
        # the key in the p12 really is the cert's key
        pub_from_p12 = sh("openssl", "pkey", "-in", self.write("k.pem", sh("openssl", "pkcs12", "-in", p, "-passin", "pass:S3cret-pass-1234", "-nocerts", "-nodes").stdout), "-pubout").stdout
        pub_from_cert = sh("openssl", "x509", "-in", self.write("c.pem", C.pem(iss.cert)), "-pubkey", "-noout").stdout
        self.assertEqual(pub_from_p12, pub_from_cert)

    def test_pem_zip(self):
        iss = self.ca.issue_generated(C.parse_names("zip.lab.test"), 30, "server", "ec-p256")
        z = zipfile.ZipFile(io.BytesIO(C.make_pem_zip(iss.key, iss.cert, self.ca.intermediate, self.ca.root, "zip.lab.test")))
        names = sorted(n.split("/")[-1] for n in z.namelist())
        self.assertEqual(names, ["README.txt", "ca-chain.pem", "zip.lab.test-fullchain.pem", "zip.lab.test.crt", "zip.lab.test.key"])
        key_info = [i for i in z.infolist() if i.filename.endswith(".key")][0]
        self.assertEqual((key_info.external_attr >> 16) & 0o777, 0o600)
        # fullchain verifies as a chain
        full = z.read("zip.lab.test/zip.lab.test-fullchain.pem")
        # openssl verifies the first cert in the file and takes the rest as the untrusted chain
        full_path = self.write("full.pem", full)
        sh("openssl", "verify", "-CAfile", str(self.root_path), "-untrusted", full_path, full_path)

    def test_p7b_contains_both(self):
        out = sh("openssl", "pkcs7", "-print_certs", "-noout", input=C.p7b(self.ca.chain())).stdout.decode()
        self.assertEqual(out.count("subject="), 2)


class TestCSR(Base):
    @classmethod
    def setUpClass(cls):
        cls.make_ca()

    def make_csr(self, keyargs, subj="/CN=files.lab.test", san="DNS:files.lab.test,DNS:nas,IP:192.168.1.9", fmt="PEM"):
        d = self.tmp.name
        cmd = ["openssl", "req", "-new", "-newkey", *keyargs, "-nodes", "-keyout", f"{d}/k.pem", "-subj", subj,
               "-outform", fmt]
        if san:
            cmd += ["-addext", f"subjectAltName={san}"]
        return sh(*cmd).stdout

    def test_rsa_csr_roundtrip(self):
        csr = C.load_csr(self.make_csr(["rsa:2048"]))
        names, skipped = C.csr_names(csr)
        self.assertEqual(names.dns, ["files.lab.test", "nas"])
        self.assertEqual(names.ips, ["192.168.1.9"])
        iss = self.ca.sign_csr(csr, names, 200, "server")
        self.assertIsNone(iss.key)
        self.verify(iss.cert, "-x509_strict", "-purpose", "sslserver", "-verify_hostname", "nas")
        # the cert carries the CSR's public key
        a = sh("openssl", "x509", "-in", self.write("c.pem", C.pem(iss.cert)), "-pubkey", "-noout").stdout
        b = sh("openssl", "req", "-in", self.write("r.pem", csr.public_bytes(serialization.Encoding.PEM)), "-pubkey", "-noout").stdout
        self.assertEqual(a, b)

    def test_ec_csr_der_and_bare_base64(self):
        pem = self.make_csr(["ec", "-pkeyopt", "ec_paramgen_curve:P-256"])
        der = self.make_csr(["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], fmt="DER")
        bare = b"\n".join(l for l in pem.splitlines() if not l.startswith(b"-----"))
        for blob in (pem, der, bare):
            self.assertEqual(C.csr_names(C.load_csr(blob))[0].dns[0], "files.lab.test")

    def test_csr_without_san_falls_back_to_cn(self):
        csr = C.load_csr(self.make_csr(["rsa:2048"], san=None))
        self.assertEqual(C.csr_names(csr)[0].dns, ["files.lab.test"])

    def test_csr_cannot_smuggle_ca_extensions(self):
        csr_pem = self.make_csr(["rsa:2048"], san="DNS:evil.lab.test")
        # add a CA:TRUE request on top
        d = self.tmp.name
        sh("openssl", "req", "-new", "-key", f"{d}/k.pem", "-subj", "/CN=evil.lab.test", "-out", f"{d}/ca.csr",
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign", "-addext", "subjectAltName=DNS:evil.lab.test")
        csr = C.load_csr(Path(f"{d}/ca.csr").read_bytes())
        iss = self.ca.sign_csr(csr, C.csr_names(csr)[0], 30, "server")
        bc = iss.cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(bc.ca)
        ku = iss.cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertFalse(ku.key_cert_sign)

    def test_bad_csrs(self):
        for blob, why in ((b"", "empty"), (b"hello", "junk"), (b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----", "bad pem")):
            with self.assertRaises(C.CAError, msg=why):
                C.load_csr(blob)
        with self.assertRaises(C.CAError):
            C.load_csr(self.make_csr(["rsa:1024"]))  # too small

    def test_tampered_csr_rejected(self):
        pem = bytearray(self.make_csr(["rsa:2048"]))
        i = pem.index(b"\n") + 40
        pem[i] = ord("B") if pem[i] != ord("B") else ord("C")
        with self.assertRaises(C.CAError):
            C.load_csr(bytes(pem))


class TestCRL(Base):
    @classmethod
    def setUpClass(cls):
        cls.make_ca(key_type="rsa-4096")  # also exercises the RSA CA path

    def test_revocation_enforced_by_openssl(self):
        good = self.ca.issue_generated(C.parse_names("good.test"), 30, "server", "ec-p256").cert
        bad = self.ca.issue_generated(C.parse_names("bad.test"), 30, "server", "ec-p256").cert
        crl = self.ca.make_crl([(bad.serial_number, dt.datetime.now(dt.timezone.utc), "keyCompromise")])
        crl_pem = self.write("crl.pem", crl.public_bytes(serialization.Encoding.PEM))
        txt = sh("openssl", "crl", "-in", crl_pem, "-noout", "-text").stdout.decode()
        self.assertIn(C.serial_hex(bad.serial_number), txt)
        self.assertIn("Key Compromise", txt)
        self.assertIn("CRL Number", txt)
        # `openssl verify -crl_check` also validates the CRL's own signature against the intermediate
        flags = ["-crl_check", "-CRLfile", crl_pem]
        self.verify(good, *flags)
        r = self.verify(bad, *flags, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("revoked", (r.stdout + r.stderr).decode())
        # number increments, file persisted as DER
        self.assertEqual(self.ca.make_crl([]).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, 2)
        self.assertIsNotNone(self.ca.crl())


class TestSealedAndRootCustody(Base):
    @classmethod
    def setUpClass(cls):
        cls.make_ca(seal=True)

    def test_sealed_after_restart(self):
        self.assertFalse(self.ca.sealed())  # create() leaves it usable
        fresh = C.CertAuthority(self.tmp.name)
        fresh.load()
        self.assertTrue(fresh.sealed())
        with self.assertRaises(C.CASealed):
            fresh.issue_generated(C.parse_names("a.test"), 5, "server", "ec-p256")
        with self.assertRaises(C.CAError):
            fresh.unlock("wrong wrong wrong")
        self.assertTrue(fresh.sealed())
        fresh.unlock(PASS)
        self.assertFalse(fresh.sealed())
        fresh.issue_generated(C.parse_names("a.test"), 5, "server", "ec-p256")

    def test_intermediate_key_on_disk_is_encrypted_when_sealed(self):
        raw = (self.ca.dir / "intermediate.key").read_bytes()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", raw)

    def test_export_remove_renew(self):
        leaf = self.ca.issue_generated(C.parse_names("old.test"), 30, "server", "ec-p256").cert
        with self.assertRaises(C.CAError):
            self.ca.export_root_key("not the passphrase")
        backup = self.ca.export_root_key(PASS)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", backup)
        self.ca.remove_root_key()
        self.assertFalse(self.ca.root_key_present())
        with self.assertRaises(C.CAError):
            self.ca.renew_intermediate(PASS)                      # key is gone
        with self.assertRaises(C.CAError):
            self.ca.renew_intermediate("nope nope nope", backup)  # wrong passphrase
        old_serial = self.ca.intermediate.serial_number
        new = self.ca.renew_intermediate(PASS, backup, years=5)
        self.assertNotEqual(new.serial_number, old_serial)
        self.assertTrue((self.ca.dir / "archive").exists())
        # old leaf still validates through the NEW intermediate (same key + name)
        self.verify(leaf)
        # and new certs work too
        self.verify(self.ca.issue_generated(C.parse_names("new.test"), 30, "server", "ec-p256").cert)

    def test_leaf_validity_is_clamped_to_intermediate(self):
        c2 = C.CertAuthority(tempfile.mkdtemp())
        c2.create(org="Short", key_type="ec-p384", passphrase=PASS, root_years=5, int_years=1)
        iss = c2.issue_generated(C.parse_names("c.test"), 825, "server", "ec-p256")
        self.assertTrue(iss.notices)
        self.assertLessEqual(iss.cert.not_valid_after_utc, c2.intermediate.not_valid_after_utc)


class TestCreateValidation(unittest.TestCase):
    def test_validation(self):
        for kw in (dict(org=""), dict(org="x" * 41), dict(org="bad/name"), dict(passphrase="short"),
                   dict(key_type="rsa-1024"), dict(root_years=1), dict(int_years=25)):
            args = dict(org="Ok", key_type="ec-p384", passphrase=PASS); args.update(kw)
            with tempfile.TemporaryDirectory() as d, self.assertRaises(C.CAError, msg=str(kw)):
                C.CertAuthority(d).create(**args)

    def test_cannot_overwrite_existing_ca(self):
        with tempfile.TemporaryDirectory() as d:
            a = C.CertAuthority(d); a.create(org="One", key_type="ec-p384", passphrase=PASS)
            with self.assertRaises(C.CAError):
                a.create(org="Two", key_type="ec-p384", passphrase=PASS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
