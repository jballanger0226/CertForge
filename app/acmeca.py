"""The ACME issuing CA: a signing authority kept apart from the main CA.

ACME clients renew on their own, so the key that signs for them has to be usable without anyone
typing a passphrase. Keeping that key apart from the main intermediate means the main CA can stay
sealed, and a leaked ACME key only affects ACME certificates.

Two shapes, both ending in an *issuing* intermediate with its own key, CRL and name limits:

* "under-main": signed by the existing root. Clients that already trust the root trust it at once.
* "own-root":   a brand-new root made just for ACME, for people who want it fully separate (a
                different name, lifetime, key type or owner). Clients have to trust that root too.

Nothing here talks to a database or the network; app/service.py wraps it.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import shutil
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import ca as C

MODES = ("under-main", "own-root")
HOLDS = ("secret", "manual")
MAX_ISSUING_YEARS = 10


class AcmeAuthority:
    def __init__(self, data_dir: str | Path):
        self.dir = Path(data_dir) / "acme-ca"
        self.retired_dir = Path(data_dir) / "acme-ca-retired"
        self.lock = threading.RLock()
        self.issuing: x509.Certificate | None = None
        self.root: x509.Certificate | None = None
        self._key = None
        self.meta: dict = {}

    # ---- state ----------------------------------------------------------
    def initialized(self) -> bool:
        return all((self.dir / f).exists() for f in ("issuing.crt", "issuing.key", "root.crt", "meta.json"))

    def loaded(self) -> bool:
        return self.issuing is not None and self.root is not None

    def sealed(self) -> bool:
        return self.loaded() and self._key is None

    def root_key_present(self) -> bool:
        return (self.dir / "root.key").exists()

    @property
    def mode(self) -> str:
        return self.meta.get("mode", "")

    @property
    def hold(self) -> str:
        return self.meta.get("hold", "manual")

    @property
    def intermediate(self) -> x509.Certificate | None:      # the same name the main CA uses, so callers can treat both alike
        return self.issuing

    def chain(self) -> list[x509.Certificate]:
        return [self.issuing, self.root]

    # ---- loading --------------------------------------------------------
    def load(self) -> bool:
        with self.lock:
            if not self.initialized():
                self.issuing = self.root = self._key = None
                self.meta = {}
                return False
            self.issuing = x509.load_pem_x509_certificate((self.dir / "issuing.crt").read_bytes())
            self.root = x509.load_pem_x509_certificate((self.dir / "root.crt").read_bytes())
            self.meta = json.loads((self.dir / "meta.json").read_text())
            self._key = None                                   # always encrypted at rest: it needs unlocking
            return True

    def unlock(self, passphrase: str) -> None:
        with self.lock:
            if not self.loaded():
                raise C.CAError("There is no ACME issuing CA yet.")
            if not self.sealed():
                return
            key = C.load_encrypted_key((self.dir / "issuing.key").read_bytes(), passphrase)
            if not C.same_key(key, self.issuing):
                raise C.CAError("The ACME issuing key doesn't match its certificate.")
            self._key = key

    def lock_now(self) -> None:
        with self.lock:
            self._key = None

    def _require_key(self):
        if not self.loaded():
            raise C.CAError("There is no ACME issuing CA yet.")
        if self._key is None:
            raise C.CASealed("The ACME issuing CA is locked. Unlock it on the ACME CA page, or give the server its passphrase.")
        return self._key

    # ---- creating ---------------------------------------------------------
    def _write(self, *, root: x509.Certificate, issuing: x509.Certificate, issuing_key, passphrase: str,
               meta: dict, root_key_blob: bytes | None) -> None:
        d = self.dir
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        C.atomic_write(d / "issuing.key", C.encrypt_key(issuing_key, passphrase), 0o600)
        if root_key_blob is not None:
            C.atomic_write(d / "root.key", root_key_blob, 0o600)
        C.atomic_write(d / "root.crt", C.pem(root), 0o644)
        C.atomic_write(d / "issuing.crt", C.pem(issuing), 0o644)
        C.atomic_write(d / "meta.json", json.dumps(meta, indent=2).encode(), 0o644)

    @staticmethod
    def _check_common(passphrase: str, hold: str, key_type: str, years: int) -> None:
        C.check_passphrase(passphrase)
        if hold not in HOLDS:
            raise C.CAError("Choose how the issuing key is unlocked.")
        if key_type not in C.CA_KEY_TYPES:
            raise C.CAError("Choose ECDSA P-384 or RSA 4096 for the CA keys.")
        if not 1 <= years <= MAX_ISSUING_YEARS:
            raise C.CAError(f"Pick an issuing CA lifetime of 1-{MAX_ISSUING_YEARS} years.")

    def create_under_main(self, main: C.CertAuthority, *, main_passphrase: str, root_key_pem: bytes | None,
                          passphrase: str, key_type: str, years: int, permitted: str, hold: str) -> None:
        """An issuing CA signed by the main CA's root (which needs its passphrase, and its key if it isn't on this server)."""
        with self.lock:
            if self.initialized():
                raise C.CAError("An ACME issuing CA already exists. Retire it first to make a new one.")
            if not main.loaded():
                raise C.CAError("Set up the main CA first.")
            self._check_common(passphrase, hold, key_type, years)
            if passphrase == main_passphrase:
                raise C.CAError("Use a different passphrase for the ACME issuing key than for the main CA. "
                                "Otherwise a leak of this one would also expose the root key.")
            dns, ips = C.parse_constraints(permitted)
            if not dns and not ips:                              # nothing chosen: keep to what the main CA is limited to
                dns, ips = list(main.meta.get("permitted_dns", [])), list(main.meta.get("permitted_ips", []))
            root_key = main.load_root_key(main_passphrase, root_key_pem)
            org = main.meta["org"]
            key = C.generate_key(key_type)
            cert = main._build_intermediate(root_key, main.root, key.public_key(), org, years, dns, ips,
                                            cn=f"{org} ACME Issuing CA")
            meta = {"mode": "under-main", "org": org, "key_type": key_type, "created": C._now().isoformat(),
                    "permitted_dns": dns, "permitted_ips": ips, "crl_number": 0, "hold": hold}
            self._write(root=main.root, issuing=cert, issuing_key=key, passphrase=passphrase, meta=meta, root_key_blob=None)
            self.load()
            self._key = key

    def create_own_root(self, *, org: str, key_type: str, root_passphrase: str, passphrase: str, root_years: int,
                        years: int, permitted: str, hold: str, keep_root_key: bool) -> bytes:
        """A new root just for ACME and an issuing CA under it. Returns the root key, encrypted with
        `root_passphrase`, for the person to back up (it is also stored when `keep_root_key`)."""
        with self.lock:
            if self.initialized():
                raise C.CAError("An ACME issuing CA already exists. Retire it first to make a new one.")
            org = C.clean_org(org)
            self._check_common(passphrase, hold, key_type, years)
            C.check_passphrase(root_passphrase)
            if passphrase == root_passphrase:
                raise C.CAError("Use a different passphrase for the root key than for the issuing key. "
                                "The issuing passphrase lives on the server; the root's should not.")
            if not (5 <= root_years <= 30 and years < root_years):
                raise C.CAError("Pick a root lifetime of 5-30 years, longer than the issuing CA's.")
            dns, ips = C.parse_constraints(permitted)
            root_key, key = C.generate_key(key_type), C.generate_key(key_type)
            root = C.CertAuthority._build_root(root_key, org, root_years, cn=f"{org} ACME Root CA")
            cert = C.CertAuthority._build_intermediate(root_key, root, key.public_key(), org, years, dns, ips,
                                                       cn=f"{org} ACME Issuing CA")
            blob = C.encrypt_key(root_key, root_passphrase)
            meta = {"mode": "own-root", "org": org, "key_type": key_type, "created": C._now().isoformat(),
                    "permitted_dns": dns, "permitted_ips": ips, "crl_number": 0, "hold": hold,
                    "root_key_exported": False}
            self._write(root=root, issuing=cert, issuing_key=key, passphrase=passphrase, meta=meta,
                        root_key_blob=blob if keep_root_key else None)
            self.load()
            self._key = key
            return blob

    # ---- own-root key custody -------------------------------------------------
    def load_root_key(self, passphrase: str, root_key_pem: bytes | None = None):
        with self.lock:
            if root_key_pem is None:
                if not self.root_key_present():
                    raise C.CAError("The ACME root key isn't on this server. Upload your backup of it to continue.")
                root_key_pem = (self.dir / "root.key").read_bytes()
            key = C.load_encrypted_key(root_key_pem, passphrase)
            if not C.same_key(key, self.root):
                raise C.CAError("That key isn't the key for this ACME root certificate.")
            return key

    def mark_root_key_exported(self) -> None:
        with self.lock:
            self.meta["root_key_exported"] = True
            self._save_meta()

    def remove_root_key(self) -> None:
        with self.lock:
            try:
                (self.dir / "root.key").unlink()
            except FileNotFoundError:
                pass

    def renew(self, root_key, years: int) -> x509.Certificate:
        """Re-sign the issuing key for a new period (same name and key, so issued certificates stay valid)."""
        with self.lock:
            self._check_years(years)
            new = C.CertAuthority._build_intermediate(
                root_key, self.root, self.issuing.public_key(), self.meta["org"], years,
                self.meta.get("permitted_dns", []), self.meta.get("permitted_ips", []),
                cn=C._cn(self.issuing.subject))
            archive = self.dir / "archive"
            archive.mkdir(exist_ok=True)
            C.atomic_write(archive / f"issuing-{C.serial_hex(self.issuing.serial_number)}.crt", C.pem(self.issuing), 0o644)
            C.atomic_write(self.dir / "issuing.crt", C.pem(new), 0o644)
            self.issuing = new
            return new

    @staticmethod
    def _check_years(years: int) -> None:
        if not 1 <= years <= MAX_ISSUING_YEARS:
            raise C.CAError(f"Pick an issuing CA lifetime of 1-{MAX_ISSUING_YEARS} years.")

    def retire(self) -> Path:
        """Move the whole thing aside (keys included) and stop using it. Nothing is deleted."""
        with self.lock:
            if not self.initialized():
                raise C.CAError("There is no ACME issuing CA.")
            self.retired_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.retired_dir, 0o700)
            dest = self.retired_dir / C._now().strftime("%Y%m%dT%H%M%SZ")
            n = 1
            while dest.exists():
                n += 1
                dest = self.retired_dir / f"{C._now():%Y%m%dT%H%M%SZ}-{n}"
            shutil.move(str(self.dir), str(dest))
            self.issuing = self.root = self._key = None
            self.meta = {}
            return dest

    def _save_meta(self) -> None:
        C.atomic_write(self.dir / "meta.json", json.dumps(self.meta, indent=2).encode(), 0o644)

    # ---- issuing ----------------------------------------------------------
    def check_policy(self, names: C.Names, days: int | None = None) -> None:
        C.check_policy(self.meta.get("permitted_dns", []), self.meta.get("permitted_ips", []), names, days)

    def sign_csr(self, csr: x509.CertificateSigningRequest, names: C.Names, days: int, purpose: str,
                 public_host: str | None) -> C.Issued:
        """Sign a CSR's public key. Only the names are taken from the request."""
        with self.lock:
            key = self._require_key()
            self.check_policy(names, days)
            cert, notices = C.build_leaf(issuer_cert=self.issuing, issuer_key=key, public_key=csr.public_key(),
                                         names=names, days=days, purpose=purpose, public_host=public_host,
                                         issuer_file="acme-intermediate")
            return C.Issued(cert, None, names, notices)

    # ---- CRL ---------------------------------------------------------------
    def make_crl(self, revoked: list[tuple[int, dt.datetime, str]]) -> x509.CertificateRevocationList:
        with self.lock:
            key = self._require_key()
            number = int(self.meta.get("crl_number", 0)) + 1
            crl = C.build_crl(issuer_cert=self.issuing, issuer_key=key, number=number, revoked=revoked)
            C.atomic_write(self.dir / "issuing.crl", crl.public_bytes(serialization.Encoding.DER), 0o644)
            self.meta["crl_number"] = number
            self._save_meta()
            return crl

    def crl(self) -> x509.CertificateRevocationList | None:
        p = self.dir / "issuing.crl"
        return x509.load_der_x509_crl(p.read_bytes()) if p.exists() else None

    # ---- what the limits cover ------------------------------------------------
    def covers(self, domains: list[str], networks: list[str]) -> list[str]:
        """Names from the ACME settings that this CA's own limits would refuse (empty when all is well)."""
        pd, pi = self.meta.get("permitted_dns", []), [ipaddress.ip_network(n) for n in self.meta.get("permitted_ips", [])]
        bad = []
        if pd:
            bad += [d for d in domains if not any(d == p or d.endswith("." + p) for p in pd)]
        if pi:
            bad += [n for n in networks if not any(ipaddress.ip_network(n).subnet_of(p) for p in pi
                                                    if ipaddress.ip_network(n).version == p.version)]
        return bad
