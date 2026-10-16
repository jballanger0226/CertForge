"""Application logic: glues the CA engine, the inventory and the on-disk TLS files together."""
from __future__ import annotations

import hmac
import logging
import os
import plistlib
import secrets
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import ca as C
from . import netinfo
from .acme import Acme
from .acmeca import AcmeAuthority
from .config import Config
from .security import MIN_PASSWORD, Ephemeral, RateLimiter, hash_password, random_password, verify_password
from .store import Store, iso, parse_iso, utcnow

log = logging.getLogger("certforge")

UI_CERT_DAYS = 365
UI_RENEW_BEFORE = timedelta(days=30)
PACKAGE_TTL = 900


@dataclass
class Package:
    """A freshly generated private key + certificate, held in memory only."""
    serial: str
    password: str
    legacy: bool
    files: dict[str, tuple[str, str, bytes]]   # format -> (filename, mime type, bytes)
    notices: list[str] = field(default_factory=list)


class Service:
    def __init__(self, cfg: Config):
        os.umask(0o077)
        self.cfg = cfg
        try:
            cfg.data.mkdir(parents=True, exist_ok=True, mode=0o700)
            (cfg.data / "ui").mkdir(exist_ok=True)
            probe = cfg.data / ".write-test"
            probe.write_text("ok"); probe.unlink()
        except OSError as e:
            raise SystemExit(f"Can't write to the data directory {cfg.data}: {e}. "
                             "Mount a writable volume there (see the README).")
        try:
            os.chmod(cfg.data, 0o700)
        except PermissionError:
            pass
        self.store = Store(cfg.data / "certforge.db")
        self.ca = C.CertAuthority(cfg.data)
        self.ca.load()
        self.acme_ca = AcmeAuthority(cfg.data)
        self.acme_ca.load()
        self.root_backups = Ephemeral(PACKAGE_TTL)        # a new ACME root's key, offered for download once
        self.packages = Ephemeral(PACKAGE_TTL)
        self.pending = Ephemeral(1800)
        self.limiter = RateLimiter()
        self.tls_changed = threading.Event()   # set when the web certificate on disk changed
        self._setup_lock = threading.Lock()
        self._setup_done = False
        self.acme = Acme(self)
        self._net_cache: dict[str, tuple[float, netinfo.NetInfo]] = {}
        self._bootstrap_names: list[str] = []
        self.secret = self._secret()
        self.unlock_acme_ca_from_secret()

    # ---- bootstrap ------------------------------------------------------
    def _secret(self) -> str:
        p = self.cfg.data / "secret.key"
        if not p.exists():
            C.atomic_write(p, secrets.token_hex(32).encode(), 0o600)
        return p.read_text().strip()

    def setup_token(self) -> str:
        if self.cfg.setup_token:
            return self.cfg.setup_token
        p = self.cfg.data / "setup.token"
        if not p.exists():
            C.atomic_write(p, secrets.token_urlsafe(15).encode(), 0o600)
        return p.read_text().strip()

    def is_setup(self) -> bool:
        if not self._setup_done:
            self._setup_done = self.ca.initialized() and self.store.get("admin_hash") is not None
        return self._setup_done

    # ---- what is this server called? ----------------------------------------------------------
    def net(self, request_host: str = "") -> netinfo.NetInfo:
        """Detected host name, domain, addresses and a suggested public address (cached briefly)."""
        key = request_host.strip().lower()
        now = time.monotonic()
        hit = self._net_cache.get(key)
        if hit and now - hit[0] < 30:
            return hit[1]
        info = netinfo.detect(key)
        self._net_cache[key] = (now, info)
        return info

    def initial_names(self, request_host: str = "") -> str:
        """Names for the first web certificate: CERTFORGE_HOSTNAMES if set, otherwise what the network tells us."""
        base = self.cfg.hostnames.replace(",", " ").split() if self.cfg.hostnames else []
        if base:
            names = [*([request_host] if request_host else []), *base]
        else:
            names = [*([request_host] if request_host else []), *(self.net().names or ["localhost", "127.0.0.1"])]
        out: list[str] = []
        for n in names:
            try:
                for x in C.parse_names(n).all():
                    if x not in out:
                        out.append(x)
            except C.CAError:
                pass
        return "\n".join(out)

    def default_public_host(self, request_host: str = "") -> tuple[str, str]:
        """(address for CA downloads and revocation checks, a warning about it or "")."""
        if self.cfg.hostnames:
            first = self.cfg.hostnames.replace(",", " ").split()[0]
            return first, ""
        info = self.net(request_host)
        return info.public_host, info.public_note

    # ---- first-run setup --------------------------------------------------
    def setup(self, *, token: str, org: str, admin_password: str, admin_password2: str, passphrase: str,
              key_type: str, root_years: int, int_years: int, seal: bool, permitted: str,
              ui_names: str, public_host: str) -> None:
        with self._setup_lock:
            if self.is_setup():
                raise C.CAError("This server has already been set up.")
            if not hmac.compare_digest(token.strip().encode(), self.setup_token().encode()):
                raise C.CAError("That setup code isn't right. It's printed in the server log when the "
                                "server starts (docker logs certforge), and saved in the data folder as setup.token.")
            if admin_password != admin_password2:
                raise C.CAError("The two admin passwords don't match.")
            if len(admin_password) < MIN_PASSWORD:
                raise C.CAError(f"The admin password must be at least {MIN_PASSWORD} characters.")
            C.check_passphrase(passphrase)
            if passphrase == admin_password:
                raise C.CAError("Use a different passphrase for the CA key than for the admin login.")
            org = org.strip() or self.net().org
            names = C.parse_names(ui_names if ui_names.strip() else self.initial_names())
            host = public_host.strip() or self.default_public_host()[0] or names.all()[0]
            host = C.parse_names(host).all()[0]
            self.ca.create(org=org, key_type=key_type, passphrase=passphrase, root_years=root_years,
                           int_years=int_years, seal=seal, permitted=permitted, public_host=host)
            self.issue_ui_cert(names)
            self.store.set("org", self.ca.meta["org"])
            self.store.set("pw_version", 1)
            self.store.set("admin_hash", hash_password(admin_password))
            self.store.set("root_key_exported", False)
            self.store.audit("admin", "setup", f"CA '{org}' created ({key_type}{', sealed' if seal else ''})")
            try:
                (self.cfg.data / "setup.token").unlink()
            except FileNotFoundError:
                pass
            self._setup_done = True
            self.notify_tls_changed()

    def auto_setup(self) -> bool:
        """Set the CA up from CERTFORGE_* settings, with no one at the keyboard. True if it did."""
        a = self.cfg.auto
        if a is None or self.is_setup():
            return False
        self.setup(token=self.setup_token(), org=a.org, admin_password=a.admin_password,
                   admin_password2=a.admin_password, passphrase=a.passphrase, key_type=a.key_type,
                   root_years=a.root_years, int_years=a.int_years, seal=a.seal, permitted=a.permitted,
                   ui_names="", public_host=a.public_host)
        if a.acme_domains or a.acme_networks:
            self.acme.save_settings("setup", enabled=True, domains_raw=a.acme_domains, networks_raw=a.acme_networks,
                                    days=a.acme_days, require_eab=a.acme_eab)
        return True

    def notify_tls_changed(self) -> None:
        """The HTTPS listener picks up the new certificate for new connections (no restart needed)."""
        self.tls_changed.set()

    # ---- the web UI's own certificate -------------------------------------
    def _ui_paths(self) -> tuple[Path, Path]:
        return self.cfg.data / "ui" / "ui.crt", self.cfg.data / "ui" / "ui.key"

    def ui_cert(self) -> x509.Certificate | None:
        crt, key = self._ui_paths()
        if not (crt.exists() and key.exists()):
            return None
        try:
            return x509.load_pem_x509_certificate(crt.read_bytes())
        except ValueError:
            return None

    def _ui_usable(self) -> bool:
        cert = self.ui_cert()
        if cert is None or not self.ca.loaded():
            return False
        if cert.not_valid_after_utc - C._now() < UI_RENEW_BEFORE:
            return False
        try:
            cert.verify_directly_issued_by(self.ca.intermediate)
        except Exception:
            return False
        want = set(self.store.get("ui_names", []))
        return not want or set(C.sans_of(cert)) == want

    def issue_ui_cert(self, names: C.Names | None = None) -> None:
        if names is None:
            names = C.parse_names(self.store.get("ui_names", []) or self.initial_names())
        with self.ca.lock:
            issued = self.ca.issue_generated(names, UI_CERT_DAYS, "server", "ec-p256")
            self._record(issued.cert, "server", "system", "system")
            crt, key = self._ui_paths()
            C.atomic_write(key, C.key_pem(issued.key), 0o600)
            C.atomic_write(crt, C.chain_pem([issued.cert, self.ca.intermediate]), 0o644)
            self.store.set("ui_names", names.all())

    def update_ui_names(self, actor: str, raw: str) -> None:
        names = C.parse_names(raw)
        self.issue_ui_cert(names)
        self.store.audit(actor, "ui-cert", "Web UI certificate re-issued for " + ", ".join(names.all()))
        self.notify_tls_changed()

    def tls_files(self) -> tuple[str, str, str]:
        """(cert file, key file, 'ca' | 'bootstrap') for the HTTPS listener."""
        if self.ca.loaded():
            if not self._ui_usable() and not self.ca.sealed():
                self.issue_ui_cert()
            crt, key = self._ui_paths()
            cert = self.ui_cert()
            if cert is not None and cert.not_valid_after_utc > C._now():
                return str(crt), str(key), "ca"
        names = C.parse_names(self.initial_names())
        crt, key = self.cfg.data / "ui" / "bootstrap.crt", self.cfg.data / "ui" / "bootstrap.key"
        self._bootstrap_names = names.all()
        if self._bootstrap_reusable(crt, key, names):
            return str(crt), str(key), "bootstrap"
        crt_pem, key_pem = C.self_signed_bootstrap(names)
        C.atomic_write(key, key_pem, 0o600)
        C.atomic_write(crt, crt_pem, 0o644)
        return str(crt), str(key), "bootstrap"

    @staticmethod
    def _bootstrap_reusable(crt: Path, key: Path, names: C.Names) -> bool:
        """Keep the existing temporary certificate while it still covers exactly these names."""
        try:
            if not (crt.exists() and key.exists()):
                return False
            cert = x509.load_pem_x509_certificate(crt.read_bytes())
            return (cert.not_valid_after_utc - C._now() > timedelta(days=7)
                    and set(C.sans_of(cert)) == set(names.all()))
        except (OSError, ValueError):
            return False

    def bootstrap_stale(self) -> bool:
        """Before setup: has the network changed (new DHCP address, new name) since the temporary certificate was made?"""
        if self.is_setup():
            return False
        if set(C.parse_names(self.initial_names()).all()) != set(self._bootstrap_names):
            return True
        crt = self.cfg.data / "ui" / "bootstrap.crt"          # the temporary certificate only lasts 30 days
        return not self._bootstrap_reusable(crt, crt.with_suffix(".key"), C.parse_names(self.initial_names()))

    def allowed_hosts(self) -> list[str]:
        hosts = list(self.store.get("ui_names", []))
        if self.ca.public_host and self.ca.public_host not in hosts:
            hosts.append(self.ca.public_host)
        return hosts

    # ---- authentication ---------------------------------------------------
    def check_admin(self, password: str) -> bool:
        return verify_password(password, self.store.get("admin_hash", ""))

    def password_version(self) -> int:
        return int(self.store.get("pw_version", 1))

    def change_password(self, actor: str, current: str, new: str, new2: str) -> None:
        if not self.check_admin(current):
            raise C.CAError("The current password isn't right.")
        if new != new2:
            raise C.CAError("The two new passwords don't match.")
        if len(new) < MIN_PASSWORD:
            raise C.CAError(f"The new password must be at least {MIN_PASSWORD} characters.")
        self.store.set("admin_hash", hash_password(new))
        self.store.set("pw_version", self.password_version() + 1)   # signs every other session out
        self.store.audit(actor, "password", "Admin password changed")

    # ---- issuing ----------------------------------------------------------
    def _record(self, cert: x509.Certificate, purpose: str, source: str, actor: str, issuer: str = "main") -> dict:
        rec = dict(issuer=issuer, 
            serial=C.serial_hex(cert.serial_number), cn=C._cn(cert.subject), sans=C.sans_of(cert),
            purpose=purpose, key_desc=C.describe_key(cert.public_key()), source=source,
            not_before=iso(cert.not_valid_before_utc), not_after=iso(cert.not_valid_after_utc),
            issued_at=iso(utcnow()), issued_by=actor, sha256=C.fingerprint(cert), pem=C.pem(cert).decode(),
        )
        self.store.add_cert(**rec)
        if source != "system":
            self.store.audit(actor, "issue", f"{rec['cn']} ({source}) serial {rec['serial']}")
        return rec

    def issue_generated(self, actor: str, owner: str, *, names_raw: str, days: int, purpose: str,
                        key_type: str, password: str, legacy: bool) -> str:
        names = C.parse_names(names_raw)
        if password and len(password) < 8:
            raise C.CAError("The .p12 password must be at least 8 characters (or leave it blank to get a strong one).")
        password = password or random_password(16)
        with self.ca.lock:
            issued = self.ca.issue_generated(names, days, purpose, key_type)
            rec = self._record(issued.cert, purpose, "generated", actor)
        cn, slug = names.cn(), C.slugify(names.cn())
        p12 = C.make_pkcs12(issued.key, issued.cert, [self.ca.intermediate], password, cn, legacy=legacy)
        zipped = C.make_pem_zip(issued.key, issued.cert, self.ca.intermediate, self.ca.root, cn)
        pkg = Package(rec["serial"], password, legacy, {
            "p12": (f"{slug}.p12", "application/x-pkcs12", p12),
            "zip": (f"{slug}-pem.zip", "application/zip", zipped),
        }, issued.notices)
        self.packages.put(pkg, key=f"{owner}:{rec['serial']}")
        return rec["serial"]

    def package(self, owner: str, serial: str) -> Package | None:
        return self.packages.get(f"{owner}:{serial.upper()}")

    def discard_package(self, owner: str, serial: str) -> None:
        self.packages.pop(f"{owner}:{serial.upper()}")

    def stage_csr(self, owner: str, data: bytes) -> str:
        csr = C.load_csr(data)
        names, skipped = C.csr_names(csr)
        return self.pending.put({
            "owner": owner, "pem": csr.public_bytes(serialization.Encoding.PEM),
            "names": names.all(), "skipped": skipped, "key": C.describe_key(csr.public_key()),
            "subject": csr.subject.rfc4514_string() or "(empty)",
        })

    def staged_csr(self, owner: str, token: str) -> dict | None:
        p = self.pending.get(token)
        return p if p and p["owner"] == owner else None

    def sign_staged(self, actor: str, owner: str, token: str, *, names_raw: str, days: int, purpose: str) -> tuple[str, list[str]]:
        p = self.staged_csr(owner, token)
        if not p:
            raise C.CAError("This request expired. Please paste or upload the CSR again.")
        csr = x509.load_pem_x509_csr(p["pem"])
        names = C.parse_names(names_raw)
        with self.ca.lock:
            issued = self.ca.sign_csr(csr, names, days, purpose)
            rec = self._record(issued.cert, purpose, "csr", actor)
        self.pending.pop(token)
        return rec["serial"], issued.notices

    # ---- downloads of public material ---------------------------------------
    def cert_files(self, row: dict) -> dict[str, tuple[str, str, bytes]]:
        cert = x509.load_pem_x509_certificate(row["pem"].encode())
        slug = C.slugify(row["cn"])
        auth = self.acme_ca if row.get("issuer") == "acme" and self.acme_ca.loaded() else self.ca
        inter, root = auth.intermediate, auth.root
        return {
            "cer": (f"{slug}.cer", "application/x-pem-file", C.pem(cert)),
            "der": (f"{slug}.der", "application/pkix-cert", C.der(cert)),
            "fullchain": (f"{slug}-fullchain.pem", "application/x-pem-file", C.chain_pem([cert, inter])),
            "p7b": (f"{slug}.p7b", "application/x-pkcs7-certificates", C.p7b([cert, inter, root])),
        }

    def pki(self, name: str) -> tuple[bytes, str, str] | None:
        """Public CA material, served without a login: (data, content type, file name)."""
        if not self.ca.loaded():
            return None
        org = C.slugify(self.ca.meta["org"])
        root, inter = self.ca.root, self.ca.intermediate
        table = {
            "root.crt": lambda: (C.pem(root), "application/x-pem-file", f"{org}-root-ca.crt"),
            "root.cer": lambda: (C.der(root), "application/pkix-cert", f"{org}-root-ca.cer"),
            "intermediate.crt": lambda: (C.pem(inter), "application/x-pem-file", f"{org}-intermediate-ca.crt"),
            "intermediate.cer": lambda: (C.der(inter), "application/pkix-cert", f"{org}-intermediate-ca.cer"),
            "chain.pem": lambda: (C.chain_pem([inter, root]), "application/x-pem-file", f"{org}-ca-chain.pem"),
            "chain.p7b": lambda: (C.p7b([inter, root]), "application/x-pkcs7-certificates", f"{org}-ca-chain.p7b"),
            "root.mobileconfig": lambda: (self.mobileconfig(), "application/x-apple-aspen-config", f"{org}-root-ca.mobileconfig"),
            "intermediate.crl": lambda: self._crl_file(binary=True),
            "intermediate.crl.pem": lambda: self._crl_file(binary=False),
        }
        if self.acme_ca.loaded():
            a_org, a_root, a_int = f"{org}-acme", self.acme_ca.root, self.acme_ca.issuing
            table.update({
                "acme-root.crt": lambda: (C.pem(a_root), "application/x-pem-file", f"{a_org}-root-ca.crt"),
                "acme-root.cer": lambda: (C.der(a_root), "application/pkix-cert", f"{a_org}-root-ca.cer"),
                "acme-intermediate.crt": lambda: (C.pem(a_int), "application/x-pem-file", f"{a_org}-issuing-ca.crt"),
                "acme-intermediate.cer": lambda: (C.der(a_int), "application/pkix-cert", f"{a_org}-issuing-ca.cer"),
                "acme-chain.pem": lambda: (C.chain_pem([a_int, a_root]), "application/x-pem-file", f"{a_org}-ca-chain.pem"),
                "acme-chain.p7b": lambda: (C.p7b([a_int, a_root]), "application/x-pkcs7-certificates", f"{a_org}-ca-chain.p7b"),
                "acme-root.mobileconfig": lambda: (self.mobileconfig(a_root, f"{self.acme_ca.meta['org']} ACME"),
                                                   "application/x-apple-aspen-config", f"{a_org}-root-ca.mobileconfig"),
                "acme-intermediate.crl": lambda: self._crl_file(binary=True, acme=True),
                "acme-intermediate.crl.pem": lambda: self._crl_file(binary=False, acme=True),
            })
        fn = table.get(name)
        return fn() if fn else None

    def _crl_file(self, binary: bool, acme: bool = False) -> tuple[bytes, str, str]:
        self.refresh_crl()
        auth = self.acme_ca if acme else self.ca
        crl = auth.crl()
        if crl is None:
            raise C.CAError("No CRL has been published yet.")
        enc = serialization.Encoding.DER if binary else serialization.Encoding.PEM
        stem = "acme-intermediate" if acme else "intermediate"
        return crl.public_bytes(enc), ("application/pkix-crl" if binary else "application/x-pem-file"), \
            f"{stem}.crl" if binary else f"{stem}.crl.pem"

    def mobileconfig(self, root: x509.Certificate | None = None, org: str | None = None) -> bytes:
        """An Apple configuration profile that installs a root CA on iOS / iPadOS / macOS."""
        root = root or self.ca.root
        fp = root.fingerprint(C.hashes.SHA256()).hex()
        ns = uuid.UUID("6f1f2f6e-9a2e-4a55-9c43-3c1d6a0b7a11")
        org = org or self.ca.meta["org"]
        payload = {
            "PayloadContent": [{
                "PayloadCertificateFileName": "root-ca.cer",
                "PayloadContent": C.der(root),
                "PayloadDescription": "Adds the root certificate of your private CA",
                "PayloadDisplayName": f"{org} Root CA",
                "PayloadIdentifier": f"com.certforge.root.{fp[:16]}",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": str(uuid.uuid5(ns, fp + "/cert")),
                "PayloadVersion": 1,
            }],
            "PayloadDescription": "Installs the root certificate so this device trusts certificates issued by your private CA.",
            "PayloadDisplayName": f"{org} Certificate Authority",
            "PayloadIdentifier": f"com.certforge.profile.{fp[:16]}",
            "PayloadOrganization": org,
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": str(uuid.uuid5(ns, fp + "/profile")),
            "PayloadVersion": 1,
        }
        return plistlib.dumps(payload, fmt=plistlib.FMT_XML)

    # ---- revocation ---------------------------------------------------------
    def revoke(self, actor: str, serial: str, reason: str) -> None:
        if reason not in C.REASONS:
            raise C.CAError("Pick a reason from the list.")
        with self.ca.lock:
            row = self.store.get_cert(serial)
            if not row:
                raise C.CAError("No such certificate.")
            if row["source"] == "system":
                raise C.CAError("This certificate secures the CertForge web UI itself. Re-issue it from the CA page instead.")
            if row["revoked_at"]:
                raise C.CAError("That certificate is already revoked.")
            which = row.get("issuer", "main")
            auth = self.acme_ca if which == "acme" else self.ca
            if which == "acme" and not self.acme_ca.loaded():
                raise C.CAError("The ACME issuing CA that signed this certificate has been retired, so a revocation list can't be updated for it.")
            if auth.sealed():
                raise C.CASealed("Unlock the ACME issuing CA first, so its revocation list can be updated." if which == "acme"
                                 else "Unlock the CA first, so the revocation list can be updated.")
            self.store.revoke(serial, reason)
            self.refresh_crl(force=True, which=which)
            self.store.audit(actor, "revoke", f"{row['cn']} serial {row['serial']} ({reason})")

    def maintain(self) -> None:
        """Periodic housekeeping: keep the CRL fresh and renew the web certificate before it expires."""
        self.refresh_crl()
        self.acme.cleanup()
        if self.ca.loaded() and not self.ca.sealed() and not self._ui_usable():
            self.issue_ui_cert()
            self.store.audit("system", "ui-cert", "Web UI certificate renewed automatically")
            self.notify_tls_changed()

    def refresh_crl(self, force: bool = False, which: str | None = None) -> None:
        """Re-sign a revocation list when it is due (or `force`). `which` limits it to "main" or "acme"."""
        for name, auth in (("main", self.ca), ("acme", self.acme_ca)):
            if which and which != name:
                continue
            with auth.lock:
                if not auth.loaded() or auth.sealed():
                    continue
                crl = auth.crl()
                due = force or crl is None or (crl.next_update_utc - C._now()) < timedelta(days=2)
                if due:
                    auth.make_crl(self.store.revoked(name))

    # ---- CA administration --------------------------------------------------
    def unlock(self, actor: str, passphrase: str) -> None:
        self.ca.unlock(passphrase)
        self.store.audit(actor, "unlock", "CA unlocked")
        self.refresh_crl()
        if not self._ui_usable():
            self.issue_ui_cert()
            self.notify_tls_changed()

    def export_root_key(self, actor: str, passphrase: str) -> tuple[bytes, str]:
        blob = self.ca.export_root_key(passphrase)
        self.store.set("root_key_exported", True)
        self.store.audit(actor, "root-key-export", "Encrypted root key downloaded")
        return blob, f"{C.slugify(self.ca.meta['org'])}-root-ca.key.enc"

    def remove_root_key(self, actor: str) -> None:
        if not self.store.get("root_key_exported"):
            raise C.CAError("Download a backup of the root key first. Once it's removed from this server, the backup is the only copy.")
        self.ca.remove_root_key()
        self.store.audit(actor, "root-key-remove", "Root key removed from this server")

    def renew_intermediate(self, actor: str, passphrase: str, years: int, key_pem: bytes | None) -> None:
        self.ca.renew_intermediate(passphrase, key_pem or None, years)
        self.store.audit(actor, "intermediate-renew", f"Intermediate re-signed for {years} years")

    def set_public_host(self, actor: str, raw: str) -> None:
        host = C.parse_names(raw).all()[0]
        self.ca.update_public_host(host)
        self.store.audit(actor, "public-host", f"Public host set to {host}")

    # ---- the ACME issuing CA --------------------------------------------------------------
    def acme_issuer(self) -> tuple[str, "C.CertAuthority | AcmeAuthority"]:
        """Who signs ACME certificates: the dedicated ACME CA when there is one, otherwise the main intermediate."""
        return ("acme", self.acme_ca) if self.acme_ca.loaded() else ("main", self.ca)

    def acme_issue(self, csr: x509.CertificateSigningRequest, names: C.Names, days: int, actor: str) -> dict:
        name, auth = self.acme_issuer()
        with auth.lock:
            if name == "acme":
                issued = auth.sign_csr(csr, names, days, "server", self.ca.public_host)
            else:
                issued = auth.sign_csr(csr, names, days, "server")
            return self._record(issued.cert, "server", "acme", actor, issuer=name)

    def issuer_chain(self, row: dict) -> list[x509.Certificate]:
        """The certificates to send after the leaf (the issuing CA; clients get the root from the trust page)."""
        if row.get("issuer") == "acme" and self.acme_ca.loaded():
            return [self.acme_ca.issuing]
        return [self.ca.intermediate]

    def unlock_acme_ca_from_secret(self) -> bool:
        """At start: unlock the ACME issuing key with CERTFORGE_ACME_CA_PASSPHRASE when the CA is set to be unlocked that way."""
        ac = self.acme_ca
        if not (ac.sealed() and ac.hold == "secret" and self.cfg.acme_ca_passphrase):
            return False
        try:
            ac.unlock(self.cfg.acme_ca_passphrase)
        except C.CAError:
            log.warning("CERTFORGE_ACME_CA_PASSPHRASE didn't unlock the ACME issuing key, so it stays locked. "
                        "Unlock it on the ACME CA page, or correct the passphrase.")
            return False
        log.info("ACME issuing CA unlocked from CERTFORGE_ACME_CA_PASSPHRASE")
        self.refresh_crl(which="acme")
        return True

    def acme_ca_create(self, actor: str, owner: str, *, mode: str, passphrase: str, passphrase2: str | None = None, hold: str = "secret",
                       key_type: str = "ec-p384", years: int = 5, permitted: str = "", main_passphrase: str = "",
                       root_key_pem: bytes | None = None, org: str = "", root_passphrase: str = "", root_years: int = 20,
                       keep_root_key: bool = False) -> str | None:
        """Create the ACME issuing CA. For "own-root" returns a token for downloading the new root's key once, else None."""
        if not self.is_setup():
            raise C.CAError("Set up the main CA first.")
        if passphrase2 is not None and passphrase != passphrase2:
            raise C.CAError("The two ACME issuing passphrases don't match.")
        if self.check_admin(passphrase):
            raise C.CAError("Use a different passphrase for the ACME issuing key than for the admin login.")
        token = None
        with self.ca.lock, self.acme_ca.lock:
            if mode == "under-main":
                self.acme_ca.create_under_main(
                    self.ca, main_passphrase=main_passphrase, root_key_pem=root_key_pem, passphrase=passphrase,
                    key_type=key_type, years=years, permitted=permitted, hold=hold)
            elif mode == "own-root":
                blob = self.acme_ca.create_own_root(
                    org=org or self.ca.meta["org"], key_type=key_type, root_passphrase=root_passphrase,
                    passphrase=passphrase, root_years=root_years, years=years, permitted=permitted, hold=hold,
                    keep_root_key=keep_root_key)
                token = self.root_backups.put({"owner": owner, "blob": blob,
                                               "name": f"{C.slugify(self.acme_ca.meta['org'])}-acme-root-ca.key.enc"})
            else:
                raise C.CAError("Choose how to make the ACME issuing CA.")
            self.refresh_crl(force=True, which="acme")
        self.store.audit(actor, "acme-ca-create", f"ACME issuing CA created ({mode}, key {hold})")
        return token

    def acme_ca_unlock(self, actor: str, passphrase: str) -> None:
        self.acme_ca.unlock(passphrase)
        self.store.audit(actor, "acme-ca-unlock", "ACME issuing CA unlocked")
        self.refresh_crl(which="acme")

    def acme_ca_root_download(self, owner: str, token: str) -> tuple[bytes, str] | None:
        """The new root's key, once. It is gone from memory after this."""
        item = self.root_backups.get(token)
        if not item or item["owner"] != owner:
            return None
        self.root_backups.pop(token)
        if self.acme_ca.loaded():
            self.acme_ca.mark_root_key_exported()
        self.store.audit("admin", "acme-root-key-export", "ACME root key downloaded")
        return item["blob"], item["name"]

    def acme_ca_export_root_key(self, actor: str, passphrase: str) -> tuple[bytes, str]:
        ac = self.acme_ca
        if ac.mode != "own-root":
            raise C.CAError("The ACME CA is signed by your main root; export that key from the CA page.")
        ac.load_root_key(passphrase)                                  # proves the passphrase
        blob = (ac.dir / "root.key").read_bytes()
        ac.mark_root_key_exported()
        self.store.audit(actor, "acme-root-key-export", "ACME root key downloaded")
        return blob, f"{C.slugify(ac.meta['org'])}-acme-root-ca.key.enc"

    def acme_ca_remove_root_key(self, actor: str) -> None:
        if not self.acme_ca.meta.get("root_key_exported"):
            raise C.CAError("Download a backup of the ACME root key first. Once it's removed from this server, the backup is the only copy.")
        self.acme_ca.remove_root_key()
        self.store.audit(actor, "acme-root-key-remove", "ACME root key removed from this server")

    def acme_ca_renew(self, actor: str, passphrase: str, years: int, key_pem: bytes | None) -> None:
        ac = self.acme_ca
        if not ac.loaded():
            raise C.CAError("There is no ACME issuing CA.")
        root_key = self.ca.load_root_key(passphrase, key_pem or None) if ac.mode == "under-main" \
            else ac.load_root_key(passphrase, key_pem or None)
        ac.renew(root_key, years)
        self.store.audit(actor, "acme-ca-renew", f"ACME issuing CA re-signed for {years} years")

    def acme_ca_retire(self, actor: str) -> str:
        """Put the ACME issuing CA aside and switch ACME off, so nothing quietly falls back to a different CA."""
        with self.acme_ca.lock:
            dest = self.acme_ca.retire()
        st = self.acme.settings()
        if st.enabled:
            self.acme.save_settings(actor, enabled=False, domains_raw="\n".join(st.domains), networks_raw="\n".join(st.networks),
                                    days=st.days, require_eab=st.require_eab)
        self.store.audit(actor, "acme-ca-retire", f"ACME issuing CA retired to {dest.name}; ACME turned off")
        return dest.name

    def auto_acme_ca(self) -> bool:
        """Create the ACME issuing CA from CERTFORGE_ACME_CA* settings (once; it does nothing when one exists)."""
        a = self.cfg.acme_ca_auto
        if a is None or not self.is_setup() or self.acme_ca.initialized():
            return False                       # (once it exists, none of the passphrases below are needed again, except to unlock)
        if not a.passphrase:
            raise C.CAError("CERTFORGE_ACME_CA needs CERTFORGE_ACME_CA_PASSPHRASE (or _FILE), at least 12 characters.")
        if a.mode == "under-main" and not a.main_passphrase:
            raise C.CAError("CERTFORGE_ACME_CA=intermediate signs with your root, so it also needs CERTFORGE_CA_PASSPHRASE "
                            "this one time. Afterwards it can be removed.")
        if a.mode == "own-root" and not a.root_passphrase:
            raise C.CAError("CERTFORGE_ACME_CA=root needs CERTFORGE_ACME_ROOT_PASSPHRASE (or _FILE) for the new root's key.")
        token = self.acme_ca_create(
            "system", "system", mode=a.mode, passphrase=a.passphrase, hold=a.hold, key_type=a.key_type, years=a.years,
            permitted=a.permitted, main_passphrase=a.main_passphrase, org=a.org, root_passphrase=a.root_passphrase,
            root_years=a.root_years, keep_root_key=True)
        self.root_backups.pop(token)      # nobody is there to download it; the key stays on this server
        return True

    def acme_ca_summary(self) -> dict | None:
        ac = self.acme_ca
        if not ac.loaded():
            return None
        st = self.acme.settings()
        crl = ac.crl()
        return {
            "mode": ac.mode, "hold": ac.hold, "sealed": ac.sealed(), "org": ac.meta.get("org"),
            "root": C.describe_cert(ac.root), "issuing": C.describe_cert(ac.issuing),
            "key_type": C.KEY_TYPES.get(ac.meta.get("key_type"), "?"),
            "permitted": [*ac.meta.get("permitted_dns", []), *ac.meta.get("permitted_ips", [])],
            "uncovered": ac.covers(st.domains, st.networks),
            "root_key_present": ac.root_key_present(), "root_key_exported": bool(ac.meta.get("root_key_exported")),
            "secret_configured": bool(self.cfg.acme_ca_passphrase),
            "crl": {"number": ac.meta.get("crl_number"), "next_update": crl.next_update_utc, "last_update": crl.last_update_utc,
                    "count": sum(1 for _ in crl)} if crl is not None else None,
            "issued": self.store._q("SELECT COUNT(*) AS n FROM certs WHERE issuer='acme'")[0]["n"],
        }

    # ---- views ----------------------------------------------------------------
    def alerts(self) -> list[dict]:
        out: list[dict] = []
        if not self.ca.loaded():
            return out
        if self.ca.sealed():
            out.append({"level": "warn", "text": "The CA is locked. Enter the CA passphrase to issue or revoke certificates.", "href": "/ca"})
        ui = self.ui_cert()
        if ui is not None and self.ca.sealed() and ui.not_valid_after_utc - C._now() < UI_RENEW_BEFORE:
            out.append({"level": "warn", "text": "This page's own certificate is about to expire. Unlock the CA so it can renew it.", "href": "/ca#unlock"})
        left = self.ca.intermediate.not_valid_after_utc - C._now()
        if left < timedelta(days=365):
            out.append({"level": "warn", "text": f"The intermediate CA expires in {left.days} days. Renew it on the CA page.", "href": "/ca"})
        if self.ca.root_key_present() and not self.store.get("root_key_exported"):
            out.append({"level": "info", "text": "Back up the root key, then take it off this server. It's only needed every few years.", "href": "/ca"})
        ac = self.acme_ca
        if ac.loaded():
            if ac.sealed():
                out.append({"level": "warn", "text": "The ACME issuing CA is locked, so ACME clients can't get certificates yet.", "href": "/acme/ca"})
            left = ac.issuing.not_valid_after_utc - C._now()
            if left < timedelta(days=180):
                out.append({"level": "warn", "text": f"The ACME issuing CA expires in {max(left.days, 0)} days. Renew it on the ACME CA page.", "href": "/acme/ca"})
            if ac.root_key_present() and ac.mode == "own-root" and not ac.meta.get("root_key_exported"):
                out.append({"level": "info", "text": "Back up the ACME root key, then take it off this server.", "href": "/acme/ca"})
            bad = ac.covers(self.acme.settings().domains, self.acme.settings().networks)
            if bad:
                out.append({"level": "warn", "text": f"The ACME issuing CA is limited to names that exclude {', '.join(bad)}. Clients asking for those will be refused.", "href": "/acme/ca"})
        elif self.acme.settings().enabled:
            out.append({"level": "info", "text": "ACME signs with your main intermediate. A separate ACME issuing CA keeps the main CA's key locked away.", "href": "/acme/ca"})
        n = self.store.counts()
        if n["expiring"]:
            out.append({"level": "info", "text": f"{n['expiring']} certificate{'s' if n['expiring'] != 1 else ''} expire within 30 days.", "href": "/certs?status=expiring"})
        return out

    def ca_summary(self) -> dict:
        ca = self.ca
        crl = ca.crl()
        ui = self.ui_cert()
        return {
            "org": ca.meta.get("org"),
            "root": C.describe_cert(ca.root), "intermediate": C.describe_cert(ca.intermediate),
            "sealed": ca.sealed(), "root_key_present": ca.root_key_present(),
            "root_key_exported": bool(self.store.get("root_key_exported")),
            "public_host": ca.public_host, "key_type": C.KEY_TYPES.get(ca.meta.get("key_type"), "?"),
            "permitted": [*ca.meta.get("permitted_dns", []), *ca.meta.get("permitted_ips", [])],
            "crl": {"number": ca.meta.get("crl_number"), "next_update": crl.next_update_utc, "last_update": crl.last_update_utc,
                    "count": sum(1 for _ in crl)} if crl is not None else None,
            "ui": C.describe_cert(ui) if ui else None,
            "ui_names": self.store.get("ui_names", []),
        }
