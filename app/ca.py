"""CertForge CA engine.

A small two-tier private PKI (offline-capable root -> online intermediate -> leaf).

All certificate work is done by the `cryptography` package, which is a binding
to OpenSSL.  The one thing done through the `openssl` command line is encrypting
CA private keys at rest: it produces a standard PKCS#8 file with a strong,
tunable key-derivation setting, which any OpenSSL install can read back.

Nothing in here talks to a database or the network; app/service.py wraps it.
"""
from __future__ import annotations

import base64
import datetime as dt
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)

UTC = dt.timezone.utc
KDF_ITERATIONS = 600_000          # PBKDF2 rounds for CA keys at rest
MAX_LEAF_DAYS = 825               # Apple's limit for TLS certs from private roots
BACKDATE = dt.timedelta(minutes=5)  # tolerate small clock differences
CRL_LIFETIME = dt.timedelta(days=7)
MIN_PASSPHRASE = 12


class CAError(Exception):
    """A problem the person can fix.  The message is safe to show them."""


class CASealed(CAError):
    """The intermediate key is encrypted and hasn't been unlocked since boot."""


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------

KEY_TYPES = {
    "ec-p256": "ECDSA P-256",
    "ec-p384": "ECDSA P-384",
    "rsa-2048": "RSA 2048",
    "rsa-3072": "RSA 3072",
    "rsa-4096": "RSA 4096",
}
CA_KEY_TYPES = ("ec-p384", "rsa-4096")
LEAF_KEY_TYPES = ("ec-p256", "ec-p384", "rsa-2048", "rsa-3072", "rsa-4096")


def generate_key(key_type: str):
    if key_type == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ec-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if key_type in ("rsa-2048", "rsa-3072", "rsa-4096"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[4:]))
    raise CAError("Unknown key type.")


_CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def describe_key(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA {_CURVES.get(public_key.curve.name, public_key.curve.name)}"
    return type(public_key).__name__


def _sig_hash(key) -> hashes.HashAlgorithm:
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        bits = key.curve.key_size
        if bits >= 521:
            return hashes.SHA512()
        if bits >= 384:
            return hashes.SHA384()
    return hashes.SHA256()


def _spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def check_passphrase(p: str) -> None:
    if len(p or "") < MIN_PASSPHRASE:
        raise CAError(f"The passphrase must be at least {MIN_PASSPHRASE} characters.")


def encrypt_key(key, passphrase: str) -> bytes:
    """PKCS#8, PBES2 / PBKDF2-HMAC-SHA256 (600k rounds) / AES-256-CBC, via OpenSSL."""
    check_passphrase(passphrase)
    openssl = shutil.which("openssl")
    if not openssl:
        raise CAError("The openssl command-line tool is missing on this server.")
    raw = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    r, w = os.pipe()  # the passphrase never appears on a command line or in the environment
    try:
        os.write(w, passphrase.encode())
        os.close(w)
        proc = subprocess.run(
            [openssl, "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256",
             "-iter", str(KDF_ITERATIONS), "-passout", f"fd:{r}"],
            input=raw, capture_output=True, pass_fds=(r,), timeout=60,
        )
    finally:
        os.close(r)
    if proc.returncode != 0 or b"ENCRYPTED PRIVATE KEY" not in proc.stdout:
        raise CAError("Could not encrypt the key with OpenSSL.")
    return proc.stdout


def load_encrypted_key(pem: bytes, passphrase: str):
    try:
        return serialization.load_pem_private_key(pem, passphrase.encode())
    except (ValueError, TypeError):
        raise CAError("That passphrase didn't unlock the key (or the key file is damaged).") from None


def _is_encrypted(pem: bytes) -> bool:
    return b"ENCRYPTED PRIVATE KEY" in pem[:80]


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_name(f"{path.name}.tmp{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,&'()_-]{0,39}$")


def clean_org(org: str) -> str:
    org = (org or "").strip()
    if not _ORG_RE.match(org):
        raise CAError("Use 1-40 letters, numbers, spaces or . , & ' ( ) _ - for the CA name.")
    return org


def _norm_dns(token: str) -> str:
    wildcard = token.startswith("*.")
    host = token[2:] if wildcard else token
    if not host or "*" in host:
        raise CAError(f"'{token}' isn't a valid name. A wildcard is only allowed as the first label, like *.example.lan.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise CAError(f"'{token}' isn't a valid host name.") from None
    if len(host) > 253:
        raise CAError(f"'{token}' is too long.")
    for label in host.split("."):
        if not _LABEL_RE.match(label):
            raise CAError(
                f"'{token}' has characters that aren't allowed in host names. "
                "Use letters, numbers and hyphens, separated by dots."
            )
    return ("*." if wildcard else "") + host


@dataclass
class Names:
    dns: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    def general_names(self) -> list[x509.GeneralName]:
        out: list[x509.GeneralName] = [x509.DNSName(d) for d in self.dns]
        out += [x509.IPAddress(ipaddress.ip_address(i)) for i in self.ips]
        return out

    def all(self) -> list[str]:
        return [*self.dns, *self.ips]

    def cn(self) -> str:
        cn = (self.dns or self.ips)[0]
        if len(cn) > 64:
            raise CAError("The first name is longer than 64 characters. Put a shorter name first.")
        return cn


def parse_names(raw: str | list[str], *, max_names: int = 100) -> Names:
    """Split on commas / spaces / newlines; accepts host names, wildcards and IPs."""
    tokens = re.split(r"[\s,;]+", raw.strip()) if isinstance(raw, str) else list(raw)
    names = Names()
    seen: set[str] = set()
    for t in tokens:
        t = t.strip().lower().rstrip(".").strip("[]")
        if not t:
            continue
        try:
            value, bucket = str(ipaddress.ip_address(t)), names.ips
        except ValueError:
            value, bucket = _norm_dns(t), names.dns
        if value not in seen:
            seen.add(value)
            bucket.append(value)
    if not names.all():
        raise CAError("Enter at least one host name or IP address.")
    if len(names.all()) > max_names:
        raise CAError(f"That's too many names (the limit is {max_names}).")
    return names


def parse_constraints(raw: str) -> tuple[list[str], list[str]]:
    """Domains (example.lan) and CIDR ranges (10.0.0.0/8) the CA may issue for."""
    dns: list[str] = []
    nets: list[str] = []
    for t in re.split(r"[\s,;]+", (raw or "").strip().lower()):
        if not t:
            continue
        try:
            nets.append(str(ipaddress.ip_network(t, strict=True)))
            continue
        except ValueError:
            pass
        t = t.lstrip("*").lstrip(".")
        d = _norm_dns(t)
        if d not in dns:
            dns.append(d)
    return dns, nets


# --------------------------------------------------------------------------
# Certificate helpers
# --------------------------------------------------------------------------

PURPOSES = {
    "both": ("Server and client", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
    "server": ("Web / TLS server", [ExtendedKeyUsageOID.SERVER_AUTH]),
    "client": ("Client authentication", [ExtendedKeyUsageOID.CLIENT_AUTH]),
}


def _now() -> dt.datetime:
    return dt.datetime.now(UTC).replace(microsecond=0)


def fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def serial_hex(n: int) -> str:
    """Serial number as OpenSSL and Windows print it: upper-case hex in whole bytes."""
    h = f"{n:X}"
    return h if len(h) % 2 == 0 else "0" + h


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def _ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def sans_of(cert: x509.Certificate) -> list[str]:
    san = _ext(cert, x509.SubjectAlternativeName)
    if not san:
        return []
    return san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]


def describe_cert(cert: x509.Certificate) -> dict:
    bc = _ext(cert, x509.BasicConstraints)
    nc = _ext(cert, x509.NameConstraints)
    eku = _ext(cert, x509.ExtendedKeyUsage)
    ku = _ext(cert, x509.KeyUsage)
    ku_names = []
    if ku:
        for attr, label in (("digital_signature", "Digital signature"), ("key_encipherment", "Key encipherment"),
                            ("key_cert_sign", "Certificate signing"), ("crl_sign", "CRL signing")):
            if getattr(ku, attr):
                ku_names.append(label)
    permitted = []
    if nc and nc.permitted_subtrees:
        for g in nc.permitted_subtrees:
            permitted.append(str(g.value))
    return {
        "subject": _cn(cert.subject),
        "issuer": _cn(cert.issuer),
        "subject_dn": cert.subject.rfc4514_string(),
        "serial": serial_hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "sha256": fingerprint(cert),
        "key": describe_key(cert.public_key()),
        "signature": cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "",
        "is_ca": bool(bc and bc.ca),
        "path_length": bc.path_length if bc else None,
        "sans": sans_of(cert),
        "permitted": permitted,
        "eku": [PURPOSE_LABELS.get(o.dotted_string, o.dotted_string) for o in (eku or [])],
        "key_usage": ku_names,
    }


PURPOSE_LABELS = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "TLS server",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "TLS client",
}


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def chain_pem(certs) -> bytes:
    return b"".join(pem(c) for c in certs)


def p7b(certs, *, binary: bool = False) -> bytes:
    enc = serialization.Encoding.DER if binary else serialization.Encoding.PEM
    return pkcs7.serialize_certificates(list(certs), enc)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9.-]+", "_", name.lower().replace("*", "wildcard")).strip("._-")
    return (s or "certificate")[:60]


def make_pkcs12(key, cert, chain, password: str, name: str, *, legacy: bool) -> bytes:
    """legacy=True uses 3DES/SHA-1, which old Windows, macOS Keychain and old Java import.
    legacy=False uses AES-256/SHA-256 (fine for current Linux, Windows 10+, Java 17+)."""
    pw = password.encode()
    if legacy:
        enc = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(pw)
        )
    else:
        enc = serialization.BestAvailableEncryption(pw)
    return pkcs12.serialize_key_and_certificates(name.encode(), key, cert, list(chain), enc)


_ZIP_README = """\
{cn}
{underline}

Files
  {slug}.crt            the certificate
  {slug}.key            the PRIVATE KEY - keep it secret, don't email it
  {slug}-fullchain.pem  certificate + intermediate (what most servers want)
  ca-chain.pem          intermediate + root (for clients/tools that need a bundle)

nginx
  ssl_certificate     /path/to/{slug}-fullchain.pem;
  ssl_certificate_key /path/to/{slug}.key;

Apache
  SSLCertificateFile    /path/to/{slug}.crt
  SSLCertificateKeyFile /path/to/{slug}.key
  SSLCertificateChainFile /path/to/ca-chain.pem

HAProxy   cat {slug}-fullchain.pem {slug}.key > {slug}.pem   (then: bind :443 ssl crt {slug}.pem)

Clients must trust the Root CA once. Get it from the CA's "Trust" page.
"""


def make_pem_zip(key, cert, intermediate, root, name: str) -> bytes:
    slug = slugify(name)
    buf = io.BytesIO()
    stamp = (2024, 1, 1, 0, 0, 0)
    files = [
        (f"{slug}.crt", pem(cert), 0o644),
        (f"{slug}.key", key_pem(key), 0o600),
        (f"{slug}-fullchain.pem", chain_pem([cert, intermediate]), 0o644),
        ("ca-chain.pem", chain_pem([intermediate, root]), 0o644),
        ("README.txt", _ZIP_README.format(cn=name, underline="=" * len(name), slug=slug).encode(), 0o644),
    ]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, data, mode in files:
            info = zipfile.ZipInfo(f"{slug}/{fname}", date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            z.writestr(info, data)
    return buf.getvalue()


def self_signed_bootstrap(names: Names) -> tuple[bytes, bytes]:
    """Throw-away certificate for the very first boot (before a CA exists).
    Nobody should trust it; it only lets the setup wizard run over HTTPS."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CertForge bootstrap (untrusted)")])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE).not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(names.general_names()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return pem(cert), key_pem(key)


# --------------------------------------------------------------------------
# CSRs
# --------------------------------------------------------------------------

def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    """Accepts PEM, PEM without the header lines, or raw DER."""
    data = data.strip()
    if not data:
        raise CAError("Paste a certificate request (CSR) or upload a file.")
    try:
        if b"-----BEGIN" in data:
            csr = x509.load_pem_x509_csr(data)
        else:
            try:
                csr = x509.load_der_x509_csr(base64.b64decode(b"".join(data.split()), validate=True))
            except Exception:
                csr = x509.load_der_x509_csr(data)
    except Exception:
        raise CAError(
            "That doesn't look like a certificate request. A CSR starts with "
            "-----BEGIN CERTIFICATE REQUEST-----."
        ) from None
    if not csr.is_signature_valid:
        raise CAError("The request's signature is invalid, so it was probably corrupted or edited.")
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise CAError(f"The request uses a {pub.key_size}-bit RSA key. 2048 bits is the minimum.")
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.curve.name not in _CURVES:
            raise CAError("Only the P-256, P-384 and P-521 curves are supported.")
    else:
        raise CAError("Only RSA and ECDSA keys are supported.")
    return csr


def csr_names(csr: x509.CertificateSigningRequest) -> tuple[Names, list[str]]:
    """Names asked for in the CSR (subject CN first, then SANs) and any that were unusable."""
    candidates: list[str] = []
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        candidates.append(str(cn_attrs[0].value))
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        candidates += san.get_values_for_type(x509.DNSName)
        candidates += [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    good: list[str] = []
    skipped: list[str] = []
    for c in candidates:
        try:
            parse_names(c)
            good.append(c)
        except CAError:
            skipped.append(c)
    names = parse_names(good) if good else Names()
    return names, skipped


# --------------------------------------------------------------------------
# Signing helpers shared by every authority (the main CA and the ACME issuing CA)
# --------------------------------------------------------------------------

def check_policy(permitted_dns: list[str], permitted_ips: list[str], names: Names, days: int | None = None) -> None:
    """Refuse names outside what an authority is limited to, and validity periods that are out of range."""
    nets = [ipaddress.ip_network(n) for n in permitted_ips]
    if permitted_dns:
        for d in names.dns:
            base = d[2:] if d.startswith("*.") else d
            if not any(base == p or base.endswith("." + p) for p in permitted_dns):
                raise CAError(f"'{d}' is outside the domains this CA is limited to ({', '.join(permitted_dns)}).")
    if nets:
        for i in names.ips:
            if not any(ipaddress.ip_address(i) in n for n in nets):
                raise CAError(f"{i} is outside the IP ranges this CA is limited to ({', '.join(map(str, nets))}).")
    if days is not None and not (1 <= days <= MAX_LEAF_DAYS):
        raise CAError(f"Validity must be between 1 and {MAX_LEAF_DAYS} days.")


def build_leaf(*, issuer_cert: x509.Certificate, issuer_key, public_key, names: Names, days: int, purpose: str,
               public_host: str | None, issuer_file: str = "intermediate") -> tuple[x509.Certificate, list[str]]:
    """A server/client certificate signed by `issuer_key`. The caller has already checked policy.
    `issuer_file` names the /pki/ downloads (<name>.cer and <name>.crl) written into the certificate."""
    if purpose not in PURPOSES:
        raise CAError("Unknown certificate purpose.")
    notices: list[str] = []
    now = _now()
    not_after = now + dt.timedelta(days=days)
    cap = issuer_cert.not_valid_after_utc
    if not_after > cap:
        not_after = cap
        notices.append(
            "The validity was shortened because the CA's intermediate certificate "
            f"expires on {cap:%Y-%m-%d}."
        )
    rsa_key = isinstance(public_key, rsa.RSAPublicKey)
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names.cn())]))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_ku(digital_signature=True, key_encipherment=rsa_key), critical=True)
        .add_extension(x509.ExtendedKeyUsage(PURPOSES[purpose][1]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names.general_names()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    )
    if public_host:
        base = f"http://{public_host}/pki"
        b = b.add_extension(
            x509.AuthorityInformationAccess([x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(f"{base}/{issuer_file}.cer"))]),
            critical=False)
        b = b.add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(f"{base}/{issuer_file}.crl")],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    cert = b.sign(issuer_key, _sig_hash(issuer_key))
    cert.verify_directly_issued_by(issuer_cert)  # belt and braces
    return cert, notices


def build_crl(*, issuer_cert: x509.Certificate, issuer_key, number: int,
              revoked: list[tuple[int, dt.datetime, str]]) -> x509.CertificateRevocationList:
    now = _now()
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now).next_update(now + CRL_LIFETIME)
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    )
    for serial, when, reason in revoked:
        rb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        flag = REASONS.get(reason, x509.ReasonFlags.unspecified)
        if flag is not x509.ReasonFlags.unspecified:
            rb = rb.add_extension(x509.CRLReason(flag), critical=False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(issuer_key, _sig_hash(issuer_key))


def same_key(key, cert: x509.Certificate) -> bool:
    return _spki(key.public_key()) == _spki(cert.public_key())


# --------------------------------------------------------------------------
# The authority
# --------------------------------------------------------------------------

def _ku(**on) -> x509.KeyUsage:
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False)
    base.update(on)
    return x509.KeyUsage(**base)


@dataclass
class Issued:
    cert: x509.Certificate
    key: object | None
    names: Names
    notices: list[str] = field(default_factory=list)


class CertAuthority:
    def __init__(self, data_dir: str | Path):
        self.dir = Path(data_dir) / "ca"
        self.lock = threading.RLock()
        self.root: x509.Certificate | None = None
        self.intermediate: x509.Certificate | None = None
        self._key = None
        self.meta: dict = {}

    # ---- state ----------------------------------------------------------
    def initialized(self) -> bool:
        return all((self.dir / f).exists() for f in ("root.crt", "intermediate.crt", "intermediate.key", "meta.json"))

    def loaded(self) -> bool:
        return self.root is not None and self.intermediate is not None

    def sealed(self) -> bool:
        return self.loaded() and self._key is None

    def root_key_present(self) -> bool:
        return (self.dir / "root.key").exists()

    @property
    def public_host(self) -> str | None:
        return self.meta.get("public_host") or None

    def chain(self) -> list[x509.Certificate]:
        return [self.intermediate, self.root]

    # ---- building certificates -----------------------------------------
    @staticmethod
    def _build_root(key, org: str, years: int, cn: str | None = None) -> x509.Certificate:
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn or f"{org} Root CA"),
        ])
        now = _now()
        return (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE).not_valid_after(now + dt.timedelta(days=int(years * 365.25)))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ku(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, _sig_hash(key))
        )

    @staticmethod
    def _build_intermediate(root_key, root_cert, int_pub, org: str, years: int,
                            permitted_dns: list[str], permitted_ips: list[str], cn: str | None = None) -> x509.Certificate:
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn or f"{org} Intermediate CA"),
        ])
        now = _now()
        not_after = min(now + dt.timedelta(days=int(years * 365.25)), root_cert.not_valid_after_utc)
        b = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(root_cert.subject).public_key(int_pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ku(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)
        )
        subtrees: list[x509.GeneralName] = [x509.DNSName(d) for d in permitted_dns]
        subtrees += [x509.IPAddress(ipaddress.ip_network(n)) for n in permitted_ips]
        if subtrees:
            b = b.add_extension(x509.NameConstraints(permitted_subtrees=subtrees, excluded_subtrees=None), critical=True)
        return b.sign(root_key, _sig_hash(root_key))

    # ---- lifecycle ------------------------------------------------------
    def create(self, *, org: str, key_type: str, passphrase: str, root_years: int = 20,
               int_years: int = 10, seal: bool = False, permitted: str = "",
               public_host: str | None = None) -> None:
        with self.lock:
            if self.initialized():
                raise CAError("A certificate authority already exists on this server.")
            org = clean_org(org)
            check_passphrase(passphrase)
            if key_type not in CA_KEY_TYPES:
                raise CAError("Choose ECDSA P-384 or RSA 4096 for the CA keys.")
            if not (5 <= root_years <= 30 and 1 <= int_years <= 15 and int_years < root_years):
                raise CAError("Pick a root lifetime of 5-30 years and a shorter intermediate lifetime (1-15 years).")
            dns, ips = parse_constraints(permitted)

            root_key, int_key = generate_key(key_type), generate_key(key_type)
            root_cert = self._build_root(root_key, org, root_years)
            int_cert = self._build_intermediate(root_key, root_cert, int_key.public_key(), org, int_years, dns, ips)

            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)
            atomic_write(self.dir / "root.key", encrypt_key(root_key, passphrase), 0o600)
            int_pem = encrypt_key(int_key, passphrase) if seal else key_pem(int_key)
            atomic_write(self.dir / "intermediate.key", int_pem, 0o600)
            atomic_write(self.dir / "root.crt", pem(root_cert), 0o644)
            atomic_write(self.dir / "intermediate.crt", pem(int_cert), 0o644)
            meta = {
                "org": org, "key_type": key_type, "created": _now().isoformat(),
                "public_host": public_host, "permitted_dns": dns, "permitted_ips": ips,
                "crl_number": 0,
            }
            atomic_write(self.dir / "meta.json", json.dumps(meta, indent=2).encode(), 0o644)
            self.load()
            # The person just typed the passphrase, so the CA is usable right now (setup issues
            # the web UI's own certificate). In sealed mode it locks again after a restart.
            self._key = int_key

    def load(self) -> bool:
        with self.lock:
            if not self.initialized():
                return False
            self.root = x509.load_pem_x509_certificate((self.dir / "root.crt").read_bytes())
            self.intermediate = x509.load_pem_x509_certificate((self.dir / "intermediate.crt").read_bytes())
            self.meta = json.loads((self.dir / "meta.json").read_text())
            raw = (self.dir / "intermediate.key").read_bytes()
            self._key = None if _is_encrypted(raw) else serialization.load_pem_private_key(raw, None)
            if self._key is not None and _spki(self._key.public_key()) != _spki(self.intermediate.public_key()):
                raise CAError("The intermediate key doesn't match the intermediate certificate.")
            return True

    def unlock(self, passphrase: str) -> None:
        with self.lock:
            if not self.sealed():
                return
            key = load_encrypted_key((self.dir / "intermediate.key").read_bytes(), passphrase)
            if _spki(key.public_key()) != _spki(self.intermediate.public_key()):
                raise CAError("The intermediate key doesn't match the intermediate certificate.")
            self._key = key

    def _require_key(self):
        if not self.loaded():
            raise CAError("The certificate authority hasn't been set up yet.")
        if self._key is None:
            raise CASealed("The CA is locked. Enter the CA passphrase to unlock it.")
        return self._key

    def update_public_host(self, host: str | None) -> None:
        with self.lock:
            self.meta["public_host"] = host
            atomic_write(self.dir / "meta.json", json.dumps(self.meta, indent=2).encode(), 0o644)

    # ---- root key custody ----------------------------------------------
    def export_root_key(self, passphrase: str) -> bytes:
        with self.lock:
            if not self.root_key_present():
                raise CAError("The root key isn't stored on this server.")
            blob = (self.dir / "root.key").read_bytes()
            key = load_encrypted_key(blob, passphrase)  # proves the passphrase works
            if _spki(key.public_key()) != _spki(self.root.public_key()):
                raise CAError("The stored root key doesn't match the root certificate.")
            return blob

    def remove_root_key(self) -> None:
        with self.lock:
            try:
                (self.dir / "root.key").unlink()
            except FileNotFoundError:
                pass

    def load_root_key(self, passphrase: str, root_key_pem: bytes | None = None):
        """The decrypted root key, from this server or from an uploaded backup. Proves the passphrase and the match."""
        with self.lock:
            if root_key_pem is None:
                if not self.root_key_present():
                    raise CAError("The root key isn't on this server. Upload your root key backup to continue.")
                root_key_pem = (self.dir / "root.key").read_bytes()
            root_key = load_encrypted_key(root_key_pem, passphrase)
            if _spki(root_key.public_key()) != _spki(self.root.public_key()):
                raise CAError("That key isn't the key for this root certificate.")
            return root_key

    def renew_intermediate(self, passphrase: str, root_key_pem: bytes | None = None, years: int = 10) -> x509.Certificate:
        """Re-sign the existing intermediate key with the root (new validity period).
        Certificates already issued stay valid: same name, same key."""
        with self.lock:
            root_key = self.load_root_key(passphrase, root_key_pem)
            new = self._build_intermediate(
                root_key, self.root, self.intermediate.public_key(), self.meta["org"], years,
                self.meta.get("permitted_dns", []), self.meta.get("permitted_ips", []),
            )
            archive = self.dir / "archive"
            archive.mkdir(exist_ok=True)
            atomic_write(archive / f"intermediate-{serial_hex(self.intermediate.serial_number)}.crt",
                          pem(self.intermediate), 0o644)
            atomic_write(self.dir / "intermediate.crt", pem(new), 0o644)
            self.intermediate = new
            return new

    # ---- policy ---------------------------------------------------------
    def check_policy(self, names: Names, days: int | None = None) -> None:
        check_policy(self.meta.get("permitted_dns", []), self.meta.get("permitted_ips", []), names, days)

    # ---- issuing --------------------------------------------------------
    def _sign_leaf(self, public_key, names: Names, days: int, purpose: str) -> tuple[x509.Certificate, list[str]]:
        key = self._require_key()
        self.check_policy(names, days)
        return build_leaf(issuer_cert=self.intermediate, issuer_key=key, public_key=public_key, names=names,
                          days=days, purpose=purpose, public_host=self.public_host)

    def issue_generated(self, names: Names, days: int, purpose: str, key_type: str) -> Issued:
        """We make the key pair too. The private key is returned once and never stored."""
        if key_type not in LEAF_KEY_TYPES:
            raise CAError("Unknown key type.")
        with self.lock:
            self._require_key()
            key = generate_key(key_type)
            cert, notices = self._sign_leaf(key.public_key(), names, days, purpose)
            return Issued(cert, key, names, notices)

    def sign_csr(self, csr: x509.CertificateSigningRequest, names: Names, days: int, purpose: str) -> Issued:
        """Sign a CSR's public key. Only the *names* are taken from the request; the CA
        decides key usage, constraints and everything else."""
        with self.lock:
            cert, notices = self._sign_leaf(csr.public_key(), names, days, purpose)
            return Issued(cert, None, names, notices)

    # ---- CRL ------------------------------------------------------------
    def make_crl(self, revoked: list[tuple[int, dt.datetime, str]]) -> x509.CertificateRevocationList:
        with self.lock:
            key = self._require_key()
            number = int(self.meta.get("crl_number", 0)) + 1
            crl = build_crl(issuer_cert=self.intermediate, issuer_key=key, number=number, revoked=revoked)
            atomic_write(self.dir / "intermediate.crl", crl.public_bytes(serialization.Encoding.DER), 0o644)
            self.meta["crl_number"] = number
            atomic_write(self.dir / "meta.json", json.dumps(self.meta, indent=2).encode(), 0o644)
            return crl

    def crl(self) -> x509.CertificateRevocationList | None:
        p = self.dir / "intermediate.crl"
        return x509.load_der_x509_crl(p.read_bytes()) if p.exists() else None


REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
}
REASON_LABELS = {
    "unspecified": "No reason given",
    "keyCompromise": "Private key was exposed",
    "affiliationChanged": "Owner or purpose changed",
    "superseded": "Replaced by a newer certificate",
    "cessationOfOperation": "No longer needed",
}
