"""A small ACME client for the tests: real JWS signing, no shortcuts.

It talks through a `transport(method, url, body, headers) -> Resp`, so the same client drives the server
in-process (fast protocol tests) or over real HTTPS (end-to-end tests).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Resp:
    status: int
    headers: dict
    body: bytes
    _json: object = field(default=None, repr=False)

    def json(self):
        return json.loads(self.body)

    @property
    def problem(self) -> str:
        return self.json()["type"].rsplit(":", 1)[-1]


def kind_for(path: str) -> tuple[str, str]:
    """URL path -> (endpoint kind, id), mirroring the routes in app/acme.py."""
    if m := re.fullmatch(r"/acme/(directory|new-nonce|new-account|new-order|revoke-cert)", path):
        return m.group(1), ""
    if m := re.fullmatch(r"/acme/acct/([^/]+)/orders", path):
        return "orders", m.group(1)
    for kind, seg in (("account", "acct"), ("order", "order"), ("authz", "authz"), ("chall", "chall"), ("finalize", "finalize"), ("cert", "cert")):
        if m := re.fullmatch(rf"/acme/{seg}/([^/]+)", path):
            return kind, m.group(1)
    raise AssertionError(f"not an ACME path: {path}")


class InProcess:
    """Calls Acme.handle directly."""

    def __init__(self, acme, base: str):
        self.acme, self.base = acme, base

    def __call__(self, method: str, url: str, body: bytes | None, headers: dict) -> Resp:
        kind, ident = kind_for(url[len(self.base):])
        r = self.acme.handle(kind, method=method, base=self.base, url=url, body=body or b"",
                             content_type=headers.get("Content-Type", ""), ident=ident, remote="127.0.0.1")
        return Resp(r.status, {k.lower(): v for k, v in r.headers.items()}, r.body if method != "HEAD" else b"")


class Http:
    def __init__(self, session, extra_headers: dict | None = None):
        self.s, self.extra = session, extra_headers or {}

    def __call__(self, method: str, url: str, body: bytes | None, headers: dict) -> Resp:
        r = self.s.request(method, url, data=body, headers={**headers, **self.extra}, allow_redirects=False, timeout=30)
        return Resp(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


class Client:
    def __init__(self, transport, base: str, alg: str = "ES256", key=None):
        self.t, self.base, self.alg = transport, base, alg
        self.key = key or {"ES256": lambda: ec.generate_private_key(ec.SECP256R1()),
                           "ES384": lambda: ec.generate_private_key(ec.SECP384R1()),
                           "RS256": lambda: rsa.generate_private_key(65537, 2048)}[alg]()
        self.kid: str | None = None
        self.nonce: str | None = None

    # ---- keys
    @property
    def jwk(self) -> dict:
        pub = self.key.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            n = pub.public_numbers()
            return {"kty": "RSA", "n": b64e(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
                    "e": b64e(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"))}
        size = 32 if self.alg == "ES256" else 48
        n = pub.public_numbers()
        return {"kty": "EC", "crv": "P-256" if size == 32 else "P-384",
                "x": b64e(n.x.to_bytes(size, "big")), "y": b64e(n.y.to_bytes(size, "big"))}

    @property
    def thumbprint(self) -> str:
        j = self.jwk
        members = ("e", "kty", "n") if j["kty"] == "RSA" else ("crv", "kty", "x", "y")
        return b64e(hashlib.sha256(json.dumps({k: j[k] for k in members}, separators=(",", ":"), sort_keys=True).encode()).digest())

    def key_authorization(self, token: str) -> str:
        return f"{token}.{self.thumbprint}"

    def sign(self, data: bytes) -> bytes:
        if self.alg == "RS256":
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        h, size = (hashes.SHA256(), 32) if self.alg == "ES256" else (hashes.SHA384(), 48)
        r, s = utils.decode_dss_signature(self.key.sign(data, ec.ECDSA(h)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    # ---- plumbing
    def get_nonce(self) -> str:
        r = self.t("HEAD", f"{self.base}/acme/new-nonce", None, {})
        return r.headers["replay-nonce"]

    def jws(self, url: str, payload, *, kid: bool = True, nonce: str | None = None, alg: str | None = None,
            protected_extra: dict | None = None, tamper: bool = False) -> bytes:
        prot = {"alg": alg or self.alg, "nonce": nonce or self.nonce or self.get_nonce(), "url": url}
        prot.update({"kid": self.kid} if (kid and self.kid) else {"jwk": self.jwk})
        prot.update(protected_extra or {})
        p64 = b64e(json.dumps(prot).encode())
        pay64 = "" if payload is None else b64e(json.dumps(payload).encode())
        sig = self.sign(f"{p64}.{pay64}".encode())
        if tamper:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        return json.dumps({"protected": p64, "payload": pay64, "signature": b64e(sig)}).encode()

    def post(self, url: str, payload, **kw) -> Resp:
        raw = kw.pop("raw", None)
        content_type = kw.pop("content_type", "application/jose+json")
        body = raw if raw is not None else self.jws(url, payload, **kw)
        self.nonce = None
        r = self.t("POST", url, body, {"Content-Type": content_type})
        self.nonce = r.headers.get("replay-nonce")
        return r

    # ---- the protocol
    def directory(self) -> dict:
        return self.t("GET", f"{self.base}/acme/directory", None, {}).json()

    def new_account(self, contact=None, eab=None, only_existing=False, **kw) -> Resp:
        payload: dict = {"termsOfServiceAgreed": True}
        if contact:
            payload["contact"] = contact
        if only_existing:
            payload["onlyReturnExisting"] = True
        if eab:
            payload["externalAccountBinding"] = self.eab_binding(*eab)
        r = self.post(f"{self.base}/acme/new-account", payload, kid=False, **kw)
        if r.status in (200, 201):
            self.kid = r.headers["location"]
        return r

    def eab_binding(self, kid: str, hmac_key_b64: str, *, alg: str = "HS256", url: str | None = None, jwk: dict | None = None) -> dict:
        prot = b64e(json.dumps({"alg": alg, "kid": kid, "url": url or f"{self.base}/acme/new-account"}).encode())
        pay = b64e(json.dumps(jwk or self.jwk).encode())
        mac = hmac.new(b64d(hmac_key_b64), f"{prot}.{pay}".encode(), {"HS256": hashlib.sha256, "HS384": hashlib.sha384}[alg]).digest()
        return {"protected": prot, "payload": pay, "signature": b64e(mac)}

    def new_order(self, identifiers: list) -> Resp:
        return self.post(f"{self.base}/acme/new-order", {"identifiers": identifiers})

    def poll(self, url: str) -> Resp:
        return self.post(url, None)

    def poke(self, chall_url: str) -> Resp:
        return self.post(chall_url, {})

    def finalize(self, order: dict, csr_der: bytes) -> Resp:
        return self.post(order["finalize"], {"csr": b64e(csr_der)})

    def revoke(self, cert_der: bytes, reason: int | None = None, **kw) -> Resp:
        payload: dict = {"certificate": b64e(cert_der)}
        if reason is not None:
            payload["reason"] = reason
        return self.post(f"{self.base}/acme/revoke-cert", payload, **kw)


def make_csr(names: list[str], key=None, *, hash_alg=None) -> tuple[bytes, object]:
    """DER CSR with a subjectAltName for each name (IPs are recognised)."""
    import ipaddress
    key = key or ec.generate_private_key(ec.SECP256R1())
    gns = []
    for n in names:
        try:
            gns.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            gns.append(x509.DNSName(n))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName(gns), critical=False)
           .sign(key, hash_alg or hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.DER), key
