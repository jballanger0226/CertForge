"""ACME server (RFC 8555), so certbot, acme.sh, lego, Caddy, Traefik, Proxmox and friends can get and renew
certificates from this CA on their own.

Scope:
  * HTTP-01 validation (the client serves a token on port 80). DNS-01 and TLS-ALPN-01 aren't offered, so no wildcards.
  * Identifier types "dns" and "ip" (RFC 8738).
  * Only names inside the allow-list set on the ACME page are issued; optional external account binding
    (EAB) restricts who may register.
  * Short-lived certificates (the lifetime is a setting, 90 days by default).

All protocol logic lives in `Acme.handle`, which takes plain values and returns a `Reply`; `routes()` is a thin
Starlette wrapper around it, so the protocol can be tested without HTTP.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils

from . import ca as C
from . import netinfo
from .store import iso, parse_iso, utcnow

PROBLEM = "urn:ietf:params:acme:error:"
ORDER_LIFETIME = timedelta(days=7)
MAX_IDENTIFIERS = 20
JWS_ALGS = ("ES256", "ES384", "RS256")
EAB_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
REVOKE_REASONS = {0: "unspecified", 1: "keyCompromise", 3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation"}
CHALLENGE_PATH = "/.well-known/acme-challenge/"


class AcmeError(Exception):
    def __init__(self, kind: str, detail: str, status: int = 400, extra: dict | None = None):
        super().__init__(detail)
        self.kind, self.detail, self.status, self.extra = kind, detail, status, extra or {}

    def problem(self) -> dict:
        return {"type": PROBLEM + self.kind, "detail": self.detail, "status": self.status, **self.extra}


@dataclass
class Reply:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


# ---- encoding, keys, signatures ------------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(s) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise AcmeError("malformed", "Expected base64url text.")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_public_key(jwk: dict):
    try:
        if jwk.get("kty") == "RSA":
            n, e = int.from_bytes(b64d(jwk["n"]), "big"), int.from_bytes(b64d(jwk["e"]), "big")
            if not (2048 <= n.bit_length() <= 8192):
                raise AcmeError("badPublicKey", "RSA account keys must be 2048 to 8192 bits.")
            if e < 3 or e % 2 == 0:
                raise AcmeError("badPublicKey", "Unusable RSA public exponent.")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if jwk.get("kty") == "EC":
            curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}.get(jwk.get("crv"))
            if curve is None:
                raise AcmeError("badPublicKey", "EC account keys must use P-256 or P-384.")
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"), curve()).public_key()
    except (KeyError, TypeError, ValueError):
        raise AcmeError("badPublicKey", "That public key isn't valid.") from None
    raise AcmeError("badPublicKey", "Supported account key types are RSA and EC (P-256, P-384).")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638."""
    members = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y")}[jwk["kty"]]
    canonical = json.dumps({k: jwk[k] for k in members}, separators=(",", ":"), sort_keys=True)
    return b64e(hashlib.sha256(canonical.encode()).digest())


def verify_signature(alg: str, key, signing_input: bytes, sig: bytes) -> None:
    try:
        if alg == "RS256":
            if not isinstance(key, rsa.RSAPublicKey):
                raise AcmeError("malformed", "The key doesn't match the signature algorithm.")
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            curve, h, size = {"ES256": ("secp256r1", hashes.SHA256, 32), "ES384": ("secp384r1", hashes.SHA384, 48)}[alg]
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != curve or len(sig) != 2 * size:
                raise AcmeError("malformed", "The key doesn't match the signature algorithm.")
            der = asym_utils.encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
            key.verify(der, signing_input, ec.ECDSA(h()))
    except InvalidSignature:
        raise AcmeError("malformed", "The request's signature is invalid.", 400) from None


# ---- small helpers -------------------------------------------------------------------------------
class Nonces:
    """Single-use, short-lived, bounded in size (the endpoint that hands them out is unauthenticated)."""

    def __init__(self, ttl: float = 600, cap: int = 20000):
        self.ttl, self.cap = ttl, cap
        self._items: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def new(self) -> str:
        n = b64e(secrets.token_bytes(16))
        with self._lock:
            self._items[n] = time.monotonic() + self.ttl
            while len(self._items) > self.cap:
                self._items.popitem(last=False)
        return n

    def use(self, n: str) -> bool:
        with self._lock:
            exp = self._items.pop(n, None)
        return exp is not None and exp > time.monotonic()


class RateGate:
    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - self.window}
            q = self._hits.setdefault(key, deque())
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


def unsafe_address(addr: str) -> str:
    """Why this CA won't connect to an address when validating, or '' if it's fine. LAN addresses are the
    whole point of a private CA, so only addresses that can never be a real host are refused."""
    ip = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for bad, why in ((ip.is_loopback, "loopback"), (ip.is_unspecified, "unspecified"), (ip.is_link_local, "link-local"),
                     (ip.is_multicast, "multicast"), (ip.is_reserved, "reserved")):
        if bad:
            return why
    return ""


def http_fetch(addr: str, host_header: str, path: str, timeout: float = 5.0, limit: int = 2048, port: int = 80) -> tuple[int, bytes]:
    """GET http://addr:80/path with a fixed Host header. Redirects are NOT followed (keeps this from being
    steered at other internal services) and the body is capped."""
    conn = http.client.HTTPConnection(addr, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": host_header, "User-Agent": "CertForge-ACME-validation", "Connection": "close"})
        resp = conn.getresponse()
        return resp.status, resp.read(limit + 1)
    finally:
        conn.close()


def resolve_all(name: str) -> list[str]:
    return sorted(netinfo.resolve(name, ttl=0))


# ---- settings --------------------------------------------------------------------------------------
@dataclass
class AcmeSettings:
    enabled: bool = False
    domains: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    days: int = 90
    require_eab: bool = False

    @classmethod
    def load(cls, store) -> "AcmeSettings":
        raw = store.get("acme", {}) or {}
        return cls(enabled=bool(raw.get("enabled")), domains=list(raw.get("domains", [])), networks=list(raw.get("networks", [])),
                   days=int(raw.get("days", 90)), require_eab=bool(raw.get("require_eab")))

    def save(self, store) -> None:
        store.set("acme", {"enabled": self.enabled, "domains": self.domains, "networks": self.networks,
                           "days": self.days, "require_eab": self.require_eab})

    def allows(self, kind: str, value: str) -> bool:
        if kind == "dns":
            return any(value == d or value.endswith("." + d) for d in self.domains)
        ip = ipaddress.ip_address(value)
        return any(ip in ipaddress.ip_network(n) for n in self.networks)


def parse_domains(raw: str) -> list[str]:
    out: list[str] = []
    for token in re.split(r"[\s,;]+", raw.strip()):
        t = token.strip().lower().strip(".")
        if not t:
            continue
        if "*" in t:
            raise C.CAError(f"'{token}': wildcards aren't supported, because they need the DNS-01 challenge.")
        try:
            parsed = C.parse_names([t])
        except C.CAError as e:
            raise C.CAError(f"'{token}': {e}") from None
        if parsed.ips or len(parsed.dns) != 1:
            raise C.CAError(f"'{token}' isn't a domain name. Put IP ranges in the networks box.")
        if parsed.dns[0] not in out:
            out.append(parsed.dns[0])
    return out


def parse_networks(raw: str) -> list[str]:
    out: list[str] = []
    for token in re.split(r"[\s,;]+", raw.strip()):
        if not token:
            continue
        try:
            n = str(ipaddress.ip_network(token, strict=False))
        except ValueError:
            raise C.CAError(f"'{token}' isn't an IP range. Example: 192.168.1.0/24") from None
        if n not in out:
            out.append(n)
    return out


# ---- the server ------------------------------------------------------------------------------------
@dataclass
class Auth:
    jwk: dict | None
    account: dict | None
    payload: dict | None      # None for POST-as-GET


class Acme:
    def __init__(self, svc, fetch=http_fetch, resolve=resolve_all):
        self.svc = svc
        self.store = svc.store
        self.fetch, self.resolve = fetch, resolve
        self.nonces = Nonces()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="acme-validate")
        self.order_gate = RateGate(60, 3600)         # new orders per account per hour
        self.account_gate = RateGate(20, 3600)       # new accounts per client address per hour
        self._reset_interrupted()

    # ---- settings and admin ------------------------------------------------------------------
    def settings(self) -> AcmeSettings:
        return AcmeSettings.load(self.store)

    def save_settings(self, actor: str, *, enabled: bool, domains_raw: str, networks_raw: str, days: int, require_eab: bool) -> None:
        domains, networks = parse_domains(domains_raw), parse_networks(networks_raw)
        if not 1 <= days <= C.MAX_LEAF_DAYS:
            raise C.CAError(f"Certificate lifetime must be between 1 and {C.MAX_LEAF_DAYS} days.")
        if enabled and not (domains or networks):
            raise C.CAError("List at least one domain or network ACME clients may request, then turn it on.")
        AcmeSettings(enabled, domains, networks, days, require_eab).save(self.store)
        self.store.audit(actor, "acme", f"ACME {'on' if enabled else 'off'}; domains: {', '.join(domains) or 'none'}; "
                                        f"networks: {', '.join(networks) or 'none'}; {days} days"
                                        f"{'; account key required' if require_eab else ''}")

    def new_eab(self, actor: str, label: str) -> tuple[str, str]:
        kid, key = secrets.token_urlsafe(9), b64e(secrets.token_bytes(32))
        self.store._x("INSERT INTO acme_eab(kid,hmac_key,label,created) VALUES(?,?,?,?)", (kid, key, label.strip()[:60] or "unnamed", iso(utcnow())))
        self.store.audit(actor, "acme", f"Account key {kid} created ({label.strip()[:60] or 'unnamed'})")
        return kid, key

    def revoke_eab(self, actor: str, kid: str) -> None:
        if not self.store._x("UPDATE acme_eab SET revoked=1 WHERE kid=?", (kid,)):
            raise C.CAError("No such account key.")
        self.store.audit(actor, "acme", f"Account key {kid} revoked")

    def deactivate_account(self, actor: str, account_id: str) -> None:
        if not self.store._x("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (account_id,)):
            raise C.CAError("No such ACME account.")
        self.store.audit(actor, "acme", f"ACME account {account_id} deactivated")

    def overview(self) -> dict:
        q = self.store._q
        return {
            "settings": self.settings(),
            "eab": q("SELECT kid,label,created,account,revoked FROM acme_eab ORDER BY created DESC"),
            "accounts": q("SELECT a.id, a.contact, a.status, a.created, a.eab_kid, "
                          "(SELECT COUNT(*) FROM acme_orders o WHERE o.account=a.id AND o.status='valid') AS issued "
                          "FROM acme_accounts a ORDER BY a.created DESC LIMIT 100"),
            "recent": q("SELECT o.id, o.account, o.status, o.identifiers, o.created, o.serial FROM acme_orders o "
                        "ORDER BY o.created DESC LIMIT 15"),
        }

    def cleanup(self) -> None:
        """Drop old orders that never produced a certificate."""
        cutoff = iso(utcnow() - timedelta(days=30))
        self.store._x("DELETE FROM acme_authz WHERE order_id IN (SELECT id FROM acme_orders WHERE status!='valid' AND expires<?)", (cutoff,))
        self.store._x("DELETE FROM acme_orders WHERE status!='valid' AND expires<?", (cutoff,))

    def _reset_interrupted(self) -> None:
        """A restart kills in-flight validations; fail them so clients start a fresh order."""
        for a in self.store._q("SELECT id, order_id FROM acme_authz WHERE chall_status='processing'"):
            self._finish_validation(a["id"], {"type": PROBLEM + "serverInternal", "detail": "The server restarted during validation.", "status": 500})

    # ---- request entry point -----------------------------------------------------------------
    def handle(self, kind: str, *, method: str, base: str, url: str, body: bytes = b"", content_type: str = "",
               ident: str = "", remote: str = "") -> Reply:
        try:
            if not self.settings().enabled:
                raise AcmeError("malformed", "ACME isn't turned on on this server.", 404)
            reply = self._dispatch(kind, method, base, url, body, content_type, ident, remote)
        except AcmeError as e:
            reply = Reply(e.status, json.dumps(e.problem()).encode(), {"Content-Type": "application/problem+json"})
        reply.headers["Replay-Nonce"] = self.nonces.new()
        reply.headers["Cache-Control"] = "no-store"
        index = f'<{base}/acme/directory>;rel="index"'
        reply.headers["Link"] = f'{reply.headers["Link"]}, {index}' if "Link" in reply.headers else index    # keep e.g. rel="up"
        return reply

    def _dispatch(self, kind, method, base, url, body, content_type, ident, remote) -> Reply:
        if kind == "directory":
            return self._need(method, "GET") or self._json({
                "newNonce": f"{base}/acme/new-nonce", "newAccount": f"{base}/acme/new-account",
                "newOrder": f"{base}/acme/new-order", "revokeCert": f"{base}/acme/revoke-cert",
                "meta": {"externalAccountRequired": self.settings().require_eab}})
        if kind == "new-nonce":
            if method not in ("GET", "HEAD"):
                raise AcmeError("malformed", "Use GET or HEAD here.", 405)
            return Reply(200 if method == "HEAD" else 204)
        if method != "POST":
            raise AcmeError("malformed", "Use POST here.", 405)
        if not content_type.lower().startswith("application/jose+json"):
            raise AcmeError("malformed", "Requests must have Content-Type: application/jose+json.", 415)
        if kind == "new-account":
            return self._new_account(self._authn(base, url, body, kid_ok=False), base, url, remote)
        if kind == "revoke-cert":
            return self._revoke(self._authn(base, url, body), base)
        auth = self._authn(base, url, body, jwk_ok=False)
        acct = auth.account
        handler = {"account": self._account, "orders": self._orders, "new-order": self._new_order, "order": self._order,
                   "authz": self._authz, "chall": self._challenge, "finalize": self._finalize, "cert": self._certificate}.get(kind)
        if handler is None:
            raise AcmeError("malformed", "Unknown ACME endpoint.", 404)
        return handler(auth, acct, base, ident)

    @staticmethod
    def _need(method: str, want: str):
        if method != want:
            raise AcmeError("malformed", f"Use {want} here.", 405)

    @staticmethod
    def _json(obj: dict, status: int = 200, headers: dict | None = None) -> Reply:
        return Reply(status, json.dumps(obj).encode(), {"Content-Type": "application/json", **(headers or {})})

    # ---- JWS -----------------------------------------------------------------------------------
    def _authn(self, base: str, url: str, body: bytes, *, jwk_ok: bool = True, kid_ok: bool = True) -> Auth:
        try:
            outer = json.loads(body)
            prot_b64, pay_b64, sig_b64 = outer["protected"], outer["payload"], outer["signature"]
            if "header" in outer or not all(isinstance(x, str) for x in (prot_b64, pay_b64, sig_b64)):
                raise ValueError
            prot = json.loads(b64d(prot_b64))
            if not isinstance(prot, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise AcmeError("malformed", "The request body isn't a valid flattened JWS.") from None
        alg = prot.get("alg")
        if alg not in JWS_ALGS:
            raise AcmeError("badSignatureAlgorithm", f"Use one of: {', '.join(JWS_ALGS)}.", 400, {"algorithms": list(JWS_ALGS)})
        if ("jwk" in prot) == ("kid" in prot):
            raise AcmeError("malformed", "Provide exactly one of jwk and kid in the protected header.")
        if prot.get("url") != url:
            raise AcmeError("malformed", f"The JWS url ({prot.get('url')}) doesn't match this request ({url}).")
        if not isinstance(prot.get("nonce"), str) or not self.nonces.use(prot["nonce"]):
            raise AcmeError("badNonce", "That nonce isn't valid (or was already used). Retry with the new one.")

        account = None
        if "jwk" in prot:
            if not jwk_ok:
                raise AcmeError("malformed", "This request must be signed with the account key id (kid), not a jwk.")
            jwk = prot["jwk"]
            if not isinstance(jwk, dict):
                raise AcmeError("malformed", "jwk must be an object.")
            key = jwk_public_key(jwk)
        else:
            if not kid_ok:
                raise AcmeError("malformed", "This request must carry the account's public key (jwk), not a kid.")
            kid = prot["kid"]
            prefix = f"{base}/acme/acct/"
            if not isinstance(kid, str) or not kid.startswith(prefix) or "/" in kid[len(prefix):]:
                raise AcmeError("malformed", "That kid isn't an account URL on this server.")
            account = self._account_row(kid[len(prefix):])
            jwk = json.loads(account["jwk"])
            key = jwk_public_key(jwk)
        verify_signature(alg, key, f"{prot_b64}.{pay_b64}".encode(), b64d(sig_b64))

        payload = None
        if pay_b64 != "":
            try:
                payload = json.loads(b64d(pay_b64))
            except ValueError:
                raise AcmeError("malformed", "The payload isn't JSON.") from None
            if not isinstance(payload, dict):
                raise AcmeError("malformed", "The payload must be a JSON object.")
        return Auth(jwk if "jwk" in prot else None, account, payload)

    def _account_row(self, acct_id: str) -> dict:
        rows = self.store._q("SELECT * FROM acme_accounts WHERE id=?", (acct_id,))
        if not rows:
            raise AcmeError("accountDoesNotExist", "There's no ACME account with that id.")
        if rows[0]["status"] != "valid":
            raise AcmeError("unauthorized", "That account has been deactivated.", 403)
        return rows[0]

    # ---- accounts ------------------------------------------------------------------------------
    @staticmethod
    def _contacts(payload: dict) -> list[str]:
        contact = payload.get("contact", [])
        if not isinstance(contact, list) or len(contact) > 5 or not all(isinstance(c, str) and len(c) < 256 for c in contact):
            raise AcmeError("invalidContact", "contact must be a short list of mailto: URLs.")
        for c in contact:
            if not c.lower().startswith("mailto:"):
                raise AcmeError("unsupportedContact", "Only mailto: contacts are supported.")
        return contact

    def _account_obj(self, base: str, row: dict) -> dict:
        return {"status": row["status"], "contact": json.loads(row["contact"]), "orders": f"{base}/acme/acct/{row['id']}/orders"}

    def _new_account(self, auth: Auth, base: str, url: str, remote: str) -> Reply:
        payload = auth.payload
        if payload is None:
            raise AcmeError("malformed", "new-account needs a payload.")
        thumb = jwk_thumbprint(auth.jwk)
        existing = self.store._q("SELECT * FROM acme_accounts WHERE thumb=?", (thumb,))
        if existing:
            if existing[0]["status"] != "valid":
                raise AcmeError("unauthorized", "That account has been deactivated.", 403)
            return self._json(self._account_obj(base, existing[0]), 200, {"Location": f"{base}/acme/acct/{existing[0]['id']}"})
        if payload.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "No account exists for that key.")
        contact = self._contacts(payload)
        eab_kid = self._check_eab(payload.get("externalAccountBinding"), auth.jwk, url, thumb)
        if not self.account_gate.allow(remote or "?"):
            raise AcmeError("rateLimited", "Too many new accounts from this address. Try again later.", 429)
        acct_id = secrets.token_urlsafe(9)
        self.store._x("INSERT INTO acme_accounts(id,thumb,jwk,contact,status,created,eab_kid) VALUES(?,?,?,?,?,?,?)",
                      (acct_id, thumb, json.dumps(auth.jwk, sort_keys=True), json.dumps(contact), "valid", iso(utcnow()), eab_kid))
        if eab_kid:
            self.store._x("UPDATE acme_eab SET account=? WHERE kid=?", (acct_id, eab_kid))
        self.store.audit("acme", "acme", f"ACME account {acct_id} registered{' with key ' + eab_kid if eab_kid else ''}")
        row = self.store._q("SELECT * FROM acme_accounts WHERE id=?", (acct_id,))[0]
        return self._json(self._account_obj(base, row), 201, {"Location": f"{base}/acme/acct/{acct_id}"})

    def _check_eab(self, eab, jwk: dict, url: str, thumb: str) -> str | None:
        required = self.settings().require_eab
        if eab is None:
            if required:
                raise AcmeError("externalAccountRequired", "This server needs an account key. Ask the administrator for a key id and HMAC key.", 403)
            return None
        try:
            prot_b64, pay_b64, sig_b64 = eab["protected"], eab["payload"], eab["signature"]
            prot = json.loads(b64d(prot_b64))
            alg, kid = prot["alg"], prot["kid"]
            signed_jwk = json.loads(b64d(pay_b64))
        except (ValueError, KeyError, TypeError):
            raise AcmeError("malformed", "The externalAccountBinding isn't a valid JWS.") from None
        if alg not in EAB_ALGS or prot.get("url") != url or signed_jwk != jwk:
            raise AcmeError("unauthorized", "The externalAccountBinding doesn't match this request.", 403)
        rows = self.store._q("SELECT * FROM acme_eab WHERE kid=?", (kid,))
        if not rows or rows[0]["revoked"]:
            raise AcmeError("unauthorized", "Unknown or revoked account key.", 403)
        want = hmac.new(b64d(rows[0]["hmac_key"]), f"{prot_b64}.{pay_b64}".encode(), EAB_ALGS[alg]).digest()
        if not hmac.compare_digest(want, b64d(sig_b64)):
            raise AcmeError("unauthorized", "The account key's signature is wrong.", 403)
        if rows[0]["account"]:
            raise AcmeError("unauthorized", "That account key has already been used. Ask for a new one.", 403)
        return kid

    def _account(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        if ident != acct["id"]:
            raise AcmeError("unauthorized", "You can only manage your own account.", 403)
        p = auth.payload
        if p:
            if "contact" in p:
                self.store._x("UPDATE acme_accounts SET contact=? WHERE id=?", (json.dumps(self._contacts(p)), acct["id"]))
            if p.get("status") == "deactivated":
                self.store._x("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (acct["id"],))
        return self._json(self._account_obj(base, self.store._q("SELECT * FROM acme_accounts WHERE id=?", (acct["id"],))[0]))

    def _orders(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        if ident != acct["id"]:
            raise AcmeError("unauthorized", "You can only list your own orders.", 403)
        rows = self.store._q("SELECT id FROM acme_orders WHERE account=? ORDER BY created DESC LIMIT 200", (acct["id"],))
        return self._json({"orders": [f"{base}/acme/order/{r['id']}" for r in rows]})

    # ---- orders --------------------------------------------------------------------------------
    def _check_identifier(self, ident, st: AcmeSettings) -> tuple[str, str]:
        if not isinstance(ident, dict) or ident.get("type") not in ("dns", "ip") or not isinstance(ident.get("value"), str):
            raise AcmeError("unsupportedIdentifier", "Identifiers must be {\"type\": \"dns\" or \"ip\", \"value\": ...}.")
        kind, value = ident["type"], ident["value"].strip().lower().rstrip(".")
        if "*" in value:
            raise AcmeError("rejectedIdentifier", "Wildcard names need the DNS-01 challenge, which this server doesn't offer.")
        try:
            names = C.parse_names([value])
        except C.CAError as e:
            raise AcmeError("rejectedIdentifier", f"'{value}': {e}") from None
        if kind == "dns":
            if names.ips or len(names.dns) != 1:
                raise AcmeError("rejectedIdentifier", f"'{value}' isn't a DNS name.")
            value = names.dns[0]
        else:
            if names.dns or len(names.ips) != 1:
                raise AcmeError("rejectedIdentifier", f"'{value}' isn't an IP address.")
            value = names.ips[0]
        if not st.allows(kind, value):
            raise AcmeError("rejectedIdentifier", f"{value} isn't one of the names this server issues for. "
                                                  "An administrator can allow it on the ACME page.")
        return kind, value

    def _new_order(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        p = auth.payload
        if not p or not isinstance(p.get("identifiers"), list) or not p["identifiers"]:
            raise AcmeError("malformed", "new-order needs a non-empty identifiers list.")
        if len(p["identifiers"]) > MAX_IDENTIFIERS:
            raise AcmeError("malformed", f"At most {MAX_IDENTIFIERS} names per order.")
        st = self.settings()
        ids = list(dict.fromkeys(self._check_identifier(i, st) for i in p["identifiers"]))
        try:
            self.svc.ca.check_policy(C.parse_names([v for _, v in ids]), st.days)
        except C.CAError as e:
            raise AcmeError("rejectedIdentifier", str(e)) from None
        if not self.svc.ca.loaded() or self.svc.ca.sealed():
            raise AcmeError("serverInternal", "The CA is locked. An administrator must unlock it before certificates can be issued.", 503)
        pending = self.store._q("SELECT COUNT(*) AS n FROM acme_orders WHERE account=? AND status IN ('pending','ready')", (acct["id"],))[0]["n"]
        if pending >= 50 or not self.order_gate.allow(acct["id"]):
            raise AcmeError("rateLimited", "Too many orders. Finish or wait for the ones in progress.", 429, {})
        order_id, exp = secrets.token_urlsafe(12), iso(utcnow() + ORDER_LIFETIME)
        self.store._x("INSERT INTO acme_orders(id,account,identifiers,status,expires,created) VALUES(?,?,?,?,?,?)",
                      (order_id, acct["id"], json.dumps([{"type": k, "value": v} for k, v in ids]), "pending", exp, iso(utcnow())))
        for k, v in ids:
            self.store._x("INSERT INTO acme_authz(id,order_id,itype,ivalue,status,expires,token,chall_status) VALUES(?,?,?,?,?,?,?,?)",
                          (secrets.token_urlsafe(12), order_id, k, v, "pending", exp, secrets.token_urlsafe(32), "pending"))
        return self._json(self._order_obj(base, self._refresh_order(order_id)), 201, {"Location": f"{base}/acme/order/{order_id}"})

    def _own_order(self, order_id: str, acct: dict) -> dict:
        rows = self.store._q("SELECT * FROM acme_orders WHERE id=?", (order_id,))
        if not rows or rows[0]["account"] != acct["id"]:
            raise AcmeError("unauthorized", "That order doesn't belong to this account.", 403)
        return self._refresh_order(order_id)

    def _refresh_order(self, order_id: str) -> dict:
        o = self.store._q("SELECT * FROM acme_orders WHERE id=?", (order_id,))[0]
        if o["status"] in ("valid", "invalid", "processing"):
            return o
        authz = self.store._q("SELECT status FROM acme_authz WHERE order_id=?", (order_id,))
        status = o["status"]
        if parse_iso(o["expires"]) < utcnow() or any(a["status"] in ("invalid", "expired") for a in authz):
            status = "invalid"
        elif authz and all(a["status"] == "valid" for a in authz):
            status = "ready"
        if status != o["status"]:
            err = None
            if status == "invalid":
                bad = self.store._q("SELECT error FROM acme_authz WHERE order_id=? AND error IS NOT NULL LIMIT 1", (order_id,))
                err = bad[0]["error"] if bad else json.dumps({"type": PROBLEM + "unauthorized", "detail": "The order expired or a challenge failed."})
            self.store._x("UPDATE acme_orders SET status=?, error=COALESCE(?, error) WHERE id=?", (status, err, order_id))
            o = self.store._q("SELECT * FROM acme_orders WHERE id=?", (order_id,))[0]
        return o

    def _order_obj(self, base: str, o: dict) -> dict:
        authz = self.store._q("SELECT id FROM acme_authz WHERE order_id=? ORDER BY rowid", (o["id"],))
        obj = {"status": o["status"], "expires": o["expires"], "identifiers": json.loads(o["identifiers"]),
               "authorizations": [f"{base}/acme/authz/{a['id']}" for a in authz], "finalize": f"{base}/acme/finalize/{o['id']}"}
        if o["status"] == "valid" and o["serial"]:
            obj["certificate"] = f"{base}/acme/cert/{o['id']}"
        if o["status"] == "invalid" and o["error"]:
            obj["error"] = json.loads(o["error"])
        return obj

    def _order(self, auth, acct, base, ident) -> Reply:
        return self._json(self._order_obj(base, self._own_order(ident, acct)))

    # ---- authorizations and challenges ---------------------------------------------------------
    def _own_authz(self, authz_id: str, acct: dict) -> dict:
        rows = self.store._q("SELECT z.*, o.account AS owner FROM acme_authz z JOIN acme_orders o ON o.id=z.order_id WHERE z.id=?", (authz_id,))
        if not rows or rows[0]["owner"] != acct["id"]:
            raise AcmeError("unauthorized", "That authorization doesn't belong to this account.", 403)
        z = rows[0]
        if z["status"] == "pending" and parse_iso(z["expires"]) < utcnow():
            self.store._x("UPDATE acme_authz SET status='expired' WHERE id=?", (authz_id,))
            z["status"] = "expired"
        return z

    def _authz_obj(self, base: str, z: dict) -> dict:
        chall = {"type": "http-01", "url": f"{base}/acme/chall/{z['id']}", "token": z["token"], "status": z["chall_status"]}
        if z["validated"]:
            chall["validated"] = z["validated"]
        if z["error"]:
            chall["error"] = json.loads(z["error"])
        return {"identifier": {"type": z["itype"], "value": z["ivalue"]}, "status": z["status"], "expires": z["expires"], "challenges": [chall]}

    def _authz(self, auth, acct, base, ident) -> Reply:
        return self._json(self._authz_obj(base, self._own_authz(ident, acct)))

    def _challenge(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        z = self._own_authz(ident, acct)
        if auth.payload is not None and z["status"] == "pending" and z["chall_status"] == "pending":
            self.store._x("UPDATE acme_authz SET chall_status='processing' WHERE id=? AND chall_status='pending'", (ident,))
            self.pool.submit(self._validate, ident, acct["thumb"])
            z["chall_status"] = "processing"
        chall = self._authz_obj(base, z)["challenges"][0]
        return self._json(chall, 200, {"Link": f'<{base}/acme/authz/{ident}>;rel="up"'})

    def _validate(self, authz_id: str, thumb: str) -> None:
        try:
            z = self.store._q("SELECT * FROM acme_authz WHERE id=?", (authz_id,))[0]
            err = self._check_http01(z["itype"], z["ivalue"], z["token"], f"{z['token']}.{thumb}")
        except Exception as e:  # never leave a challenge stuck in 'processing'
            err = {"type": PROBLEM + "serverInternal", "detail": f"Validation failed unexpectedly: {e}", "status": 500}
        self._finish_validation(authz_id, err)

    def _finish_validation(self, authz_id: str, err: dict | None) -> None:
        if err is None:
            self.store._x("UPDATE acme_authz SET status='valid', chall_status='valid', validated=? WHERE id=?", (iso(utcnow()), authz_id))
        else:
            self.store._x("UPDATE acme_authz SET status='invalid', chall_status='invalid', error=? WHERE id=?", (json.dumps(err), authz_id))
        row = self.store._q("SELECT order_id, ivalue FROM acme_authz WHERE id=?", (authz_id,))
        if row:
            self._refresh_order(row[0]["order_id"])
            self.store.audit("acme", "acme", f"Validation of {row[0]['ivalue']}: {'passed' if err is None else 'failed (' + err['detail'] + ')'}")

    def _check_http01(self, itype: str, value: str, token: str, keyauth: str) -> dict | None:
        def problem(kind: str, detail: str, status: int = 400) -> dict:
            return {"type": PROBLEM + kind, "detail": detail, "status": status}

        addrs = [value] if itype == "ip" else list(self.resolve(value))
        if not addrs:
            return problem("dns", f"Couldn't find an address for {value}.")
        safe = [a for a in addrs if not unsafe_address(a)]
        if not safe:
            why = unsafe_address(addrs[0])
            return problem("connection", f"{value} points to {addrs[0]} ({why}), which this CA won't connect to.")
        host_header = f"[{value}]" if ":" in value else value
        last = ""
        for addr in safe[:4]:
            try:
                status, body = self.fetch(addr, host_header, CHALLENGE_PATH + token)
            except OSError as e:
                last = str(e)
                continue
            if status != 200:
                return problem("unauthorized", f"http://{host_header}{CHALLENGE_PATH}{token} answered HTTP {status} (redirects aren't followed).", 403)
            if body.strip() != keyauth.encode():
                return problem("unauthorized", "The challenge response didn't contain the expected key authorization.", 403)
            return None
        return problem("connection", f"Couldn't connect to {value} on port 80: {last or 'no answer'}")

    # ---- finalize, download, revoke --------------------------------------------------------------
    def _finalize(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        o = self._own_order(ident, acct)
        if o["status"] != "ready":
            raise AcmeError("orderNotReady", f"The order is {o['status']}, not ready. Finish the challenges first.", 403)
        if not auth.payload or "csr" not in auth.payload:
            raise AcmeError("malformed", "finalize needs a csr.")
        try:
            csr = x509.load_der_x509_csr(b64d(auth.payload["csr"]))
            sig_ok = csr.is_signature_valid
        except ValueError:
            raise AcmeError("badCSR", "That isn't a valid certificate request.") from None
        if not sig_ok:
            raise AcmeError("badCSR", "The request's own signature is invalid.")
        key = csr.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048:
                raise AcmeError("badPublicKey", "RSA keys must be at least 2048 bits.")
        elif not (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name in ("secp256r1", "secp384r1", "secp521r1")):
            raise AcmeError("badPublicKey", "Use an RSA (2048+) or EC (P-256, P-384, P-521) key.")
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            asked = {("dns", d.lower().rstrip(".")) for d in san.get_values_for_type(x509.DNSName)} | \
                    {("ip", str(i)) for i in san.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            asked = set()
        want = {(i["type"], i["value"]) for i in json.loads(o["identifiers"])}
        if asked != want:
            raise AcmeError("badCSR", "The request must name exactly the identifiers in the order "
                                      f"({', '.join(sorted(v for _, v in want))}) in its subjectAltName.")
        try:
            with self.svc.ca.lock:
                issued = self.svc.ca.sign_csr(csr, C.parse_names([v for _, v in sorted(want)]), self.settings().days, "server")
                rec = self.svc._record(issued.cert, "server", "acme", f"acme:{acct['id']}")
        except C.CASealed:
            raise AcmeError("serverInternal", "The CA is locked. An administrator must unlock it.", 503) from None
        except C.CAError as e:
            raise AcmeError("rejectedIdentifier", str(e)) from None
        self.store._x("UPDATE acme_orders SET status='valid', serial=? WHERE id=?", (rec["serial"], ident))
        return self._json(self._order_obj(base, self.store._q("SELECT * FROM acme_orders WHERE id=?", (ident,))[0]))

    def _certificate(self, auth: Auth, acct: dict, base: str, ident: str) -> Reply:
        o = self._own_order(ident, acct)
        row = self.store.get_cert(o["serial"]) if o["status"] == "valid" and o["serial"] else None
        if not row:
            raise AcmeError("malformed", "That order has no certificate (yet).", 404)
        leaf = x509.load_pem_x509_certificate(row["pem"].encode())
        return Reply(200, C.chain_pem([leaf, self.svc.ca.intermediate]), {"Content-Type": "application/pem-certificate-chain"})

    def _revoke(self, auth: Auth, base: str) -> Reply:
        p = auth.payload or {}
        try:
            cert = x509.load_der_x509_certificate(b64d(p["certificate"]))
        except (KeyError, ValueError):
            raise AcmeError("malformed", "revoke-cert needs a DER certificate.") from None
        row = self.store.get_cert(C.serial_hex(cert.serial_number))
        if not row or row["source"] != "acme" or C.pem(cert).decode() != row["pem"]:
            raise AcmeError("malformed", "That certificate wasn't issued by this server's ACME service.", 404)
        if row["revoked_at"]:
            raise AcmeError("alreadyRevoked", "That certificate is already revoked.")
        if auth.account is not None:
            owner = self.store._q("SELECT account FROM acme_orders WHERE serial=?", (row["serial"],))
            if not owner or owner[0]["account"] != auth.account["id"]:
                raise AcmeError("unauthorized", "Only the account that requested this certificate may revoke it (or sign with its private key).", 403)
        else:
            spki = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
            if spki(jwk_public_key(auth.jwk)) != spki(cert.public_key()):
                raise AcmeError("unauthorized", "The request wasn't signed with the certificate's private key.", 403)
        code = p.get("reason", 0)
        if code not in REVOKE_REASONS:
            raise AcmeError("badRevocationReason", "Unsupported revocation reason.", 400, {})
        try:
            self.svc.revoke("acme", row["serial"], REVOKE_REASONS[code])
        except C.CASealed:
            raise AcmeError("serverInternal", "The CA is locked. An administrator must unlock it.", 503) from None
        except C.CAError as e:
            raise AcmeError("serverInternal", str(e), 500) from None
        return Reply(200)


# ---- HTTP wiring -----------------------------------------------------------------------------------
def routes(svc):
    from starlette.concurrency import run_in_threadpool
    from starlette.responses import Response
    from starlette.routing import Route

    def host_ok(host: str) -> bool:
        h = host.split("]")[0].lstrip("[") if host.startswith("[") else (host.rsplit(":", 1)[0] if host.count(":") == 1 else host)
        return h.lower() in {x.lower() for x in svc.allowed_hosts()}

    def endpoint(kind: str):
        async def view(request):
            host = request.headers.get("host", "")
            if not host_ok(host):
                p = AcmeError("malformed", f"'{host}' isn't one of this server's names. Use an address from the web certificate.").problem()
                return Response(json.dumps(p), 400, {"Content-Type": "application/problem+json"})
            base = f"https://{host}"
            reply = await run_in_threadpool(
                svc.acme.handle, kind, method=request.method, base=base, url=base + request.url.path,
                body=await request.body(), content_type=request.headers.get("content-type", ""),
                ident=request.path_params.get("id", ""), remote=request.client.host if request.client else "")
            return Response(reply.body if request.method != "HEAD" else b"", reply.status, reply.headers)
        return view

    plain = [("directory", "/acme/directory", ["GET"]), ("new-nonce", "/acme/new-nonce", ["GET", "HEAD"]),
             ("new-account", "/acme/new-account", ["POST"]), ("new-order", "/acme/new-order", ["POST"]),
             ("revoke-cert", "/acme/revoke-cert", ["POST"])]
    ided = [("account", "/acme/acct/{id}"), ("orders", "/acme/acct/{id}/orders"), ("order", "/acme/order/{id}"),
            ("authz", "/acme/authz/{id}"), ("chall", "/acme/chall/{id}"), ("finalize", "/acme/finalize/{id}"), ("cert", "/acme/cert/{id}")]
    return [Route(path, endpoint(kind), methods=m) for kind, path, m in plain] + \
           [Route(path, endpoint(kind), methods=["POST"]) for kind, path in ided]
