"""The web application (Starlette)."""
from __future__ import annotations

import functools
import logging
import hmac
import secrets
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from . import ca as C
from .security import safe_next
from .service import PACKAGE_TTL, Service
from .store import parse_iso

HERE = Path(__file__).parent
BODY_LIMIT = 1_000_000

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")


# --------------------------------------------------------------------------
# Middleware (plain ASGI, so it stays out of the way of streaming and uploads)
# --------------------------------------------------------------------------

class SecurityHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                h = {k.lower(): v for k, v in message.get("headers", [])}
                extra = [
                    (b"content-security-policy", CSP.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ]
                if b"cache-control" not in h:
                    extra.append((b"cache-control", b"no-store"))
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        await self.app(scope, receive, send_wrapper)


log = logging.getLogger('certforge')


class _TooLarge(Exception):
    pass


class BodyLimit:
    """Refuse request bodies over BODY_LIMIT, including chunked ones with no Content-Length."""

    def __init__(self, app, limit: int = BODY_LIMIT):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False
        for k, v in scope["headers"]:
            if k == b"content-length" and v.isdigit() and int(v) > self.limit:
                return await self._reject(send)
        got = 0

        async def limited():
            nonlocal got
            msg = await receive()
            if msg["type"] == "http.request":
                got += len(msg.get("body", b""))
                if got > self.limit:
                    raise _TooLarge
            return msg

        async def watch(message):
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited, watch)
        except _TooLarge:
            if not started:
                await self._reject(send)

    @staticmethod
    async def _reject(send):
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": b"That request is too large."})


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

def create_app(svc: Service) -> Starlette:
    templates = Jinja2Templates(directory=str(HERE / "templates"))

    def _date(v) -> str:
        if isinstance(v, str):
            v = parse_iso(v)
        return v.strftime("%-d %b %Y") if v else ""

    def _datetime(v) -> str:
        if isinstance(v, str):
            v = parse_iso(v)
        return v.strftime("%Y-%m-%d %H:%M UTC") if v else ""

    def _fp_lines(fp: str) -> list[str]:
        parts = fp.split(":")
        return [":".join(parts[i:i + 8]) for i in range(0, len(parts), 8)]

    templates.env.filters.update(date=_date, datetime=_datetime, fp_lines=_fp_lines)
    templates.env.globals.update(KEY_TYPES={k: v for k, v in C.KEY_TYPES.items() if k in C.LEAF_KEY_TYPES},
                                 CA_KEY_TYPES={k: C.KEY_TYPES[k] for k in C.CA_KEY_TYPES},
                                 PURPOSES={k: v[0] for k, v in C.PURPOSES.items()},
                                 REASONS=C.REASON_LABELS, MAX_DAYS=C.MAX_LEAF_DAYS)

    # ---- session helpers --------------------------------------------------
    def user(request: Request) -> str | None:
        s = request.session
        if s.get("uid") and s.get("pwv") == svc.password_version():
            return s["uid"]
        return None

    def csrf_token(request: Request) -> str:
        s = request.session
        if "csrf" not in s:
            s["csrf"] = secrets.token_urlsafe(24)
        return s["csrf"]

    def sid(request: Request) -> str:
        return request.session.get("sid", "")

    def flash(request: Request, level: str, text: str) -> None:
        items = list(request.session.get("flash", []))
        items.append([level, text])
        request.session["flash"] = items

    def request_host(request: Request) -> str:
        h = request.headers.get("host", "")
        if h.startswith("["):
            return h.split("]")[0].lstrip("[")
        return h.rsplit(":", 1)[0] if h.count(":") == 1 else h

    def render(request: Request, template: str, status: int = 200, **ctx) -> Response:
        loaded = svc.ca.loaded()
        base = {
            "org": svc.ca.meta.get("org") if loaded else "CertForge",
            "authed": bool(user(request)), "csrf": csrf_token(request),
            "flashes": [tuple(f) for f in request.session.pop("flash", [])],
            "sealed": svc.ca.sealed() if loaded else False,
            "host": request_host(request), "path": request.url.path,
        }
        return templates.TemplateResponse(request, template, {**base, **ctx}, status_code=status)

    def go(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=303)

    async def read_form(request: Request):
        form = await request.form()
        want = request.session.get("csrf", "")
        if not want or not hmac.compare_digest(str(form.get("csrf_token", "")), want):
            raise HTTPException(403, "Your session expired. Go back, reload the page and try again.")
        return form

    def authed(fn):
        @functools.wraps(fn)
        async def wrapper(request: Request):
            if not svc.is_setup():
                return go("/setup")
            if not user(request):
                return go("/login?next=" + quote(request.url.path))
            return await fn(request)
        return wrapper

    def intval(form, key: str, default: int, label: str) -> int:
        raw = str(form.get(key, "")).strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            raise C.CAError(f"{label} must be a whole number.") from None

    def download(data: bytes, name: str, mime: str, *, inline: bool = False, cache: str | None = None) -> Response:
        h = {"Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{name}"',
             "Cache-Control": cache or "no-store"}
        return Response(data, media_type=mime, headers=h)

    # ---- public ---------------------------------------------------------------
    async def healthz(request):
        return PlainTextResponse("ok")

    async def favicon(request):
        return Response(status_code=204)

    async def pki(request):
        name = request.path_params["name"]
        try:
            hit = await run_in_threadpool(svc.pki, name)
        except C.CAError as e:
            return PlainTextResponse(str(e), status_code=503)
        if not hit:
            return PlainTextResponse("Not found", status_code=404)
        data, mime, fname = hit
        return download(data, fname, mime, inline=name.endswith((".crl", ".crl.pem")), cache="public, max-age=300")

    async def trust(request):
        if not svc.is_setup():
            return go("/setup")
        return render(request, "trust.html", ca=svc.ca_summary(), slug=C.slugify(svc.ca.meta["org"]))

    # ---- setup / login ----------------------------------------------------------
    async def setup_get(request):
        if svc.is_setup():
            return go("/")
        return render(request, "setup.html", f={"ui_names": svc.initial_names(request_host(request)),
                                                 "key_type": "ec-p384", "root_years": 20, "int_years": 10,
                                                 "org": "", "permitted": "", "public_host": "", "seal": ""},
                      error=None)

    async def setup_post(request):
        if svc.is_setup():
            return go("/")
        form = await read_form(request)
        f = {k: str(form.get(k, "")).strip() for k in ("org", "key_type", "permitted", "public_host", "ui_names")}
        f["seal"] = "1" if form.get("seal") else ""
        try:
            f["root_years"] = intval(form, "root_years", 20, "The root lifetime")
            f["int_years"] = intval(form, "int_years", 10, "The intermediate lifetime")
            await run_in_threadpool(
                svc.setup, token=str(form.get("token", "")), org=f["org"],
                admin_password=str(form.get("admin_password", "")), admin_password2=str(form.get("admin_password2", "")),
                passphrase=str(form.get("passphrase", "")), key_type=f["key_type"], root_years=f["root_years"],
                int_years=f["int_years"], seal=bool(f["seal"]), permitted=f["permitted"],
                ui_names=f["ui_names"], public_host=f["public_host"])
        except C.CAError as e:
            return render(request, "setup.html", status=400, f=f, error=str(e))
        request.session.clear()
        request.session.update(uid="admin", pwv=svc.password_version(), csrf=secrets.token_urlsafe(24), sid=secrets.token_urlsafe(12))
        return render(request, "setup_done.html", ca=svc.ca_summary(), slug=C.slugify(svc.ca.meta["org"]))

    async def login_get(request):
        if not svc.is_setup():
            return go("/setup")
        if user(request):
            return go("/")
        return render(request, "login.html", next=safe_next(request.query_params.get("next")), error=None)

    async def login_post(request):
        if not svc.is_setup():
            return go("/setup")
        form = await read_form(request)
        nxt = safe_next(str(form.get("next", "")))
        ip = request.client.host if request.client else "?"
        wait = svc.limiter.locked_for(ip)
        if wait:
            return render(request, "login.html", status=429, next=nxt,
                          error=f"Too many wrong passwords. Try again in {wait} seconds.")
        if await run_in_threadpool(svc.check_admin, str(form.get("password", ""))):
            svc.limiter.succeeded(ip)
            request.session.clear()
            request.session.update(uid="admin", pwv=svc.password_version(), csrf=secrets.token_urlsafe(24), sid=secrets.token_urlsafe(12))
            svc.store.audit("admin", "login", f"from {ip}")
            return go(nxt)
        svc.limiter.failed(ip)
        svc.store.audit("unknown", "login-failed", f"from {ip}")
        return render(request, "login.html", status=401, next=nxt, error="That password isn't right.")

    async def logout(request):
        await read_form(request)
        request.session.clear()
        return go("/login")

    # ---- dashboard ------------------------------------------------------------
    @authed
    async def dashboard(request):
        return render(request, "dashboard.html", counts=svc.store.counts(), recent=svc.store.list_certs(limit=8),
                      alerts=svc.alerts(), ca=svc.ca_summary(), f={"names": "", "days": 365, "purpose": "both", "key_type": "ec-p256", "p12": "compat", "password": ""})

    # ---- issuing ------------------------------------------------------------------
    @authed
    async def issue_get(request):
        q = request.query_params
        return render(request, "issue.html", error=None, f={
            "names": q.get("names", ""), "days": q.get("days", 365), "purpose": q.get("purpose", "both"),
            "key_type": q.get("key_type", "ec-p256"), "p12": "compat", "password": ""})

    @authed
    async def issue_post(request):
        form = await read_form(request)
        f = {"names": str(form.get("names", "")), "purpose": str(form.get("purpose", "both")),
             "key_type": str(form.get("key_type", "ec-p256")), "p12": str(form.get("p12", "compat")),
             "password": "", "days": str(form.get("days", "365"))}
        try:
            days = intval(form, "days", 365, "The validity")
            serial = await run_in_threadpool(
                svc.issue_generated, "admin", sid(request), names_raw=f["names"], days=days,
                purpose=f["purpose"], key_type=f["key_type"], password=str(form.get("password", "")),
                legacy=f["p12"] != "modern")
        except C.CAError as e:
            tpl = "issue.html"
            return render(request, tpl, status=423 if isinstance(e, C.CASealed) else 400, error=str(e), f=f)
        return go(f"/certs/{serial}?new=1")

    @authed
    async def csr_get(request):
        return render(request, "csr.html", error=None, text="")

    @authed
    async def csr_post(request):
        form = await read_form(request)
        text = str(form.get("csr_text", ""))
        data = text.encode()
        up = form.get("csr_file")
        if up is not None and not isinstance(up, str) and getattr(up, "filename", ""):
            data = await up.read(65537)
            if len(data) > 65536:
                return render(request, "csr.html", status=400, error="That file is too big to be a certificate request.", text="")
        elif len(data) > 65536:
            return render(request, "csr.html", status=400, error="That's too big to be a certificate request.", text="")
        try:
            token = await run_in_threadpool(svc.stage_csr, sid(request), data)
        except C.CAError as e:
            return render(request, "csr.html", status=400, error=str(e), text=text[:20000])
        return go(f"/issue/csr/{token}")

    @authed
    async def csr_review_get(request):
        token = request.path_params["token"]
        p = svc.staged_csr(sid(request), token)
        if not p:
            flash(request, "error", "That request expired. Paste or upload the CSR again.")
            return go("/issue/csr")
        names = "\n".join(p["names"])
        return render(request, "csr_review.html", p=p, token=token, error=None,
                      f={"names": names, "days": 365, "purpose": "both"})

    @authed
    async def csr_review_post(request):
        token = request.path_params["token"]
        form = await read_form(request)
        p = svc.staged_csr(sid(request), token)
        if not p:
            flash(request, "error", "That request expired. Paste or upload the CSR again.")
            return go("/issue/csr")
        f = {"names": str(form.get("names", "")), "days": str(form.get("days", "365")), "purpose": str(form.get("purpose", "both"))}
        try:
            serial, notices = await run_in_threadpool(
                svc.sign_staged, "admin", sid(request), token, names_raw=f["names"],
                days=intval(form, "days", 365, "The validity"), purpose=f["purpose"])
        except C.CAError as e:
            return render(request, "csr_review.html", status=423 if isinstance(e, C.CASealed) else 400, p=p, token=token, error=str(e), f=f)
        for n in notices:
            flash(request, "info", n)
        return go(f"/certs/{serial}?new=1")

    # ---- inventory ------------------------------------------------------------------
    @authed
    async def certs(request):
        q, status = request.query_params.get("q", "").strip(), request.query_params.get("status", "")
        if status not in ("", "valid", "expiring", "expired", "revoked"):
            status = ""
        return render(request, "certs.html", rows=svc.store.list_certs(q, status), q=q, flt=status, counts=svc.store.counts())

    @authed
    async def cert_detail(request):
        serial = request.path_params["serial"]
        row = svc.store.get_cert(serial)
        if not row:
            raise HTTPException(404, "There's no certificate with that serial number.")
        pkg = svc.package(sid(request), row["serial"])
        files = await run_in_threadpool(svc.cert_files, row)
        info = C.describe_cert(x509.load_pem_x509_certificate(row["pem"].encode()))
        return render(request, "cert.html", c=row, info=info, pkg=pkg, files={k: v[0] for k, v in files.items()},
                      pkg_minutes=max(1, svc.packages.expires_in(f"{sid(request)}:{row['serial']}") // 60) if pkg else 0,
                      new=bool(request.query_params.get("new")), pkg_ttl=PACKAGE_TTL // 60)

    @authed
    async def cert_download(request):
        serial, fmt = request.path_params["serial"], request.path_params["fmt"]
        row = svc.store.get_cert(serial)
        if not row:
            raise HTTPException(404, "There's no certificate with that serial number.")
        if fmt in ("p12", "zip"):
            pkg = svc.package(sid(request), row["serial"])
            if not pkg or fmt not in pkg.files:
                raise HTTPException(404, "The private key isn't kept on the server, and this download has expired. "
                                         "Create a new certificate to get a new key.")
            name, mime, data = pkg.files[fmt]
            return download(data, name, mime)
        files = await run_in_threadpool(svc.cert_files, row)
        if fmt not in files:
            raise HTTPException(404, "Unknown download.")
        name, mime, data = files[fmt]
        return download(data, name, mime)

    @authed
    async def cert_discard(request):
        form = await read_form(request)
        svc.discard_package(sid(request), request.path_params["serial"])
        flash(request, "ok", "The private key has been wiped from the server's memory.")
        return go(f"/certs/{request.path_params['serial']}")

    @authed
    async def cert_revoke(request):
        form = await read_form(request)
        serial = request.path_params["serial"]
        try:
            await run_in_threadpool(svc.revoke, "admin", serial, str(form.get("reason", "")))
            flash(request, "ok", "Revoked. The revocation list has been updated.")
        except C.CAError as e:
            flash(request, "error", str(e))
        return go(f"/certs/{serial}")

    # ---- the CA ----------------------------------------------------------------------
    @authed
    async def ca_page(request):
        return render(request, "ca.html", ca=svc.ca_summary(), audit=svc.store.recent_audit(25),
                      names="\n".join(svc.store.get("ui_names", [])), slug=C.slugify(svc.ca.meta["org"]))

    def ca_action(fn):
        """POST handler that reports success/failure with a flash message and goes back to /ca."""
        @authed
        async def wrapper(request):
            form = await read_form(request)
            try:
                msg = await fn(request, form)
                flash(request, "ok", msg)
            except C.CAError as e:
                flash(request, "error", str(e))
            return go("/ca")
        return wrapper

    @ca_action
    async def ca_unlock(request, form):
        await run_in_threadpool(svc.unlock, "admin", str(form.get("passphrase", "")))
        return "Unlocked. The CA can issue and revoke certificates again."

    @ca_action
    async def ca_ui_names(request, form):
        raw = str(form.get("names", ""))
        here = request_host(request).lower()
        if here and here not in C.parse_names(raw).all():
            raise C.CAError(f"Keep {here} in the list. It's the address you're using right now, and removing it would lock you out of this page.")
        await run_in_threadpool(svc.update_ui_names, "admin", raw)
        return "Saved. This page now uses the new certificate. Reload it to see the change."

    @ca_action
    async def ca_public_host(request, form):
        await run_in_threadpool(svc.set_public_host, "admin", str(form.get("host", "")))
        return "Saved. New certificates will point to this address for CA downloads and revocation checks."

    @ca_action
    async def ca_remove_key(request, form):
        if str(form.get("confirm", "")).strip() != "remove root key":
            raise C.CAError("Type remove root key exactly to confirm.")
        await run_in_threadpool(svc.remove_root_key, "admin")
        return "The root key has been removed from this server. Keep your backup safe."

    @ca_action
    async def ca_renew(request, form):
        up = form.get("root_key")
        key = await up.read(20000) if up is not None and not isinstance(up, str) and getattr(up, "filename", "") else None
        await run_in_threadpool(svc.renew_intermediate, "admin", str(form.get("passphrase", "")),
                                intval(form, "years", 10, "The lifetime"), key)
        return "The intermediate certificate has been renewed. Certificates you've already issued keep working."

    @ca_action
    async def account_password(request, form):
        await run_in_threadpool(svc.change_password, "admin", str(form.get("current", "")), str(form.get("new", "")), str(form.get("new2", "")))
        request.session["pwv"] = svc.password_version()
        return "Password changed."

    @authed
    async def ca_export_key(request):
        form = await read_form(request)
        try:
            blob, name = await run_in_threadpool(svc.export_root_key, "admin", str(form.get("passphrase", "")))
        except C.CAError as e:
            flash(request, "error", str(e))
            return go("/ca")
        return download(blob, name, "application/x-pem-file")

    # ---- errors -------------------------------------------------------------------------
    async def http_error(request, exc: HTTPException):
        return render(request, "error.html", status=exc.status_code, code=exc.status_code, message=exc.detail)

    async def server_error(request, exc: Exception):
        # Runs outside the session middleware, so it can't use render(). Keep it self-contained.
        log.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>Something went wrong</title>"
            "<body style='font:16px system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem'>"
            "<h1>Something went wrong</h1><p>The server hit an unexpected error. "
            "The details are in the server log. <a href='/'>Back to the start</a></p>",
            status_code=500)

    routes = [
        Route("/healthz", healthz), Route("/favicon.ico", favicon),
        Route("/pki/{name}", pki),
        Route("/trust", trust),
        Route("/setup", setup_get, methods=["GET"]), Route("/setup", setup_post, methods=["POST"]),
        Route("/login", login_get, methods=["GET"]), Route("/login", login_post, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/", dashboard),
        Route("/issue", issue_get, methods=["GET"]), Route("/issue", issue_post, methods=["POST"]),
        Route("/issue/csr", csr_get, methods=["GET"]), Route("/issue/csr", csr_post, methods=["POST"]),
        Route("/issue/csr/{token}", csr_review_get, methods=["GET"]), Route("/issue/csr/{token}", csr_review_post, methods=["POST"]),
        Route("/certs", certs),
        Route("/certs/{serial}", cert_detail),
        Route("/certs/{serial}/download/{fmt}", cert_download),
        Route("/certs/{serial}/discard-key", cert_discard, methods=["POST"]),
        Route("/certs/{serial}/revoke", cert_revoke, methods=["POST"]),
        Route("/ca", ca_page),
        Route("/ca/unlock", ca_unlock, methods=["POST"]),
        Route("/ca/ui-names", ca_ui_names, methods=["POST"]),
        Route("/ca/public-host", ca_public_host, methods=["POST"]),
        Route("/ca/root-key/export", ca_export_key, methods=["POST"]),
        Route("/ca/root-key/remove", ca_remove_key, methods=["POST"]),
        Route("/ca/intermediate/renew", ca_renew, methods=["POST"]),
        Route("/account/password", account_password, methods=["POST"]),
        Mount("/static", StaticFiles(directory=str(HERE / "static")), name="static"),
    ]
    middleware = [
        Middleware(BodyLimit),
        Middleware(SecurityHeaders),
        Middleware(SessionMiddleware, secret_key=svc.secret, session_cookie="certforge", max_age=8 * 3600,
                   same_site="strict", https_only=True),
    ]
    return Starlette(routes=routes, middleware=middleware,
                     exception_handlers={HTTPException: http_error, Exception: server_error})
