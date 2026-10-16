"""Entry point:  python -m app.server

Serves the web UI on HTTPS (443 by default). A tiny helper on port 80 only redirects to HTTPS and
serves the public CA downloads / revocation list under /pki/, which is where clients look for them.
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import uvicorn

from . import ca as C
from .config import Config
from .main import create_app
from .service import Service


def log(msg: str) -> None:
    print(msg, flush=True)


# ---- port 80 helper ----------------------------------------------------------

def make_http_handler(svc: Service, cfg: Config):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CertForge"
        sys_version = ""

        def log_message(self, *args):  # keep the log quiet
            pass

        def _host(self) -> str:
            raw = self.headers.get("Host", "")
            host = raw.split("]")[0].lstrip("[") if raw.startswith("[") else raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
            allowed = svc.allowed_hosts()
            if allowed:
                return host if host in allowed else allowed[0]   # never redirect to an arbitrary Host header
            try:
                return C.parse_names(host).all()[0]
            except C.CAError:
                return "localhost"

        def _send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8", extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == "/healthz":
                return self._send(200, b"ok")
            if url.path.startswith("/pki/"):
                try:
                    hit = svc.pki(url.path[5:])
                except C.CAError as e:
                    return self._send(503, str(e).encode())
                if not hit:
                    return self._send(404, b"Not found")
                data, mime, fname = hit
                return self._send(200, data, mime, {"Content-Disposition": f'attachment; filename="{fname}"',
                                                    "Cache-Control": "public, max-age=300"})
            port = "" if cfg.https_port == 443 else f":{cfg.https_port}"
            host = self._host()
            host = f"[{host}]" if ":" in host else host
            target = f"https://{host}{port}{url.path}" + (f"?{url.query}" if url.query else "")
            self._send(307, b"Redirecting to HTTPS", extra={"Location": target})

        do_HEAD = do_GET

        def do_POST(self):
            self._send(405, b"Use HTTPS", extra={"Allow": "GET, HEAD"})

        do_PUT = do_DELETE = do_PATCH = do_POST

    return Handler


class DualStackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class V6Server(DualStackServer):
    address_family = socket.AF_INET6


def start_http_helper(svc: Service, cfg: Config) -> None:
    if not cfg.http_port:
        return
    cls = V6Server if ":" in cfg.bind else DualStackServer
    try:
        srv = cls((cfg.bind, cfg.http_port), make_http_handler(svc, cfg))
    except OSError as e:
        log(f"Not starting the port {cfg.http_port} helper ({e}). HTTPS still works; "
            "set CERTFORGE_HTTP_PORT=0 to silence this.")
        return
    threading.Thread(target=srv.serve_forever, name="http-helper", daemon=True).start()
    log(f"Port {cfg.http_port}: redirects to HTTPS and serves /pki/* (CA downloads, revocation list)")


# ---- background jobs ------------------------------------------------------------

def maintenance_loop(svc: Service) -> None:
    while True:
        try:
            svc.maintain()
        except Exception as e:  # never let this thread die
            log(f"Maintenance failed: {e}")
        time.sleep(6 * 3600)


class TlsHolder:
    """Lets the HTTPS listener switch to a new certificate without restarting the process.

    uvicorn builds one SSLContext at startup. We hang an SNI callback on it that hands every new
    connection the freshest context (loaded from the files on disk), so re-issuing the web
    certificate takes effect immediately and the CA stays unlocked.
    """

    def __init__(self, svc: Service):
        self.svc = svc
        self.ctx: ssl.SSLContext | None = None
        self._lock = threading.Lock()

    def build(self) -> ssl.SSLContext:
        certfile, keyfile, _ = self.svc.tls_files()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        return ctx

    def reload(self) -> None:
        fresh = self.build()
        with self._lock:
            self.ctx = fresh

    def sni(self, sslobj, server_name, original_ctx) -> None:
        try:
            with self._lock:
                ctx = self.ctx
            if ctx is not None:
                sslobj.context = ctx
        except Exception as e:  # never break a handshake over this
            log(f"TLS context switch failed: {e}")


def tls_watcher(svc: Service, holder: TlsHolder | None) -> None:
    """Waits for the web certificate to change, then applies it."""
    while True:
        svc.tls_changed.wait()
        svc.tls_changed.clear()
        time.sleep(0.3)  # let the response that triggered this finish first
        if holder is not None:
            try:
                holder.reload()
                log("Switched to the new web certificate.")
                continue
            except Exception as e:
                log(f"Couldn't hot-swap the certificate ({e}); restarting instead.")
        log("Restarting to load the new web certificate...")
        os.execv(sys.executable, [sys.executable, *sys.orig_argv[1:]])


def check_port(bind: str, port: int) -> None:
    fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port))
    except PermissionError:
        raise SystemExit(
            f"Not allowed to listen on port {port}. Run as root, grant CAP_NET_BIND_SERVICE, or in Docker add "
            "--sysctl net.ipv4.ip_unprivileged_port_start=0 (see the README).")
    except OSError as e:
        raise SystemExit(f"Can't listen on {bind}:{port}: {e}. Is something else using that port?")
    finally:
        s.close()


def main() -> None:
    cfg = Config.from_env()
    svc = Service(cfg)
    if not shutil_which("openssl"):
        raise SystemExit("The openssl command-line tool is required (it encrypts the CA keys). Install it and retry.")
    check_port(cfg.bind, cfg.https_port)

    if not svc.is_setup():
        first = (svc.initial_names().splitlines() or ["this-server"])[0]
        url = f"https://{first}" + ("" if cfg.https_port == 443 else f":{cfg.https_port}") + "/"
        log("=" * 64)
        log(" CertForge needs one-time setup.")
        log(f" Open {url}")
        log(" and enter this setup code:")
        log(f"     {svc.setup_token()}")
        log(" (your browser will warn about the certificate, which is expected")
        log("  until the CA exists and you trust it)")
        log("=" * 64)
    elif svc.ca.sealed():
        log("The CA is locked (its key is encrypted). Sign in and enter the CA passphrase to issue certificates.")

    certfile, keyfile, kind = svc.tls_files()
    log(f"HTTPS on {cfg.bind}:{cfg.https_port} using the {'CA-issued' if kind == 'ca' else 'temporary bootstrap'} certificate")
    start_http_helper(svc, cfg)

    config = uvicorn.Config(create_app(svc), host=cfg.bind, port=cfg.https_port, ssl_certfile=certfile,
                            ssl_keyfile=keyfile, log_level="warning", access_log=False, server_header=False,
                            date_header=False, proxy_headers=False)
    config.load()
    holder: TlsHolder | None = TlsHolder(svc)
    try:
        holder.reload()
        config.ssl.sni_callback = holder.sni
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception as e:
        log(f"Live certificate switching isn't available here ({e}); the server will restart instead.")
        holder = None
    threading.Thread(target=maintenance_loop, args=(svc,), name="maintenance", daemon=True).start()
    threading.Thread(target=tls_watcher, args=(svc, holder), name="tls", daemon=True).start()
    uvicorn.Server(config).run()


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    main()
