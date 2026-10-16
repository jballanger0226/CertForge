from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AutoSetup:
    """Everything needed to set the CA up with nobody at the keyboard (see README, "Zero-touch setup")."""
    admin_password: str
    passphrase: str
    org: str = ""             # blank: suggested from the network domain
    seal: bool = False
    key_type: str = "ec-p384"
    root_years: int = 20
    int_years: int = 10
    permitted: str = ""
    public_host: str = ""     # blank: detected


@dataclass(frozen=True)
class Config:
    data: Path            # everything persistent lives here (mount it as a volume)
    bind: str             # address to listen on
    https_port: int       # the web UI. 443 by default, as it should be.
    http_port: int        # 0 disables. Only redirects to HTTPS and serves /pki/* (CRL, CA certs)
    hostnames: str        # initial names for the web UI's certificate (comma separated)
    setup_token: str | None
    auto: AutoSetup | None = None

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        def num(key: str, default: int) -> int:
            try:
                return int(env.get(key, default))
            except ValueError:
                raise SystemExit(f"{key} must be a number")

        def secret(key: str) -> str:
            """KEY, or the contents of the file named by KEY_FILE (Docker/Kubernetes secrets)."""
            path = env.get(key + "_FILE")
            if path:
                try:
                    return Path(path).read_text().rstrip("\r\n")
                except OSError as e:
                    raise SystemExit(f"{key}_FILE: can't read {path}: {e.strerror}")
            return env.get(key, "")

        admin_pw, passphrase = secret("CERTFORGE_ADMIN_PASSWORD"), secret("CERTFORGE_CA_PASSPHRASE")
        auto = None
        if admin_pw or passphrase:
            if not (admin_pw and passphrase):
                raise SystemExit("For automatic setup, set both CERTFORGE_ADMIN_PASSWORD and CERTFORGE_CA_PASSPHRASE "
                                 "(or their _FILE versions), not just one.")
            auto = AutoSetup(
                admin_password=admin_pw, passphrase=passphrase, org=env.get("CERTFORGE_ORG", "").strip(),
                seal=env.get("CERTFORGE_SEAL", "").strip().lower() in ("1", "true", "yes", "on"),
                key_type=env.get("CERTFORGE_KEY_TYPE", "ec-p384").strip() or "ec-p384",
                root_years=num("CERTFORGE_ROOT_YEARS", 20), int_years=num("CERTFORGE_INT_YEARS", 10),
                permitted=env.get("CERTFORGE_PERMITTED", "").strip(),
                public_host=env.get("CERTFORGE_PUBLIC_HOST", "").strip())

        return cls(
            data=Path(env.get("CERTFORGE_DATA", "/data")),
            bind=env.get("CERTFORGE_BIND", "0.0.0.0"),
            https_port=num("CERTFORGE_HTTPS_PORT", 443),
            http_port=num("CERTFORGE_HTTP_PORT", 80),
            hostnames=env.get("CERTFORGE_HOSTNAMES", "").strip(),
            setup_token=env.get("CERTFORGE_SETUP_TOKEN") or None,
            auto=auto,
        )
