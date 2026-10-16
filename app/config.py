from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    data: Path            # everything persistent lives here (mount it as a volume)
    bind: str             # address to listen on
    https_port: int       # the web UI. 443 by default, as it should be.
    http_port: int        # 0 disables. Only redirects to HTTPS and serves /pki/* (CRL, CA certs)
    hostnames: str        # initial names for the web UI's certificate (comma separated)
    setup_token: str | None

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        def num(key: str, default: int) -> int:
            try:
                return int(env.get(key, default))
            except ValueError:
                raise SystemExit(f"{key} must be a number")

        return cls(
            data=Path(env.get("CERTFORGE_DATA", "/data")),
            bind=env.get("CERTFORGE_BIND", "0.0.0.0"),
            https_port=num("CERTFORGE_HTTPS_PORT", 443),
            http_port=num("CERTFORGE_HTTP_PORT", 80),
            hostnames=env.get("CERTFORGE_HOSTNAMES", "").strip(),
            setup_token=env.get("CERTFORGE_SETUP_TOKEN") or None,
        )
