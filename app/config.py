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
    acme_domains: str = ""    # turns the ACME server on for these domains (and networks) at setup
    acme_networks: str = ""
    acme_days: int = 90
    acme_eab: bool = False


@dataclass(frozen=True)
class AutoAcmeCa:
    """Creates the ACME issuing CA at start-up, with nobody at the keyboard (README, "A separate CA for ACME")."""
    mode: str                  # "under-main" (signed by the existing root) or "own-root"
    passphrase: str            # encrypts the issuing key; also unlocks it at every start
    main_passphrase: str = ""  # under-main only: the main CA passphrase, to sign with the root
    root_passphrase: str = ""  # own-root only: encrypts the new root's key, which is then kept on the server
    hold: str = "secret"
    key_type: str = "ec-p384"
    years: int = 5
    root_years: int = 20
    permitted: str = ""
    org: str = ""              # own-root only; blank: the main CA's name


@dataclass(frozen=True)
class Config:
    data: Path            # everything persistent lives here (mount it as a volume)
    bind: str             # address to listen on
    https_port: int       # the web UI. 443 by default, as it should be.
    http_port: int        # 0 disables. Only redirects to HTTPS and serves /pki/* (CRL, CA certs)
    hostnames: str        # initial names for the web UI's certificate (comma separated)
    setup_token: str | None
    auto: AutoSetup | None = None
    acme_ca_passphrase: str = ""          # unlocks the ACME issuing key at start (when it is set to unlock that way)
    acme_ca_auto: AutoAcmeCa | None = None
    update_check: bool = False            # look for newer releases (off unless asked; the CA page can switch it too)
    update_repo: str = "jballanger0226/CertForge"

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
                public_host=env.get("CERTFORGE_PUBLIC_HOST", "").strip(),
                acme_domains=env.get("CERTFORGE_ACME_DOMAINS", "").strip(), acme_networks=env.get("CERTFORGE_ACME_NETWORKS", "").strip(),
                acme_days=num("CERTFORGE_ACME_DAYS", 90),
                acme_eab=env.get("CERTFORGE_ACME_EAB", "").strip().lower() in ("1", "true", "yes", "on"))

        acme_pw = secret("CERTFORGE_ACME_CA_PASSPHRASE")
        acme_auto = None
        wanted = env.get("CERTFORGE_ACME_CA", "").strip().lower()
        if wanted not in ("", "0", "off", "no", "false"):
            if wanted in ("1", "on", "yes", "true", "intermediate", "under-main"):
                mode = "under-main"
            elif wanted in ("root", "own-root", "own"):
                mode = "own-root"
            else:
                raise SystemExit("CERTFORGE_ACME_CA must be 'intermediate' (signed by your existing root) or 'root' (its own root).")
            hold = env.get("CERTFORGE_ACME_CA_HOLD", "secret").strip().lower() or "secret"
            if hold not in ("secret", "manual"):
                raise SystemExit("CERTFORGE_ACME_CA_HOLD must be 'secret' or 'manual'.")
            root_pw = secret("CERTFORGE_ACME_ROOT_PASSPHRASE")      # whether the right ones are there is checked when it's created
            acme_auto = AutoAcmeCa(
                mode=mode, passphrase=acme_pw, main_passphrase=passphrase, root_passphrase=root_pw, hold=hold,
                key_type=env.get("CERTFORGE_ACME_CA_KEY_TYPE", "ec-p384").strip() or "ec-p384",
                years=num("CERTFORGE_ACME_CA_YEARS", 5), root_years=num("CERTFORGE_ACME_ROOT_YEARS", 20),
                permitted=env.get("CERTFORGE_ACME_CA_PERMITTED", "").strip(), org=env.get("CERTFORGE_ACME_CA_ORG", "").strip())

        return cls(
            data=Path(env.get("CERTFORGE_DATA", "/data")),
            bind=env.get("CERTFORGE_BIND", "0.0.0.0"),
            https_port=num("CERTFORGE_HTTPS_PORT", 443),
            http_port=num("CERTFORGE_HTTP_PORT", 80),
            hostnames=env.get("CERTFORGE_HOSTNAMES", "").strip(),
            setup_token=env.get("CERTFORGE_SETUP_TOKEN") or None,
            auto=auto, acme_ca_passphrase=acme_pw, acme_ca_auto=acme_auto,
            update_check=env.get("CERTFORGE_UPDATE_CHECK", "").strip().lower() in ("1", "true", "yes", "on"),
            update_repo=env.get("CERTFORGE_UPDATE_REPO", "").strip() or "jballanger0226/CertForge",
        )
