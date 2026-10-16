"""Which CertForge is this, and is there a newer one?

The build is identified by two small files next to the `app` folder, written when it is built or
installed: VERSION (a release such as 1.2.0, or something like 0.0.0-abc1234 for an unreleased build)
and REVISION (the git commit). Environment variables of the same names, CERTFORGE_VERSION and
CERTFORGE_REVISION, win over the files. From a git checkout the revision is read from git.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class Build:
    version: str          # "1.2.0", "0.0.0-abc1234" or "dev"
    revision: str         # git commit, shortened; "" when unknown
    deploy: str           # "docker", "host" or "" (unknown): how this copy is updated

    @property
    def released(self) -> bool:
        """A tagged release, as opposed to a development or unreleased build."""
        v = parse(self.version)
        return bool(v) and v[:3] != (0, 0, 0) and not v[3]

    @property
    def label(self) -> str:
        return f"{self.version} ({self.revision})" if self.revision else self.version


def parse(version: str) -> tuple[int, int, int, str] | None:
    """(major, minor, patch, prerelease) for "1.2.3", "v1.2.3" or "1.2.3-rc1"; None if it isn't one."""
    m = _SEMVER.match((version or "").strip())
    return (int(m[1]), int(m[2]), int(m[3]), m[4] or "") if m else None


def _key(v: tuple[int, int, int, str]):
    # a release sorts after its own prereleases: 1.2.0-rc1 < 1.2.0
    return (v[0], v[1], v[2], v[3] == "", v[3])


def is_newer(candidate: str, current: str) -> bool | None:
    """True/False when both are versions we can compare; None when we can't tell (e.g. a development build)."""
    a, b = parse(candidate), parse(current)
    if not a or not b:
        return None
    return _key(a) > _key(b)


def _read(path: Path) -> str:
    try:
        return path.read_text().strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return ""


def _git_revision() -> str:
    if not (ROOT / ".git").exists():
        return ""
    try:
        p = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short=7", "HEAD"], capture_output=True, text=True, timeout=3)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def current(env=os.environ, root: Path = ROOT) -> Build:
    version = env.get("CERTFORGE_VERSION", "").strip() or _read(root / "VERSION") or "dev"
    revision = env.get("CERTFORGE_REVISION", "").strip() or _read(root / "REVISION") or (_git_revision() if root == ROOT else "")
    return Build(version=version.lstrip("v") if parse(version) else version, revision=revision[:12],
                 deploy=env.get("CERTFORGE_DEPLOY", "").strip().lower())


def update_command(deploy: str) -> str:
    """What an administrator types on the host to update, for the way this copy is deployed."""
    if deploy == "docker":
        return "docker compose pull && docker compose up -d"
    if deploy == "host":
        return "sudo certforge-update"
    return "see the README, \"Updating\""
