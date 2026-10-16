"""SQLite inventory of issued certificates, settings and an audit trail.

Only PUBLIC material is stored here. Private keys for 'generate for me' certificates are
never written to disk; they exist in memory just long enough to be downloaded.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
FMT = "%Y-%m-%dT%H:%M:%SZ"
EXPIRING_DAYS = 30


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(d: datetime) -> str:
    return d.astimezone(UTC).strftime(FMT)


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, FMT).replace(tzinfo=UTC)


def cert_status(row: dict, now: datetime | None = None) -> str:
    now = now or utcnow()
    if row["revoked_at"]:
        return "revoked"
    left = parse_iso(row["not_after"]) - now
    if left <= timedelta(0):
        return "expired"
    return "expiring" if left <= timedelta(days=EXPIRING_DAYS) else "valid"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certs(
    serial        TEXT PRIMARY KEY,
    cn            TEXT NOT NULL,
    sans          TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    key_desc      TEXT NOT NULL,
    source        TEXT NOT NULL,
    not_before    TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    issued_at     TEXT NOT NULL,
    issued_by     TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    pem           TEXT NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS certs_issued ON certs(issued_at);
CREATE TABLE IF NOT EXISTS audit(
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
"""


def _like(s: str) -> str:
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path: Path):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _q(self, sql: str, args=()) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def _x(self, sql: str, args=()) -> int:
        c = self._conn()
        try:
            return c.execute(sql, args).rowcount
        finally:
            c.close()

    # ---- settings -------------------------------------------------------
    def get(self, key: str, default=None):
        rows = self._q("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set(self, key: str, value) -> None:
        self._x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))

    # ---- certificates ---------------------------------------------------
    def add_cert(self, **f) -> None:
        f["sans"] = json.dumps(f["sans"])
        cols = ",".join(f)
        self._x(f"INSERT INTO certs({cols}) VALUES({','.join('?' * len(f))})", tuple(f.values()))

    def _decorate(self, row: dict) -> dict:
        row["sans"] = json.loads(row["sans"])
        row["status"] = cert_status(row)
        row["days_left"] = (parse_iso(row["not_after"]) - utcnow()).days
        return row

    def get_cert(self, serial: str) -> dict | None:
        rows = self._q("SELECT * FROM certs WHERE serial=?", (serial.upper(),))
        return self._decorate(rows[0]) if rows else None

    def list_certs(self, q: str = "", status: str = "", limit: int = 500) -> list[dict]:
        now, soon = utcnow(), utcnow() + timedelta(days=EXPIRING_DAYS)
        where, args = [], []
        if q:
            where.append("(cn LIKE ? ESCAPE '\\' OR sans LIKE ? ESCAPE '\\' OR serial LIKE ? ESCAPE '\\')")
            args += [_like(q)] * 3
        if status == "revoked":
            where.append("revoked_at IS NOT NULL")
        elif status == "expired":
            where.append("revoked_at IS NULL AND not_after <= ?"); args.append(iso(now))
        elif status == "expiring":
            where.append("revoked_at IS NULL AND not_after > ? AND not_after <= ?"); args += [iso(now), iso(soon)]
        elif status == "valid":
            where.append("revoked_at IS NULL AND not_after > ?"); args.append(iso(soon))
        sql = "SELECT * FROM certs" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY issued_at DESC, rowid DESC LIMIT ?"
        return [self._decorate(r) for r in self._q(sql, (*args, limit))]

    def counts(self) -> dict:
        out = {"valid": 0, "expiring": 0, "expired": 0, "revoked": 0}
        for r in self._q("SELECT revoked_at, not_after FROM certs"):
            out[cert_status(r)] += 1
        out["total"] = sum(out.values())
        return out

    def revoke(self, serial: str, reason: str) -> bool:
        return self._x("UPDATE certs SET revoked_at=?, revoke_reason=? WHERE serial=? AND revoked_at IS NULL",
                       (iso(utcnow()), reason, serial.upper())) == 1

    def revoked(self) -> list[tuple[int, datetime, str]]:
        rows = self._q("SELECT serial, revoked_at, revoke_reason FROM certs WHERE revoked_at IS NOT NULL")
        return [(int(r["serial"], 16), parse_iso(r["revoked_at"]), r["revoke_reason"] or "unspecified") for r in rows]

    # ---- audit ----------------------------------------------------------
    def audit(self, actor: str, action: str, detail: str = "") -> None:
        self._x("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)", (iso(utcnow()), actor, action, detail[:500]))

    def recent_audit(self, limit: int = 40) -> list[dict]:
        return self._q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
