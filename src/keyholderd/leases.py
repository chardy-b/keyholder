from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_ts(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


@dataclass(frozen=True)
class Lease:
    lease_id: str
    caller_user: str
    profile: str
    grant_name: str
    provider: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    reason: str | None

    def is_expired(self) -> bool:
        return self.expires_at <= utcnow()


class LeaseStore:
    def __init__(self, path: str):
        self.path = path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS leases (
              lease_id TEXT PRIMARY KEY,
              caller_user TEXT NOT NULL,
              profile TEXT NOT NULL,
              grant_name TEXT NOT NULL,
              provider TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              revoked_at TEXT,
              reason TEXT
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_grant ON leases(grant_name, caller_user)")

    def create_lease(self, caller_user: str, profile: str, grant_name: str, provider: str, ttl_seconds: int, reason: str | None) -> Lease:
        issued = utcnow()
        expires = issued + timedelta(seconds=ttl_seconds)
        lease_id = f"lease_{uuid.uuid4().hex}"
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (lease_id, caller_user, profile, grant_name, provider, issued.isoformat(), expires.isoformat(), None, reason),
            )
        return Lease(lease_id, caller_user, profile, grant_name, provider, issued, expires, None, reason)

    def get_lease(self, lease_id: str) -> Lease:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM leases WHERE lease_id = ?", (lease_id,)).fetchone()
        if row is None:
            raise KeyError(lease_id)
        return Lease(row["lease_id"], row["caller_user"], row["profile"], row["grant_name"], row["provider"], parse_ts(row["issued_at"]), parse_ts(row["expires_at"]), parse_ts(row["revoked_at"]), row["reason"])

    def revoke(self, lease_id: str) -> None:
        revoked = utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute("UPDATE leases SET revoked_at = ? WHERE lease_id = ?", (revoked, lease_id))
            if cur.rowcount == 0:
                raise KeyError(lease_id)
