"""Storage. SQLite is more than enough here.

The schema is deliberately simple: a user, their hosts, and a full record of
every block. Teams and roles will arrive as separate tables later and will not
break anything here.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

import aiosqlite

from .config import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    tg_user_id     INTEGER PRIMARY KEY,
    username       TEXT,
    first_name     TEXT,
    active_host_id INTEGER,
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL,
    name        TEXT NOT NULL,
    hostname    TEXT,
    ip          TEXT NOT NULL,
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    ssh_user    TEXT NOT NULL,
    os_info     TEXT,
    host_pubkey TEXT,
    kind        TEXT NOT NULL DEFAULT 'ssh',
    status      TEXT NOT NULL DEFAULT 'pending',
    last_seen   INTEGER,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(tg_user_id)
);
CREATE INDEX IF NOT EXISTS idx_hosts_owner ON hosts(owner_id);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token      TEXT PRIMARY KEY,
    owner_id   INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    host_id    INTEGER
);

-- Who the owner granted access to.
-- Linked by Telegram ID: people change their username, the id stays.
CREATE TABLE IF NOT EXISTS shares (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL,
    owner_id   INTEGER NOT NULL,
    grantee_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_shares_grantee ON shares(grantee_id);
CREATE INDEX IF NOT EXISTS idx_shares_host ON shares(host_id);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    host_id    INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER
);

-- The full record: every executed block in full.
CREATE TABLE IF NOT EXISTS blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    host_id     INTEGER NOT NULL,
    command     TEXT NOT NULL,
    output      TEXT,
    exit_code   INTEGER,
    cwd         TEXT,
    duration_ms INTEGER,
    truncated   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_blocks_session ON blocks(session_id);
CREATE INDEX IF NOT EXISTS idx_blocks_user_time ON blocks(user_id, created_at DESC);
"""


@dataclass
class Host:
    id: int
    owner_id: int
    name: str
    hostname: str | None
    ip: str
    ssh_port: int
    ssh_user: str
    os_info: str | None
    status: str
    last_seen: int | None
    kind: str = "ssh"

    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> "Host":
        return cls(
            id=row["id"],
            owner_id=row["owner_id"],
            name=row["name"],
            hostname=row["hostname"],
            ip=row["ip"],
            ssh_port=row["ssh_port"],
            ssh_user=row["ssh_user"],
            os_info=row["os_info"],
            status=row["status"],
            last_seen=row["last_seen"],
            kind=row["kind"] if "kind" in row.keys() else "ssh",
        )


def now() -> int:
    return int(time.time())


class Database:
    def __init__(self) -> None:
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        config.ensure_dirs()
        self._rename_legacy_db()
        self._conn = await aiosqlite.connect(config.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._migrate()
        await self._conn.commit()

    @staticmethod
    def _rename_legacy_db() -> None:
        """Picks up a database from before the project was renamed.

        Until v0.12.0 the project was called tTerminal and the file was
        `tterminal.db`. Without this move an upgrade would look like losing
        every connected server and the whole command history.
        """
        new = config.db_path
        old = new.with_name("tterminal.db")
        if old.exists() and not new.exists():
            old.rename(new)

    async def _migrate(self) -> None:
        """Brings an existing database up to the current schema.

        CREATE TABLE IF NOT EXISTS does not add columns to a table that
        already exists, so new fields have to be poured in separately. We look
        at what is actually there rather than at a version number: that keeps
        the migration idempotent and survives any upgrade order.
        """
        # Nothing to catch up on right now. Columns added for the "tab per
        # machine" layout were dropped along with it; where they already exist
        # they simply stay unused, which is no reason to fail an upgrade.
        wanted: dict[str, list[tuple[str, str]]] = {
            "hosts": [("kind", "TEXT NOT NULL DEFAULT 'ssh'"),
                      ("agent_token", "TEXT")],
        }
        for table, columns in wanted.items():
            cur = await self.conn.execute(f"PRAGMA table_info({table})")
            have = {row["name"] for row in await cur.fetchall()}
            for name, kind in columns:
                if name not in have:
                    await self.conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {kind}"
                    )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("The database is not open — call connect() at startup")
        return self._conn

    # ---------- users ----------

    async def find_user_by_username(self, username: str) -> int | None:
        """Looks up a Telegram ID by username.

        The Bot API cannot search people by username: an id is only known for
        someone who has already written to the bot. Hence the rule that the
        person being granted access must start the bot themselves first.
        """
        cur = await self.conn.execute(
            "SELECT tg_user_id FROM users WHERE lower(username) = ?",
            (username.lstrip("@").lower(),),
        )
        row = await cur.fetchone()
        return row["tg_user_id"] if row else None

    async def username_of(self, tg_user_id: int) -> str | None:
        cur = await self.conn.execute(
            "SELECT username, first_name FROM users WHERE tg_user_id = ?",
            (tg_user_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        return f"@{row['username']}" if row["username"] else row["first_name"]

    async def upsert_user(self, tg_user_id: int, username: str | None, first_name: str | None) -> None:
        await self.conn.execute(
            """INSERT INTO users (tg_user_id, username, first_name, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(tg_user_id) DO UPDATE SET username=excluded.username,
                                                     first_name=excluded.first_name""",
            (tg_user_id, username, first_name, now()),
        )
        await self.conn.commit()

    async def get_active_host(self, tg_user_id: int) -> Host | None:
        """The machine commands currently go to.

        The permission is checked here, not only at selection time: a share
        may expire or be revoked after the machine was picked. Without this
        check an expired share kept working — the machine disappeared from the
        list while commands still reached it.
        """
        cur = await self.conn.execute(
            """SELECT h.* FROM hosts h
               JOIN users u ON u.active_host_id = h.id
               WHERE u.tg_user_id = ? AND h.status = 'active'""",
            (tg_user_id,),
        )
        row = await cur.fetchone()
        if row is not None:
            host = Host.from_row(row)
            if await self.can_use(tg_user_id, host.id):
                return host
            # Permission is gone: clear the selection so it stops showing as
            # active.
            await self.set_active_host(tg_user_id, None)

        # No active machine: if exactly one is available, take it.
        hosts = await self.list_hosts(tg_user_id)
        if len(hosts) == 1:
            await self.set_active_host(tg_user_id, hosts[0].id)
            return hosts[0]
        return None

    async def set_active_host(self, tg_user_id: int, host_id: int | None) -> None:
        await self.conn.execute(
            "UPDATE users SET active_host_id = ? WHERE tg_user_id = ?", (host_id, tg_user_id)
        )
        await self.conn.commit()

    # ---------- hosts ----------

    async def list_hosts(self, owner_id: int) -> list[Host]:
        """Own machines plus those shared with this user."""
        cur = await self.conn.execute(
            "SELECT * FROM hosts WHERE owner_id = ? AND status = 'active' "
            "ORDER BY created_at",
            (owner_id,),
        )
        own = [Host.from_row(r) for r in await cur.fetchall()]
        seen = {h.id for h in own}
        return own + [h for h in await self.shared_with_me(owner_id)
                      if h.id not in seen]

    async def get_host(self, host_id: int) -> Host | None:
        cur = await self.conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        row = await cur.fetchone()
        return Host.from_row(row) if row else None

    async def find_host_by_name(self, owner_id: int, name: str) -> Host | None:
        cur = await self.conn.execute(
            "SELECT * FROM hosts WHERE owner_id = ? AND name = ? AND status = 'active'",
            (owner_id, name),
        )
        row = await cur.fetchone()
        return Host.from_row(row) if row else None

    async def create_pending_host(self, owner_id: int, **kw: Any) -> int:
        cur = await self.conn.execute(
            """INSERT INTO hosts (owner_id, name, hostname, ip, ssh_port, ssh_user,
                                  os_info, host_pubkey, status, last_seen, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (
                owner_id,
                kw.get("name", "unnamed"),
                kw.get("hostname"),
                kw.get("ip", ""),
                kw.get("ssh_port", 22),
                kw.get("ssh_user", config.SSH_USER),
                kw.get("os_info"),
                kw.get("host_pubkey"),
                now(),
                now(),
            ),
        )
        await self.conn.commit()
        return cur.lastrowid or 0

    async def activate_host(self, host_id: int) -> None:
        await self.conn.execute(
            "UPDATE hosts SET status = 'active', last_seen = ? WHERE id = ?", (now(), host_id)
        )
        await self.conn.commit()

    async def reject_host(self, host_id: int) -> None:
        await self.conn.execute("UPDATE hosts SET status = 'rejected' WHERE id = ?", (host_id,))
        await self.conn.commit()

    async def remove_host(self, host_id: int) -> None:
        await self.conn.execute("UPDATE hosts SET status = 'removed' WHERE id = ?", (host_id,))
        await self.conn.commit()

    async def issue_agent_token(self, host_id: int) -> str:
        """A long-lived machine token.

        Unlike the install token it is not one-shot: the agent presents it on
        every reconnect, after sleep, a network change or a reboot. It is
        revoked by removing the host.
        """
        token = secrets.token_urlsafe(24)
        await self.conn.execute(
            "UPDATE hosts SET agent_token = ?, kind = 'agent' WHERE id = ?",
            (token, host_id),
        )
        await self.conn.commit()
        return token

    async def resolve_agent_token(self, token: str) -> int | None:
        """A placeholder answers too: the first connection is what activates it."""
        cur = await self.conn.execute(
            "SELECT id FROM hosts WHERE agent_token = ? "
            "AND status IN ('active', 'pending')",
            (token,),
        )
        row = await cur.fetchone()
        return row["id"] if row else None

    async def create_agent_host(self, owner_id: int, name: str) -> int:
        """A placeholder for an agent machine.

        Created as pending, so it is invisible in the list and cannot become
        active: until the agent is online the machine does not really exist.
        It used to be created active and stole the selection from a working
        machine, so commands went nowhere.
        """
        # Clear this owner's earlier placeholders: otherwise every tap on
        # "connect a computer" would leave a dead record behind, even when the
        # person changed their mind halfway.
        await self.conn.execute(
            """UPDATE hosts SET status = 'removed', agent_token = NULL
               WHERE owner_id = ? AND kind = 'agent'
                 AND (status = 'pending'
                      OR (status = 'active' AND name LIKE '%-computer'))""",
            (owner_id,),
        )
        cur = await self.conn.execute(
            """INSERT INTO hosts (owner_id, name, ip, ssh_user, kind, status,
                                  last_seen, created_at)
               VALUES (?, ?, '', '', 'agent', 'pending', ?, ?)""",
            (owner_id, name, now(), now()),
        )
        await self.conn.commit()
        return cur.lastrowid or 0

    async def cleanup_agent_hosts(self) -> int:
        """Clears stale machine records. Returns how many were cleared.

        Two kinds of junk:
          * placeholders that never connected. A real machine names itself the
            moment it first comes online, so a name like "*-computer" means the
            agent never got there;
          * same-name duplicates, produced by repeated installs before merging
            by name existed.

        Records are not deleted: they move to removed so that the command
        history behind them stays intact.
        """
        cur = await self.conn.execute(
            """UPDATE hosts SET status = 'removed', agent_token = NULL
               WHERE kind = 'agent'
                 AND (status = 'pending'
                      OR (status = 'active' AND name LIKE '%-computer'))"""
        )
        removed = cur.rowcount or 0

        # Of the same-name records keep the newest: it holds the live token.
        cur = await self.conn.execute(
            """UPDATE hosts SET status = 'removed', agent_token = NULL
               WHERE kind = 'agent' AND status = 'active' AND id NOT IN (
                   SELECT MAX(id) FROM hosts
                   WHERE kind = 'agent' AND status = 'active'
                   GROUP BY owner_id, name
               )"""
        )
        removed += cur.rowcount or 0
        await self.conn.commit()
        return removed

    async def find_agent_by_name(self, owner_id: int, name: str,
                                 exclude_id: int) -> int | None:
        """Finds an already connected machine with the same name.

        Needed when the agent is reinstalled: otherwise the list would grow
        a second machine of the same name that never comes online.
        """
        cur = await self.conn.execute(
            """SELECT id FROM hosts
               WHERE owner_id = ? AND name = ? AND kind = 'agent'
                 AND status = 'active' AND id != ?
               ORDER BY id LIMIT 1""",
            (owner_id, name, exclude_id),
        )
        row = await cur.fetchone()
        return row["id"] if row else None

    async def move_agent_token(self, from_id: int, to_id: int) -> None:
        """Moves the fresh token onto the existing machine record."""
        cur = await self.conn.execute(
            "SELECT agent_token FROM hosts WHERE id = ?", (from_id,)
        )
        row = await cur.fetchone()
        if row is None:
            return
        await self.conn.execute(
            "UPDATE hosts SET agent_token = ?, status = 'active' WHERE id = ?",
            (row["agent_token"], to_id),
        )
        await self.conn.execute(
            "UPDATE hosts SET status = 'removed', agent_token = NULL WHERE id = ?",
            (from_id,),
        )
        await self.conn.commit()

    async def revoke_agent_token(self, host_id: int) -> None:
        """Kills the machine token: the agent will not connect again.

        The agent itself stays installed: only someone with access to the
        machine can remove it, and that is how it should be.
        """
        await self.conn.execute(
            "UPDATE hosts SET agent_token = NULL WHERE id = ?", (host_id,)
        )
        await self.conn.commit()

    async def rename_host(self, host_id: int, name: str) -> None:
        await self.conn.execute(
            "UPDATE hosts SET name = ? WHERE id = ?", (name[:40], host_id)
        )
        await self.conn.commit()

    async def touch_host(self, host_id: int) -> None:
        await self.conn.execute("UPDATE hosts SET last_seen = ? WHERE id = ?", (now(), host_id))
        await self.conn.commit()

    # ---------- enroll tokens ----------

    async def create_enroll_token(self, owner_id: int) -> str:
        token = secrets.token_urlsafe(9)
        await self.conn.execute(
            "INSERT INTO enroll_tokens (token, owner_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, owner_id, now(), now() + config.ENROLL_TOKEN_TTL_SECONDS),
        )
        await self.conn.commit()
        return token

    async def consume_enroll_token(self, token: str) -> int | None:
        """Returns owner_id and burns the token. One-shot: a repeat call returns None."""
        cur = await self.conn.execute(
            "SELECT owner_id, expires_at, used_at FROM enroll_tokens WHERE token = ?", (token,)
        )
        row = await cur.fetchone()
        if not row or row["used_at"] is not None or row["expires_at"] < now():
            return None
        await self.conn.execute(
            "UPDATE enroll_tokens SET used_at = ? WHERE token = ?", (now(), token)
        )
        await self.conn.commit()
        return row["owner_id"]

    async def bind_token_to_host(self, token: str, host_id: int) -> None:
        await self.conn.execute(
            "UPDATE enroll_tokens SET host_id = ? WHERE token = ?", (host_id, token)
        )
        await self.conn.commit()

    # ---------- sessions & recording ----------

    # ---------- shares ----------

    async def grant(self, host_id: int, owner_id: int, grantee_id: int,
                    ttl_seconds: int | None = None) -> None:
        """Grants access. Granting again updates the deadline instead of duplicating."""
        await self.conn.execute(
            """UPDATE shares SET revoked_at = ?
               WHERE host_id = ? AND grantee_id = ? AND revoked_at IS NULL""",
            (now(), host_id, grantee_id),
        )
        await self.conn.execute(
            """INSERT INTO shares (host_id, owner_id, grantee_id, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (host_id, owner_id, grantee_id, now(),
             now() + ttl_seconds if ttl_seconds else None),
        )
        await self.conn.commit()

    async def revoke(self, host_id: int, grantee_id: int) -> bool:
        cur = await self.conn.execute(
            """UPDATE shares SET revoked_at = ?
               WHERE host_id = ? AND grantee_id = ? AND revoked_at IS NULL""",
            (now(), host_id, grantee_id),
        )
        await self.conn.commit()
        return bool(cur.rowcount)

    async def expire_shares(self) -> list[aiosqlite.Row]:
        """Closes shares whose deadline has passed. Returns the closed ones.

        Expiry alone already blocks access, but silently: the person cannot
        tell why the machine vanished. So we close them explicitly and return
        the list in order to warn both sides.
        """
        cur = await self.conn.execute(
            """SELECT s.id, s.host_id, s.owner_id, s.grantee_id, h.name AS host_name
               FROM shares s JOIN hosts h ON h.id = s.host_id
               WHERE s.revoked_at IS NULL AND s.expires_at IS NOT NULL
                 AND s.expires_at <= ?""",
            (now(),),
        )
        rows = list(await cur.fetchall())
        if rows:
            await self.conn.execute(
                "UPDATE shares SET revoked_at = ? WHERE id IN (%s)"
                % ",".join("?" * len(rows)),
                [now(), *[r["id"] for r in rows]],
            )
            await self.conn.commit()
        return rows

    async def shares_of(self, host_id: int) -> list[aiosqlite.Row]:
        """Who currently has access to the machine."""
        cur = await self.conn.execute(
            """SELECT s.grantee_id, s.expires_at, u.username, u.first_name
               FROM shares s LEFT JOIN users u ON u.tg_user_id = s.grantee_id
               WHERE s.host_id = ? AND s.revoked_at IS NULL
                 AND (s.expires_at IS NULL OR s.expires_at > ?)
               ORDER BY s.created_at""",
            (host_id, now()),
        )
        return list(await cur.fetchall())

    async def can_use(self, user_id: int, host_id: int) -> bool:
        """The owner, or somebody whose share is granted and not yet expired."""
        host = await self.get_host(host_id)
        if host is None or host.status != "active":
            return False
        if host.owner_id == user_id:
            return True
        cur = await self.conn.execute(
            """SELECT 1 FROM shares
               WHERE host_id = ? AND grantee_id = ? AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > ?)""",
            (host_id, user_id, now()),
        )
        return await cur.fetchone() is not None

    async def shared_with_me(self, user_id: int) -> list[Host]:
        cur = await self.conn.execute(
            """SELECT h.* FROM hosts h
               JOIN shares s ON s.host_id = h.id
               WHERE s.grantee_id = ? AND s.revoked_at IS NULL
                 AND (s.expires_at IS NULL OR s.expires_at > ?)
                 AND h.status = 'active'
               ORDER BY h.id""",
            (user_id, now()),
        )
        return [Host.from_row(r) for r in await cur.fetchall()]

    async def open_session(self, user_id: int, host_id: int) -> int:
        cur = await self.conn.execute(
            "INSERT INTO sessions (user_id, host_id, started_at) VALUES (?, ?, ?)",
            (user_id, host_id, now()),
        )
        await self.conn.commit()
        return cur.lastrowid or 0

    async def close_session(self, session_id: int) -> None:
        await self.conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ?", (now(), session_id)
        )
        await self.conn.commit()

    async def record_block(
        self,
        session_id: int,
        user_id: int,
        host_id: int,
        command: str,
        output: str,
        exit_code: int | None,
        cwd: str | None,
        duration_ms: int,
        truncated: bool = False,
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO blocks (session_id, user_id, host_id, command, output, exit_code,
                                   cwd, duration_ms, truncated, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                user_id,
                host_id,
                command,
                output,
                exit_code,
                cwd,
                duration_ms,
                1 if truncated else 0,
                now(),
            ),
        )
        await self.conn.commit()
        return cur.lastrowid or 0

    async def recent_blocks(self, user_id: int, limit: int = 30) -> list[aiosqlite.Row]:
        """Own commands plus everything others ran on this user's machines.

        The owner has to see who did what on their machine; sharing access
        without that would be reckless.
        """
        cur = await self.conn.execute(
            """SELECT b.*, h.name AS host_name, h.owner_id AS host_owner,
                      u.username AS actor_name, u.first_name AS actor_first
               FROM blocks b
               JOIN hosts h ON h.id = b.host_id
               LEFT JOIN users u ON u.tg_user_id = b.user_id
               WHERE b.user_id = ? OR h.owner_id = ?
               ORDER BY b.created_at DESC, b.id DESC LIMIT ?""",
            (user_id, user_id, limit),
        )
        return list(await cur.fetchall())

    async def all_blocks(self, user_id: int) -> list[aiosqlite.Row]:
        """The whole history, oldest first, for export as a file.

        In a chat it is unreadable: a thousand lines would drown the
        conversation. As a file it is exactly what an auditor or somebody
        investigating an incident asks for.
        """
        cur = await self.conn.execute(
            """SELECT b.*, h.name AS host_name,
                      u.username AS actor_name, u.first_name AS actor_first
               FROM blocks b
               JOIN hosts h ON h.id = b.host_id
               LEFT JOIN users u ON u.tg_user_id = b.user_id
               WHERE b.user_id = ? OR h.owner_id = ?
               ORDER BY b.created_at, b.id""",
            (user_id, user_id),
        )
        return list(await cur.fetchall())


db = Database()
