"""A pool of live sessions.

The connection is opened once and stays up while the user is working.
If SSH were reopened for every message, the command after `cd /var/log`
would find itself back in the home directory.
"""
from __future__ import annotations

import asyncio
import logging

from .config import config
from .db import Host, db
from .agent_hub import AgentSession
from .session_base import Block, IdleCallback, ProgressCallback, TerminalSession
from .ssh_session import ShellSession

log = logging.getLogger(__name__)


class SessionManager:
    def __init__(self) -> None:
        # (user_id, host_id) -> session
        self._sessions: dict[tuple[int, int], TerminalSession] = {}
        self._db_session_ids: dict[tuple[int, int], int] = {}
        self._locks: dict[tuple[int, int], asyncio.Lock] = {}
        self._reaper: asyncio.Task | None = None

    def _lock_for(self, key: int) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def get_or_create(self, user_id: int, host: Host,
                            terminal_id: int) -> TerminalSession:
        """One live session per terminal.

        The key is the terminal rather than the machine: several windows on the
        same server are the normal way to work — one tailing a log, another
        doing something — and they must not share a shell.
        """
        key = terminal_id
        async with self._lock_for(key):
            session = self._sessions.get(key)
            if session and session.is_alive:
                return session

            if session:  # dead, clean it up
                await session.close()

            log.info("Opening a session user=%s host=%s terminal=%s (%s, %s)",
                     user_id, host.id, terminal_id, host.name, host.kind)
            # The transport follows the host kind: we dial out to a server,
            # a laptop dials in to us.
            session = AgentSession(host) if host.kind == "agent" else ShellSession(host)
            await session.connect()
            self._sessions[key] = session
            self._db_session_ids[key] = await db.open_session(user_id, host.id)
            await db.touch_host(host.id)
            return session

    async def execute(
        self,
        user_id: int,
        host: Host,
        command: str,
        on_progress: ProgressCallback | None = None,
        terminal_id: int = 0,
        on_idle: IdleCallback | None = None,
    ) -> Block:
        """Runs a command and records it in the session log right away."""
        session = await self.get_or_create(user_id, host, terminal_id)
        key = terminal_id

        try:
            block = await session.run(command, on_progress=on_progress,
                                      on_idle=on_idle)
        except ConnectionError:
            # One reconnect attempt: the network blinked, the laptop woke up.
            log.warning("Session dropped, reconnecting: user=%s terminal=%s",
                        user_id, terminal_id)
            await self.drop(terminal_id)
            session = await self.get_or_create(user_id, host, terminal_id)
            block = await session.run(command, on_progress=on_progress,
                                      on_idle=on_idle)

        await db.record_block(
            session_id=self._db_session_ids.get(key, 0),
            user_id=user_id,
            host_id=host.id,
            command=command,
            output=block.output,
            exit_code=block.exit_code,
            cwd=block.cwd,
            duration_ms=block.duration_ms,
            truncated=block.truncated,
            terminal_id=terminal_id,
        )
        return block

    def peek(self, terminal_id: int) -> TerminalSession | None:
        return self._sessions.get(terminal_id)

    async def drop(self, terminal_id: int) -> bool:
        key = terminal_id
        session = self._sessions.pop(key, None)
        if not session:
            return False
        await session.close()
        db_id = self._db_session_ids.pop(key, None)
        if db_id:
            await db.close_session(db_id)
        return True

    async def drop_all_for_user(self, user_id: int) -> int:
        """Closes every terminal this person has open, on any machine."""
        mine = [int(r["id"]) for r in await db.terminals_of_user(user_id)]
        closed = 0
        for terminal_id in mine:
            if await self.drop(terminal_id):
                closed += 1
        return closed

    async def drop_host(self, user_id: int, host_id: int,
                        forget: bool = False) -> int:
        """Closes this person's terminals on one machine.

        With `forget`, the terminals themselves are closed too, not just their
        live sessions. That is what revoking access means: leaving the records
        open would keep someone listed as the owner of windows on a machine
        they can no longer reach, and hand those windows back if access ever
        returned.

        Order matters — the sessions are found through the terminal records,
        so they have to be dropped before the records go.
        """
        rows = await db.terminals_of(user_id, host_id)
        closed = 0
        for row in rows:
            if await self.drop(int(row["id"])):
                closed += 1
        if forget:
            for row in rows:
                await db.close_terminal(int(row["id"]))
        return closed

    # ------------------------------------------------------------------ reaper

    #: Called when a share expires. Injected by the bot so that the core
    #: does not depend on aiogram.
    on_share_expired = None

    def start_reaper(self) -> None:
        if self._reaper is None:
            self._reaper = asyncio.create_task(self._reap_loop())

    #: How often expired shares are checked. Separate from idle-session
    #: cleanup: a minute between expiry and the notice reads as a machine
    #: vanishing — access is already gone while nobody has been told.
    SHARE_TICK = 15
    IDLE_EVERY = 4

    async def _reap_loop(self) -> None:
        tick = 0
        while True:
            try:
                await asyncio.sleep(self.SHARE_TICK)
                tick += 1
                stale = [
                    key
                    for key, s in self._sessions.items()
                    if s.idle_seconds > config.SESSION_IDLE_SECONDS or not s.is_alive
                ] if tick % self.IDLE_EVERY == 0 else []
                for user_id, host_id in stale:
                    log.info("Closing an idle session user=%s host=%s",
                             user_id, host_id)
                    await self.drop(user_id, host_id)

                # Expired shares: cut the session and warn both sides.
                for row in await db.expire_shares():
                    log.info("Access expired: host=%s for user=%s",
                             row["host_id"], row["grantee_id"])
                    # Same as a manual revoke: cut the live windows and let
                    # go of the records. Expiry that only hides the machine
                    # would leave a working shell behind it.
                    await self.drop_host(int(row["grantee_id"]),
                                         int(row["host_id"]), forget=True)
                    if self.on_share_expired is not None:
                        await self.on_share_expired(dict(row))

            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("The session reaper stumbled")

    async def shutdown(self) -> None:
        if self._reaper:
            self._reaper.cancel()
        for key in list(self._sessions):
            await self.drop(*key)


sessions = SessionManager()
