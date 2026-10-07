"""The agent hub: machines that dial in to us.

A laptop cannot be reached from the outside — no stable address, behind NAT,
and it sleeps. So the direction is reversed: the agent opens a WebSocket to us
and keeps it open.

The agent is deliberately dumb: it is only a pipe to a local PTY. Marker
parsing, the bootstrap and the layout all live here, on the hub. That way the
agent does not have to be updated on every machine whenever the output format
changes — and updating an agent on someone else's machine is far more
expensive than shipping our own backend.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field

from .config import config
from .formatter import bootstrap_for, parse_marker
from .session_base import (
    IDLE_HINT_AFTER,
    MAX_LIVE_BYTES,
    Block,
    IdleCallback,
    ProgressCallback,
    SessionBusy,
    ShellExited,
    TerminalSession,
)

log = logging.getLogger(__name__)

ALT_SCREEN_ENTER = re.compile(r"\x1b\[\?(?:1049|47|1047)h")
ALT_SCREEN_EXIT = re.compile(r"\x1b\[\?(?:1049|47|1047)l")


#: Output chunks a shell may pile up while nobody reads it – a program left
#: running in the background with its output on the terminal. Past this the
#: oldest go, so a forgotten window cannot fill the bot's memory.
INBOX_LIMIT = 4000


@dataclass
class Channel:
    """One shell on the agent's side, as seen from here."""

    #: Everything the shell printed that we have not parsed yet.
    inbox: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    booted: bool = False
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))
    #: One command at a time per shell, whichever window sent it.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    #: Terminals typing into this shell. Exactly one with a current agent; on
    #: an older agent every window of the machine shares its single shell.
    users: set[int] = field(default_factory=set)

    def push(self, chunk: str) -> None:
        if self.inbox.qsize() >= INBOX_LIMIT:
            with contextlib.suppress(asyncio.QueueEmpty):
                self.inbox.get_nowait()
        self.inbox.put_nowait(chunk)

    def drain_nowait(self) -> str:
        """Drains everything buffered without waiting for more."""
        parts = []
        while not self.inbox.empty():
            parts.append(self.inbox.get_nowait())
        return "".join(parts)


@dataclass
class AgentLink:
    """A live connection to one machine."""

    host_id: int
    owner_id: int
    name: str
    os_info: str
    version: str
    #: Which shell runs on that machine. The marker is written differently for
    #: each, so this decides which bootstrap gets sent.
    shell: str
    send: object  # async callable: (dict) -> None
    #: Whether the agent keeps a shell per terminal window. Older ones keep a
    #: single shell for the whole machine, and every window types into it.
    channels: bool = False
    connected_at: float = field(default_factory=time.time)
    _chans: dict[int | None, Channel] = field(default_factory=dict)

    def key_for(self, terminal_id: int) -> int | None:
        """The agent-side shell a terminal types into."""
        return terminal_id if self.channels else None

    def channel(self, terminal_id: int) -> Channel:
        key = self.key_for(terminal_id)
        chan = self._chans.get(key)
        if chan is None:
            chan = self._chans[key] = Channel()
        return chan

    def peek(self, terminal_id: int) -> Channel | None:
        return self._chans.get(self.key_for(terminal_id))

    def forget(self, terminal_id: int) -> None:
        self._chans.pop(self.key_for(terminal_id), None)

    async def push(self, key: int | None, chunk: str) -> None:
        """Output from the agent, for the shell it names."""
        chan = self._chans.get(key)
        if chan is None and not self.channels:
            chan = self._chans[None] = Channel()
        if chan is not None:
            # A shell we already closed may still say its last words. Nobody
            # reads them, and keeping them would only grow.
            chan.push(chunk)

    def exited(self, key: int | None) -> None:
        """The agent says this shell is gone – someone typed `exit`."""
        chan = self._chans.get(key)
        if chan is not None:
            chan.booted = False


class AgentRegistry:
    """Who is online right now, keyed by host id."""

    def __init__(self) -> None:
        self._links: dict[int, AgentLink] = {}

    def attach(self, link: AgentLink) -> None:
        old = self._links.get(link.host_id)
        if old is not None:
            log.info("Agent host=%s reconnected, evicting the previous link",
                     link.host_id)
        self._links[link.host_id] = link

    def detach(self, link: AgentLink) -> bool:
        """Forgets a link that went away – but only if it is still current.

        An agent that notices a dead connection reconnects at once, while our
        end of the old connection may take a while longer to notice. Removing
        by host id then took the new link off the registry: the agent stayed
        happily connected, the bot showed the machine offline, and nothing in
        either log said why. Only a restart of the agent helped.
        """
        if self._links.get(link.host_id) is link:
            del self._links[link.host_id]
            return True
        return False

    def get(self, host_id: int) -> AgentLink | None:
        return self._links.get(host_id)

    def online(self) -> list[int]:
        return list(self._links)


registry = AgentRegistry()


class SharedShellBusy(SessionBusy):
    """An older agent's single shell is busy in another window."""


class AgentSession(TerminalSession):
    """A session over an agent. Indistinguishable from SSH from the outside.

    Each terminal window has its own shell on the agent's side, named by the
    terminal id. With an older agent all windows share one shell; then the
    session still works, but cannot pretend the windows are independent.
    """

    def __init__(self, host, terminal_id: int = 0) -> None:
        super().__init__()
        self.host = host
        self.terminal_id = terminal_id

    @property
    def _link(self) -> AgentLink | None:
        return registry.get(self.host.id)

    @property
    def _chan(self) -> Channel:
        link = self._link
        if link is None:
            raise ConnectionError(f"{self.host.name} disconnected")
        return link.channel(self.terminal_id)

    @property
    def is_alive(self) -> bool:
        link = self._link
        chan = link.peek(self.terminal_id) if link is not None else None
        return chan is not None and chan.booted

    # ------------------------------------------------------------- connect

    async def connect(self) -> None:
        link = self._link
        if link is None:
            raise ConnectionError(
                f"{self.host.name} is offline. Check that the agent is running "
                "on that machine."
            )
        chan = link.channel(self.terminal_id)
        chan.users.add(self.terminal_id)
        if chan.booted:
            return          # an older agent: another window booted the shell

        # The same bootstrap as over SSH: marker, pagers off, echo off.
        # Sent line by line — the terminal input buffer is small, and on macOS
        # a single write over a kilobyte blocks forever.
        prelude = [
            "stty -echo 2>/dev/null; PS1=''; PS2=''; PS4=''",
            "export COLUMNS=100 LINES=40 LESS=FRX",
            f"__TT_NONCE={chan.nonce}",
        ]
        boot = bootstrap_for(link.shell)
        for line in prelude + boot.strip("\n").split("\n"):
            await self._write(line + "\n")
            await asyncio.sleep(0.01)

        await self._drain(quiet=0.7, limit=15.0)
        chan.booted = True

        probe = await self._exchange("__tt_selfcheck=1", timeout=10)
        if probe is None:
            chan.booted = False
            raise ConnectionError(
                f"The shell on {self.host.name} is not printing the marker."
            )

    # ------------------------------------------------------------- execute

    async def run(
        self,
        command: str,
        on_progress: ProgressCallback | None = None,
        on_idle: IdleCallback | None = None,
        timeout: int | None = None,
    ) -> Block:
        link = self._link
        if link is None:
            raise ConnectionError(f"{self.host.name} is offline")
        chan = self._chan
        if not link.channels and chan.lock.locked() and len(chan.users) > 1:
            # An older agent has one shell for every window. Waiting for it
            # would mean waiting for whatever runs in the other window – a
            # server, forever – and typing into it was worse: the command
            # went to that program as input.
            raise SharedShellBusy(
                f"Every window on {self.host.name} shares one shell (agent "
                f"{link.version or '?'}), and it is busy in another window. "
                "Updating the agent gives each window its own: /addhost → "
                "Computer, then run the command it gives once more.")
        async with chan.lock:
            if not self.is_alive:
                raise ConnectionError(f"{self.host.name} is offline")

            block = Block(command=command)
            started = time.perf_counter()
            await self._write(command + "\n")

            parsed = await self._exchange(
                None,
                timeout=timeout or config.COMMAND_TIMEOUT_SECONDS,
                on_progress=on_progress,
                on_idle=on_idle,
                block=block,
            )
            block.duration_ms = int((time.perf_counter() - started) * 1000)
            if parsed is not None:
                block.output, block.state, code = parsed
                block.exit_code = code
                block.cwd = block.state.cwd or None
                if block.cwd:
                    self.cwd = block.cwd
            else:
                block.timed_out = True
            self._touch()
            return block

    async def _exchange(
        self,
        command: str | None,
        timeout: float,
        on_progress: ProgressCallback | None = None,
        on_idle: IdleCallback | None = None,
        block: Block | None = None,
    ):
        """Reads the agent stream up to the marker. Returns (output, state, code)."""
        chan = self._chan
        if command is not None:
            await self._write(command + "\n")

        buf = ""
        deadline = time.monotonic() + timeout
        last_progress = 0.0
        last_output = time.monotonic()

        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(chan.inbox.get(), timeout=0.5)
            except asyncio.TimeoutError:
                chunk = ""
            if chunk:
                buf += chunk
                # Same cap as over SSH: the head goes as it arrives, so a
                # command that never stops printing cannot fill memory.
                if len(buf) > MAX_LIVE_BYTES:
                    buf = buf[-MAX_LIVE_BYTES:]
                    if block:
                        block.truncated = True
                if ALT_SCREEN_ENTER.search(chunk):
                    self.in_alt_screen = True
                    if block:
                        block.alt_screen = True
                if ALT_SCREEN_EXIT.search(chunk):
                    self.in_alt_screen = False

            parsed = parse_marker(buf, chan.nonce)
            if parsed is not None:
                return parsed
            if not chan.booted:
                # The agent said this shell is gone – `exit`, most likely.
                # Waiting on would mean waiting for the full timeout.
                raise ShellExited(
                    "The shell in this window has exited. The next command "
                    "opens a new one.")

            now = time.monotonic()
            if on_progress and buf and now - last_progress >= config.STREAM_EDIT_INTERVAL:
                last_progress = now
                await on_progress(buf)

            # Same as over SSH: silence may mean a question, not work.
            if on_idle and buf and now - last_output >= IDLE_HINT_AFTER:
                last_output = now
                await on_idle(buf)
        return None

    async def _drain(self, quiet: float = 0.7, limit: float = 10.0) -> None:
        link = self._link
        if link is None:
            return
        chan = link.channel(self.terminal_id)
        last = started = time.monotonic()
        while time.monotonic() - started < limit:
            try:
                await asyncio.wait_for(chan.inbox.get(), timeout=0.2)
                last = time.monotonic()
            except asyncio.TimeoutError:
                if time.monotonic() - last > quiet:
                    return

    # ------------------------------------------------------------- control

    def _msg(self, link: AgentLink, msg: dict) -> dict:
        key = link.key_for(self.terminal_id)
        if key is not None:
            msg["ch"] = key     # an older agent knows nothing of channels
        return msg

    async def _write(self, data: str) -> None:
        link = self._link
        if link is None:
            raise ConnectionError(f"{self.host.name} disconnected")
        await link.send(self._msg(link, {"t": "in", "data": data}))  # type: ignore[operator]

    async def send_key(self, data: bytes) -> None:
        await self._write(data.decode("utf-8", "replace"))

    async def snapshot(self, wait: float = 0.4) -> str:
        await asyncio.sleep(wait)
        link = self._link
        chan = link.peek(self.terminal_id) if link else None
        return chan.drain_nowait() if chan else ""

    async def close(self) -> None:
        """Closes this window's shell – and never anybody else's.

        It used to close the machine's only shell, so the idle reaper tidying
        one window, or the person closing one, killed whatever ran in the
        others.
        """
        link = self._link
        if link is None:
            return
        chan = link.peek(self.terminal_id)
        if chan is not None:
            chan.users.discard(self.terminal_id)
            if chan.users:
                return      # an older agent: other windows still use it
            chan.booted = False
        link.forget(self.terminal_id)
        try:
            await link.send(self._msg(link, {"t": "close"}))  # type: ignore[operator]
        except Exception:
            pass


def decode_hello(raw: str) -> dict | None:
    """Parses the agent's first message. Returns None if it is not valid."""
    try:
        msg = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(msg, dict) or msg.get("t") != "hello":
        return None
    if not isinstance(msg.get("token"), str) or not msg["token"]:
        return None
    return msg
