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
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field

from .config import config
from .formatter import BOOTSTRAP, parse_marker
from .session_base import Block, ProgressCallback, TerminalSession

log = logging.getLogger(__name__)

ALT_SCREEN_ENTER = re.compile(r"\x1b\[\?(?:1049|47|1047)h")
ALT_SCREEN_EXIT = re.compile(r"\x1b\[\?(?:1049|47|1047)l")


@dataclass
class AgentLink:
    """A live connection to one machine."""

    host_id: int
    owner_id: int
    name: str
    os_info: str
    version: str
    send: object  # async callable: (dict) -> None
    #: Everything the agent sent that we have not parsed yet.
    inbox: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    connected_at: float = field(default_factory=time.time)
    booted: bool = False
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))

    async def push(self, chunk: str) -> None:
        await self.inbox.put(chunk)

    def drain_nowait(self) -> str:
        """Drains everything buffered without waiting for more."""
        parts = []
        while not self.inbox.empty():
            parts.append(self.inbox.get_nowait())
        return "".join(parts)


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

    def detach(self, host_id: int) -> None:
        self._links.pop(host_id, None)

    def get(self, host_id: int) -> AgentLink | None:
        return self._links.get(host_id)

    def online(self) -> list[int]:
        return list(self._links)


registry = AgentRegistry()


class AgentSession(TerminalSession):
    """A session over an agent. Indistinguishable from SSH from the outside."""

    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._lock = asyncio.Lock()

    @property
    def _link(self) -> AgentLink | None:
        return registry.get(self.host.id)

    @property
    def is_alive(self) -> bool:
        link = self._link
        return link is not None and link.booted

    # ------------------------------------------------------------- connect

    async def connect(self) -> None:
        link = self._link
        if link is None:
            raise ConnectionError(
                f"{self.host.name} is offline. Check that the agent is running "
                "on that machine."
            )
        if link.booted:
            return

        # The same bootstrap as over SSH: marker, pagers off, echo off.
        # Sent line by line — the terminal input buffer is small, and on macOS
        # a single write over a kilobyte blocks forever.
        prelude = [
            "stty -echo 2>/dev/null; PS1=''; PS2=''; PS4=''",
            "export COLUMNS=100 LINES=40 LESS=FRX",
            f"__TT_NONCE={link.nonce}",
        ]
        for line in prelude + BOOTSTRAP.strip("\n").split("\n"):
            await self._write(line + "\n")
            await asyncio.sleep(0.01)

        await self._drain(quiet=0.7, limit=15.0)
        link.booted = True

        probe = await self._exchange("__tt_selfcheck=1", timeout=10)
        if probe is None:
            link.booted = False
            raise ConnectionError(
                f"The shell on {self.host.name} is not printing the marker. "
                "The machine may not be running bash."
            )

    # ------------------------------------------------------------- execute

    async def run(
        self,
        command: str,
        on_progress: ProgressCallback | None = None,
        timeout: int | None = None,
    ) -> Block:
        async with self._lock:
            if not self.is_alive:
                raise ConnectionError(f"{self.host.name} is offline")

            block = Block(command=command)
            started = time.perf_counter()
            await self._write(command + "\n")

            parsed = await self._exchange(
                None,
                timeout=timeout or config.COMMAND_TIMEOUT_SECONDS,
                on_progress=on_progress,
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
        block: Block | None = None,
    ):
        """Reads the agent stream up to the marker. Returns (output, state, code)."""
        link = self._link
        if link is None:
            raise ConnectionError(f"{self.host.name} disconnected")
        if command is not None:
            await self._write(command + "\n")

        buf = ""
        deadline = time.monotonic() + timeout
        last_progress = 0.0

        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(link.inbox.get(), timeout=0.5)
            except asyncio.TimeoutError:
                chunk = ""
            if chunk:
                buf += chunk
                if ALT_SCREEN_ENTER.search(chunk):
                    self.in_alt_screen = True
                    if block:
                        block.alt_screen = True
                if ALT_SCREEN_EXIT.search(chunk):
                    self.in_alt_screen = False

            parsed = parse_marker(buf, link.nonce)
            if parsed is not None:
                return parsed

            now = time.monotonic()
            if on_progress and buf and now - last_progress >= config.STREAM_EDIT_INTERVAL:
                last_progress = now
                await on_progress(buf)
        return None

    async def _drain(self, quiet: float = 0.7, limit: float = 10.0) -> None:
        link = self._link
        if link is None:
            return
        last = started = time.monotonic()
        while time.monotonic() - started < limit:
            try:
                await asyncio.wait_for(link.inbox.get(), timeout=0.2)
                last = time.monotonic()
            except asyncio.TimeoutError:
                if time.monotonic() - last > quiet:
                    return

    # ------------------------------------------------------------- control

    async def _write(self, data: str) -> None:
        link = self._link
        if link is None:
            raise ConnectionError(f"{self.host.name} disconnected")
        await link.send({"t": "in", "data": data})  # type: ignore[operator]

    async def send_key(self, data: bytes) -> None:
        await self._write(data.decode("utf-8", "replace"))

    async def snapshot(self, wait: float = 0.4) -> str:
        await asyncio.sleep(wait)
        link = self._link
        return link.drain_nowait() if link else ""

    async def close(self) -> None:
        link = self._link
        if link is None:
            return
        link.booted = False
        try:
            await link.send({"t": "close"})  # type: ignore[operator]
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
