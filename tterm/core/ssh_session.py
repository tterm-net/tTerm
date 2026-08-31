"""A persistent SSH session that splits output into blocks.

The core idea, borrowed from Warp and iTerm2: a terminal does not know where
one command ends and the next begins — only the shell does. So we ask the
shell to tell us, by printing a marker from PROMPT_COMMAND.

The marker carries the exit code and the working directory, so we get them
exactly instead of guessing from a timeout. Format:

    \\x1e<nonce>\\x1e<exit_code>\\x1e<cwd>\\x1e\\x1f

The separators 0x1E (RS) and 0x1F (US) are deliberate: bash gives them no
special meaning. Do not use \\x01/\\x02 — readline reserves those for marking
non-printing parts of the prompt, the same as \\[ and \\], and on bash 3.2 in
macOS $? and ${PWD} then stop expanding.

The connection is persistent: without it `cd` would not carry over between
messages.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import time

import asyncssh

from .ca import ca
from .formatter import BOOTSTRAP, parse_marker
from .session_base import (
    IDLE_HINT_AFTER,
    Block,
    IdleCallback,
    ProgressCallback,
    TerminalSession,
)
from .config import config
from .db import Host

# Sequences entering and leaving the alternate screen (htop, vim, less).
ALT_SCREEN_ENTER = re.compile(rb"\x1b\[\?(?:1049|47|1047)h")
ALT_SCREEN_EXIT = re.compile(rb"\x1b\[\?(?:1049|47|1047)l")


class ShellSession(TerminalSession):
    """A live SSH connection to one host, with an interactive bash over a PTY."""

    def __init__(self, host: Host) -> None:
        super().__init__()
        self.host = host
        self.nonce = secrets.token_hex(8)
        self._last_parse_ok = False

        self._conn: asyncssh.SSHClientConnection | None = None
        self._proc: asyncssh.SSHClientProcess | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ connect

    async def connect(self) -> None:
        """Connects with a certificate and starts bash with our marker in place."""
        client_key, cert = ca.issue_client_cert(self.host.ssh_user)

        self._conn = await asyncssh.connect(
            host=self.host.ip,
            port=self.host.ssh_port,
            username=self.host.ssh_user,
            client_keys=[(client_key, cert)],
            known_hosts=None,  # TODO: pin the host key at registration time
            keepalive_interval=30,
            keepalive_count_max=3,
            connect_timeout=15,
        )

        self._proc = await self._conn.create_process(
            "exec bash --noediting -i",
            term_type="xterm-256color",
            term_size=(100, 40),
            encoding=None,
            stderr=asyncssh.STDOUT,
        )
        await self._bootstrap()

    async def _bootstrap(self) -> None:
        """Prepares the shell: echo off, pagers off, marker in place.

        The bootstrap is multi-line, and once PROMPT_COMMAND is set every
        remaining line prints its own marker. So we read until silence rather
        than until the first marker: otherwise the extra markers would stay in
        the buffer and shift onto the next command.
        """
        prelude = (
            "stty -echo 2>/dev/null; PS1=''; PS2=''; PS4=''",
            "export COLUMNS=100 LINES=40 LESS=FRX",
            f"__TT_NONCE={self.nonce}",
        )
        await self._feed(list(prelude) + BOOTSTRAP.strip("\n").split("\n"))
        await self._drain(quiet=0.7, limit=20.0)
        await self._verify_bootstrap()

    async def _feed(self, lines: list[str]) -> None:
        """Sends a script line by line.

        The terminal input buffer is small — 1024 bytes on macOS. Writing more
        than that in one go, while the shell is busy parsing the previous
        line, fills the buffer and blocks forever.
        """
        for line in lines:
            self._write(line + "\n")
            await asyncio.sleep(0.01)

    async def _verify_bootstrap(self) -> None:
        """Confirms the marker is printed before the user's first command.

        If the bootstrap did not take — incompatible syntax, a different
        shell, a stripped-down busybox — then without this check it is not the
        session that breaks but every command separately: the marker is never
        found and everything hangs until its timeout. A silent hang is far
        more expensive to diagnose than a clear error here.
        """
        self._write("__tt_prompt_selfcheck=1\n")
        raw = await self._read_until_marker(timeout=10)
        if self._last_parse_ok:
            return
        tail = _decode(raw)[-300:].replace("\n", "\\n")
        raise ConnectionError(
            f"Could not prepare the shell on {self.host.name}: no marker printed. "
            f"The server is probably not running bash. Last output: {tail!r}"
        )

    async def _drain(self, quiet: float = 0.7, limit: float = 10.0) -> bytes:
        """Reads the stream until it falls silent. Everything read is discarded."""
        assert self._proc is not None
        buf = bytearray()
        started = time.monotonic()
        last = time.monotonic()
        while time.monotonic() - started < limit:
            try:
                chunk = await asyncio.wait_for(self._proc.stdout.read(65536), timeout=0.2)
            except asyncio.TimeoutError:
                chunk = b""
            except (asyncssh.Error, ConnectionResetError):
                break
            if chunk:
                buf.extend(chunk)
                last = time.monotonic()
            elif time.monotonic() - last > quiet:
                break
        return bytes(buf)

    # ------------------------------------------------------------------ execute

    async def run(
        self,
        command: str,
        on_progress: ProgressCallback | None = None,
        on_idle: IdleCallback | None = None,
        timeout: int | None = None,
    ) -> Block:
        """Runs a command and returns a finished block.

        on_progress is called as output arrives, to stream long commands into
        an editable message.
        """
        async with self._lock:
            if not self.is_alive:
                raise ConnectionError("The session is closed")

            block = Block(command=command)
            started = time.perf_counter()
            self._write(command + "\n")

            raw = await self._read_until_marker(
                timeout=timeout or config.COMMAND_TIMEOUT_SECONDS,
                on_progress=on_progress,
                on_idle=on_idle,
                block=block,
            )

            block.duration_ms = int((time.perf_counter() - started) * 1000)
            block.output = _decode(raw)
            if block.cwd:
                self.cwd = block.cwd

            self._touch()
            return block

    async def _read_until_marker(
        self,
        timeout: int,
        on_progress: ProgressCallback | None = None,
        on_idle: IdleCallback | None = None,
        block: Block | None = None,
    ) -> bytes:
        """Reads the stream up to the prompt marker and returns what came before."""
        assert self._proc is not None
        buf = bytearray()
        deadline = time.monotonic() + timeout
        last_progress = 0.0
        last_output = time.monotonic()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if block:
                    block.timed_out = True
                return bytes(buf)

            try:
                chunk = await asyncio.wait_for(
                    self._proc.stdout.read(65536), timeout=min(remaining, 1.0)
                )
            except asyncio.TimeoutError:
                # Silence is normal here; just keep checking the deadline.
                chunk = b""
            except (asyncssh.Error, ConnectionResetError) as exc:
                raise ConnectionError(f"Lost the connection to {self.host.name}") from exc

            if chunk:
                buf.extend(chunk)
                last_output = time.monotonic()
                if ALT_SCREEN_ENTER.search(chunk):
                    self.in_alt_screen = True
                    if block:
                        block.alt_screen = True
                if ALT_SCREEN_EXIT.search(chunk):
                    self.in_alt_screen = False
            elif self._proc.stdout.at_eof():
                raise ConnectionError(f"The session on {self.host.name} ended")

            parsed = parse_marker(_decode(bytes(buf)), self.nonce)
            self._last_parse_ok = parsed is not None
            if parsed is not None:
                clean, state, code = parsed
                if block:
                    block.exit_code = code
                    block.state = state
                    block.cwd = state.cwd or None
                return clean.encode("utf-8", "replace")

            # Streaming: hand out partial output no more often than the
            # configured interval.
            now = time.monotonic()
            if on_progress and buf and now - last_progress >= config.STREAM_EDIT_INTERVAL:
                last_progress = now
                await on_progress(_decode(bytes(buf)))

            # Nothing new for a while: the command may be waiting for an
            # answer rather than working. Hand the output over and let the
            # bot decide — it can read a prompt, this loop cannot.
            if on_idle and buf and now - last_output >= IDLE_HINT_AFTER:
                last_output = now
                await on_idle(_decode(bytes(buf)))

    # ------------------------------------------------------------------ control

    def _write(self, data: str) -> None:
        assert self._proc is not None
        self._proc.stdin.write(data.encode())

    async def send_key(self, data: bytes) -> None:
        """Sends raw bytes: Ctrl+C, arrow keys, y/n answers."""
        assert self._proc is not None
        self._proc.stdin.write(data)

    async def interrupt(self) -> None:
        await self.send_key(b"\x03")

    async def snapshot(self, wait: float = 0.4) -> str:
        """A snapshot of the current screen, for full-screen programs."""
        assert self._proc is not None
        await asyncio.sleep(wait)
        buf = bytearray()
        try:
            while True:
                chunk = await asyncio.wait_for(self._proc.stdout.read(65536), timeout=0.2)
                if not chunk:
                    break
                buf.extend(chunk)
        except asyncio.TimeoutError:
            pass
        return _decode(bytes(buf))

    @property
    def is_alive(self) -> bool:
        return (
            self._conn is not None
            and self._proc is not None
            and not self._proc.stdout.at_eof()
        )

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.stats.last_activity

    async def close(self) -> None:
        """Closes the connection without insisting on the server's reply.

        `wait_closed()` can hang when the server no longer answers: the
        network dropped, the machine was powered off. At shutdown that turned
        into a process that never exits. We wait briefly and move on — the
        connection dies with the process anyway.
        """
        try:
            if self._proc is not None:
                self._proc.close()
            if self._conn is not None:
                self._conn.close()
                try:
                    await asyncio.wait_for(self._conn.wait_closed(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
        except Exception:
            pass
        finally:
            self._proc = None
            self._conn = None


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")
