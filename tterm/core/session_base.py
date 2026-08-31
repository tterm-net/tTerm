"""The common interface of a terminal session.

There are two kinds and they are interchangeable:

  * `ShellSession` — SSH to a server with a public address. We dial out.
  * `AgentSession` — a laptop or a machine behind NAT. It dials in.

Everything above — the session pool, the handlers, the layout — neither knows
nor needs to know the difference. Hence the shared base class: adding a third
transport means touching only this file.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .formatter import State

#: Silence longer than this is worth a second look: the command may be waiting
#: for an answer rather than working. Deliberately generous — plenty of honest
#: commands think for two seconds — and the check that follows is narrow, so
#: a false alarm costs nothing but a glance.
IDLE_HINT_AFTER = 3.0

#: Called when the output has gone quiet for a while, so the bot can look at
#: it and decide whether the command is waiting for an answer. Separate from
#: on_progress because silence, not new output, is what makes it interesting.
IdleCallback = Callable[[str], Awaitable[None]]

#: Called as output arrives, used to stream long-running commands.
ProgressCallback = Callable[[str], Awaitable[None]]


@dataclass
class Block:
    """One executed block: the command, its output and metadata."""

    command: str
    output: str = ""
    exit_code: int | None = None
    cwd: str | None = None
    duration_ms: int = 0
    timed_out: bool = False
    alt_screen: bool = False
    truncated: bool = False
    #: State after the command: user, euid, host, venv, branch.
    #: Comes from the extended marker; on an older server some fields are
    #: empty.
    state: State = field(default_factory=State)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def duration_s(self) -> float:
        return self.duration_ms / 1000


@dataclass
class SessionStats:
    opened_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    commands_run: int = 0


class TerminalSession(ABC):
    """What every session can do, whatever the transport."""

    def __init__(self) -> None:
        self.stats = SessionStats()
        self.cwd: str | None = None
        self.in_alt_screen = False

    @abstractmethod
    async def connect(self) -> None:
        """Opens the connection and prepares the shell."""

    @abstractmethod
    async def run(
        self,
        command: str,
        on_progress: ProgressCallback | None = None,
        on_idle: IdleCallback | None = None,
        timeout: int | None = None,
    ) -> Block:
        """Runs a command and returns a finished block."""

    @abstractmethod
    async def send_key(self, data: bytes) -> None:
        """Sends raw bytes: Ctrl+C, arrow keys, y/n answers."""

    @abstractmethod
    async def snapshot(self, wait: float = 0.4) -> str:
        """A snapshot of the current screen, for full-screen programs."""

    @abstractmethod
    async def close(self) -> None:
        """Closes the connection. Must not hang if the other side is silent."""

    @property
    @abstractmethod
    def is_alive(self) -> bool:
        ...

    async def interrupt(self) -> None:
        await self.send_key(b"\x03")

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.stats.last_activity

    def _touch(self) -> None:
        self.stats.last_activity = time.time()
        self.stats.commands_run += 1
