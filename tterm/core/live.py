"""Live output while a command is still running.

Two problems solved in one place, because they are the same problem seen from
different sides: a command that takes a while tells the person nothing.

**Streaming.** Telegram has drafts — the mechanism added for AI answers that
arrive word by word. Ours arrive line by line, which is the same shape. A draft
is addressed by a number, updated by sending the same number again, and carries
a Stop button of its own.

The previous approach edited one ordinary message every 1.5 seconds. It worked,
but frequent edits run into rate limits, the message flickers, and between
edits the output piles up invisibly.

**Waiting for input.** A command can stop and wait for an answer — `git pull`
asking for a username, `apt` asking to confirm. The shell then produces nothing
and returns no marker, so from the outside it is indistinguishable from a long
computation. The session stays busy, later messages do not get through, and the
person sees a counter going up.

We look for the shape of a question: the output stops mid-line, and that line
ends the way prompts end. It cannot be certain — a program is free to print
whatever it likes — so the guess is offered, never acted upon.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

#: How often the draft is refreshed. Drafts are meant for streaming, so this
#: can be tighter than the 1.5s an ordinary message edit needed.
DRAFT_INTERVAL = 0.7

#: How long the output has to stay completely still before a trailing prompt
#: is treated as a question rather than a line that is still being written.
QUIET_BEFORE_PROMPT = 2.0

#: Lines that end like this are asking for something. Kept deliberately short:
#: every entry here is a chance to interrupt a command that was doing fine.
PROMPT_PATTERNS = [
    re.compile(r"\[[yY]/[nN]\]\s*[:?]?\s*$"),          # [y/N]
    re.compile(r"\([yY]es/[nN]o\)\s*[:?]?\s*$"),        # (yes/no)
    # The keyword may be far from the colon — `Username for 'https://host':`
    # has two of its own in the URL — so the line only has to end with one.
    re.compile(r"\b(password|passphrase)\b.*:\s*$", re.I),
    re.compile(r"\b(username|user name|login)\b.*:\s*$", re.I),
    re.compile(r"\bcontinue\b[^?]*\?\s*$", re.I),
    re.compile(r"\bare you sure\b[^?]*\?\s*$", re.I),
    re.compile(r"\bpress\s+(enter|any key)\b.*$", re.I),
]

#: Answers offered for a yes/no question, in the order they are shown.
YES_NO = ("y", "n")


def looks_like_prompt(text: str) -> str | None:
    """Returns the line that looks like a question, or None.

    The test is deliberately narrow: the output must end mid-line — a finished
    line means the program moved on — and that line must match one of the known
    shapes. Anything else is treated as a command that is simply busy.
    """
    if not text or text.endswith(("\n", "\r")):
        return None

    tail = text.rsplit("\n", 1)[-1].strip()
    if not tail or len(tail) > 200:
        return None

    for pattern in PROMPT_PATTERNS:
        if pattern.search(tail):
            return tail
    return None


def is_yes_no(line: str) -> bool:
    """Whether the question can be answered with a single letter."""
    lowered = line.lower()
    return "[y/n" in lowered or "(yes/no" in lowered or "[Y/n" in line


@dataclass
class LiveOutput:
    """Tracks one running command and decides when to redraw it.

    Holds no Telegram objects on purpose: the bot layer asks it what to show
    and when, which keeps this testable without a network.
    """

    started: float = field(default_factory=time.monotonic)
    text: str = ""
    last_draw: float = 0.0
    last_change: float = field(default_factory=time.monotonic)
    stopped: bool = False
    #: The prompt we have already told the person about, so we say it once.
    announced: str | None = None

    def feed(self, chunk: str) -> None:
        if not chunk:
            return
        self.text += chunk
        self.last_change = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def should_draw(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return now - self.last_draw >= DRAFT_INTERVAL

    def drawn(self, now: float | None = None) -> None:
        self.last_draw = time.monotonic() if now is None else now

    def pending_prompt(self, now: float | None = None) -> str | None:
        """The question the command is waiting on, if it has settled into one.

        The pause matters: output arrives in pieces, and a line that merely has
        not been finished yet would otherwise read as a question every time.
        """
        now = time.monotonic() if now is None else now
        if now - self.last_change < QUIET_BEFORE_PROMPT:
            return None
        line = looks_like_prompt(self.text)
        if line is None or line == self.announced:
            return None
        return line
