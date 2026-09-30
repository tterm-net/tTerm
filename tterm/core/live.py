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

#: How often the card is refreshed when nothing new has been printed. The only
#: thing moving then is the clock, and a message repainting twice a second to
#: advance a timer is noise — especially for something like a running server,
#: which prints once at startup and then stays quiet for hours.
QUIET_REDRAW = 6.0

#: How long the output has to stay completely still before a trailing prompt
#: is treated as a question rather than a line that is still being written.
QUIET_BEFORE_PROMPT = 2.0

#: Lines that end like this are asking for something. Kept deliberately short:
#: every entry here is a chance to interrupt a command that was doing fine.
PROMPT_PATTERNS = [
    re.compile(r"\[[yY]/[nN]\]\s*[:?]?\s*$"),          # [y/N]
    re.compile(r"\([yY]/[nN]\)\s*[:?]?\s*$"),          # (Y/n) — Node CLIs, wrangler
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


#: Questions that can only be a question. These are recognised even while the
#: output is still moving — a spinner turning under `Continue? (Y/n)` keeps
#: the output busy forever, and waiting for silence meant never noticing.
#: Weaker shapes like `Password:` still need the output to settle first:
#: that word turns up in ordinary output too.
UNMISTAKABLE = [
    re.compile(r"\[[yY]/[nN]\]"),
    re.compile(r"\([yY]/[nN]\)"),
    re.compile(r"\([yY]es/[nN]o\)"),
]

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\r")


def unmistakable_question(text: str, lines: int = 6) -> str | None:
    """A yes/no question among the last few lines, even if more came after.

    Interactive tools redraw a spinner or a progress line below the question,
    so it is rarely the very last thing printed. Only the unmistakable shapes
    are looked for here, so ordinary output does not trigger buttons.
    """
    if not text:
        return None
    recent = _ANSI.sub("", text).split("\n")[-lines:]
    for line in reversed(recent):
        line = line.strip()
        if 0 < len(line) <= 200 and any(p.search(line) for p in UNMISTAKABLE):
            return line
    return None


def is_yes_no(line: str) -> bool:
    """Whether the question can be answered with a single letter."""
    lowered = line.lower()
    return ("[y/n" in lowered or "(y/n" in lowered or "(yes/no" in lowered)


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
    #: The last question a message was sent about. Kept apart from
    #: `announced`, which new output clears on purpose: a spinner below the
    #: question produces new output every frame, and clearing this one with it
    #: announced the same question over and over.
    last_asked: str | None = None

    def feed(self, chunk: str) -> None:
        if not chunk:
            return
        self.text += chunk
        self.last_change = time.monotonic()
        # New output means the question was answered — or was never one.
        self.announced = None

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def should_draw(self, changed: bool = True,
                    now: float | None = None) -> bool:
        """Whether the card is worth refreshing.

        Two different reasons to redraw, and they deserve different rates. New
        output should appear promptly. A clock ticking beside output that has
        not moved is not news, and repainting for it makes the chat flicker.

        Once a question has been announced the card stops entirely: the output
        is not moving, and a timer counting up next to a repeat of the same
        question only makes the screen busier.
        """
        if self.announced is not None:
            return False
        now = time.monotonic() if now is None else now
        gap = now - self.last_draw
        return gap >= (DRAFT_INTERVAL if changed else QUIET_REDRAW)

    def drawn(self, now: float | None = None) -> None:
        self.last_draw = time.monotonic() if now is None else now

    def pending_prompt(self, now: float | None = None) -> str | None:
        """The question the command is waiting on, if it has settled into one.

        The pause matters: output arrives in pieces, and a line that merely has
        not been finished yet would otherwise read as a question every time.
        """
        now = time.monotonic() if now is None else now

        # A yes/no question is plain from its shape, and the output around it
        # may never go quiet — so it does not wait.
        clear = unmistakable_question(self.text)
        if clear is None:
            self.last_asked = None        # scrolled away: the next one counts
        elif clear != self.last_asked:
            return clear

        if now - self.last_change < QUIET_BEFORE_PROMPT:
            return None
        line = looks_like_prompt(self.text)
        if line is None or line in (self.announced, self.last_asked):
            return None
        return line
