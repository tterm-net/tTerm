"""Commands worth asking about twice.

A terminal in a chat makes some mistakes easier than they are at a keyboard.
Messages get sent to the wrong chat. With several terminals open on one
machine, the window you are looking at is not always the one that answers.
And on a phone, a command is often reused by tapping an old message and
editing a word.

So a small set of commands is held back for one confirmation. The set is
deliberately small: a bot that asks about everything trains people to confirm
without reading, which is worse than not asking at all.

What qualifies: the damage is immediate, and nothing brings it back. Deleting
a file tree, wiping a disk, dropping a database, cutting the machine off the
network. Not `git reset --hard` — unpleasant, but the work is usually still
somewhere. Not `rm file.txt` — one file, named deliberately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: How long a pending confirmation stays valid. Long enough to read what is
#: about to happen, short enough that a forgotten one does not fire later.
CONFIRM_WINDOW = 120.0


@dataclass(frozen=True)
class Danger:
    """Why a command was held back."""

    pattern: re.Pattern[str]
    what: str          # what it does, in plain words
    lost: str          # what does not come back


#: Ordered by how bad it is, because the first match wins and the worst
#: description should be the one shown.
RULES: list[Danger] = [
    Danger(
        re.compile(r"\brm\b(?=[^|;&]*\s-\w*[rR]\w*\b)"
                   r"(?=[^|;&]*\s-\w*[fF]\w*\b)", re.I),
        "delete a directory and everything inside it",
        "There is no undo and no bin to look in.",
    ),
    Danger(
        re.compile(r"\bmkfs(\.\w+)?\b|\bfdisk\b|\bparted\b|\bwipefs\b", re.I),
        "rewrite a disk's filesystem",
        "Everything on that disk goes, not just files.",
    ),
    Danger(
        re.compile(r"\bdd\b[^|;&]*\bof=\s*/dev/", re.I),
        "write directly onto a device",
        "Whatever was on it is gone the moment this starts.",
    ),
    Danger(
        re.compile(r"\b(DROP\s+(DATABASE|TABLE)|TRUNCATE\s+TABLE)\b", re.I),
        "drop a database or a table",
        "Only a backup brings it back.",
    ),
    Danger(
        re.compile(r"\b(shutdown|poweroff|halt)\b|\binit\s+0\b", re.I),
        "turn the machine off",
        "Nothing here can turn it back on — that needs the provider's panel.",
    ),
    Danger(
        re.compile(r"\breboot\b|\binit\s+6\b", re.I),
        "reboot the machine",
        "The session drops, and whatever was running stops with it.",
    ),
    Danger(
        re.compile(r"\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd)\b", re.I),
        "stop the SSH service",
        "That is the way in. Stopping it locks the door from the inside.",
    ),
    Danger(
        re.compile(r"\bufw\s+(deny|reject)\b|\biptables\b[^|;&]*\bDROP\b", re.I),
        "change the firewall",
        "A wrong rule can cut the machine off with no way back in.",
    ),
    Danger(
        re.compile(r"\buserdel\b|\bdeluser\b", re.I),
        "delete a user account",
        "Their files and access go with them.",
    ),
]

#: Paths where a recursive delete is not a mistake to be confirmed but one to
#: be refused: nothing on the machine survives them.
ROOT_TARGETS = re.compile(
    r"\brm\b[^|;&]*\s(?:/|/\*|~|~/\*|/\w+/\.\.|\$HOME|\${HOME})\s*(?:$|[|;&])"
)


def looks_destructive(command: str) -> Danger | None:
    """The rule this command trips, or None.

    Only the first command of a line is inspected on purpose. Chains like
    `cd /tmp && rm -rf build` are ordinary work, and asking about every `&&`
    would make the question meaningless.
    """
    text = command.strip()
    if not text:
        return None

    for rule in RULES:
        if rule.pattern.search(text):
            return rule
    return None


def hits_everything(command: str) -> bool:
    """Whether a recursive delete points at the root or a home directory.

    Kept apart from the rest because the answer is different: this is worth
    saying out loud rather than confirming, and no one types it on purpose.
    """
    return bool(ROOT_TARGETS.search(command.strip()))
