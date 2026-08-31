"""The machine list, built as a rich message.

The machine name is a small button inside the line (`RichTextButton`).
Tapping it makes the machine active and reveals its actions underneath:
Access and Remove. The single tap stays with the main action while rare
operations take no space until needed.

There is no status dot: the button carries that role — the active machine
is blue, an unreachable one is grey and not clickable.

Only an agent machine that is currently offline is greyed out: it truly
cannot be reached. An SSH server stays clickable at all times — the absence
of a live session does not mean it is unavailable, the session opens on the
first command.

The command output card is not built here: it stayed a plain message.
"""
from __future__ import annotations

from aiogram.types import (
    CopyTextButton,
    DisabledButton,
    InputRichBlockButtons,
    InputRichBlockParagraph,
    InputRichMessage,
    RichMessageButton,
    RichTextBold,
    RichTextButton,
    RichTextCode,
    RichTextItalic,
)

from ..core.db import Host, db
from ..core.formatter import PC_ICON, SERVER_ICON

#: No heading block on purpose: a `SectionHeading` of any size still renders
#: in the heading font and makes the message look larger than its neighbours.
#: A bold paragraph keeps the same size as the rest of the chat.
#:
#: "Machines", not "servers": a laptop can be connected too.
TITLE = "Your machines"

#: The add button uses a different verb on purpose: the machine name already
#: acts as "connect", and two identical words side by side would read as one
#: action.
ADD_LABEL = "+ Add a machine"


def _icon(host: Host) -> str:
    return PC_ICON if host.kind == "agent" else SERVER_ICON


def _reachable(host: Host, online: bool) -> bool:
    """Whether the machine can be reached right now."""
    return online if host.kind == "agent" else True


def _name_button(host: Host, active: bool, online: bool) -> RichTextButton:
    return RichTextButton(button=RichMessageButton(
        text=host.name,
        callback_data=f"use:{host.id}",
        style="primary" if active else None,
        # An object, and only at creation time: the model is frozen.
        disabled=None if _reachable(host, online) else DisabledButton(),
    ))


def screen(text_blocks: list, rows: list[list[RichMessageButton]]) -> InputRichMessage:
    """A screen made of text and rows of in-message buttons.

    Shared by every menu in the bot: buttons inside a message look tidier and
    do not stretch across the full width like a keyboard below it.
    """
    blocks = list(text_blocks)
    for row in rows:
        blocks.append(InputRichBlockButtons(align="left", buttons=row))
    return InputRichMessage(blocks=blocks)


def para(*parts) -> InputRichBlockParagraph:
    return InputRichBlockParagraph(text=list(parts))


def bold(text: str) -> RichTextBold:
    return RichTextBold(text=text)


def button(text: str, data: str, style: str | None = None,
           enabled: bool = True) -> RichMessageButton:
    return RichMessageButton(
        text=text, callback_data=data, style=style,
        disabled=None if enabled else DisabledButton(),
    )


def code(text: str) -> RichTextCode:
    return RichTextCode(text=text)


def italic(text: str) -> RichTextItalic:
    return RichTextItalic(text=text)


def link(text: str, url: str) -> RichMessageButton:
    return RichMessageButton(text=text, url=url)


def copy(text: str, payload: str) -> RichMessageButton:
    """A button that copies text to the clipboard.

    Needed because a `pre` block inside a rich message has no copy affordance
    of its own, unlike a `<pre>` in a plain message. Without this the install
    command has to be retyped by hand.
    """
    return RichMessageButton(text=text, copy_text=CopyTextButton(text=payload))


def back(to: str = "addhost") -> RichMessageButton:
    return button("‹ Back", to)


async def build(hosts: list[Host], active: Host | None, user_id: int,
                online: dict[int, bool],
                active_terminal: int | None = None) -> InputRichMessage:
    """Builds the machine list message."""
    blocks: list = [InputRichBlockParagraph(text=[RichTextBold(text=TITLE)])]

    for h in hosts:
        is_active = bool(active and h.id == active.id)
        tail = h.ip or ("computer" if h.kind == "agent" else "—")
        if h.owner_id != user_id:
            owner = await db.username_of(h.owner_id) or "its owner"
            tail = f"from {owner}"
        elif not _reachable(h, online.get(h.id, False)):
            tail = "offline"

        blocks.append(InputRichBlockParagraph(text=[
            f"{_icon(h)} ", RichTextCode(text=f"#{h.id}"), " ",
            _name_button(h, is_active, online.get(h.id, False)),
            RichTextItalic(text=f"  {tail}"),
        ]))

        if not is_active:
            continue

        # A machine can carry several terminals, the way you keep more than one
        # window open on a server. They show up only under the selected
        # machine — listing everyone's windows all the time would bury the list.
        terminals = await db.terminals_of(user_id, h.id)
        if len(terminals) > 1:
            # Numbered by position, so closing one in the middle renumbers the
            # rest instead of leaving a gap. A named terminal keeps its name.
            row = [
                RichMessageButton(
                    text=term["name"] or str(n),
                    callback_data=f"term:{term['id']}",
                    style="primary" if term["id"] == active_terminal else None,
                )
                for n, term in enumerate(terminals, start=1)
            ]
            blocks.append(InputRichBlockButtons(align="left", buttons=row))

        actions = [RichMessageButton(text="+ Terminal",
                                     callback_data=f"newterm:{h.id}")]
        if len(terminals) > 1 and active_terminal:
            actions.append(RichMessageButton(
                text="Rename", callback_data=f"renameterm:{active_terminal}"))
            actions.append(RichMessageButton(
                text="Close", style="danger",
                callback_data=f"closeterm:{active_terminal}"))

        # The rest is management, and only the owner has any: someone granted
        # access can work on the machine but not dispose of it.
        if h.owner_id == user_id:
            shares = await db.shares_of(h.id)
            actions.append(RichMessageButton(
                text=f"Access ({len(shares)})" if shares else "Access",
                callback_data=f"shares:{h.id}"))
            actions.append(RichMessageButton(text="Remove", style="danger",
                                             callback_data=f"askrm:{h.id}"))
        blocks.append(InputRichBlockButtons(align="left", buttons=actions))

    blocks.append(InputRichBlockButtons(align="left", buttons=[
        RichMessageButton(text=ADD_LABEL, callback_data="addhost",
                          style="success"),
    ]))
    return InputRichMessage(blocks=blocks)
