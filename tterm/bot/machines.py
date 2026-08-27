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


def back(to: str = "addhost") -> RichMessageButton:
    return button("‹ Back", to)


async def build(hosts: list[Host], active: Host | None, user_id: int,
                online: dict[int, bool]) -> InputRichMessage:
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

        # Actions appear only under the selected machine and only for its
        # owner: someone granted access has nothing to manage.
        if is_active and h.owner_id == user_id:
            shares = await db.shares_of(h.id)
            blocks.append(InputRichBlockButtons(align="left", buttons=[
                RichMessageButton(
                    text=f"Access ({len(shares)})" if shares else "Access",
                    callback_data=f"shares:{h.id}"),
                RichMessageButton(text="Remove", style="danger",
                                  callback_data=f"askrm:{h.id}"),
            ]))

    blocks.append(InputRichBlockButtons(align="left", buttons=[
        RichMessageButton(text=ADD_LABEL, callback_data="addhost",
                          style="success"),
    ]))
    return InputRichMessage(blocks=blocks)
