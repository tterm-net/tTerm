"""Telegram handlers.

The routing rule is simple: a known slash command goes to the bot, everything
else goes to the shell of the active machine. That is why `/usr/bin/php -v`
reaches the server instead of being treated as a typo.

The active machine is picked with `/use` and stored in the database. Its name
is shown above every reply: with several machines there is otherwise no way to
tell whose output this is.
"""
from __future__ import annotations

import html
import logging
import re
import time

from aiogram import Bot, F, Router
from aiogram.enums import ButtonStyle, ChatAction, ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import BufferedInputFile, CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder

from ..core.config import config
from ..core.db import Host, db
from ..core.formatter import (
    PC_ICON,
    SERVER_ICON,
    State,
    clean_output,
    detect_lang,
    render,
    render_running,
)
from ..core.agent_hub import registry as agents
from ..core.session_manager import sessions
from . import machines

log = logging.getLogger(__name__)
router = Router()

BOT_COMMANDS = {
    "start", "help", "addhost", "hosts", "use", "log", "kill",
    "reset", "share", "revoke", "cancel",
}


#: Split by how the machine connects, not by OS: we dial out over SSH to
#: a server with a permanent address, while a computer dials in because there
#: is no other way to reach it. For a computer the OS only matters to the
#: installer (sh or PowerShell); the protocol is the same.
ADD_MENU_TEXT = "<b>What are we connecting?</b>"


def add_menu_keyboard():
    """The plain keyboard, kept only as a fallback if rich is rejected."""
    kb = InlineKeyboardBuilder()
    kb.button(text=f"{SERVER_ICON} Server (Linux)", callback_data="add:server",
              style=ButtonStyle.PRIMARY)
    kb.button(text=f"{SERVER_ICON} Server (Windows)", callback_data="add:win",
              style=ButtonStyle.PRIMARY)
    kb.button(text=f"{PC_ICON} Computer (macOS or Linux)",
              callback_data="add:agent", style=ButtonStyle.PRIMARY)
    kb.button(text=f"{PC_ICON} Computer (Windows)", callback_data="add:win",
              style=ButtonStyle.PRIMARY)
    kb.adjust(1)
    return kb.as_markup()


def add_menu_rich():
    """Four options: a person knows their machine's OS and role right away,
    while how it connects is our business, not theirs."""
    return machines.screen(
        [machines.para(machines.bold("What are we connecting?"))],
        [[machines.button(f"{SERVER_ICON} Server (Linux)", "add:server", "primary"),
          machines.button(f"{SERVER_ICON} Server (Windows)", "add:win", "primary")],
         [machines.button(f"{PC_ICON} Computer (macOS or Linux)",
                          "add:agent", "primary"),
          machines.button(f"{PC_ICON} Computer (Windows)", "add:win", "primary")]],
    )


def back_button(kb: InlineKeyboardBuilder, to: str = "addhost") -> None:
    """Goes back to the previous menu in the same message, not a new one."""
    kb.button(text="‹ Back", callback_data=to)


#: Dots of the same size: filled means online, hollow means not. There is no
#: green dot smaller than 🟢 in the emoji set, and mixing an emoji with a text
#: glyph yields a line of marks at different heights.
ONLINE, OFFLINE = "●", "○"

#: The command that removes the agent completely. Shown where the person is
#: already thinking about disconnecting, always as its own block so it copies
#: with a single tap.
AGENT_UNINSTALL = "~/.tterm/uninstall.sh"


#: Telegram refuses an edit that would change nothing. That is not a failure —
#: the screen already shows what we wanted — but treating it as one made the
#: bot fall back to the old keyboard whenever a machine was tapped twice.
UNCHANGED = "message is not modified"


async def show_screen(bot: Bot, chat_id: int, rich, call: CallbackQuery | None,
                      fallback_text: str = "", fallback_markup=None) -> None:
    """Shows a rich screen, as a new message or by editing the previous one.

    On refusal it falls back to a plain message: showing the screen matters
    more than showing it nicely.
    """
    try:
        if call is not None and call.message is not None:
            await bot.edit_message_text(chat_id=chat_id,
                                        message_id=call.message.message_id,
                                        rich_message=rich)
        else:
            await bot.send_rich_message(chat_id=chat_id, rich_message=rich)
        return
    except TelegramBadRequest as exc:
        if UNCHANGED in str(exc):
            return
        log.warning("Rich screen was rejected, falling back to plain", exc_info=True)
    if not fallback_text:
        return
    if call is not None:
        await _replace(call, fallback_text, fallback_markup)
    else:
        await bot.send_message(chat_id, fallback_text,
                               parse_mode=ParseMode.HTML,
                               reply_markup=fallback_markup)


async def show_machines(bot: Bot, chat_id: int, user_id: int,
                        call: CallbackQuery | None = None) -> None:
    """Shows the machine list, as a new message or by editing the previous one.

    If the rich message is rejected for any reason we fall back to the plain
    layout: showing the list matters more than showing it nicely.
    """
    hosts = await db.list_hosts(user_id)
    active = await db.get_active_host(user_id)
    online = {h.id: _is_online(user_id, h) for h in hosts}
    rich = await machines.build(hosts, active, user_id, online)

    try:
        if call is not None and call.message is not None:
            await bot.edit_message_text(
                chat_id=chat_id, message_id=call.message.message_id,
                rich_message=rich)
        else:
            await bot.send_rich_message(chat_id=chat_id, rich_message=rich)
        return
    except TelegramBadRequest as exc:
        if UNCHANGED in str(exc):
            return
        log.warning("Could not show the list as a rich message, "
                    "falling back to plain", exc_info=True)

    text = await _servers_text(hosts, active, user_id)
    markup = servers_keyboard(hosts, active.id if active else None)
    if call is not None:
        await _replace(call, text, markup)
    else:
        await bot.send_message(chat_id, text, parse_mode=ParseMode.HTML,
                               reply_markup=markup)


async def _replace(call: CallbackQuery, text: str, markup=None) -> None:
    """Edits the message the button was pressed in.

    Every tap that spawns a new message clutters the chat: after ten machine
    switches the command history is no longer findable. If the edit fails —
    the message is too old — we send a new one: replying matters more than
    keeping things tidy.
    """
    if call.message is None:
        return
    try:
        await call.message.edit_text(text, parse_mode=ParseMode.HTML,
                                     reply_markup=markup)
    except TelegramBadRequest as exc:
        if UNCHANGED in str(exc):
            return
        log.debug("Edit failed, sending a new message instead", exc_info=True)
        await call.message.answer(text, parse_mode=ParseMode.HTML,
                                  reply_markup=markup)
    except Exception:
        log.debug("Edit failed, sending a new message instead", exc_info=True)
        await call.message.answer(text, parse_mode=ParseMode.HTML,
                                  reply_markup=markup)


def _is_online(user_id: int, host: Host) -> bool:
    """Whether the machine is online.

    For a server that means an open SSH session; for a computer, a connected
    agent — it holds the link itself even when nobody is sending commands.
    """
    if host.kind == "agent":
        return agents.get(host.id) is not None
    live = sessions.peek(user_id, host.id)
    return bool(live and live.is_alive)


def _share_label(share) -> str:
    """Who has access and how long it lasts."""
    name = f"@{share['username']}" if share["username"] else (
        share["first_name"] or "someone")
    label = html.escape(name)
    if share["expires_at"]:
        left = share["expires_at"] - int(time.time())
        if left > 0:
            label += f" ({human_duration(max(left, 60))} left)"
    return label


async def _servers_text(hosts: list[Host], active: Host | None, user_id: int) -> str:
    """The machine list with numbers: /share takes a number."""
    lines = ["<b>Your machines</b>", ""]
    for h in hosts:
        dot = ONLINE if _is_online(user_id, h) else OFFLINE
        icon = PC_ICON if h.kind == "agent" else SERVER_ICON
        name = html.escape(h.name)
        name = f"<b>{name}</b>" if active and h.id == active.id else name
        row = f"{dot} {icon} <code>#{h.id}</code> {name}"

        if h.owner_id != user_id:
            owner = await db.username_of(h.owner_id) or "its owner"
            row += f" · <i>from {html.escape(owner)}</i>"
        else:
            shares = await db.shares_of(h.id)
            if shares:
                # The remaining time is shown here: otherwise a share simply
                # vanishes and it is unclear whether it expired or was revoked.
                who = ", ".join(_share_label(s) for s in shares)
                row += f" · <i>shared with: {who}</i>"
        lines.append(row)

    lines.append("")
    lines.append("<i>Bold is the active one. Commands go there.</i>")
    return "\n".join(lines)


def servers_keyboard(hosts: list[Host], active_id: int | None = None):
    """Machines as buttons, plus "add".

    Colour carries meaning here rather than decoration: blue is what already
    exists and can be switched to, green is the one action that creates
    something new.
    """
    kb = InlineKeyboardBuilder()
    for h in hosts:
        icon = PC_ICON if h.kind == "agent" else SERVER_ICON
        kb.button(text=f"{icon} {h.name}", callback_data=f"use:{h.id}",
                  style=ButtonStyle.PRIMARY)
    kb.button(text="+ Add a machine", callback_data="addhost",
              style=ButtonStyle.SUCCESS)
    kb.adjust(2)
    return kb.as_markup()


async def _shares_view(host: Host):
    """Who the machine is shared with, one revoke button each.

    One per person rather than a single "revoke all": a machine can be shared
    with several people, and a blanket button eventually cuts the wrong one.
    """
    shares = await db.shares_of(host.id)
    icon = PC_ICON if host.kind == "agent" else SERVER_ICON

    def who(s) -> str:
        return (f"@{s['username']}" if s["username"]
                else s["first_name"] or str(s["grantee_id"]))

    text_blocks = [machines.para(
        f"{icon} ", machines.code(f"#{host.id}"), " ",
        machines.bold(host.name), " · access")]
    if shares:
        text_blocks += [machines.para(f"• {_share_label(s)}") for s in shares]
    else:
        text_blocks.append(machines.para(machines.italic("Not shared with anyone.")))
    text_blocks.append(machines.para("Share: ",
                                     machines.code(f"/share #{host.id} @who 4h")))

    # One button per person: revoking cuts a live session, so it must never
    # hit somebody who was not meant.
    rows = [[machines.button(f"Revoke {who(s)[:24]}",
                             f"unshare:{host.id}:{s['grantee_id']}", "danger")]
            for s in shares]
    rows.append([machines.back("use:list")])
    rich = machines.screen(text_blocks, rows)

    kb = InlineKeyboardBuilder()
    for s in shares:
        kb.button(text=f"Revoke {who(s)[:24]}",
                  callback_data=f"unshare:{host.id}:{s['grantee_id']}",
                  style=ButtonStyle.DANGER)
    kb.button(text="‹ Back", callback_data="use:list")
    kb.adjust(1)
    body = ("\n".join(f"• {_share_label(s)}" for s in shares)
            if shares else "<i>Not shared with anyone.</i>")
    fallback = (f"{icon} <code>#{host.id}</code> <b>{html.escape(host.name)}</b>"
                f" · access\n\n{body}")
    return rich, fallback, kb.as_markup()


@router.callback_query(F.data.startswith("shares:"))
async def cb_shares(call: CallbackQuery) -> None:
    """Who the machine is shared with, one revoke button per person.

    A machine can be shared with several people at once and they must be
    revoked separately: a single "revoke all" eventually cuts the wrong one.
    """
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if host is None or call.from_user is None or host.owner_id != call.from_user.id:
        await call.answer("Machine not found", show_alert=True)
        return
    await call.answer()

    rich, fallback, markup = await _shares_view(host)
    await show_screen(call.bot, call.message.chat.id if call.message
                      else call.from_user.id, rich, call, fallback, markup)


@router.callback_query(F.data.startswith("unshare:"))
async def cb_unshare(call: CallbackQuery) -> None:
    _, host_id_s, grantee_s = call.data.split(":")  # type: ignore[union-attr]
    host_id, grantee = int(host_id_s), int(grantee_s)
    host = await db.get_host(host_id)
    if host is None or call.from_user is None or host.owner_id != call.from_user.id:
        await call.answer("Machine not found", show_alert=True)
        return

    await db.revoke(host_id, grantee)
    await sessions.drop(grantee, host_id)
    who = await db.username_of(grantee) or "the user"
    await call.answer(f"Access for {who} revoked")
    try:
        await call.bot.send_message(
            grantee, f"Your access to <b>{html.escape(host.name)}</b> was revoked by its owner.",
            parse_mode=ParseMode.HTML)
    except Exception:
        pass
    await cb_shares(call)


@router.callback_query(F.data == "use:list")
async def cb_use_list(call: CallbackQuery) -> None:
    if call.from_user is None:
        return
    await call.answer()
    await show_machines(call.bot, call.message.chat.id if call.message
                        else call.from_user.id, call.from_user.id, call)


# ---------------------------------------------------------------- onboarding


@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    user = message.from_user
    assert user is not None
    await db.upsert_user(user.id, user.username, user.first_name)

    if await db.list_hosts(user.id):
        await show_machines(message.bot, message.chat.id, user.id)
        return

    rich = machines.screen(
        [machines.para(machines.bold("A terminal for your machines, right here.")),
         machines.para("Connect a server or a computer with a single command and run it "
                       "from this chat: logs, restarts, deploys — everything "
                       "you do over SSH.")],
        [[machines.button("+ Add a machine", "addhost", "success"),
          machines.button("How does it work?", "how")]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="+ Add a machine", callback_data="addhost",
              style=ButtonStyle.SUCCESS)
    kb.button(text="How does it work?", callback_data="how")
    kb.adjust(1)
    await show_screen(
        message.bot, message.chat.id, rich, None,
        "<b>A terminal for your machines, right here.</b>\n\n"
        "Connect a server or a computer with a single command and run it "
        "from this chat.", kb.as_markup())


@router.callback_query(F.data == "how")
async def cb_how(call: CallbackQuery) -> None:
    await call.answer()
    if call.message is None:
        return
    await call.message.answer(
        "<b>How it works</b>\n\n"
        "1. You run a single command on your server.\n"
        "2. It creates a separate user and allows login with short-lived "
        "certificates — <b>without touching sshd_config</b>, so there is no "
        "risk of locking yourself out.\n"
        "3. That user is granted passwordless sudo — otherwise the bot could not "
        "restart a service or read the system log. To remove it: "
        f"<code>sudo rm /etc/sudoers.d/{config.SSH_USER}</code>\n"
        "4. We never store your SSH keys. Every connection gets a fresh "
        f"certificate valid for {config.CERT_TTL_SECONDS // 60} minutes.\n\n"
        f"Our CA public key is open: {config.PUBLIC_URL}/ca.pub\n"
        "Removing everything is one command — see the Remove button.\n\n"
        "⚠️ Traffic goes through Telegram servers and they can see its "
        "contents. Do not print private keys or passwords into the chat.\n\n"
        "Source code and how it is built: https://tterm.net\n"
        "Updates: https://t.me/tTermBlog",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("addhost"))
@router.callback_query(F.data == "addhost")
async def cmd_addhost(event: Message | CallbackQuery) -> None:
    """Asks what is being connected: the method depends on the direction."""
    if isinstance(event, CallbackQuery):
        await event.answer()
        if event.from_user is None:
            return
        await db.upsert_user(event.from_user.id, event.from_user.username,
                             event.from_user.first_name)
        await show_screen(event.bot, event.message.chat.id if event.message
                          else event.from_user.id, add_menu_rich(), event,
                          ADD_MENU_TEXT, add_menu_keyboard())
        return

    if event.from_user is None:
        return
    await db.upsert_user(event.from_user.id, event.from_user.username,
                         event.from_user.first_name)
    await show_screen(event.bot, event.chat.id, add_menu_rich(), None,
                      ADD_MENU_TEXT, add_menu_keyboard())


@router.callback_query(F.data == "add:win")
async def cb_add_windows(call: CallbackQuery) -> None:
    """Windows is unsupported, but WSL2 works — the command is given right here."""
    await call.answer()
    if call.from_user is None:
        return
    token = await db.create_enroll_token(call.from_user.id)
    _ = token  # the server token is unused here, but the path stays uniform

    host_id = await db.create_agent_host(call.from_user.id, _agent_placeholder(call))
    agent_token = await db.issue_agent_token(host_id)
    cmd = f"curl -fsSL {config.PUBLIC_URL}/a/{agent_token} | sh"

    rich = machines.screen(
        [machines.para(machines.bold("Windows is not supported directly yet")),
         machines.para("We run commands in a pseudo-terminal and ask the shell "
                       "to mark up its output — on Windows both work "
                       "differently. Once done, one agent will fit both "
                       "servers and laptops."),
         machines.para(machines.bold("It already works through WSL2."),
                       " Open Ubuntu from WSL and run this there:"),
         {"type": "pre", "text": cmd},
         machines.para("Commands go to the Linux environment, not to Windows "
                       "itself — but your drives are visible there, and for "
                       "most tasks that is enough.")],
        [[machines.copy("Copy", cmd),
          machines.link("Read it", f"{config.PUBLIC_URL}/a/{agent_token}"),
          machines.link("Install WSL2",
                        "https://learn.microsoft.com/windows/wsl/install"),
          machines.back()]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="How to install WSL2",
              url="https://learn.microsoft.com/windows/wsl/install")
    back_button(kb)
    kb.adjust(1)
    await show_screen(
        call.bot, call.message.chat.id if call.message else call.from_user.id,
        rich, call,
        "<b>Windows is not supported directly yet</b>\n\n"
        f"It works through WSL2:\n<pre>{html.escape(cmd)}</pre>",
        kb.as_markup())


@router.callback_query(F.data == "add:server")
async def cb_add_server(call: CallbackQuery) -> None:
    await call.answer()
    if call.from_user is None:
        return
    token = await db.create_enroll_token(call.from_user.id)
    cmd = f"curl -sSL {config.PUBLIC_URL}/s/{token} | sudo sh"

    minutes = config.ENROLL_TOKEN_TTL_SECONDS // 60
    rich = machines.screen(
        [machines.para(machines.bold("Connect a server")),
         machines.para("Run this on the server:"),
         {"type": "pre", "text": cmd},
         machines.para(machines.italic(
             f"Valid for {minutes} minutes. The script is short — "
             "read it first if you like."))],
        [[machines.copy("Copy", cmd),
          machines.link("Read it", f"{config.PUBLIC_URL}/s/{token}"),
          machines.back()]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="What the script does", url=f"{config.PUBLIC_URL}/s/{token}")
    back_button(kb)
    kb.adjust(1)
    await show_screen(
        call.bot, call.message.chat.id if call.message else call.from_user.id,
        rich, call,
        f"<b>Connecting a server</b>\n\n<pre>{html.escape(cmd)}</pre>",
        kb.as_markup())


def _agent_placeholder(call: CallbackQuery) -> str:
    """A temporary machine name: the agent sends the real one on connect."""
    who = (call.from_user.first_name or "my") if call.from_user else "my"
    return f"{who}-computer".lower()


@router.callback_query(F.data == "add:agent")
async def cb_add_agent(call: CallbackQuery) -> None:
    """A computer connects through the agent: it calls us, not the other way."""
    await call.answer()
    if call.message is None or call.from_user is None:
        return
    host_id = await db.create_agent_host(call.from_user.id,
                                        _agent_placeholder(call))
    token = await db.issue_agent_token(host_id)
    # It becomes the active machine once the agent is online, not before:
    # otherwise a placeholder steals the choice from a working machine.
    cmd = f"curl -fsSL {config.PUBLIC_URL}/a/{token} | sh"

    rich = machines.screen(
        [machines.para(machines.bold("Connect a computer")),
         machines.para("Run this on the machine you are connecting:"),
         {"type": "pre", "text": cmd},
         machines.para(machines.bold("No sudo."),
                       " The agent uses your own permissions and opens "
                       "no ports."),
         machines.para(machines.italic(
             "macOS and Linux. I will write here once it connects."))],
        [[machines.copy("Copy", cmd),
          machines.link("Read it", f"{config.PUBLIC_URL}/a/{token}"),
          machines.link("Source", "https://github.com/tterm-net/tterm-agent"),
          machines.back()]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="What the script does", url=f"{config.PUBLIC_URL}/a/{token}")
    back_button(kb)
    kb.adjust(1)
    await show_screen(
        call.bot, call.message.chat.id, rich, call,
        f"<b>Connecting a computer</b>\n\n<pre>{html.escape(cmd)}</pre>",
        kb.as_markup())


async def notify_host_registered(bot: Bot, owner_id: int, host_id: int) -> None:
    """Called from the HTTP API when a server reports in."""
    host = await db.get_host(host_id)
    if host is None:
        return

    rich = machines.screen(
        [machines.para(machines.bold("A server is online")),
         machines.para(machines.code(host.hostname or host.name)),
         machines.para(f"{host.ip} · {host.os_info or 'unknown OS'}"),
         machines.para(f"port {host.ssh_port}, user {host.ssh_user}"),
         machines.para("Is this your server?")],
        [[machines.button("Yes, connect it", f"confirm:{host_id}", "success"),
          machines.button("No, not mine", f"reject:{host_id}", "danger")]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="Yes, connect it", callback_data=f"confirm:{host_id}",
              style=ButtonStyle.SUCCESS)
    kb.button(text="No, not mine", callback_data=f"reject:{host_id}",
              style=ButtonStyle.DANGER)
    kb.adjust(2)
    await show_screen(
        bot, owner_id, rich, None,
        f"<b>A server is online</b>\n\n<code>{html.escape(host.ip)}</code>\n\n"
        "Is this your server?", kb.as_markup())


async def notify_agent_online(bot: Bot, owner_id: int, host_id: int,
                              first_time: bool) -> None:
    """Announces that a computer came online.

    Without it nothing happens in the chat after the agent is installed and
    the person cannot tell whether it worked.
    """
    host = await db.get_host(host_id)
    if host is None:
        return
    if not first_time:
        # Reconnecting after sleep or a network change is routine; saying so
        # every time would be spam.
        return

    await db.set_active_host(owner_id, host_id)
    icon = PC_ICON if host.kind == "agent" else SERVER_ICON
    await bot.send_message(
        owner_id,
        f"{icon} <b>{html.escape(host.name)}</b> is connected {ONLINE}\n"
        "<code>~ ❯</code>",
        parse_mode=ParseMode.HTML,
    )


@router.callback_query(F.data.startswith("confirm:"))
async def cb_confirm(call: CallbackQuery) -> None:
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if host is None or call.from_user is None or host.owner_id != call.from_user.id:
        await call.answer("Server not found", show_alert=True)
        return

    await db.activate_host(host_id)
    await db.set_active_host(call.from_user.id, host_id)
    await call.answer("Connected")
    if call.message is None:
        return

    # The question was sent as a rich message, so its buttons live inside the
    # blocks rather than in reply_markup. Clearing reply_markup fails there and
    # the reply below would never be sent, so the whole message is replaced.
    await show_screen(
        call.bot, call.message.chat.id,
        machines.screen(
            [machines.para(f"{SERVER_ICON} ", machines.bold(host.name),
                           " connected"),
             machines.para(machines.italic(
                 "Type commands straight into the chat."))],
            [],
        ),
        call,
        f"{SERVER_ICON} <b>{html.escape(host.name)}</b> connected",
    )
    # Same as picking a machine: show where we landed and warm up the session.
    await send_prompt(call.bot, call.message.chat.id, call.from_user.id, host)


@router.callback_query(F.data.startswith("reject:"))
async def cb_reject(call: CallbackQuery) -> None:
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if host and call.from_user and host.owner_id == call.from_user.id:
        await db.reject_host(host_id)
    await call.answer("Rejected")
    if call.message is None:
        return
    await show_screen(
        call.bot, call.message.chat.id,
        machines.screen(
            [machines.para("The host was rejected and is not connected."),
             machines.para("If you did not start this, someone may have sent "
                           "you their own install link. Check that there is "
                           "no user named ", machines.code(config.SSH_USER),
                           " on that machine.")],
            [],
        ),
        call,
        "The host was rejected and is not connected.",
    )


# ------------------------------------------------------ picking a machine


@router.message(Command("use"))
@router.message(Command("hosts"))
async def cmd_use(message: Message) -> None:
    assert message.from_user is not None
    hosts = await db.list_hosts(message.from_user.id)
    if not hosts:
        await cmd_addhost(message)
        return

    await show_machines(message.bot, message.chat.id, message.from_user.id)


async def send_prompt(bot: Bot, chat_id: int, user_id: int, host: Host) -> None:
    """Sends the prompt for a machine.

    Without it there is no telling which directory we landed in, whether it is
    a git repo, or who we run as. It also warms up the session so the first
    real command answers faster.
    """
    icon = PC_ICON if host.kind == "agent" else SERVER_ICON
    try:
        block = await sessions.execute(user_id, host, "true")
    except Exception as exc:
        await bot.send_message(
            chat_id,
            f"{icon} <b>{html.escape(host.name)}</b>\n"
            f"<i>{html.escape(str(exc)[:200])}</i>",
            parse_mode=ParseMode.HTML)
        return

    block.state.host = host.name
    block.state.icon = icon
    # No status dot here: the machine button in the list already carries it.
    await bot.send_message(
        chat_id,
        f"{icon} <b>{html.escape(host.name)}</b>\n"
        f"<code>{html.escape(block.state.prompt())}</code>",
        parse_mode=ParseMode.HTML)


@router.callback_query(F.data.startswith("use:"))
async def cb_use(call: CallbackQuery) -> None:
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if (host is None or call.from_user is None
            or not await db.can_use(call.from_user.id, host_id)):
        await call.answer("Machine unavailable", show_alert=True)
        return
    await db.set_active_host(call.from_user.id, host_id)
    await call.answer(f"{host.name} is active")

    await show_machines(call.bot, call.message.chat.id if call.message
                        else call.from_user.id, call.from_user.id, call)
    if call.message is not None:
        await send_prompt(call.bot, call.message.chat.id, call.from_user.id, host)


# ---------------------------------------------------------------- sharing


#: `2h`, `30m`, `7d`. With no duration the share lasts until revoked.
DURATION_RE = re.compile(r"^(\d+)\s*([mhd])$", re.I)
DURATION_UNITS = {"m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int | None:
    m = DURATION_RE.match(text.strip())
    if not m:
        return None
    return int(m.group(1)) * DURATION_UNITS[m.group(2).lower()]


def human_duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


SHARE_HELP = (
    "<b>Share a machine</b>\n\n"
    "<code>/share #12 @john</code> — until you revoke it\n"
    "<code>/share #12 @john 4h</code> — for 4 hours\n\n"
    "Duration: <code>30m</code>, <code>4h</code>, <code>7d</code>.\n"
    "The machine number is shown in <code>/use</code>.\n\n"
    "<i>They must start the bot themselves first — otherwise I have no way "
    "to tell who is behind the username.</i>\n\n"
    "Revoke: <code>/revoke #12 @john</code>"
)


def _parse_share_args(args: str) -> tuple[int | None, str | None, int | None]:
    """Parses `#12 @john 4h`. Only the first two are order-sensitive."""
    host_id = username = ttl = None
    for part in args.split():
        if part.startswith("#") and part[1:].isdigit():
            host_id = int(part[1:])
        elif part.startswith("@") or (username is None and not part[0].isdigit()):
            username = part
        else:
            ttl = parse_duration(part) or ttl
    return host_id, username, ttl


@router.message(Command("share"))
async def cmd_share(message: Message, command: CommandObject) -> None:
    assert message.from_user is not None
    user_id = message.from_user.id
    args = (command.args or "").strip()
    if not args:
        await message.answer(SHARE_HELP, parse_mode=ParseMode.HTML)
        return

    host_id, username, ttl = _parse_share_args(args)
    if host_id is None:
        await message.answer(SHARE_HELP, parse_mode=ParseMode.HTML)
        return

    host = await db.get_host(host_id)
    if username is None:
        # `/share #6` without a name shows who the machine is shared with,
        # with a revoke button for each.
        if host is None or host.owner_id != user_id or host.status != "active":
            await message.answer(f"You have no machine <code>#{host_id}</code>.",
                                 parse_mode=ParseMode.HTML)
            return
        rich, fallback, markup = await _shares_view(host)
        await show_screen(message.bot, message.chat.id, rich, None,
                          fallback, markup)
        return

    if host is None or host.owner_id != user_id or host.status != "active":
        # We do not reveal whether the machine exists: there is no reason to
        # let anyone probe other people's numbers. For the owner the answer
        # reads the same either way.
        await message.answer(f"You have no machine <code>#{host_id}</code>.",
                             parse_mode=ParseMode.HTML)
        return

    grantee = await db.find_user_by_username(username)
    if grantee is None:
        await message.answer(
            f"I do not know who <b>{html.escape(username)}</b> is.\n\n"
            "Telegram does not let bots look people up by username — I only "
            "know those who started the bot themselves. Ask them to open "
            f"@{(await _bot_username(message.bot))} and press Start.",
            parse_mode=ParseMode.HTML)
        return
    if grantee == user_id:
        await message.answer("This is your own machine, you already have access.")
        return

    await db.grant(host_id, user_id, grantee, ttl)
    icon = PC_ICON if host.kind == "agent" else SERVER_ICON
    period = f"for {human_duration(ttl)}" if ttl else "with no time limit"
    await message.answer(
        f"✅ {icon} <b>{html.escape(host.name)}</b> is now shared with "
        f"<b>{html.escape(username)}</b> {period}.\n\n"
        f"Revoke: <code>/revoke #{host_id} {username}</code>",
        parse_mode=ParseMode.HTML)

    # Tell the person we shared with, or they will never know.
    try:
        await message.bot.send_message(
            grantee,
            f"{icon} <b>{html.escape(host.name)}</b> — you were given access "
            f"{period}.\n\n"
            f"Shared by: {html.escape(await db.username_of(user_id) or 'the owner')}\n\n"
            "The machine now shows up in <code>/use</code>. "
            "Everything you run is visible to the owner in the log.",
            parse_mode=ParseMode.HTML)
    except Exception:
        log.info("Could not notify %s about the shared access", grantee, exc_info=True)


@router.message(Command("revoke"))
async def cmd_revoke(message: Message, command: CommandObject) -> None:
    assert message.from_user is not None
    user_id = message.from_user.id
    host_id, username, _ = _parse_share_args((command.args or "").strip())
    if host_id is None or username is None:
        await message.answer(
            "<code>/revoke #12 @john</code> — revoke access.\n"
            "Who has access to what is shown in <code>/use</code>.",
            parse_mode=ParseMode.HTML)
        return

    host = await db.get_host(host_id)
    if host is None or host.owner_id != user_id:
        await message.answer(f"You have no machine <code>#{host_id}</code>.",
                             parse_mode=ParseMode.HTML)
        return

    grantee = await db.find_user_by_username(username)
    if grantee is None or not await db.revoke(host_id, grantee):
        await message.answer(
            f"<b>{html.escape(username)}</b> had no access to "
            f"<code>#{host_id}</code> anyway.", parse_mode=ParseMode.HTML)
        return

    await sessions.drop(grantee, host_id)
    await message.answer(
        f"🛑 Access for <b>{html.escape(username)}</b> to "
        f"<b>{html.escape(host.name)}</b> is revoked. The session was cut.",
        parse_mode=ParseMode.HTML)
    try:
        await message.bot.send_message(
            grantee,
            f"Your access to <b>{html.escape(host.name)}</b> was revoked by its owner.",
            parse_mode=ParseMode.HTML)
    except Exception:
        pass


async def notify_share_expired(bot: Bot, share: dict) -> None:
    """Tells both sides the share has expired.

    Both on purpose: otherwise the recipient cannot tell why the machine
    vanished, and the owner needs to know it closed in case it should be
    extended.
    """
    name = html.escape(share.get("host_name") or "the machine")
    grantee = share["grantee_id"]
    owner = share["owner_id"]
    who = await db.username_of(grantee) or "them"

    for uid, text in (
        (grantee, f"⏳ Your access to <b>{name}</b> has expired."),
        (owner, f"⏳ Access for {html.escape(who)} to <b>{name}</b> has expired.\n"
                f"Extend: <code>/share #{share['host_id']} {html.escape(who)} 4h</code>"),
    ):
        try:
            await bot.send_message(uid, text, parse_mode=ParseMode.HTML)
        except Exception:
            log.info("Could not tell %s that access expired", uid,
                     exc_info=True)


async def _not_owner(message: Message, host: Host) -> bool:
    """Blocks actions only the machine owner may perform.

    Somebody granted access gets a terminal, not control: they cannot remove
    the machine from someone else's list, pass it on, or uninstall the agent.
    """
    assert message.from_user is not None
    if host.owner_id == message.from_user.id:
        return False
    owner = await db.username_of(host.owner_id) or "its owner"
    await message.answer(
        f"This is not your machine — {html.escape(owner)} shared it with you.\n"
        "Only the owner can manage it.",
        parse_mode=ParseMode.HTML)
    return True


async def _bot_username(bot: Bot) -> str:
    me = await bot.me()
    return me.username or "bot"


# ---------------------------------------------------------------- sessions


@router.message(Command("reset"))
async def cmd_disconnect(message: Message) -> None:
    """Closes the session. Leaves the machine in the list and the agent alone."""
    assert message.from_user is not None
    host = await db.get_active_host(message.from_user.id)
    if host is None:
        await message.answer("No active machine selected.")
        return
    closed = await sessions.drop(message.from_user.id, host.id)
    text = [f"🛑 The session on <b>{html.escape(host.name)}</b> "
            + ("was closed." if closed else "was not open.")]
    if host.kind == "agent":
        text.append("")
        text.append("The agent stays on the machine and keeps the link — "
                    "your next command will open a new session.")
        text.append("")
        text.append("To remove the agent completely, run this on the machine itself:")
        text.append(f"<pre>{AGENT_UNINSTALL}</pre>")
    else:
        text.append("\nYour next command will open a new one.")
    await message.answer("\n".join(text), parse_mode=ParseMode.HTML)


@router.callback_query(F.data.startswith("askrm:"))
async def cb_ask_remove(call: CallbackQuery) -> None:
    """Asks for confirmation. The list button leads here rather than straight to
    removal: one stray tap must not take a machine away."""
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if host is None or call.from_user is None or host.owner_id != call.from_user.id:
        await call.answer("Machine not found", show_alert=True)
        return
    await call.answer()

    if host.kind == "agent":
        how = [machines.para("The agent will stop connecting but stays "
                             "installed. Only someone with access to the "
                             "machine itself can remove it:"),
               {"type": "pre", "text": AGENT_UNINSTALL}]
    else:
        how = [machines.para("SSH access is revoked. To remove the service user "
                             "from the server:"),
               {"type": "pre", "text": f"sudo userdel -r {config.SSH_USER}\n"
                                       f"sudo rm -f /etc/sudoers.d/{config.SSH_USER}"}]
    rich = machines.screen(
        [machines.para("Remove ", machines.bold(host.name), " from the list?"),
         *how],
        [[machines.button("Yes, remove", f"remove:{host_id}", "danger"),
          machines.button("Cancel", "use:list")]],
    )
    kb = InlineKeyboardBuilder()
    kb.button(text="Yes, remove", callback_data=f"remove:{host_id}",
              style=ButtonStyle.DANGER)
    kb.button(text="Cancel", callback_data="use:list")
    kb.adjust(1)
    await show_screen(
        call.bot, call.message.chat.id if call.message else call.from_user.id,
        rich, call,
        f"Remove <b>{html.escape(host.name)}</b> from the list?", kb.as_markup())


@router.callback_query(F.data == "remove:cancel")
async def cb_remove_cancel(call: CallbackQuery) -> None:
    await call.answer("Cancelled")
    await _replace(call, "Nothing was removed.")


@router.callback_query(F.data.startswith("remove:"))
async def cb_remove(call: CallbackQuery) -> None:
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    host = await db.get_host(host_id)
    if host is None or call.from_user is None or host.owner_id != call.from_user.id:
        await call.answer("Machine not found", show_alert=True)
        return
    await call.answer("Removed")
    await sessions.drop(call.from_user.id, host_id)
    if host.kind == "agent":
        await db.revoke_agent_token(host_id)
    await db.remove_host(host_id)
    hosts = await db.list_hosts(call.from_user.id)
    if hosts:
        await _replace(call, await _servers_text(hosts, None, call.from_user.id),
                       servers_keyboard(hosts))
    else:
        await _replace(call, f"<b>{html.escape(host.name)}</b> removed. "
                             "No machines left — <code>/addhost</code>.")


@router.callback_query(F.data.startswith("reset:"))
async def cb_reset(call: CallbackQuery) -> None:
    """Resets the machine's session. The machine and the agent stay."""
    host_id = int(call.data.split(":")[1])  # type: ignore[union-attr]
    if call.from_user is None or not await db.can_use(call.from_user.id, host_id):
        await call.answer("Machine unavailable", show_alert=True)
        return
    closed = await sessions.drop(call.from_user.id, host_id)
    await call.answer("Session reset" if closed else "No session was open")


@router.message(Command("log"))
async def cmd_log(message: Message) -> None:
    assert message.from_user is not None
    rows = await db.recent_blocks(message.from_user.id, limit=30)
    if not rows:
        await message.answer("The log is empty.")
        return

    # Markup as objects, not tags: HTML is not parsed inside rich blocks and
    # shows up as literal text.
    blocks = [machines.para(machines.bold(f"Recent commands ({len(rows)})"))]
    lines = [f"<b>Recent commands</b> ({len(rows)})", ""]
    for r in reversed(rows):
        ts = time.strftime("%d.%m %H:%M", time.localtime(r["created_at"]))
        mark = "🟢" if r["exit_code"] == 0 else "🔴"
        cmd = r["command"][:60]
        actor = ""
        if r["user_id"] != message.from_user.id:
            who = r["actor_name"] or r["actor_first"] or "someone"
            actor = f" ({'@' + who if r['actor_name'] else who})"

        parts = [machines.code(ts), f" {mark} {r['host_name']}"]
        if actor:
            parts.append(machines.italic(actor))
        parts += [": ", machines.code(cmd)]
        blocks.append(machines.para(*parts))

        lines.append(f"<code>{ts}</code> {mark} {html.escape(r['host_name'])}"
                     f"{html.escape(actor)}: <code>{html.escape(cmd)}</code>")

    rich = machines.screen(
        blocks, [[machines.button("Export full history", "log:all")]])
    kb = InlineKeyboardBuilder()
    kb.button(text="Export full history", callback_data="log:all")
    await show_screen(message.bot, message.chat.id, rich, None,
                      "\n".join(lines), kb.as_markup())


@router.callback_query(F.data == "log:all")
async def cb_log_all(call: CallbackQuery) -> None:
    """The full history as a file: it is unreadable inside a chat."""
    await call.answer("Collecting")
    if call.from_user is None or call.message is None:
        return
    rows = await db.all_blocks(call.from_user.id)
    if not rows:
        await call.message.answer("The log is empty.")
        return

    out = []
    for r in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
        actor = r["actor_name"] or r["actor_first"] or str(r["user_id"])
        code = "-" if r["exit_code"] is None else r["exit_code"]
        out.append(f"{ts}  {r['host_name']}  {actor}  exit={code}  "
                   f"{r['duration_ms']}ms  {r['cwd'] or ''}")
        out.append(f"$ {r['command']}")
        if r["output"]:
            out.append(clean_output(r["output"]))
        out.append("")

    body = "\n".join(out).encode("utf-8")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    await call.message.answer_document(
        BufferedInputFile(body, filename=f"tterm-history-{stamp}.txt"),
        caption=f"Full history: {len(rows)} commands, "
                f"{len(body) // 1024} KB.\n"
                "<i>Including what others ran on your machines.</i>",
        parse_mode=ParseMode.HTML)


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "<b>How to use it</b>\n\n"
        "Type commands straight into the chat — they run on the active "
        "machine, whose name is shown above every reply. The working "
        "directory is kept between messages, just like in a real terminal."
        "\n\n"
        "<b>Commands</b>\n"
        "/addhost — connect a machine\n"
        "/use — your machines\n"
        "/share — share a machine\n"
        "/revoke — revoke access\n"
        "/log — command history\n"
        "/reset — reset a stuck session\n\n"
        "<b>Sharing</b>\n"
        "<code>/share #12 @john</code> — until revoked\n"
        "<code>/share #12 @john 4h</code> — for 4 hours\n"
        "The machine number is shown in <code>/use</code>. The other person "
        "must start the bot themselves first.\n\n"
        "<i>Removing a machine and seeing who it is shared with are "
        "buttons in <code>/use</code>.</i>\n\n"
        "<i>Anything that does not start with a slash goes to the machine.</i>",
        parse_mode=ParseMode.HTML,
    )


# ------------------------------------------------------------- interactive


@router.callback_query(F.data.startswith("key:"))
async def cb_key(call: CallbackQuery) -> None:
    """Key buttons for programs that took over the screen."""
    assert call.data is not None and call.from_user is not None
    _, host_id_s, key = call.data.split(":", 2)
    live = sessions.peek(call.from_user.id, int(host_id_s))
    if live is None or not live.is_alive:
        await call.answer("The session is already closed", show_alert=True)
        return

    payload = {"ctrl_c": b"\x03", "q": b"q", "enter": b"\r",
               "up": b"\x1b[A", "down": b"\x1b[B"}
    await live.send_key(payload.get(key, b""))
    await call.answer("Sent")

    screen = clean_output(await live.snapshot())
    if screen and call.message:
        await call.message.answer(f"<pre>{html.escape(screen[-1500:])}</pre>",
                                  parse_mode=ParseMode.HTML)


def _screen_keyboard(host_id: int):
    kb = InlineKeyboardBuilder()
    kb.button(text="Ctrl+C", callback_data=f"key:{host_id}:ctrl_c",
              style=ButtonStyle.DANGER)
    for text, key in [("q", "q"), ("Enter", "enter"), ("↑", "up"), ("↓", "down")]:
        kb.button(text=text, callback_data=f"key:{host_id}:{key}")
    kb.adjust(3, 2)
    return kb.as_markup()


# ------------------------------------------------------------- execution


@router.message(F.text)
async def run_command(message: Message, bot: Bot) -> None:
    """Anything not recognised as a bot command goes to the shell."""
    assert message.from_user is not None and message.text is not None
    text = message.text.strip()
    if not text:
        return

    # Known bot commands were already caught above. `/usr/bin/php -v` reaches
    # this point, and rightly so: it is a path, not a command.
    first = text.split()[0].lstrip("/").split("@")[0]
    if text.startswith("/") and first in BOT_COMMANDS:
        return

    user_id = message.from_user.id
    host = await db.get_active_host(user_id)
    if host is None:
        hosts = await db.list_hosts(user_id)
        if not hosts:
            kb = InlineKeyboardBuilder()
            kb.button(text="+ Add a machine", callback_data="addhost",
                      style=ButtonStyle.SUCCESS)
            await show_screen(
                bot, message.chat.id,
                machines.screen([machines.para("Connect a machine first.")],
                                [[machines.button("+ Add a machine",
                                                  "addhost", "success")]]),
                None, "Connect a machine first.", kb.as_markup())
            return
        # No active machine: show the list and let them pick.
        await show_machines(bot, message.chat.id, user_id)
        return

    await bot.send_chat_action(message.chat.id, ChatAction.TYPING)
    started = time.perf_counter()
    placeholder: Message | None = None
    last_rendered = ""
    running_state = State(host=host.name,
                          icon=PC_ICON if host.kind == "agent" else SERVER_ICON)

    async def on_progress(partial: str) -> None:
        """For a long command we edit one message instead of spawning new ones."""
        nonlocal placeholder, last_rendered
        rendered = render_running(partial, time.perf_counter() - started,
                                  lang=detect_lang(text), state=running_state)
        if rendered == last_rendered:
            return
        last_rendered = rendered
        try:
            if placeholder is None:
                placeholder = await message.answer(rendered, parse_mode=ParseMode.HTML)
            else:
                await placeholder.edit_text(rendered, parse_mode=ParseMode.HTML)
        except Exception:
            log.debug("Could not update the streaming message", exc_info=True)

    try:
        block = await sessions.execute(user_id, host, text, on_progress=on_progress)
    except ConnectionError as exc:
        await message.answer(
            f"⚠️ {html.escape(str(exc))}\n\n"
            f"Check that <b>{html.escape(host.name)}</b> is alive. "
            "The command was not queued.",
            parse_mode=ParseMode.HTML,
        )
        return
    except Exception as exc:
        log.exception("Command execution failed")
        detail = f"{type(exc).__name__}: {exc}"[:300]
        await message.answer(
            "⚠️ The command did not run.\n"
            f"<pre>{html.escape(detail)}</pre>",
            parse_mode=ParseMode.HTML,
        )
        return

    # The card header uses the name the machine has in the bot, not the
    # hostname from the marker: renaming is possible here, not on the server.
    block.state.host = host.name
    block.state.icon = PC_ICON if host.kind == "agent" else SERVER_ICON

    card = render(
        output=block.output,
        exit_code=block.exit_code if block.exit_code is not None else -1,
        duration=block.duration_s,
        state=block.state,
        command=text,
    )
    markup = _screen_keyboard(host.id) if block.alt_screen else None

    if card.mode == "file":
        # The result goes out as a file with the tail in the caption, so the
        # interim streaming message would only duplicate it.
        if placeholder is not None:
            try:
                await placeholder.delete()
            except Exception:
                log.debug("Could not remove the streaming message", exc_info=True)
        await message.answer_document(
            BufferedInputFile(card.file_body.encode("utf-8"), filename=card.file_name),
            caption=card.text, parse_mode=ParseMode.HTML,
            reply_markup=markup,  # type: ignore[arg-type]
        )
        return

    if placeholder is not None:
        try:
            await placeholder.edit_text(card.text, parse_mode=ParseMode.HTML,
                                        reply_markup=markup)  # type: ignore[arg-type]
            return
        except Exception:
            log.debug("Edit failed, sending a new message instead", exc_info=True)

    await message.answer(card.text, parse_mode=ParseMode.HTML,
                         reply_markup=markup)  # type: ignore[arg-type]
