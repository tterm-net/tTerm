"""Entry point. The bot and the HTTP API share one process and one event loop."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

import uvicorn
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand

from . import __version__
from .api import server as api_server
from .bot import resilience
from .bot.handlers import (
    notify_agent_online,
    notify_host_registered,
    notify_share_expired,
    router,
)
from .core.ca import ca
from .core.config import config
from .core.db import db
from .core.session_manager import sessions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tterm")

MENU = [
    BotCommand(command="addhost", description="Connect a machine"),
    BotCommand(command="use", description="Your machines"),
    BotCommand(command="donate", description="Support the project"),
    BotCommand(command="share", description="Share a machine"),
    BotCommand(command="revoke", description="Revoke access"),
    BotCommand(command="log", description="Command history"),
    BotCommand(command="reset", description="Reset a stuck session"),
    BotCommand(command="help", description="Help"),
]


async def run() -> None:
    # Signals are trapped first, before any network call. KeyboardInterrupt
    # lands at an arbitrary await point and tears apart whatever was running;
    # an event lets us stop where it is convenient. A second Ctrl+C exits at
    # once: if shutdown is stuck there is nothing to wait for.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _on_signal() -> None:
        if stop.is_set():
            log.warning("Second signal — exiting immediately")
            os._exit(130)
        log.info("Shutdown signal received")
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:  # Windows
            pass

    config.validate()
    config.ensure_dirs()

    await db.connect()
    stale = await db.cleanup_agent_hosts()
    if stale:
        log.info("Stale machine records cleaned up: %s", stale)
    ca.load_or_create()
    log.info("CA ready: %s", ca.public_key_line()[:52] + "…")

    bot = Bot(
        token=config.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    resilience.install(bot)
    dp = Dispatcher()
    dp.include_router(router)
    try:
        # The menu is decoration. If Telegram is unreachable the bot must
        # still start: polling survives a network failure and connects later.
        await bot.set_my_commands(MENU)
    except Exception:
        log.warning("Could not set the command menu — carrying on")

    # The HTTP API notifies the bot when a client server reports in.
    async def _on_registered(owner_id: int, host_id: int) -> None:
        try:
            await notify_host_registered(bot, owner_id, host_id)
        except Exception:
            log.exception("Could not notify the owner about the new host")

    async def _on_agent(owner_id: int, host_id: int, first_time: bool) -> None:
        try:
            await notify_agent_online(bot, owner_id, host_id, first_time)
        except Exception:
            log.exception("Could not announce the agent connection")

    api_server.on_host_registered = _on_registered
    api_server.on_agent_online = _on_agent

    async def _on_share_expired(share: dict) -> None:
        try:
            await notify_share_expired(bot, share)
        except Exception:
            log.exception("Could not announce the access expiry")

    sessions.on_share_expired = _on_share_expired


    app = api_server.create_app()
    http = uvicorn.Server(
        uvicorn.Config(
            app,
            host=config.API_HOST,
            port=config.API_PORT,
            log_level="warning",
            access_log=False,
        )
    )

    sessions.start_reaper()
    log.info("HTTP listening on %s:%s, public address %s",
             config.API_HOST, config.API_PORT, config.PUBLIC_URL)
    log.info("tTerm v%s starting up...", __version__)

    tasks = [
        asyncio.create_task(http.serve(), name="http"),
        # drop_pending_updates is mandatory. Telegram keeps undelivered
        # updates for up to a day and dumps them at the next start. For a chat
        # bot that is a nuisance; for a terminal it means yesterday's commands
        # running on a live server at startup. A command sent and forgotten
        # must not execute a day later.
        asyncio.create_task(
            dp.start_polling(bot, drop_pending_updates=True), name="bot"
        ),
    ]

    try:
        waiter = asyncio.create_task(stop.wait(), name="stop")
        done, _ = await asyncio.wait([*tasks, waiter],
                                     return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        for task in done:
            if task is not waiter and not task.cancelled() and task.exception():
                raise task.exception()  # type: ignore[misc]
    finally:
        await _shutdown(http, dp, bot, tasks)


async def _shutdown(http, dp, bot, tasks) -> None:
    """Stops everything in order, with a timeout on each step.

    Any of these can hang: SSH waiting on a dead server, uvicorn waiting for
    connections to close, Telegram waiting on a long poll. Without timeouts
    the process never exits and only kill -9 is left.

    The timeouts are deliberately short: after Ctrl+C a person waits seconds,
    not half a minute. Unclosed connections die with the process anyway, so
    hurrying is safer than waiting.
    """
    log.info("Shutting down...")

    async def step(name: str, coro, timeout: float = 2.0) -> None:
        try:
            await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("%s did not finish within %.0fs — moving on", name, timeout)
        except Exception:
            log.debug("%s finished with an error", name, exc_info=True)

    # First ask nicely: uvicorn finishes its replies, the long poll ends its
    # current request.
    http.should_exit = True
    await step("Telegram polling", dp.stop_polling(), timeout=2)
    await step("HTTP server", asyncio.gather(*tasks, return_exceptions=True),
               timeout=3)

    for task in tasks:
        task.cancel()

    await step("SSH sessions", sessions.shutdown(), timeout=3)
    await step("Database", db.close(), timeout=2)
    await step("Telegram session", bot.session.close(), timeout=2)
    log.info("Stopped")


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        # On platforms without add_signal_handler the signal lands here.
        pass
    except RuntimeError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
