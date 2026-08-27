"""A resilience layer on top of the Telegram API.

Workarounds for Telegram behaviour that belong neither to layout nor to bot
logic, but without which the bot fails for no good reason.
"""
from __future__ import annotations

import logging
from typing import Any

from aiogram import Bot
from aiogram.client.session.middlewares.base import NextRequestMiddlewareType
from aiogram.exceptions import TelegramBadRequest
from aiogram.methods import TelegramMethod
from aiogram.methods.base import TelegramType

log = logging.getLogger(__name__)

#: The topic is gone while the message still points at it.
THREAD_GONE = "message thread not found"


async def retry_without_thread(
    handler: NextRequestMiddlewareType[TelegramType],
    bot: Bot,
    method: TelegramMethod[TelegramType],
) -> Any:
    """Retries the send into the main chat when the topic is gone.

    aiogram copies `message_thread_id` from the incoming message so the reply
    lands in the same topic. If the topic was deleted and the update arrived
    late, Telegram answers `message thread not found` and the reply is lost
    entirely, which looks like a silent bot.

    Answering in the main chat beats not answering at all, so the send is
    retried without the topic.
    """
    try:
        return await handler(bot, method)
    except TelegramBadRequest as exc:
        if THREAD_GONE not in str(exc) or not getattr(method, "message_thread_id", None):
            raise
        log.info("Topic is gone, retrying in the main chat: %s", type(method).__name__)
        method.message_thread_id = None
        return await handler(bot, method)


def install(bot: Bot) -> None:
    bot.session.middleware(retry_without_thread)
