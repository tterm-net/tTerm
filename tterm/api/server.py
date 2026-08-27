"""The HTTP side: serves the install script and accepts host registration.

The only part exposed to the internet, so it holds minimal logic and maximal
validation.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from ..core.ca import ca
from ..core.config import config
from ..core.agent_hub import AgentLink, decode_hello, registry
from ..core.db import db

log = logging.getLogger(__name__)
router = APIRouter()

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "install.sh"

# The bot injects its callbacks here, so the API does not depend on aiogram.
on_host_registered = None
on_agent_online = None


class EnrollPayload(BaseModel):
    token: str = Field(min_length=4, max_length=64)
    hostname: str = Field(default="", max_length=255)
    os: str = Field(default="", max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(default=config.SSH_USER, max_length=64)
    host_pubkey: str = Field(default="", max_length=1024)


def _client_ip(request: Request) -> str:
    """The client IP, honouring a reverse proxy."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return request.client.host if request.client else ""


@router.get("/s/{token}", response_class=PlainTextResponse)
async def install_script(token: str) -> PlainTextResponse:
    """Serves the install script.

    The token is not burned here, only at registration: otherwise a second
    `curl` — or a preview — would consume the invitation.
    """
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    script = (
        template.replace("{{SSH_USER}}", config.SSH_USER)
        .replace("{{CA_PUBKEY}}", ca.public_key_line())
        .replace("{{API_URL}}", config.PUBLIC_URL)
        .replace("{{TOKEN}}", token)
        .replace("{{CERT_TTL}}", str(config.CERT_TTL_SECONDS))
    )
    return PlainTextResponse(
        script,
        headers={
            "Content-Type": "text/x-shellscript; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


@router.post("/enroll")
async def enroll(payload: EnrollPayload, request: Request) -> JSONResponse:
    """The client's server reports it is ready. The token is burned here."""
    owner_id = await db.consume_enroll_token(payload.token)
    if owner_id is None:
        log.warning("Rejected enrolment with an invalid token from %s", _client_ip(request))
        return JSONResponse(
            {"error": "The token is invalid or expired. Request a new one: /addhost"},
            status_code=400,
        )

    ip = _client_ip(request)
    if not ip:
        return JSONResponse({"error": "Could not determine the server IP"},
                            status_code=400)

    short_name = (payload.hostname or ip).split(".")[0][:40] or "server"

    host_id = await db.create_pending_host(
        owner_id=owner_id,
        name=short_name,
        hostname=payload.hostname or None,
        ip=ip,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        os_info=payload.os or None,
        host_pubkey=payload.host_pubkey or None,
    )
    await db.bind_token_to_host(payload.token, host_id)

    # The host stays pending until the user confirms it in the chat.
    # Without that step a stranger could attach someone else's server
    # to their own account.
    if on_host_registered is not None:
        await on_host_registered(owner_id, host_id)

    log.info("Host %s registered for owner=%s, awaiting confirmation", host_id, owner_id)
    return JSONResponse({"ok": True, "status": "pending_confirmation"})


@router.get("/a/{token}", response_class=PlainTextResponse)
async def agent_script(token: str) -> PlainTextResponse:
    """The agent installer for macOS and Linux with the token filled in."""
    template = (TEMPLATE_PATH.parent / "install_agent.sh").read_text(encoding="utf-8")
    script = template.replace("{{TOKEN}}", token).replace(
        "{{HUB}}", config.PUBLIC_URL.replace("https://", "wss://").replace(
            "http://", "ws://") + "/agent")
    return PlainTextResponse(script, headers={
        "Content-Type": "text/x-shellscript; charset=utf-8",
        "Cache-Control": "no-store",
    })


@router.websocket("/agent")
async def agent_socket(ws: WebSocket) -> None:
    """Where agents from laptops and machines behind NAT dial in.

    The direction is reversed on purpose: a laptop cannot be reached from the
    outside, it has no stable address. So it connects itself and holds the
    channel open.
    """
    await ws.accept()
    link: AgentLink | None = None
    try:
        hello = decode_hello(await ws.receive_text())
        if hello is None:
            await ws.send_json({"t": "error", "error": "malformed hello"})
            await ws.close()
            return

        host_id = await db.resolve_agent_token(hello["token"])
        if host_id is None:
            # `revoked` tells the agent to stop for good: if the machine was
            # removed from the list, retrying is pointless and noisy.
            await ws.send_json({"t": "error", "revoked": True,
                                "error": "the machine was removed from the list"})
            await ws.close()
            return

        host = await db.get_host(host_id)
        if host is None:
            await ws.close()
            return

        # The machine names itself: its hostname is more accurate than what
        # we invented from the Telegram display name when issuing the token.
        reported = (hello.get("name") or "").strip()
        first_time = host.status == "pending" or host.name.endswith("-computer")
        if host.status == "pending":
            # Only from this moment does the machine really exist.
            await db.activate_host(host.id)
            host = await db.get_host(host.id) or host
        if reported and reported != host.name:
            # A machine with this name may already be connected, for example
            # after the agent was reinstalled. Move the token onto the older
            # record instead of growing a second "MacBook" in the list.
            twin = await db.find_agent_by_name(host.owner_id, reported, host.id)
            if twin is not None:
                log.info("Machine %s already exists (host=%s), moving the token",
                         reported, twin)
                await db.move_agent_token(host.id, twin)
                host = await db.get_host(twin) or host
                first_time = False
            else:
                await db.rename_host(host.id, reported)
                host = await db.get_host(host.id) or host

        async def send(msg: dict) -> None:
            await ws.send_json(msg)

        link = AgentLink(
            host_id=host.id, owner_id=host.owner_id, name=host.name,
            os_info=hello.get("os", ""), version=hello.get("agent", ""),
            send=send,
        )
        registry.attach(link)
        await db.touch_host(host.id)
        await ws.send_json({"t": "welcome", "name": host.name})
        log.info("Agent online: host=%s (%s, %s)",
                 host.id, host.name, link.os_info)
        if on_agent_online is not None:
            await on_agent_online(host.owner_id, host.id, first_time)

        while True:
            msg = await ws.receive_json()
            kind = msg.get("t")
            if kind == "out":
                await link.push(msg.get("data", ""))
            elif kind in ("hb", "pong"):
                # Answering is mandatory. The agent treats a long silence as
                # a dead link, and apart from commands there is nothing for us
                # to send: the hub is silent by nature. Without a reply the
                # agent would drop a healthy connection every half minute.
                await ws.send_json({"t": "hb"})
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("The agent connection broke")
    finally:
        if link is not None:
            registry.detach(link.host_id)
            log.info("Agent disconnected: host=%s", link.host_id)


@router.get("/ca.pub", response_class=PlainTextResponse)
async def ca_pubkey() -> str:
    """The CA public key, so a client can compare it by eye."""
    return ca.public_key_line() + "\n"


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> FastAPI:
    app = FastAPI(title="tterm", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(router)
    return app
