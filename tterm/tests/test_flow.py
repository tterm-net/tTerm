"""End-to-end checks that never touch Telegram.

What is covered:
  1. onboarding: token -> script -> registration -> confirmation;
  2. the install token being single-use;
  3. block parsing against a real bash over a local PTY;
  4. blocks being written to the database;
  5. sharing, expiry and the audit trail;
  6. layout, buttons and shutdown.

Run with:  python -m tterm.tests.test_flow
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import pty
import secrets
import select
import shutil
import signal
import sys
import tempfile
import time

os.environ.setdefault("BOT_TOKEN", "test")
TMP = tempfile.mkdtemp(prefix="tterm-test-")
os.environ["DATA_DIR"] = TMP

from tterm.core.ca import ca  # noqa: E402
from tterm.core.db import db  # noqa: E402
from tterm.core.formatter import (  # noqa: E402
    BOOTSTRAP, HOST_ICON, State, clean_output, parse_marker, render,
    render_running,
)

OK = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
_passed = 0
_failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  {OK} {name}")
    else:
        _failed += 1
        print(f"  {FAIL} {name} {detail}")


# -------------------------------------------------------------- onboarding


async def test_onboarding() -> None:
    print("\nOnboarding")
    from fastapi.testclient import TestClient

    from tterm.api import server as api

    await db.connect()
    ca.load_or_create()

    user_id = 111222
    await db.upsert_user(user_id, "tester", "Tester")

    registered: list[tuple[int, int]] = []

    async def on_registered(owner_id: int, host_id: int) -> None:
        registered.append((owner_id, host_id))

    api.on_host_registered = on_registered
    client = TestClient(api.create_app())

    token = await db.create_enroll_token(user_id)
    check("install token created", len(token) > 8)

    script = client.get(f"/s/{token}")
    check("script served", script.status_code == 200)
    check("token injected into the script", token in script.text)
    check("CA key injected", ca.public_key_line() in script.text)
    check("trust via cert-authority", "cert-authority $CA_PUBKEY" in script.text)
    check("sshd is never restarted", "systemctl restart ssh" not in script.text
          and "service ssh restart" not in script.text)
    # sudo is granted through a drop-in rather than by editing /etc/sudoers,
    # and the syntax is validated: a broken file in sudoers.d breaks sudo for
    # everyone, including the admin.
    check("sudo granted through its own file", "/etc/sudoers.d/" in script.text)
    check("sudo rule validated with visudo", "visudo -c" in script.text)
    check("the main sudoers is left alone",
          "/etc/sudoers\n" not in script.text.replace("/etc/sudoers.d", ""))

    payload = {
        "token": token,
        "hostname": "web-01.acme.io",
        "os": "Ubuntu 24.04 LTS",
        "ssh_port": 22,
        "ssh_user": "tterm",
        "host_pubkey": "ssh-ed25519 AAAA",
    }
    resp = client.post("/enroll", json=payload)
    check("registration accepted", resp.status_code == 200, resp.text)
    check("status is pending, not active right away",
          resp.json().get("status") == "pending_confirmation")
    check("owner notified", len(registered) == 1)

    # A repeat with the same token must be rejected.
    resp2 = client.post("/enroll", json=payload)
    check("the token is single-use", resp2.status_code == 400)

    host_id = registered[0][1]
    host = await db.get_host(host_id)
    check("host name shortened to web-01", host is not None and host.name == "web-01")

    active_before = await db.get_active_host(user_id)
    check("host is inactive until confirmed", active_before is None)

    await db.activate_host(host_id)
    await db.set_active_host(user_id, host_id)
    active_after = await db.get_active_host(user_id)
    check("host is active after confirmation",
          active_after is not None and active_after.id == host_id)

    # An expired token.
    stale = await db.create_enroll_token(user_id)
    await db.conn.execute(
        "UPDATE enroll_tokens SET expires_at = ? WHERE token = ?", (int(time.time()) - 5, stale)
    )
    await db.conn.commit()
    check("an expired token is rejected", await db.consume_enroll_token(stale) is None)

    return host_id, user_id


# ------------------------------------------------------- block parsing


class _Watchdog:
    """A hard limit on the whole PTY section.

    Anything talking to a terminal can hang for good: a full input buffer,
    a shell waiting for an answer, a program that took the screen. A silent
    hang is the most expensive thing to diagnose, so an alarm is set here:
    when time runs out we fail and say where we stalled.
    """

    def __init__(self, seconds: int, what: str) -> None:
        self.seconds, self.what = seconds, what

    def __enter__(self):
        def fire(*_):
            raise TimeoutError(f"{self.what}: did not finish within {self.seconds}s")
        self._old = signal.signal(signal.SIGALRM, fire)
        signal.alarm(self.seconds)
        return self

    def __exit__(self, *exc):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old)
        return False


def test_block_framing() -> None:
    """Checks the marker and bootstrap against real bash over a local PTY."""
    import subprocess
    ver = subprocess.run(["bash", "--version"], capture_output=True,
                         text=True).stdout.splitlines()[0]
    print(f"\nBlock parsing on real bash\n  {ver}")
    nonce = secrets.token_hex(8)

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "--noediting", "-i"])

    def drain(quiet: float = 0.6, limit: float = 8.0) -> None:
        """Reads until silence. The bootstrap is multi-line and prints several
        markers in a row: stopping at the first would shift the rest."""
        last = time.time()
        start = time.time()
        while time.time() - start < limit:
            if select.select([fd], [], [], 0.15)[0]:
                try:
                    os.read(fd, 65536)
                    last = time.time()
                except OSError:
                    break
            elif time.time() - last > quiet:
                break

    def run(cmd: str, timeout: float = 6.0):
        os.write(fd, (cmd + "\n").encode())
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    buf.extend(os.read(fd, 65536))
                except OSError:
                    break
            parsed = parse_marker(buf.decode("utf-8", "replace"), nonce)
            if parsed:
                return parsed
        # No marker. Staying silent is not an option: without this dump every
        # following command would simply burn its timeout with no clue why.
        raw = buf.decode("utf-8", "replace")
        print(f"    !  no marker within {timeout:g}s for command {cmd!r}")
        print(f"        raw stream: {raw[-300:]!r}")
        return raw, State(), None

    def feed(lines: list[str]) -> None:
        """Line by line, draining between lines.

        The terminal input buffer on macOS is 1024 bytes. Once the bootstrap
        grew past a kilobyte, writing it in one go blocked forever: the shell
        could not drain the queue fast enough while write waited for room.
        """
        for line in lines:
            os.write(fd, (line + "\n").encode())
            if select.select([fd], [], [], 0.02)[0]:
                try:
                    os.read(fd, 65536)
                except OSError:
                    pass

    feed([
        "stty -echo 2>/dev/null; PS1=''; PS2=''; PS4=''",
        "export COLUMNS=100 LINES=40 LESS=FRX",
        f"__TT_NONCE={nonce}",
    ] + BOOTSTRAP.strip("\n").split("\n"))
    drain()

    out, state, code = run("echo hello")
    check("bootstrap took, the marker is printed", code is not None,
          "the prompt function broke, see the raw stream above")
    if code is None:
        os.write(fd, b"exit\n")
        return
    check("output captured", clean_output(out) == "hello", repr(out))
    check("the command is not echoed back", "echo hello" not in out)
    check("exit code 0", code == 0)

    out, state, code = run("ls /nope-xyz")
    # The exact number depends on the ls implementation: BSD gives 1, GNU 2.
    check("a non-zero exit code is caught", code is not None and code != 0, f"code={code}")

    out, state, code = run("(exit 42)")
    check("the exit code is exact", code == 42, f"code={code}")

    run("cd /tmp")
    out, state, code = run("pwd")
    check("the directory persists between commands", state.cwd == "/tmp", f"cwd={state.cwd}")

    out, state, code = run("export FOO=bar")
    out, state, code = run("echo $FOO")
    check("environment variables persist", clean_output(out) == "bar")

    out, state, code = run("printf 'a\\nb\\nc\\n'")
    check("multi-line output arrives whole", clean_output(out) == "a\nb\nc")

    out, state, code = run("printf 'X 10%%\\rX 99%%\\n'")
    check("progress bars collapse", clean_output(out) == "X 99%",
          repr(clean_output(out)))

    out, state, code = run("printf '\\033[1;31mred\\033[0m\\n'")
    check("ANSI colours stripped", clean_output(out) == "red")

    # --- fields of the extended marker ---
    out, state, code = run("true")
    check("user present in the marker", bool(state.user), f"user={state.user!r}")
    check("euid present in the marker", isinstance(state.euid, int), f"euid={state.euid}")
    check("the root flag matches euid", state.is_root == (state.euid == 0))

    run("mkdir -p /tmp/tt-git && cd /tmp/tt-git && git init -q 2>/dev/null; true")
    out, state, code = run("true")
    check("git branch read from .git/HEAD", bool(state.branch), f"branch={state.branch!r}")
    # The branch has its own line above the prompt: buried at the end of one
    # it went unread, and it is often the first thing you want to know.
    check("the branch reaches the card", state.branch in state.branch_line())
    check("and stays out of the prompt itself",
          state.branch not in state.prompt(),
          state.prompt())

    # the dirty-tree asterisk against a real repository
    run("cd /tmp/tt-git && git config user.email a@b && git config user.name a "
        "&& echo hi > f.txt && git add -A && git commit -qm init")
    out, state, code = run("true")
    check("a clean tree shows no asterisk", not state.branch.endswith("*"),
          f"branch={state.branch!r}")
    run("echo changed >> /tmp/tt-git/f.txt")
    out, state, code = run("true")
    check("an edit adds the asterisk", state.branch.endswith("*"),
          f"branch={state.branch!r}")

    run("cd /tmp && rm -rf /tmp/tt-git")
    out, state, code = run("VIRTUAL_ENV=/tmp/myenv; export VIRTUAL_ENV; true")
    out, state, code = run("true")
    check("venv is visible in the prompt", "myenv" in state.prompt(), state.prompt())

    os.write(fd, b"exit\n")
    os.close(fd)


# --------------------------------------------------------------- recording


async def test_recording(host_id: int, user_id: int) -> None:
    print("\nSession recording")
    sid = await db.open_session(user_id, host_id)
    await db.record_block(sid, user_id, host_id, "uptime", " 14:32 up 12 days", 0, "/root", 84)
    await db.record_block(sid, user_id, host_id, "ls /nope", "No such file", 2, "/root", 61)

    rows = await db.recent_blocks(user_id, limit=10)
    check("both blocks recorded", len(rows) == 2)
    check("exit code stored", rows[0]["exit_code"] == 2)
    check("output stored in full", "No such file" in rows[0]["output"])
    check("host name joined in", rows[0]["host_name"] == "web-01")
    await db.close_session(sid)


def test_rendering() -> None:
    print("\nMessage layout")
    st = State(cwd="~/app", user="denis", euid=1000, host="web-01", branch="main")

    card = render(" 14:32:07 up 12 days\r\n", 0, 0.084, st, command="uptime")
    check("short output goes as text", card.mode == "text")
    check("success status rendered", "🟢" in card.text)
    check("the prompt closes the card", card.text.rstrip().endswith("</code>"))
    check("state is shown by the prompt",
          "~/app" in card.text and "main" in card.text and "❯" in card.text)
    check("the command is not repeated", "uptime" not in card.text)

    card = render("boom\n", 2, 0.06, st, command="ls /nope")
    check("error status rendered", "🔴" in card.text and "<b>2</b>" in card.text)

    card = render("\n".join(f"line {i}" for i in range(200)), 0, 1.2, st,
                  command="ls -la /etc")
    check("many lines go out as a file", card.mode == "file", f"mode={card.mode}")
    check("the file is named after the command", card.file_name.startswith("ls-la-etc"),
          card.file_name)
    check("the caption fits Telegram's limit", len(card.text) <= 1024, len(card.text))
    check("the caption holds the tail, not the head", "line 199" in card.text
          and "line 0\n" not in card.text)
    from tterm.core.formatter import CAPTION_LINE_CHARS, TAIL_LINES
    wide = "\n".join("z" * 200 for _ in range(50))
    wide_card = render(wide, 0, 0.1, st, command="cat wide")
    body = wide_card.text.split("\n")
    # The last lines are left whole on purpose — the result and the error live
    # there, and a wrapped conclusion beats a truncated one. Everything above
    # them is cut to the width of the column.
    above = body[:-(TAIL_LINES // 2 + 2)]
    longest = max((len(x) for x in above), default=0)
    check("long caption lines are cut, not wrapped",
          longest <= CAPTION_LINE_CHARS + 10, f"longest={longest}")

    # The tilde in the replacement must be escaped, or bash expands it to the
    # home directory before substitution and the full path stays.
    check("the tilde in the bootstrap is escaped", r"/\~}" in BOOTSTRAP,
          "without the backslash ~ never expands and the full path stays")

    card = render("x" * 50_000, 0, 0.12, st, command="cat big")
    check("one long line also goes as a file", card.mode == "file")
    check("the file body is not empty", len(card.file_body) > 40_000)

    card = render("<script>alert(1)</script>", 0, 0.005, st, command="cat x.html")
    check("HTML is escaped", "&lt;script&gt;" in card.text
          and "<script>" not in card.text)

    card = render("- a\n+ b\n", 0, 0.02, st, command="git diff")
    check("highlighting picked from the command", 'class="language-diff"' in card.text)

    who = State(cwd="~", user="alice", host="MacBookPro")
    check("the user is visible in the prompt", who.prompt().startswith("alice"),
          who.prompt())
    check("under sudo it is visible we are root",
          State(cwd="/etc", user="root", euid=0).prompt().startswith("root"))

    root = State(cwd="/etc", user="root", euid=0, host="web-01")
    check("root is shown with a hash", root.prompt().endswith("#"), root.prompt())

    # --- prompt icons ---
    icon_st = State(cwd="~/app", user="denis", host="web-01", branch="main", venv="venv")
    check("the prompt has no icons by default", "📁" not in icon_st.prompt(),
          icon_st.prompt())
    check("the default style omits the host name", "web-01" not in icon_st.prompt())
    check("venv shown in brackets", "(venv)" in icon_st.prompt(), icon_st.prompt())
    with_icons = icon_st.prompt(icons=True)
    check("directory icon in the prompt", "📁" in with_icons, with_icons)
    check("branch icon on its own line", "🌿" in dirty_state.branch_line()
          if (dirty_state := State(cwd="~/app", branch="main*")) else False)
    check("venv icon in the prompt", "🐍" in with_icons, with_icons)
    check("icons switch off with a flag", "📁" not in icon_st.prompt(icons=False))
    plain = State(cwd="/var/log", user="denis", host="web-01")
    check("no branch icon outside a repo", "🌿" not in plain.prompt(icons=True),
          plain.prompt(icons=True))
    check("classic bash style has no icons", "📁" not in icon_st.prompt(style=3))
    check("icons stay out of the card by default",
          "📁" not in render("x", 0, 0.1, icon_st, command="ls").text)

    # --- the dirty-tree asterisk ---
    dirty = State(cwd="~/app", user="denis", host="web-01", branch="main*")
    check("the asterisk is visible", "main*" in dirty.branch_line(),
          dirty.branch_line())
    from tterm.core.formatter import render as _render
    in_repo = _render("ok", 0, 0.4,
                      State(cwd="/opt/app", user="deploy", branch="main*",
                            host="web-01"), command="git status").text
    check("the card puts the branch above the prompt",
          in_repo.index("🌿") < in_repo.index("deploy /opt/app"),
          in_repo)
    check("outside a repository there is no branch line",
          State(cwd="/etc", user="root").branch_line() == "",
          "a blank line kept for alignment reads worse than none")
    check("the asterisk does not break the bash style", "main" not in dirty.prompt(style=3))
    check("the bootstrap detects uncommitted changes",
          "--no-optional-locks" in BOOTSTRAP and "status --porcelain" in BOOTSTRAP)
    check("the dirty check switches off with a flag", "__TT_GIT_DIRTY" in BOOTSTRAP)
    # bash 3.2 in macOS parses quotes inside $( ) inside " " differently:
    # the whole function breaks and the marker stops being printed.
    check("no nested quotes in the git call",
          '"$(git' not in BOOTSTRAP, "nesting is back and will break bash 3.2")
    # The terminal input buffer on macOS is 1024 bytes and the bootstrap is
    # already larger, so sending it in one go would block forever.
    check("the bootstrap is sent line by line",
          "def feed(" in pathlib.Path(__file__).read_text(encoding="utf-8"))

    running = render_running("Downloading 42%\n", 8.0,
                             state=State(host="tterm-test-01"))
    check("the machine name shows while running", running.startswith(HOST_ICON),
          running.split("\n")[0])
    check("the interim card carries no exit code", "⏳" in running
          and "🟢" not in running)


async def test_buttons() -> None:
    """Button colour carries meaning, so it is pinned by a test."""
    print("\nButtons")
    from aiogram.enums import ButtonStyle

    from tterm.bot.handlers import servers_keyboard

    hosts = await db.list_hosts(111222)
    markup = servers_keyboard(hosts, active_id=hosts[0].id if hosts else None)
    flat = [b for row in markup.inline_keyboard for b in row]

    server_btns = [b for b in flat if (b.callback_data or "").startswith("use:")]
    add_btns = [b for b in flat if b.callback_data == "addhost"]

    check("machines are blue", all(b.style == ButtonStyle.PRIMARY for b in server_btns),
          str([b.style for b in server_btns]))
    check("the add button is green",
          all(b.style == ButtonStyle.SUCCESS for b in add_btns))
    check("there is exactly one add button", len(add_btns) == 1)
    check("the plus is light, no heavy emoji",
          all("➕" not in b.text for b in add_btns),
          str([b.text for b in add_btns]))
    check("the plus is a plain character", all(b.text.startswith("+") for b in add_btns))

    # The active machine is marked in the text rather than by an arrow on the
    # button: on a button it eats space and the names are long already.
    from tterm.bot.handlers import ONLINE, OFFLINE, _servers_text
    if hosts:
        txt = await _servers_text(hosts, hosts[0], 111222)
        check("the active machine is bold", f"<b>{hosts[0].name}</b>" in txt, txt)
        check("status is shown with a dot", ONLINE in txt or OFFLINE in txt, txt)
        check("the dots are the same size", len(ONLINE) == 1 and len(OFFLINE) == 1)
        check("an offline machine shows a hollow dot",
              OFFLINE in txt, txt)
        check("the machine number for /share is visible", f"#{hosts[0].id}" in txt, txt)


def test_certificates() -> None:
    """The certificate must match the key we connect with.

    Checking that a certificate object was created guarantees nothing: swap
    the arguments and the certificate is issued for the CA key, signed by the
    throwaway one. Everything looks fine until connect time, where asyncssh
    fails with "Certificate key mismatch".
    """
    print("\nCertificates")
    from asyncssh.public_key import load_keypairs

    from tterm.core.ca import ca as authority

    authority.load_or_create()
    key, cert = authority.issue_client_cert("tterm")

    check("the certificate is issued for our key", cert.key.public_data == key.public_data)
    check("the certificate is signed by the CA key",
          cert.signing_key.public_data == authority.ca_key.public_data)
    check("the principal is the service user", cert.principals == ["tterm"])

    pairs = load_keypairs([(key, cert)])
    check("asyncssh accepts the key and certificate pair", bool(pairs))
    check("the connection uses the certificate, not a bare key",
          any(b"cert-v01" in p.algorithm for p in pairs),
          str([p.algorithm for p in pairs]))

    line = authority.public_key_line()
    check("the CA public key fits authorized_keys",
          line.startswith("ssh-ed25519 ") and "\n" not in line)


async def test_agent() -> None:
    """The agent: a machine dials in because a laptop cannot be dialled."""
    print("\nAgent")
    from tterm.core.agent_hub import AgentSession, decode_hello, registry
    from tterm.core.session_base import TerminalSession

    check("an agent session is the same type as SSH",
          issubclass(AgentSession, TerminalSession),
          "otherwise the session pool and handlers would need branching")

    uid = 909090
    await db.upsert_user(uid, "agent", "Agent")
    hid = await db.create_agent_host(uid, "MacBook-Test")
    # A placeholder becomes a machine only once the agent is online.
    await db.activate_host(hid)
    host = await db.get_host(hid)
    check("the host kind is agent", host is not None and host.kind == "agent")

    token = await db.issue_agent_token(hid)
    check("the machine token is issued", len(token) > 20)
    check("the token resolves to a host", await db.resolve_agent_token(token) == hid)
    check("an unknown token resolves to nothing", await db.resolve_agent_token("nope") is None)

    # The machine token is deliberately long-lived: the agent presents it on
    # every reconnect, after sleep, a network change or a reboot.
    check("the machine token is reusable",
          await db.resolve_agent_token(token) == hid)

    check("the hello message parses",
          decode_hello('{"t":"hello","token":"x","name":"mac"}') is not None)
    check("garbage is rejected", decode_hello("not json") is None)
    check("no token, no entry",
          decode_hello('{"t":"hello","name":"mac"}') is None)
    check("a wrong message type is rejected",
          decode_hello('{"t":"out","token":"x"}') is None)

    session = AgentSession(host)
    check("without a connected agent the session is dead", not session.is_alive)
    raised = False
    try:
        await session.connect()
    except ConnectionError as exc:
        raised = "offline" in str(exc)
    check("connecting to an offline machine gives a clear error", raised)
    check("the registry is empty", registry.get(hid) is None)

    # The agent repo is separate and not always checked out next to this one;
    # then these checks are skipped and the total is lower.
    agent_src = (pathlib.Path(__file__).resolve().parents[2].parent
                 / "tterm-agent" / "agent.py")
    if not agent_src.exists():
        print("  . tterm-agent repo not found next to this one, some checks skipped")
    else:
        src = agent_src.read_text(encoding="utf-8")
        check("the agent refuses to run as root", "geteuid() == 0" in src)
        check("the agent does not parse output, it is a pipe",
              "parse_marker" not in src,
              "parsing belongs on the hub, otherwise every agent needs updating")
        check("the agent reconnects with a backoff", "BACKOFF_MAX" in src)
        check("the shell starts in the home directory", "os.chdir(home)" in src,
              "started from autostart it would otherwise land in the filesystem root")
        check("the agent venv does not leak into the shell", 'pop("VIRTUAL_ENV"' in src)
        check("the machine name drops the .local suffix", 'removesuffix(".local")' in src)
        # The agent repo is public: a way around the root check would
        # contradict what the README claims about it.
        import re as _re3
        cyr = _re3.findall(r"[а-яА-Я]{3,}", src)
        check("the agent is fully in English", not cyr, str(cyr[:3]))
        check("there is no root escape hatch", "ALLOW_ROOT" not in src)
        check("the link points at the organisation",
              "github.com/tterm-net/tterm-agent" in src)
        # gather used to wait for both tasks while the PTY read hung in its
        # thread forever, so the agent never came back after the lid closed.
        check("a dropped link does not hang the agent",
              "FIRST_COMPLETED" in src and "gather(pump_shell" not in src,
              "otherwise os.read in its thread blocks reconnection")
        check("the agent stops when access is revoked", "Revoked" in src)
        # When a laptop sleeps the socket is left half-open: the server sees
        # the drop, the client does not, no error is raised and there is
        # nothing to read. So the agent must notice a dead link itself.
        check("the agent watches the link itself", "class Health" in src
              and "watchdog" in src,
              "otherwise it hangs on a half-open socket after sleep")
        check("machine sleep is caught by clock drift", "SLEEP_JUMP" in src
              and "slept" in src)
        check("hub silence drops the connection too", "SILENCE_LIMIT" in src)
        # A wrapper script gives no name: exec replaces the process with python.
        check("the process is genuinely renamed",
              "setproctitle" in src,
              "otherwise macOS shows a nameless python in its background items")

    # --- closing a session is not removing a machine ---
    hid2 = await db.create_agent_host(uid, "Second-Mac")
    await db.activate_host(hid2)
    tok2 = await db.issue_agent_token(hid2)
    check("the token works", await db.resolve_agent_token(tok2) == hid2)
    await db.revoke_agent_token(hid2)
    check("the token is dead after revocation", await db.resolve_agent_token(tok2) is None)
    still = await db.get_host(hid2)
    check("the host record survives", still is not None)

    # --- reinstalling does not create duplicates ---
    dup = await db.create_agent_host(uid, "MacBook-Pro-Denis")
    await db.activate_host(dup)
    fresh = await db.create_agent_host(uid, "denis-computer")
    await db.activate_host(fresh)
    fresh_token = await db.issue_agent_token(fresh)
    twin = await db.find_agent_by_name(uid, "MacBook-Pro-Denis", fresh)
    check("a same-name machine is found", twin == dup, f"{twin} vs {dup}")

    await db.move_agent_token(fresh, dup)
    check("the token moved to the existing record",
          await db.resolve_agent_token(fresh_token) == dup)
    gone = await db.get_host(fresh)
    check("the temporary record is gone", gone is not None and gone.status == "removed")
    names = [h.name for h in await db.list_hosts(uid)]
    check("no two identical machines in the list",
          names.count("MacBook-Pro-Denis") == 1, str(names))

    # --- cleaning up stale records ---
    junk_uid = 424242
    await db.upsert_user(junk_uid, "junk", "Junk")
    for _ in range(3):
        await db.create_agent_host(junk_uid, "someone-computer")
    check("abandoned placeholders never show up",
          not await db.list_hosts(junk_uid),
          "they are not machines until the agent comes online")

    for _ in range(3):
        h = await db.create_agent_host(junk_uid, "Real-Mac")
        await db.activate_host(h)
        await db.issue_agent_token(h)
    await db.cleanup_agent_hosts()
    left = [h.name for h in await db.list_hosts(junk_uid)]
    check("same-name duplicates collapse", left.count("Real-Mac") == 1, str(left))
    check("placeholders that never connected are cleared",
          not any(n.endswith("-computer") for n in left), str(left))

    installer = (pathlib.Path(__file__).resolve().parents[2].parent
                 / "tterm-agent" / "install.sh")
    if installer.exists():
        isrc = installer.read_text(encoding="utf-8")
        check("the installer stops the previous agent",
              "Agent already installed" in isrc,
              "otherwise two instances fight over one connection")
        # `rm -rf "$DIR"` is in the file, but only inside the generated
        # uninstall.sh, which is where it belongs. We check the install part:
        # rebuilding the venv on every update is slow and pointless.
        install_part = isrc.split('cat > "$DIR/uninstall.sh"')[0]
        check("the installer keeps the venv on update",
              "rm -rf" not in install_part)
        cyr_i = _re3.findall(r"[а-яА-Я]{3,}", isrc)
        check("the installer is fully in English", not cyr_i, str(cyr_i[:3]))
        check("no dead wrapper left in the installer", "LAUNCHER" not in isrc,
              "exec replaced it with python and the name was lost anyway")

    from tterm.bot.handlers import ADD_MENU_TEXT, add_menu_keyboard
    menu = [b for row in add_menu_keyboard().inline_keyboard for b in row]
    check("the menu offers four ways to connect", len(menu) == 4, str(len(menu)))
    check("the menu carries no long explanations", len(ADD_MENU_TEXT) < 60, ADD_MENU_TEXT)

    handlers_all = (pathlib.Path(__file__).resolve().parents[1]
                    / "bot" / "handlers.py").read_text("utf-8")
    check("Windows gets a ready command, not a pointer elsewhere",
          "/a/{agent_token}" in handlers_all and "WSL" in handlers_all)
    check("picking a machine shows the prompt",
          'state.prompt()' in handlers_all,
          "otherwise there is no telling which directory you landed in")
    check("the hub answers the agent's heartbeat",
          '"hb"' in (pathlib.Path(__file__).resolve().parents[1]
                     / "api" / "server.py").read_text("utf-8"),
          "otherwise the agent reads silence as a drop and keeps reconnecting")
    labels = " ".join(b.text for b in menu)
    for want in ("Linux", "Windows", "macOS"):
        check(f"the menu offers {want}", want in labels, labels)
    from tterm.core.formatter import PC_ICON, SERVER_ICON
    check("servers and computers differ by icon",
          labels.count(SERVER_ICON) == 2 and labels.count(PC_ICON) == 2, labels)
    check("the icons are not the same", SERVER_ICON != PC_ICON)
    _ = ADD_MENU_TEXT

    handlers_src = (pathlib.Path(__file__).resolve().parents[1]
                    / "bot" / "handlers.py").read_text("utf-8")
    check("submenus offer a way back", "‹ Back" in handlers_src)
    check("removing a machine is separate from closing a session",
          "revoke_agent_token" in handlers_src and "askrm:" in handlers_src)
    check("removal asks for confirmation", "remove:cancel" in handlers_src)


async def test_sharing() -> None:
    """Sharing: somebody else works on my machine."""
    print("\nSharing with others")
    from tterm.bot.handlers import _parse_share_args, human_duration, parse_duration

    owner, john, mary = 700001, 700002, 700003
    await db.upsert_user(owner, "owner", "Owner")
    await db.upsert_user(john, "John", "John")
    await db.upsert_user(mary, None, "Mary")
    hid = await db.create_agent_host(owner, "Prod-Mac")
    await db.activate_host(hid)

    # Telegram does not let bots search by username: we only know people who
    # started the bot themselves. Hence the rule for the recipient.
    check("username lookup ignores case",
          await db.find_user_by_username("@JOHN") == john)
    check("an unknown username is not found",
          await db.find_user_by_username("@stranger") is None)
    check("someone without a username shows by first name",
          await db.username_of(mary) == "Mary")

    check("no access before it is granted", not await db.can_use(john, hid))
    await db.grant(hid, owner, john)
    check("access exists once granted", await db.can_use(john, hid))
    check("the machine appears in the recipient's list",
          hid in [h.id for h in await db.list_hosts(john)])
    check("an outsider gets no access", not await db.can_use(mary, hid))

    await db.grant(hid, owner, john)
    check("granting again does not duplicate records", len(await db.shares_of(hid)) == 1)

    await db.grant(hid, owner, john, ttl_seconds=-1)
    check("an expired share does not work", not await db.can_use(john, hid))
    check("an expired share is not listed", not await db.shares_of(hid))
    check("the machine leaves the recipient's list",
          hid not in [h.id for h in await db.list_hosts(john)])

    await db.grant(hid, owner, john, ttl_seconds=3600)
    check("a time-limited share works", await db.can_use(john, hid))
    check("revocation takes effect", await db.revoke(hid, john))
    check("no access after revocation", not await db.can_use(john, hid))
    check("revoking twice finds nothing", not await db.revoke(hid, john))
    check("the owner never loses access", await db.can_use(owner, hid))

    check("duration 4h parses", parse_duration("4h") == 14400)
    check("duration 30m parses", parse_duration("30m") == 1800)
    check("garbage is not a duration", parse_duration("tomorrow") is None)
    check("durations print readably", human_duration(14400) == "4h")
    check("arguments parse in any order",
          _parse_share_args("@john #12") == (12, "@john", None))
    check("the duration is recognised as the third argument",
          _parse_share_args("#12 @john 7d")[2] == 604800)

    handlers_src = (pathlib.Path(__file__).resolve().parents[1]
                    / "bot" / "handlers.py").read_text("utf-8")
    check("picking a machine checks permission", "db.can_use" in handlers_src,
          "otherwise someone else's machine could be picked by number")
    check("revocation cuts the session",
          "sessions.drop_host(grantee" in handlers_src,
          "every terminal of theirs on that machine, not just one")
    check("a recipient cannot manage someone else's machine",
          "_not_owner" in handlers_src,
          "otherwise they could uninstall the agent or remove the machine")

    # The limitation has to be stated before the command is typed, not after
    # it fails. A bot cannot resolve a username it has never seen, and finding
    # that out through a refusal reads as a broken feature.
    check("the share help leads with the requirement",
          "have to start the bot first" in handlers_src
          and handlers_src.index("have to start the bot first")
              < handlers_src.index("Duration:"),
          "it used to sit at the bottom as a footnote")
    check("an unknown username gets a forwardable invite",
          "Copy invite" in handlers_src)
    check("revoke tells an unknown name from one without access",
          "nothing to revoke" in handlers_src)

    # The owner has to see other people's commands on their machine, or
    # sharing access would be reckless.
    await db.grant(hid, owner, john)
    sid = await db.open_session(john, hid)
    await db.record_block(sid, john, hid, "rm -rf /tmp/x", "", 0, "/", 10)
    seen = await db.recent_blocks(owner, limit=5)
    check("the owner sees others' commands on their machine",
          any(r["user_id"] == john for r in seen))
    check("the log shows who ran what",
          any(r["actor_name"] == "John" for r in seen))
    other = await db.recent_blocks(mary, limit=5)
    check("an outsider sees no one else's log",
          not any(r["host_id"] == hid for r in other))

    # Permission is checked beyond selection time: a share may expire later.
    # Otherwise an expired share kept working — the machine left the list
    # while commands still reached it.
    await db.grant(hid, owner, john)
    await db.set_active_host(john, hid)
    check("the active machine holds while access lasts",
          (await db.get_active_host(john)) is not None)
    await db.grant(hid, owner, john, ttl_seconds=-1)
    check("an expired share clears the active machine",
          (await db.get_active_host(john)) is None,
          "otherwise commands keep reaching someone else's machine")

    await db.grant(hid, owner, john, ttl_seconds=-1)
    expired = await db.expire_shares()
    check("expired shares are closed explicitly", len(expired) == 1)
    check("the same ones are not closed twice", not await db.expire_shares())
    check("there is someone to warn about the expiry",
          expired[0]["owner_id"] == owner and expired[0]["grantee_id"] == john)

    full = await db.all_blocks(owner)
    check("the full history exports", len(full) >= 1)
    check("history runs oldest first",
          all(full[i]["created_at"] <= full[i + 1]["created_at"]
              for i in range(len(full) - 1)))
    check("the bot can hand the history over as a file", "log:all" in handlers_src)
    check("the log shows 30 commands, not 20",
          "recent_blocks(message.from_user.id, limit=30)" in handlers_src)

    # A machine can be shared with several people and they must be revoked
    # separately: a single "revoke all" eventually cuts the wrong one.
    await db.grant(hid, owner, john, ttl_seconds=3600)
    await db.grant(hid, owner, mary)
    many = await db.shares_of(hid)
    check("the machine is shared with two people at once", len(many) == 2, str(len(many)))
    await db.revoke(hid, john)
    left = await db.shares_of(hid)
    check("revoking one does not touch the other",
          len(left) == 1 and left[0]["grantee_id"] == mary)
    check("there is a revoke button per person", "unshare:" in handlers_src)

    from tterm.bot.handlers import _shares_view
    shost = await db.get_host(hid)
    srich, stext, skb = await _shares_view(shost)
    import json as _j
    sd = _j.dumps(srich.model_dump(exclude_none=True, mode="json"),
                  ensure_ascii=False)
    labels = [b["text"] for blk in srich.model_dump(exclude_none=True,
                                                    mode="json")["blocks"]
              if blk.get("type") == "buttons" for b in blk["buttons"]]
    check("the sharing screen uses in-message buttons", '"type": "buttons"' in sd)
    check("the machine number shows in the sharing header", f"#{hid}" in sd, sd[:120])
    check("the sharing screen offers a way back", "‹ Back" in labels, str(labels))
    check("one revoke button per recipient",
          sum(1 for x in labels if x.startswith("Revoke")) == len(
              await db.shares_of(hid)),
          str(labels))
    check("the plain layout remains as a fallback", "<b>" in stext and skb is not None)
    # A column of large buttons under the list read badly: there was no
    # telling which machine they belonged to.
    check("picking a machine does not replace the list with a button column",
          "machine_keyboard" not in handlers_src)
    check("/share without a name opens the sharing screen",
          "_shares_view" in handlers_src)

    from tterm.bot.handlers import _share_label
    timed = [s for s in many if s["expires_at"]]
    check("the list shows the time left",
          any("left" in _share_label(s) for s in timed), str(timed))
    check("an open-ended share shows no deadline",
          "left" not in _share_label(left[0]), _share_label(left[0]))


async def test_machines_view() -> None:
    """The machine list: the name is a button, actions sit under the selected one."""
    print("\nMachine list layout")
    import json as _json

    from tterm.bot import machines

    uid, other = 800001, 800002
    await db.upsert_user(uid, "own", "Own")
    await db.upsert_user(other, "john", "John")
    srv = await db.create_pending_host(uid, name="prod-1", ip="10.0.0.1")
    await db.activate_host(srv)
    mac = await db.create_agent_host(uid, "MacBook")
    await db.activate_host(mac)
    hosts = await db.list_hosts(uid)
    active = next(h for h in hosts if h.id == srv)

    msg = await machines.build(hosts, active, uid, {srv: True, mac: False})
    d = msg.model_dump(exclude_none=True, mode="json")
    txt = _json.dumps(d, ensure_ascii=False)

    check("the machine name is a button inside the line", '"type": "button"' in txt,
          "otherwise it is just a keyboard below the message")
    check("the active machine is coloured", '"style": "primary"' in txt)
    # No heading block is used: at any size it renders in the heading font and
    # makes the message look larger than its neighbours.
    check("there are no heading blocks",
          not any(b.get("type") == "heading" for b in d["blocks"]),
          str([b.get("type") for b in d["blocks"]]))
    check("the title is a bold line at normal size",
          d["blocks"][0]["text"][0]["type"] == "bold",
          str(d["blocks"][0]))
    check("there is no status dot", "●" not in txt and "○" not in txt,
          "the button itself took over that role")

    # Only an offline agent is greyed out: an SSH server can be connected to
    # at any time, and no live session does not mean unavailable.
    check("an unreachable agent gets a greyed-out button", '"disabled": {}' in txt)
    only_srv = await machines.build([active], active, uid, {srv: False})
    check("a server without a session stays clickable",
          '"disabled"' not in _json.dumps(
              only_srv.model_dump(exclude_none=True, mode="json")),
          "otherwise the server could not be connected to at all")

    check("removal goes through a confirmation",
          "askrm:" in txt and '"callback_data": "remove:' not in txt,
          "one tap must not take a machine away")

    await db.grant(srv, uid, other)
    msg = await machines.build(hosts, active, uid, {srv: True, mac: False})
    txt2 = _json.dumps(msg.model_dump(exclude_none=True, mode="json"),
                       ensure_ascii=False)
    check("the access button shows a counter", "Access (1)" in txt2)

    guest = await db.list_hosts(other)
    gmsg = await machines.build(guest, guest[0], other, {srv: True})
    gtxt = _json.dumps(gmsg.model_dump(exclude_none=True, mode="json"),
                       ensure_ascii=False)
    check("a recipient has nothing to remove", "askrm" not in gtxt)
    check("a recipient sees whose machine it is", "from " in gtxt)

    # A placeholder must not steal the selection from a working machine:
    # tapping "Computer" used to make it active and commands went to a machine
    # the agent had not reached yet.
    await db.set_active_host(uid, srv)
    ph = await db.create_agent_host(uid, "someone-computer")
    still = await db.get_active_host(uid)
    check("a placeholder does not steal the active machine",
          still is not None and still.id == srv, str(still))
    check("a placeholder is not listed",
          ph not in [h.id for h in await db.list_hosts(uid)])
    tok = await db.issue_agent_token(ph)
    check("the placeholder token still works and activates it",
          await db.resolve_agent_token(tok) == ph)

    handlers_all = (pathlib.Path(__file__).resolve().parents[1]
                    / "bot" / "handlers.py").read_text("utf-8")
    check("the connect menu uses in-message buttons", "add_menu_rich" in handlers_all)
    check("the start screen uses in-message buttons",
          "machines.screen" in handlers_all)
    check("redundant commands are gone",
          'Command("remove")' not in handlers_all
          and 'Command("uninstall")' not in handlers_all
          and 'Command("kill")' not in handlers_all,
          "the machine list buttons took over their role")
    # Every screen must go through show_screen: it sends in-message buttons
    # and falls back to the plain layout only if Telegram refused them.
    import re as _re
    # Four are allowed: two fallback branches inside _replace, the command
    # output card that stays a plain message on purpose, and the one-question
    # rename prompt, which needs a Cancel button and nothing else.
    answers = _re.findall(r"\.answer\([^)]*reply_markup=", handlers_all)
    check("menus and screens do not send the old keyboard directly",
          len(answers) <= 4, str(answers[:5]))
    # HTML tags are not parsed inside rich blocks and show up as literal text.
    # Check that none are fed into machines.para anywhere.
    import re as _re2
    bad = _re2.findall(r"machines\.para\(f?\"[^\"]*<[a-z]", handlers_all)
    check("no HTML tags are fed into rich blocks", not bad, str(bad[:3]))

    main_menu = (pathlib.Path(__file__).resolve().parents[1]
                 / "main.py").read_text("utf-8")
    order = _re2.findall(r'BotCommand\(command="(\w+)"', main_menu)
    check("the menu lists connect first, then the machines",
          order[:2] == ["addhost", "use"], str(order))

    # The product speaks English. Look for Russian where text certainly goes
    # into the chat.
    import re as _re4
    user_calls = _re4.findall(
        r'(?:answer|para|bold|italic|button|link|text=|caption=)\([^)]*'
        r'"[^"\n]*[а-яА-Я]{3,}', handlers_all)
    check("bot texts contain no Russian", not user_calls,
          str(user_calls[:2]))

    # Logs are read by a person too: whoever self-hosts the bot. The repo is
    # public and the README's Self-hosting section invites exactly that.
    pkg = pathlib.Path(__file__).resolve().parents[1]
    russian_logs = []
    for src in pkg.rglob("*.py"):
        if src.name == "test_flow.py":
            continue
        for line in src.read_text("utf-8").splitlines():
            if _re4.search(r"log\.(info|debug|warning|error|exception)\("
                           r"[^)]*[а-яА-Я]{3,}", line):
                russian_logs.append(f"{src.name}: {line.strip()[:60]}")
    check("logs are in English", not russian_logs, str(russian_logs[:2]))

    installer_src = (pathlib.Path(__file__).resolve().parents[1]
                     / "templates" / "install.sh").read_text("utf-8")
    runtime = [ln for ln in installer_src.splitlines()
               if _re4.search(r"[а-яА-Я]{3,}", ln) and not ln.lstrip().startswith("#")]
    check("the server installer is in English", not runtime, str(runtime[:2]))

    # A rich message keeps its buttons inside the blocks, not in reply_markup.
    # Clearing reply_markup there fails and the reply that follows is never
    # sent — which is how server confirmation silently stopped working.
    # Telegram refuses an edit that changes nothing. Tapping the machine that
    # is already active produced exactly that, and treating it as a failure
    # made the bot fall back to the old keyboard in the middle of a session.
    check("an unchanged screen is not treated as a failure",
          'UNCHANGED = "message is not modified"' in handlers_all
          and handlers_all.count("if UNCHANGED in str(exc)") >= 3,
          "every edit path has to recognise it")

    check("no reply_markup edits on rich messages",
          "edit_reply_markup" not in handlers_all,
          "replace the whole message via show_screen instead")

    # A `pre` block inside a rich message has no copy affordance of its own,
    # so the install command had to be retyped by hand.
    # The same addresses live in the site repository. If the two copies ever
    # disagree, somebody's money goes to the wrong place — so the test reads
    # the site's generator and compares, when it is checked out alongside.
    from tterm.bot.handlers import WALLETS
    check("both networks are offered", len(WALLETS) == 2, str(len(WALLETS)))
    check("addresses are not empty",
          all(len(a) > 25 for _, _, a in WALLETS))
    check("the network is named next to each address",
          all("only" in n for _, n, _ in WALLETS),
          "sending from the wrong network loses the money")

    site_gen = (pathlib.Path(__file__).resolve().parents[2].parent
                / "tterm-site" / "build_donate.py")
    if site_gen.exists():
        site_src = site_gen.read_text(encoding="utf-8")
        missing = [a for _, _, a in WALLETS if a not in site_src]
        check("bot and site show the same addresses", not missing, str(missing))
    else:
        print("  · tterm-site рядом не найден, сверка адресов пропущена")

    # Three install screens plus the wallets on /donate: a long string nobody
    # is going to retype needs a button next to it.
    # Three install screens, the donate wallets, and the invite handed over
    # when a username is unknown: anything long enough to mistype gets a button.
    check("long strings come with a copy button",
          handlers_all.count("machines.copy(") == 5,
          "three install screens, donate wallets, share invite")

    from tterm.bot import machines as _m
    cmd = "curl -sSL https://example/s/tok | sudo sh"
    btn = _m.copy("Copy command", cmd).model_dump(exclude_none=True, mode="json")
    # Confirming a server must end with the prompt, exactly like picking one:
    # otherwise there is no telling where you landed and the session stays cold.
    # Confirming a server ends with a prompt, like picking one: otherwise
    # there is no telling where you landed and the session stays cold.
    check("confirming a server shows the prompt",
          "await select_terminal(call.bot, call.message.chat.id, "
          "call.from_user.id, host)" in handlers_all)

    # Button labels sit in one row only while they are short. Long ones wrap
    # and the screen turns into a stack.
    import re as _re5
    labels = _re5.findall(r'machines\.(?:copy|link|back)\(\s*"([^"]+)"', handlers_all)
    long_labels = [x for x in labels if len(x) > 14]
    check("button labels stay short", not long_labels, str(long_labels))

    check("the copy button carries the exact command",
          btn["copy_text"]["text"] == cmd, str(btn))

    check("the command card stayed a plain message",
          "card.text, parse_mode=ParseMode.HTML" in handlers_all,
          "the rich-block version was rejected")
    check("every screen goes through the shared renderer",
          handlers_all.count("show_screen(") >= 7,
          str(handlers_all.count("show_screen(")))
    check("there is no reset button in the list",
          "Reset" not in (pathlib.Path(__file__).resolve().parents[1]
                             / "bot" / "machines.py").read_text("utf-8"),
          "a single Remove button is enough")


async def test_output_thresholds() -> None:
    """Where the line between a message and a file falls."""
    print("\nMessage or file")
    from tterm.core.formatter import MAX_LINES, SAFE_CHARS, State, render

    st = State(cwd="~", user="deploy", host="web-01")

    def mode(text: str) -> str:
        return render(text, 0, 1.0, st, command="pytest").mode

    # Forty lines of test output is about 1.4 KB — a third of what a message
    # holds. Sending that as a file left a stub in the chat and the rest a tap
    # away, which is how the old limit of 30 lines was found to be too eager.
    forty = "\n".join(f"  ✓ check number {i}" for i in range(40))
    check("forty lines still fit in a message", mode(forty) == "text",
          f"{len(forty)} chars")

    check("the line limit is generous but finite", 40 < MAX_LINES < 100,
          f"MAX_LINES={MAX_LINES}")
    check("past it, a file", mode("\n".join(f"line {i}" for i in range(200)))
          == "file")

    # The two limits catch different things: one long `cat` line is short on
    # lines and huge on characters.
    check("a single very long line goes to a file",
          mode("x" * (SAFE_CHARS + 100)) == "file")
    check("and a short one does not", mode("done") == "text")

    # When it does go to a file, the file holds everything. The caption is the
    # abridged part — piecing a full answer together from a stub and a partial
    # file would be worse than either.
    from tterm.core.formatter import MAX_FILE_CHARS

    body = "\n".join(f"line {i}" for i in range(200))
    card = render(body, 0, 1.0, st, command="ls")
    check("the file keeps every line", card.file_body.strip() == body,
          f"{len(card.file_body.splitlines())} of {len(body.splitlines())}")
    check("the caption only shows the tail",
          card.text.count("line ") < 10,
          "the details are in the file")

    long_line = "x" * (SAFE_CHARS + 2000)
    check("a single huge line survives whole",
          render(long_line, 0, 1.0, st, command="cat").file_body.strip()
          == long_line)

    # The one place output is cut is far beyond any real command, and it says
    # so in the first line rather than leaving a silent gap.
    huge = "\n".join(f"x{i}" for i in range(400_000))
    trimmed = render(huge, 0, 1.0, st, command="ls").file_body
    check("an enormous output is trimmed from the top",
          len(trimmed) <= MAX_FILE_CHARS + 100 and trimmed.endswith("x399999\n"),
          "the end is what a command that verbose is judged by")
    check("and the cut is stated, not silent",
          "dropped" in trimmed.splitlines()[0])


async def test_live_output() -> None:
    """Streaming and spotting a command that is waiting for an answer."""
    print("\nLive output")
    from tterm.core.live import (DRAFT_INTERVAL, LiveOutput, is_yes_no,
                                 looks_like_prompt)

    # Questions, taken from what actually stalled us: git asking for a login.
    asks = [
        "Username for 'https://github.com': ",
        "Password for https://x@github.com: ",
        "Enter passphrase for key /root/.ssh/id_ed25519: ",
        "[sudo] password for deploy: ",
        "Do you want to continue? [Y/n] ",
        "Remove packages? [y/N]",
        "Are you sure you want to continue connecting (yes/no)? ",
        "Press ENTER to continue",
    ]
    for line in asks:
        check(f"a question is recognised: {line[:28]!r}",
              looks_like_prompt(line) is not None, line)

    # Ordinary output must not be mistaken for one: a false alarm interrupts
    # a command that was doing fine.
    quiet = [
        "Reading package lists... Done\n",
        "Get:1 http://archive.ubuntu.com noble InRelease",
        "total 48",
        "https://github.com/tterm-net",
        "Cloning into '/opt/x'...",
        "  Username: alice, role: admin",
    ]
    for line in quiet:
        check(f"plain output is left alone: {line[:28]!r}",
              looks_like_prompt(line) is None, line)

    check("a finished line is never a question",
          looks_like_prompt("Password: \n") is None,
          "the program moved on, so it is not waiting")
    check("a yes/no question is offered buttons",
          is_yes_no("Continue? [Y/n]") and not is_yes_no("Password:"))

    # The pause matters: output arrives in pieces, and a line that simply has
    # not been finished yet would otherwise read as a question every time.
    live = LiveOutput()
    live.feed("Username for 'https://github.com': ")
    check("a fresh line is not called a question yet",
          live.pending_prompt() is None)
    check("after the output settles, it is",
          live.pending_prompt(now=live.last_change + 5) is not None)
    live.announced = looks_like_prompt(live.text)
    check("the same question is not announced twice",
          live.pending_prompt(now=live.last_change + 6) is None)

    from tterm.core.config import config as _cfg
    # on_progress runs on a timer, not on new output. Stamping the "changed"
    # mark on every call meant the output never looked quiet, and a command
    # waiting for an answer was never noticed — which is exactly what happened
    # on the first live try.
    repeat = LiveOutput()
    repeat.feed("Password: ")
    mark = repeat.last_change
    for _ in range(5):
        same = "Password: "
        repeat.feed(same[len(repeat.text):] if same.startswith(repeat.text)
                    else same)
    check("repeated identical output does not reset the mark",
          repeat.last_change == mark)
    check("so the question is still spotted",
          repeat.pending_prompt(now=mark + 3) is not None)

    growing = LiveOutput()
    growing.feed("step 1\n")
    growing.feed("step 2\n")
    # Once the question is announced the card stops ticking: a timer counting
    # up beside a repeat of the same question only makes the screen busier.
    frozen = LiveOutput()
    frozen.feed("Password: ")
    frozen.last_draw = 0.0
    check("the card ticks while output is expected", frozen.should_draw())
    frozen.announced = "Password:"
    check("and freezes once the question is announced", not frozen.should_draw())
    frozen.feed("ok\n")
    frozen.last_draw = 0.0
    check("new output un-freezes it", frozen.should_draw())
    check("and clears the announcement", frozen.announced is None,
          "so the next question is announced too")

    check("output that keeps growing is not a question",
          growing.pending_prompt(now=growing.last_change + 5) is None)

    check("the draft is refreshed several times a second",
          DRAFT_INTERVAL < _cfg.STREAM_EDIT_INTERVAL,
          "drafts are made for streaming, plain edits were not")

    handlers = (pathlib.Path(__file__).resolve().parents[1]
                / "bot" / "handlers.py").read_text("utf-8")
    check("output streams into a draft", "send_message_draft" in handlers)
    check("answer buttons go through the shared key handler",
          'callback_data=f"key:{host.id}:{answer}"' in handlers,
          "a private format would silently do nothing")
    check("the draft carries a stop button", "can_stop=True" in handlers)
    check("the announcement is a real newline, not two characters",
          '\\\\n"' not in handlers.split("is waiting for an answer")[1][:40],
          "an over-escaped break shows up as \\n in the chat")

    check("stopping the draft interrupts the command",
          "stopped_message_generation" in handlers
          and 'send_key(b"\\x03")' in handlers,
          "otherwise Stop only hides the draft and the command runs on")
    check("a yes/no answer is sent with a newline",
          '"y": b"y\\n"' in handlers,
          "without it the program waits with the letter already typed")

    check("editing a message remains as a fallback",
          "Draft refused, streaming into a message instead" in handlers,
          "an older client should still see progress")


async def test_terminals() -> None:
    """Several terminals on one machine, the way you keep windows open."""
    print("\nTerminals")

    uid, other = 900001, 900002
    await db.upsert_user(uid, "own", "Own")
    await db.upsert_user(other, "guest", "Guest")
    hid = await db.create_pending_host(uid, name="web-01", ip="10.7.7.7")
    await db.activate_host(hid)

    first = await db.ensure_terminal(uid, hid)
    check("the first terminal is implied, not asked for",
          await db.ensure_terminal(uid, hid) == first)
    check("and carries no number of its own",
          (await db.get_terminal(first))["name"] is None,
          "numbering the only window would be noise")

    second = await db.open_terminal(uid, hid)
    third = await db.open_terminal(uid, hid)
    check("no numbers are stored in the rows",
          [r["name"] for r in await db.terminals_of(uid, hid)] == [None] * 3,
          "a stored number goes wrong as soon as one is closed")

    # Numbering lives in the list, not in the row: closing the middle window
    # renumbers the rest instead of leaving a gap or repeating a number.
    await db.close_terminal(second)
    await db.open_terminal(uid, hid)
    check("closing one in the middle leaves no gap",
          [r["name"] for r in await db.terminals_of(uid, hid)] == [None] * 3,
          "positions are assigned when the list is drawn")

    named = await db.open_terminal(uid, hid, name="logs")
    check("a terminal can be named at birth",
          (await db.get_terminal(named))["name"] == "logs")
    await db.rename_terminal(named, "deploy")
    check("and renamed later",
          (await db.get_terminal(named))["name"] == "deploy")
    await db.rename_terminal(named, None)
    check("and put back to a number",
          (await db.get_terminal(named))["name"] is None)

    check("terminals belong to a person, not to the machine",
          not await db.terminals_of(other, hid),
          "someone the machine is shared with opens their own")

    await db.set_active_terminal(uid, third)
    active = await db.get_active_terminal(uid)
    check("the active terminal is remembered", active and active["id"] == third)

    await db.close_terminal(third)
    check("a closed terminal stops being active",
          await db.get_active_terminal(uid) is None)

    # Someone the machine is shared with opens their own windows, and losing
    # access has to take all of them — records included. Leaving the records
    # open would list them as owning windows on a machine they cannot reach,
    # and hand those windows back if access ever returned.
    from tterm.bot import machines
    from tterm.core.session_manager import sessions

    guest_host = await db.create_pending_host(uid, name="shared-01",
                                              ip="10.7.7.8")
    await db.activate_host(guest_host)
    await db.grant(guest_host, uid, other)
    for _ in range(3):
        await db.open_terminal(other, guest_host)
    await db.set_active_terminal(other,
                                 int((await db.terminals_of(other, guest_host))[1]["id"]))
    check("a recipient opens terminals of their own",
          len(await db.terminals_of(other, guest_host)) == 3)
    check("the owner does not see them",
          not await db.terminals_of(uid, guest_host))

    await db.revoke(guest_host, other)
    await sessions.drop_host(other, guest_host, forget=True)
    check("revoking takes every terminal with it",
          not await db.terminals_of(other, guest_host))
    check("and clears the active one",
          await db.get_active_terminal(other) is None)

    # Expiry must behave exactly like a manual revoke. It used to call drop()
    # with the wrong arguments and quietly closed nothing at all.
    await db.grant(guest_host, uid, other, ttl_seconds=-1)
    for _ in range(2):
        await db.open_terminal(other, guest_host)
    for row in await db.expire_shares():
        await sessions.drop_host(int(row["grantee_id"]), int(row["host_id"]),
                                 forget=True)
    check("an expired share closes the terminals too",
          not await db.terminals_of(other, guest_host),
          "hiding the machine while a shell stays open is worse than nothing")

    await db.grant(guest_host, uid, other)
    await db.ensure_terminal(other, guest_host)
    check("access granted again starts from a clean window",
          len(await db.terminals_of(other, guest_host)) == 1)

    # Sharing is per machine, not per window: whichever line is selected, the
    # owner sees the same people, and the recipient sees no management at all.
    own_a = await db.ensure_terminal(uid, guest_host)
    own_b = await db.open_terminal(uid, guest_host)
    seen = []
    for picked in (own_a, own_b):
        drawn = await machines.build([await db.get_host(guest_host)],
                                     await db.get_host(guest_host), uid,
                                     {guest_host: True}, picked)
        rows = [b["text"]
                for blk in drawn.model_dump(exclude_none=True, mode="json")["blocks"]
                if blk["type"] == "buttons" for b in blk["buttons"]]
        seen.append([r for r in rows if r.startswith("Access")])
    check("every line offers the same sharing", seen[0] == seen[1] == ["Access (1)"],
          str(seen))

    guest_view = await machines.build([await db.get_host(guest_host)],
                                      await db.get_host(guest_host), other,
                                      {guest_host: True},
                                      int((await db.terminals_of(other, guest_host))[0]["id"]))
    guest_rows = [b["text"]
                  for blk in guest_view.model_dump(exclude_none=True, mode="json")["blocks"]
                  if blk["type"] == "buttons" for b in blk["buttons"]]
    check("a recipient gets no management buttons",
          not any(r.startswith(("Access", "Remove")) for r in guest_rows),
          str(guest_rows))
    check("but can still open windows of their own", "+ Terminal" in guest_rows)

    # Every one of their lines goes at once, not just the selected one.
    for _ in range(2):
        await db.open_terminal(other, guest_host)
    await db.revoke(guest_host, other)
    await sessions.drop_host(other, guest_host, forget=True)
    gone = await machines.build(await db.list_hosts(other), None, other, {}, None)
    check("all of a recipient's lines disappear together",
          "web-01" not in gone.model_dump_json() and
          "shared-01" not in gone.model_dump_json())

    manager_src = (pathlib.Path(__file__).resolve().parents[1]
                   / "core" / "session_manager.py").read_text("utf-8")
    check("expiry drops the terminals, not a stale key",
          "drop_host(int(row[\"grantee_id\"])" in manager_src)

    handlers = (pathlib.Path(__file__).resolve().parents[1]
                / "bot" / "handlers.py").read_text("utf-8")
    check("there is a way to open another", "newterm:" in handlers)
    check("and to switch between them", '"term:' in handlers)

    # Each terminal is a line of its own, the same shape as a machine: picking
    # one is the same gesture either way.
    import json as _tj

    view_host = await db.get_host(hid)
    extra = await db.open_terminal(uid, hid)
    drawn = _tj.dumps((await machines.build(
        [view_host], view_host, uid, {hid: True}, extra
    )).model_dump(exclude_none=True, mode="json"), ensure_ascii=False)
    # The list and the output card have to agree on the name. Seeing
    # `web-01 (2)` in the list and a bare `web-01` above the answer leaves no
    # way to tell which window replied.
    named_term = await db.open_terminal(uid, hid, name="логи")
    check("the card header names the terminal",
          await machines.label_for(view_host, uid, named_term)
          == f"{view_host.name} (логи)")
    check("the first terminal keeps the plain name",
          await machines.label_for(view_host, uid, first) == view_host.name)
    check("an unnamed one gets its position",
          (await machines.label_for(view_host, uid, extra)).endswith(")"))
    await db.close_terminal(named_term)

    handlers_card = (pathlib.Path(__file__).resolve().parents[1]
                     / "bot" / "handlers.py").read_text("utf-8")
    check("both the running card and the finished one use it",
          handlers_card.count("State(host=label") == 1
          and handlers_card.count("block.state.host = label") == 2,
          "a header built twice will drift apart")

    check("the first line carries the plain machine name",
          '"text": "web-01"' in drawn)
    check("the others say which one they are",
          '"web-01 (' in drawn,
          "a number in brackets is what tells them apart")
    await db.close_terminal(extra)
    check("and to close one", "closeterm:" in handlers)

    # One button in that slot, and the word matches what it will do: closing
    # a spare window and taking the machine off the list are worlds apart.
    async def slot(host_obj, viewer, term):
        drawn = await machines.build([host_obj], host_obj, viewer,
                                     {host_obj.id: True}, term)
        rows = [b["text"]
                for blk in drawn.model_dump(exclude_none=True, mode="json")["blocks"]
                if blk["type"] == "buttons" for b in blk["buttons"]]
        return [r for r in rows if r in ("Close", "Remove")]

    solo = await db.get_host(hid)
    only = int((await db.terminals_of(uid, hid))[0]["id"])
    while len(await db.terminals_of(uid, hid)) > 1:
        await db.close_terminal(int((await db.terminals_of(uid, hid))[-1]["id"]))
    check("the last window offers Remove", await slot(solo, uid, only) == ["Remove"])
    spare = await db.open_terminal(uid, hid)
    check("a spare window offers Close", await slot(solo, uid, spare) == ["Close"])
    check("never both at once",
          len(await slot(solo, uid, spare)) == 1)
    await db.close_terminal(spare)

    # Selecting and showing the prompt belong together: kept apart, picking a
    # machine set the active host but left the active terminal alone, and the
    # prompt then described one window while commands went to another.
    # Every way of landing somewhere has to end with a prompt — including the
    # ones nobody asked for: closing a window drops you on a neighbour, and
    # opening the list shows a machine already picked out.
    check("opening the list shows where you are",
          "async def show_machines_and_prompt" in handlers
          and handlers.count("await show_machines_and_prompt(") >= 2,
          "/use and /start both land on a selection")
    check("closing a window announces the one you land on",
          "await select_terminal(call.bot, call.message.chat.id, "
          "call.from_user.id,\n                          host, "
          "int(others[0][\"id\"]))" in handlers)

    check("choosing a terminal always shows its prompt",
          "async def select_terminal" in handlers
          and handlers.count("await select_terminal(") >= 4,
          "every path that selects has to go through it")
    check("commands go to the selected terminal",
          "terminal_id=terminal_id" in handlers)
    check("a terminal can be renamed from the list", "renameterm:" in handlers)
    check("the rename question expires",
          "RENAME_WINDOW" in handlers,
          "otherwise a forgotten prompt swallows a command later")
    check("renaming can be called off", "renamecancel" in handlers)
    check("a rename ends with the prompt under the new name",
          "await select_terminal(message.bot, message.chat.id, user_id, host,"
          in handlers,
          "the prompt carries the name, so it is the confirmation")

    # A session is keyed by terminal, not by machine — otherwise two windows
    # would share one shell and a `cd` in either would move both.
    manager = (pathlib.Path(__file__).resolve().parents[1]
               / "core" / "session_manager.py").read_text("utf-8")
    check("one live session per terminal", "key = terminal_id" in manager)


async def test_short_paths() -> None:
    """A deep path is squeezed so the prompt stays on one line."""
    print("\nLong paths")
    from tterm.core.formatter import State

    short = State(cwd="/opt/tterm-src", user="tterm").prompt()
    check("a short path is left alone", "/opt/tterm-src" in short, short)
    check("and so is the home directory",
          State(cwd="~", user="tterm").prompt() == "tterm ~ ❯")

    deep = State(cwd="/opt/tterm-src/tterm/core/templates", user="tterm").prompt()
    check("a deep one is squeezed", "…" in deep, deep)
    check("the last part is never touched", deep.endswith("templates ❯"), deep)
    check("the root of the path stays", "/opt/" in deep, deep)
    check("and the line fits", len(deep) <= State.PROMPT_BUDGET, f"{len(deep)}")

    # The budget covers the whole line: a virtualenv name takes room too, and
    # measuring only the path would let the prompt wrap anyway.
    with_venv = State(cwd="/opt/tterm-src/tterm/core/templates", user="tterm",
                      venv="venv").prompt()
    check("a virtualenv is counted in", "…" in with_venv, with_venv)

    check("a path with nothing in the middle is kept whole",
          "…" not in State(cwd="/var/log", user="x").prompt())


async def test_condensed_caption() -> None:
    """A long output gets a summary in the caption, not its last six lines."""
    print("\nNoisy commands")
    from tterm.core.formatter import State, condense, render

    apt = "\n".join(
        [f"Get:{i} http://archive.ubuntu.com noble pkg-{i} [{i * 12} kB]"
         for i in range(1, 40)]
        + ["Fetched 12.4 MB in 3s (4,100 kB/s)"]
        + [f"Unpacking pkg-{i} (1.{i}) over (1.{i - 1}) ..." for i in range(1, 30)]
        + [f"Setting up pkg-{i} (1.{i}) ..." for i in range(1, 30)]
        + ["Processing triggers for man-db (2.12.0-4build2) ...",
           "39 upgraded, 0 newly installed, 0 to remove and 1 not upgraded."])

    short = condense(apt)
    check("a hundred lines of apt become a handful",
          len(short.split("\n")) < 12, f"{len(short.split(chr(10)))} lines")
    check("runs of similar lines are counted", "… 39 lines" in short, short)
    check("the result survives",
          "39 upgraded, 0 newly installed" in short,
          "the line people actually read")

    # Errors are never part of a run of routine chatter and must come through
    # word for word.
    noisy_error = "\n".join(
        [f"Get:{i} http://archive.ubuntu.com pkg-{i}" for i in range(1, 9)]
        + ["E: Unable to locate package nonexistent"])
    check("an error among the noise is kept in full",
          "E: Unable to locate package nonexistent" in condense(noisy_error))

    check("a short output is left alone",
          condense("one\ntwo\nthree") == "one\ntwo\nthree")

    # The point is the caption, not the output: the file still holds every
    # line, so nothing is hidden — only the summary above it changes.
    st = State(cwd="~", user="deploy", host="web-01")
    card = render(apt, 0, 41.2, st, command="apt upgrade -y")
    check("the file keeps all of it",
          card.file_body.strip("\n") == apt,
          "the summary replaces the caption, never the output")
    check("the caption summarises instead of trailing off",
          "… 39 lines" in card.text and "39 upgraded" in card.text)

    # The caption sits in a narrow column, so lines are cut — but the count
    # has to survive the cut, and the conclusion must not be cut at all.
    from tterm.core.formatter import CAPTION_LINE_CHARS
    narrow = condense(apt, keep_last=3, budget=12, width=CAPTION_LINE_CHARS)
    for line in narrow.split("\n"):
        if "…" in line and "lines" in line:
            check("a collapsed line keeps its count",
                  line.rstrip().endswith("lines"), line)
            break
    check("the last line is never cut",
          "39 upgraded, 0 newly installed, 0 to remove and 1 not upgraded."
          in narrow,
          "a wrapped conclusion beats a truncated one")


async def test_dangerous_commands() -> None:
    """Commands worth one question before they run."""
    print("\nDestructive commands")
    from tterm.core.danger import hits_everything, looks_destructive

    # Things that leave nothing to fix afterwards.
    for cmd in ("rm -rf /var/log/old", "rm -fr build",
                "sudo rm -rf node_modules", "mkfs.ext4 /dev/sdb1",
                "dd if=/dev/zero of=/dev/sda bs=1M",
                "psql -c 'DROP DATABASE prod'", "shutdown -h now", "reboot",
                "systemctl stop sshd", "userdel deploy", "ufw deny 22"):
        check(f"asks about: {cmd[:34]}", looks_destructive(cmd) is not None, cmd)

    # Everyday work must go through untouched. A bot that asks about
    # everything teaches people to confirm without reading, which is worse
    # than not asking at all.
    for cmd in ("rm file.txt", "ls -la", "git reset --hard", "cd /tmp && ls",
                "docker ps", "grep -r pattern .", "systemctl restart tterm",
                "cat /etc/passwd", "rmdir empty", "df -h", "rm -i old.log"):
        check(f"stays quiet on: {cmd[:34]}", looks_destructive(cmd) is None, cmd)

    check("a delete aimed at everything is called out",
          hits_everything("rm -rf /") and hits_everything("rm -rf ~")
          and hits_everything("rm -rf $HOME"))
    check("but an ordinary path is not",
          not hits_everything("rm -rf /var/log/old"))

    handlers = (pathlib.Path(__file__).resolve().parents[1]
                / "bot" / "handlers.py").read_text("utf-8")
    check("the command is held until confirmed", "_PENDING[user_id]" in handlers)
    check("the confirmation expires", "CONFIRM_WINDOW" in handlers,
          "a forgotten question must not fire an hour later")
    check("confirming does not ask again", "_confirmed.pop(user_id" in handlers)
    check("the command text is kept out of the button",
          'callback_data="runyes"' in handlers,
          "callback data is capped at 64 bytes, commands are not")


async def test_host_key_pinning() -> None:
    """The server has to be the one we registered, not just something at that
    address."""
    print("\nHost key")
    import asyncssh
    from tterm.core.ssh_session import ShellSession

    uid = 700700
    await db.upsert_user(uid, "pin", "Pin")
    real = asyncssh.generate_private_key("ssh-ed25519")
    pub = real.export_public_key().decode().strip()

    hid = await db.create_pending_host(uid, name="pinned", ip="10.20.30.40",
                                       ssh_port=22, host_pubkey=pub)
    await db.activate_host(hid)
    host = await db.get_host(hid)
    check("the key survives the round trip through the database",
          host.host_pubkey == pub)

    session = ShellSession(host)
    known = session._pinned_key()
    check("a pinned key becomes a known-hosts entry", known is not None)
    check("handed to asyncssh as bytes", isinstance(known, bytes),
          "the documented form; a parsed object is version-dependent")
    # On the default port asyncssh looks the entry up with no port at all,
    # so `[addr]:22` is never found — which reads as "wrong key" and locks the
    # machine out. This is the OpenSSH convention too: brackets are for other
    # ports only. Cost one production server its access before it was noticed.
    import asyncssh as _assh
    check("on port 22 the entry carries no port",
          known and known.startswith(b"10.20.30.40 "), str(known))
    found = _assh.import_known_hosts(known.decode()).match(
        "10.20.30.40", "10.20.30.40", None)[0]
    check("and is found the way asyncssh looks for it", len(found) > 0)

    odd = await db.create_pending_host(uid, name="odd-port", ip="10.20.30.43",
                                       ssh_port=2222, host_pubkey=pub)
    await db.activate_host(odd)
    odd_entry = ShellSession(await db.get_host(odd))._pinned_key()
    check("on any other port it does carry one",
          odd_entry.startswith(b"[10.20.30.43]:2222 "), str(odd_entry))
    check("and is found with that port",
          len(_assh.import_known_hosts(odd_entry.decode()).match(
              "10.20.30.43", "10.20.30.43", 2222)[0]) > 0)

    # Machines registered before this check existed have no key. Refusing them
    # would lock people out of servers that work; the key is recorded the next
    # time they re-register.
    bare = await db.create_pending_host(uid, name="legacy", ip="10.20.30.41")
    await db.activate_host(bare)
    check("a machine without a key still connects",
          ShellSession(await db.get_host(bare))._pinned_key() is None,
          "otherwise an upgrade locks people out of working servers")

    # A broken record is ours to fix, and must not stand between someone and
    # their server.
    broken = await db.create_pending_host(uid, name="broken", ip="10.20.30.42",
                                          host_pubkey="not-a-key at all")
    await db.activate_host(broken)
    import logging as _lg
    _lg.getLogger("tterm.ssh").setLevel(_lg.CRITICAL)   # ожидаемая жалоба
    check("an unreadable record is ignored, not fatal",
          ShellSession(await db.get_host(broken))._pinned_key() is None,
          "asyncssh turns nonsense into an entry with no keys, which rejects "
          "everything — that would lock the owner out")
    _lg.getLogger("tterm.ssh").setLevel(_lg.WARNING)

    check("the key itself is validated first",
          "import_public_key" in (pathlib.Path(__file__).resolve().parents[1]
                                  / "core" / "ssh_session.py").read_text("utf-8"))

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "core" / "ssh_session.py").read_text("utf-8")
    check("the connection actually checks it",
          "known_hosts=self._pinned_key()" in src)
    check("nothing accepts every key any more",
          "known_hosts=None," not in src,
          "that was the hole: anything answering on the address got our cert")


async def test_shutdown() -> None:
    """Shutdown must not hang the process.

    Every step can stall: SSH waiting on a dead server, uvicorn on connections
    closing, Telegram on a long poll. This checks that a stalled step does not
    block the rest and that shutdown finishes within seconds.
    """
    print("\nShutdown")
    import signal as _signal

    from tterm.main import _shutdown

    main_src = (pathlib.Path(__file__).resolve().parents[1] / "main.py").read_text("utf-8")
    check("signals are trapped, not caught as an exception",
          "add_signal_handler" in main_src)
    check("a second signal exits immediately", "os._exit(130)" in main_src)
    check("signal handlers are installed before any network call",
          main_src.index("add_signal_handler") < main_src.index("set_my_commands"),
          "otherwise Ctrl+C at startup arrives as KeyboardInterrupt")
    check("an unreachable Telegram does not break startup",
          "Could not set the command menu" in main_src)

    class FakeHttp:
        should_exit = False

    class FakeDp:
        async def stop_polling(self):
            await asyncio.sleep(30)          # stalls on purpose

    class FakeSession:
        closed = False

        async def close(self):
            FakeSession.closed = True

    class FakeBot:
        session = FakeSession()

    async def hanging():
        await asyncio.sleep(30)

    tasks = [asyncio.create_task(hanging())]
    started = time.monotonic()
    await _shutdown(FakeHttp(), FakeDp(), FakeBot(), tasks)
    elapsed = time.monotonic() - started

    check("stuck steps do not block shutdown", elapsed < 10,
          f"took {elapsed:.1f}s")
    check("steps after a stuck one still run", FakeSession.closed)
    check("hung tasks are cancelled", all(t.cancelled() or t.done() for t in tasks))
    check("SIGTERM is handled too", "SIGTERM" in main_src)
    check("the database closes on shutdown", db._conn is None)
    _ = _signal.SIGINT  # used in main.py

    # _shutdown closed the real database; later checks still need it.
    await db.connect()


async def test_resilience() -> None:
    """Resilience to Telegram quirks, without touching Telegram."""
    print("\nResilience")
    from aiogram.exceptions import TelegramBadRequest

    from tterm.bot.resilience import retry_without_thread

    class FakeMethod:
        def __init__(self, thread): self.message_thread_id = thread

    tries: list = []

    async def handler(bot, method):
        tries.append(method.message_thread_id)
        if method.message_thread_id is not None:
            raise TelegramBadRequest(method=method,
                                     message="Bad Request: message thread not found")
        return "ok"

    res = await retry_without_thread(handler, None, FakeMethod(42))
    check("a vanished topic retries into the main chat", res == "ok" and tries == [42, None],
          f"attempts={tries}")

    tries.clear()
    res = await retry_without_thread(handler, None, FakeMethod(None))
    check("no extra retry when there is no topic", tries == [None], f"attempts={tries}")

    tries.clear()

    async def other(bot, method):
        tries.append(1)
        raise TelegramBadRequest(method=method, message="Bad Request: chat not found")

    raised = False
    try:
        await retry_without_thread(other, None, FakeMethod(42))
    except TelegramBadRequest:
        raised = True
    check("an unrelated error propagates", raised and len(tries) == 1)

    main_src = (pathlib.Path(__file__).resolve().parents[1] / "main.py").read_text("utf-8")
    check("the pending update queue is dropped at startup",
          "drop_pending_updates=True" in main_src,
          "otherwise yesterday's commands run on the server at startup")


async def main() -> int:
    print("=" * 58)
    print("  tterm — end-to-end tests")
    print("=" * 58)

    host_id, user_id = await test_onboarding()
    try:
        with _Watchdog(120, "block parsing on a PTY"):
            test_block_framing()
    except TimeoutError as exc:
        check(f"the parsing block finished ({exc})", False)
    await test_recording(host_id, user_id)
    test_certificates()
    await test_agent()
    await test_sharing()
    await test_machines_view()
    await test_terminals()
    await test_output_thresholds()
    await test_live_output()
    await test_short_paths()
    await test_condensed_caption()
    await test_dangerous_commands()
    await test_host_key_pinning()
    await test_shutdown()
    await test_resilience()
    test_rendering()
    await test_buttons()

    await db.close()
    shutil.rmtree(TMP, ignore_errors=True)

    print("\n" + "=" * 58)
    print(f"  Passed: {_passed}   Failed: {_failed}")
    print("=" * 58)
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
