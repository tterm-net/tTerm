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
    check("the branch reaches the prompt", state.branch in state.prompt())

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
    from tterm.core.formatter import CAPTION_LINE_CHARS
    wide = "\n".join("z" * 200 for _ in range(50))
    wide_card = render(wide, 0, 0.1, st, command="cat wide")
    longest = max(len(x) for x in wide_card.text.split("\n"))
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
    check("branch icon in the prompt", "🌿" in with_icons, with_icons)
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
    check("the asterisk is visible in the prompt", "main*" in dirty.prompt(), dirty.prompt())
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
    check("revocation cuts the session", "sessions.drop(grantee" in handlers_src)
    check("a recipient cannot manage someone else's machine",
          "_not_owner" in handlers_src,
          "otherwise they could uninstall the agent or remove the machine")

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
    # Three are allowed: the two fallback branches inside _replace — one per
    # exception type — and the command output card, which stays a plain
    # message on purpose.
    answers = _re.findall(r"\.answer\([^)]*reply_markup=", handlers_all)
    check("menus and screens do not send the old keyboard directly",
          len(answers) <= 3, str(answers[:4]))
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
    check("install commands offer a copy button",
          handlers_all.count("machines.copy(") == 3,
          "one per install screen: server, computer, WSL2")

    from tterm.bot import machines as _m
    cmd = "curl -sSL https://example/s/tok | sudo sh"
    btn = _m.copy("Copy command", cmd).model_dump(exclude_none=True, mode="json")
    # Confirming a server must end with the prompt, exactly like picking one:
    # otherwise there is no telling where you landed and the session stays cold.
    check("confirming a server shows the prompt",
          handlers_all.count("send_prompt(") >= 3,
          "one definition plus a call from cb_use and cb_confirm")

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
