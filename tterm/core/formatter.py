"""
tterm/core/formatter.py

Lays out the bot's replies. Three jobs:

  1. clean the raw shell output (ANSI, progress bars, control characters);
  2. parse the state marker printed by PROMPT_COMMAND;
  3. build the reply card, as text or as a file when the output is too big.

The card mirrors a terminal, adjusted for a chat: the user already sees their
command in their own message, so the bot does not repeat it.

    🟢 0 · 0.4s           exit status
    <command output>      monospace block, copies as a whole
    ~/app (venv) ❯        the prompt as it became AFTER the command

A directory change, an activated venv, switching to root or another branch are
all visible in the prompt itself — the bot writes no extra hints, just like
a real shell.
"""

from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass, field

# ─────────────────────────────────────────────────────────────────────────────
# APPEARANCE
# ─────────────────────────────────────────────────────────────────────────────

PROMPT_STYLE = 2      # 1 with host name, 2 without it, 3 classic bash

#: Icons in the prompt, like a status bar. Text inside <pre> cannot be
#: coloured in Telegram, so icons would take the role of colour.
#: Only base-set emoji: glyphs such as ⎇ and ⑂ render as an empty box on some
#: devices.
PROMPT_ICONS = False   # tried and rejected: too noisy next to the status mark

#: The machine name above the card. With several machines and a single chat
#: there is otherwise no way to tell whose output this is.
SHOW_HOST_HEADER = True

#: The user name in the prompt: who the commands actually run as.
SHOW_USER = True
#: There is no "server" emoji in the standard set. The globe highlights what
#: makes a server different — a permanent address on the network — and does
#: not blur into the monitor glyph.
SERVER_ICON = "🌐"
#: Computers and laptops.
PC_ICON = "🖥"
#: Default for the card header; overridden by the machine kind.
HOST_ICON = SERVER_ICON
DIR_ICON = "📁"
BRANCH_ICON = "🌿"
VENV_ICON = "🐍"
SEP = " · "           # separates sections of the prompt

OK_MARK = "🟢"
ERR_MARK = "🔴"
RUN_MARK = "⏳"
SIGN = "❯"
ROOT_SIGN = "#"

# ─────────────────────────────────────────────────────────────────────────────
# THRESHOLDS: text or file
#
# Hard Telegram limits: 4096 characters per message, 1024 per file caption.
# MAX_LINES is not a technical limit but a readability one: that many lines
# are still worth scrolling on a phone. Either threshold can fire, and they
# catch different cases: `apt install` hits the line count, a single long
# `cat` line hits the character count.
#
# It was 30, which turned out too eager: forty lines of test output — under
# 1.5 KB, a third of what a message holds — went out as a file, leaving a
# stub in the chat and the rest a tap away. A file earns its place at
# hundreds of lines, not at forty.
# ─────────────────────────────────────────────────────────────────────────────

SAFE_CHARS = 3200         # headroom under 4096 for status, prompt and markup
MAX_LINES = 60
# Telegram lays out a document caption in a column as wide as the file card,
# not the full message width. On desktop long lines wrap into three and the
# tail becomes unreadable. So the caption keeps few and short lines: the
# details are in the file anyway, the caption only shows how it ended.
TAIL_LINES = 6            # last lines kept in the file caption
CAPTION_CHARS = 400       # headroom under the 1024 limit
# The caption sits in a narrow column beside the file card — measured on the
# real thing at about 33 characters, well under a message. At 72 a single line
# wrapped into three and a six-line summary became a wall.
CAPTION_LINE_CHARS = 33

# The last lines get more room before they are cut: a conclusion like
# "39 upgraded, 0 newly installed, 0 to remove" runs to about sixty characters
# and is worth two wrapped lines. Beyond that it is not a conclusion but more
# of the same, and cutting it keeps the summary a summary.
CAPTION_TAIL_CHARS = 66
MAX_FILE_CHARS = 2_000_000  # beyond this the file itself is trimmed from the top

# Streaming: while editing one message we show the tail, not everything
STREAM_TAIL_LINES = 18

# ─────────────────────────────────────────────────────────────────────────────
# STATE MARKER
#
# Printed by the shell from PROMPT_COMMAND after every command.
#
# The separators are 0x1E (RS) and 0x1F (US). Do NOT switch to \001/\002:
# bash reserves those for marking non-printing regions of the prompt, which
# stops $? and ${PWD} from expanding — seen on bash 3.2 in macOS.
#
# Fields: nonce, exit, cwd, user, euid, host, venv, branch.
# The parser deliberately tolerates a different field count so that an older
# server keeps working with a newer bot, just without the newer fields.
# ─────────────────────────────────────────────────────────────────────────────

RS = "\x1e"
US = "\x1f"

# The anchor is the nonce, not the first RS encountered. A stray 0x1E byte in
# the output — a binary file, dd, curl without -s — would otherwise shift the
# match, the nonce would not line up and the marker would never be found. The
# stray byte stays in the buffer, so every following command would hang until
# its timeout.
_MARKER_CACHE: dict[str, re.Pattern[str]] = {}


def _marker_re(nonce: str) -> re.Pattern[str]:
    rx = _MARKER_CACHE.get(nonce)
    if rx is None:
        rx = re.compile(
            RS + re.escape(nonce) + RS + r"(?P<body>[^" + US + r"]*)" + US
        )
        _MARKER_CACHE[nonce] = rx
    return rx

#: The bootstrap installed into the shell.
#:
#: The branch is read straight from .git/HEAD, with no git process per prompt.
#: The dirty-tree marker (an asterisk) does cost one git call per command.
#: In a real terminal that would be expensive because the prompt redraws on
#: every Enter; here it redraws once per message, and a Telegram round trip
#: already costs 200-500 ms.
#:
#: The git call is assigned to a variable and NOT nested as
#: `[ -n "$(git ... "$g" ...)" ]`. Double quotes inside $( ) that itself sits
#: inside double quotes are parsed differently by bash 3.2, the default in
#: macOS, than by bash 4+: the function breaks silently, the marker stops
#: being printed and every command hangs until its timeout.
#: Do not fold it back into one line.
#:
#: The tilde in the replacement is escaped: `${PWD/#$HOME/\~}`. Without the
#: backslash bash expands `~` to the home directory before the substitution,
#: the replacement collapses into itself and the prompt keeps the full path.
#:
#: --no-optional-locks is required: without it git status may write to
#: .git/index and fight for the lock with whatever the user is running.
#: Disable on a server with: __TT_GIT_DIRTY=0
BOOTSTRAP = r"""
__TT_USER="${USER:-${LOGNAME:-}}"
[ -n "$__TT_USER" ] || __TT_USER="$(id -un 2>/dev/null)"
__TT_HOST="${HOSTNAME:-}"
[ -n "$__TT_HOST" ] || __TT_HOST="$(hostname 2>/dev/null)"
__TT_HOST="${__TT_HOST%%.*}"
: "${__TT_GIT_DIRTY:=1}"
__tt_prompt() {
  local e=$?
  local b= d="$PWD" h= g=
  while [ -n "$d" ] && [ "$d" != "/" ]; do
    if [ -r "$d/.git/HEAD" ]; then read -r h < "$d/.git/HEAD"; b="${h##*/}"; g="$d"; break; fi
    d="${d%/*}"
  done
  if [ -n "$b" ] && [ "$__TT_GIT_DIRTY" = 1 ]; then
    local st=
    st=$(cd "$g" 2>/dev/null && git --no-optional-locks status --porcelain -uno 2>/dev/null)
    [ -n "$st" ] && b="$b*"
  fi
  printf '\x1e%s\x1e%s\x1e%s\x1e%s\x1e%s\x1e%s\x1e%s\x1e%s\x1e\x1f' \
    "$__TT_NONCE" "$e" "${PWD/#$HOME/\~}" "$__TT_USER" "$EUID" "$__TT_HOST" \
    "${VIRTUAL_ENV##*/}" "$b"
}
PROMPT_COMMAND=__tt_prompt
PAGER=cat
SYSTEMD_PAGER=
GIT_PAGER=cat
DEBIAN_FRONTEND=noninteractive
export PAGER SYSTEMD_PAGER GIT_PAGER DEBIAN_FRONTEND
"""


@dataclass
class State:
    """Session state after a command has run."""

    cwd: str = "~"
    user: str = ""
    euid: int = 1000
    host: str = ""
    venv: str = ""
    branch: str = ""
    #: The machine icon in the card header, different for servers and computers.
    icon: str = HOST_ICON

    @property
    def is_root(self) -> bool:
        return self.euid == 0

    #: Prompts longer than this get their path shortened. Measured on the whole
    #: line, not on the path: a short path next to a long user name still adds
    #: up to something that wraps on a phone.
    PROMPT_BUDGET = 40

    #: Path components kept at the end. The last one answers "where am I" and
    #: is never touched; the one before it usually says which project.
    KEEP_TAIL = 2

    @staticmethod
    def short_path(path: str, room: int) -> str:
        """Squeezes the middle out of a deep path.

        `/opt/tterm-src/tterm/core/templates` becomes `/opt/…/core/templates`.
        The same thing fish and starship do, so it reads as shortening rather
        than as a mangled path.
        """
        if len(path) <= room:
            return path

        head, sep, rest = path.partition("/")
        parts = [p for p in rest.split("/") if p] if sep else path.split("/")
        if len(parts) <= State.KEEP_TAIL + 1:
            return path                      # nothing in the middle to drop

        first, tail = parts[0], parts[-State.KEEP_TAIL:]
        prefix = f"{head}/" if sep else ""
        return prefix + "/".join([first, "…", *tail])

    def _cwd_for(self, other_parts: int) -> str:
        """The directory, shortened only if the whole line would run long."""
        room = State.PROMPT_BUDGET - other_parts
        return self.short_path(self.cwd, max(room, 12))

    def branch_line(self) -> str:
        """The git branch, on its own line above the prompt.

        Kept out of the prompt itself: the prompt answers "where am I and as
        whom", and a branch buried at the end of it went unread. On its own
        line it is the first thing seen.

        Empty outside a repository — most directories are not one, and a blank
        line kept for the sake of alignment reads worse than no line at all.
        The virtualenv stays in the prompt: it describes how the command runs,
        not where it runs.
        """
        return f"{BRANCH_ICON} {self.branch}" if self.branch else ""

    def prompt(self, style: int | None = None, icons: bool | None = None) -> str:
        style = PROMPT_STYLE if style is None else style
        icons = PROMPT_ICONS if icons is None else icons

        if style == 3:
            # Classic bash: no icons here, the whole point is familiarity.
            tail = f" ({self.venv})" if self.venv else ""
            return (f"{self.user or 'user'}@{self.host or 'srv'}:{self.cwd}{tail}"
                    f"{'#' if self.is_root else '$'}")

        sign = ROOT_SIGN if self.is_root else SIGN
        if not icons:
            parts = [self.host] if style == 1 and self.host else []
            # The user name matters because of sudo: the directory alone does
            # not say who the command runs as.
            if SHOW_USER and self.user:
                parts.append(self.user)
            # Everything else is measured first: the directory gets whatever
            # room is left before the line starts wrapping on a phone.
            around = len(" ".join(parts)) + len(sign) + 2
            if self.venv:
                around += len(self.venv) + 3
            parts.append(self._cwd_for(around))
            if self.venv:
                parts.append(f"({self.venv})")
            parts.append(sign)
            return " ".join(p for p in parts if p)

        parts = []
        if style == 1 and self.host:
            parts.append(f"🖥 {self.host}")
        parts.append(f"{DIR_ICON} {self._cwd_for(len(' '.join(parts)) + 6)}")
        if self.venv:
            parts.append(f"{VENV_ICON} {self.venv}")
        return SEP.join(parts) + f" {sign}"


@dataclass
class Rendered:
    """What to send. mode: 'text' for sendMessage, 'file' for sendDocument."""

    mode: str
    text: str                       # message text, or the file caption
    file_name: str = ""
    file_body: str = ""
    lines: int = 0
    chars: int = 0
    meta: dict = field(default_factory=dict)


def parse_marker(chunk: str, nonce: str) -> tuple[str, State, int] | None:
    """Cuts the marker out of the stream.

    Returns (output without the marker, state, exit code), or None if the
    marker has not arrived in full yet.
    """
    m = _marker_re(nonce).search(chunk)
    if not m:
        return None
    # The nonce was consumed by the anchor, so the fields are shifted:
    # fields[0] is the exit code.
    fields = m.group("body").split(RS)

    def at(i: int, default: str = "") -> str:
        j = i - 1
        return fields[j] if len(fields) > j and fields[j] else default

    try:
        code = int(at(1, "0"))
    except ValueError:
        code = 0
    try:
        euid = int(at(4, "1000"))
    except ValueError:
        euid = 1000

    state = State(
        cwd=at(2, "~"),
        user=at(3),
        euid=euid,
        host=at(5),
        venv=at(6),
        branch=at(7),
    )
    return chunk[: m.start()] + chunk[m.end():], state, code


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT CLEANUP
# ─────────────────────────────────────────────────────────────────────────────

_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ESC_MISC = re.compile(r"\x1b[()][A-Za-z0-9]|\x1b[=>78MDEHc]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BLANKS = re.compile(r"\n{3,}")


def clean_output(raw: str) -> str:
    """Raw PTY stream to readable text.

    Collapses progress bars: a line redrawn with \\r is shown only in its final
    state, otherwise a single `pip install` yields a hundred nearly identical
    lines.
    """
    text = _OSC.sub("", raw)
    text = _CSI.sub("", text)
    text = _ESC_MISC.sub("", text)
    text = text.replace("\r\n", "\n")

    out = []
    for line in text.split("\n"):
        if "\r" in line:
            line = line.split("\r")[-1]
        out.append(line.rstrip())
    text = "\n".join(out)

    text = _CTRL.sub("", text)
    text = _BLANKS.sub("\n\n", text)
    return text.strip("\n")


#: Lines are grouped by their first word with the numbers taken out, so
#: `Get:1 http://a` and `Get:2 http://b` land together as `Get:#`, and every
#: `Unpacking …` line does too. Anything past the first word varies too much
#: to group on — that was the first attempt, and it grouped nothing.
_LEAD = re.compile(r"^\s*(\S+)")
_NUMS = re.compile(r"\d+")

#: A run shorter than this is left alone: three lines said in full read better
#: than three lines summarised.
COLLAPSE_RUN = 4


def condense(text: str, keep_last: int = 4, budget: int = 14,
             width: int | None = None, tail_width: int | None = None) -> str:
    """A readable summary of a long output, for the file caption.

    Never used in place of the output itself — only where the caption would
    otherwise show the last six lines, which for `apt` means `Processing
    triggers` and nothing about what was installed.

    Runs of similar lines become one line with a count; the last few are kept
    word for word, because that is where the result and the error are.
    """
    def cut(line: str, room: int) -> str:
        return line if len(line) <= room else line[: room - 1] + "…"

    lines = [ln for ln in text.split("\n")]
    if len(lines) <= keep_last:
        return text

    head, tail = lines[:-keep_last], lines[-keep_last:]

    grouped: list[str] = []
    run_key: str | None = None
    run: list[str] = []

    def flush() -> None:
        if not run:
            return
        if len(run) >= COLLAPSE_RUN:
            note = f"   … {len(run)} lines"
            # The sample is trimmed to make room for the count. Cutting the
            # finished line instead would take the count off the end, which
            # is the one part worth keeping.
            head = cut(run[0], width - len(note)) if width else run[0]
            grouped.append(head + note)
        else:
            grouped.extend(cut(ln, width) if width else ln for ln in run)
        run.clear()

    for line in head:
        match = _LEAD.match(line)
        key = _NUMS.sub("#", match.group(1)) if match and line.strip() else None
        if key is not None and key == run_key:
            run.append(line)
            continue
        flush()
        run_key = key
        run = [line] if line.strip() else []
        if not line.strip():
            grouped.append(line)
    flush()

    # Still too long: the middle is what goes, not the end.
    if len(grouped) > budget:
        dropped = len(grouped) - budget
        grouped = grouped[:budget - 1] + [f"…   {dropped} more lines"]

    # The tail gets more room than the rest rather than none at all: the
    # result usually lives there, but on something like `apt list` the last
    # lines are simply more of the same, and left whole they fill the caption.
    if width:
        tail = [cut(ln, tail_width or width * 2) for ln in tail]
    return "\n".join(grouped + tail).strip("\n")


# Telegram does the highlighting itself from the language-* class. Output
# cannot be coloured "like a terminal" — nothing nests inside <pre> — but
# guessing the language is nearly free, and `git diff` turns red and green
# on its own.
_LANG_BY_CMD = (
    (re.compile(r"^\s*git\s+(diff|show|log\s+-p|format-patch)\b"), "diff"),
    (re.compile(r"^\s*diff\b"), "diff"),
    (re.compile(r"^\s*(cat|bat|head|tail|less)\b.*\.json\b"), "json"),
    (re.compile(r"^\s*(cat|bat|head|tail)\b.*\.(ya?ml)\b"), "yaml"),
    (re.compile(r"^\s*(cat|bat|head|tail)\b.*\.py\b"), "python"),
    (re.compile(r"^\s*(cat|bat|head|tail)\b.*\.(sh|bash)\b"), "bash"),
    (re.compile(r"^\s*(cat|bat|head|tail)\b.*\.sql\b"), "sql"),
    (re.compile(r"\|\s*jq\b"), "json"),
    (re.compile(r"^\s*python[0-9.]*\b"), "python"),
)


def detect_lang(command: str, output: str = "") -> str | None:
    for rx, lang in _LANG_BY_CMD:
        if rx.search(command or ""):
            return lang
    head = (output or "").lstrip()[:1]
    if head in "{[" and (output or "").rstrip()[-1:] in "}]":
        return "json"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# BUILDING THE CARD
# ─────────────────────────────────────────────────────────────────────────────


def esc(text: str) -> str:
    return html.escape(text, quote=False)


def _pre(text: str, lang: str | None) -> str:
    body = esc(text.rstrip("\n"))
    if lang:
        return f'<pre><code class="language-{lang}">{body}</code></pre>'
    return f"<pre>{body}</pre>"


def _status(code: int, duration: float) -> str:
    mark = OK_MARK if code == 0 else ERR_MARK
    return f"{mark} <b>{code}</b> · {_secs(duration)}"


def _secs(duration: float) -> str:
    if duration < 60:
        return f"{duration:.1f}s"
    m, s = divmod(int(duration), 60)
    return f"{m}m {s:02d}s"


def _file_name(command: str) -> str:
    stem = re.sub(r"[^a-zA-Z0-9]+", "-", command or "").strip("-")[:32] or "output"
    return f"{stem}_{time.strftime('%H%M%S')}.txt"


def render(
    output: str,
    exit_code: int,
    duration: float,
    state: State,
    command: str = "",
    stderr: str = "",
    lang: str | None = None,
) -> Rendered:
    """The main entry point: raw output to a finished card.

    There is deliberately no "...N more lines" truncation: a promise to show
    the rest has to be kept immediately. If it does not fit, a file is sent
    and the caption keeps the tail of the output — in a terminal you look at
    the end, not the beginning, because that is where the result and the error
    are.
    """
    text = clean_output(output)
    lang = lang or detect_lang(command, text)
    lines = text.split("\n") if text else []
    # The branch sits above the prompt, not inside it: buried at the end of
    # a prompt it went unread, and knowing which branch a command ran on is
    # often the first thing you want.
    branch = state.branch_line()
    prompt = (f"<i>{esc(branch)}</i>\n" if branch else "") + \
             f"<code>{esc(state.prompt())}</code>"
    header = _host_header(state)

    fits = len(text) <= SAFE_CHARS and len(lines) <= MAX_LINES

    if fits:
        parts = ([header] if header else []) + [_status(exit_code, duration)]
        if text:
            parts.append(_pre(text, lang))
        if exit_code != 0 and stderr:
            parts.append(f"<i>{esc(clean_output(stderr).split(chr(10))[0])}</i>")
        parts.append(prompt)
        return Rendered("text", "\n".join(parts), lines=len(lines), chars=len(text))

    # A summary rather than the last six lines. For `apt` those are
    # "Processing triggers", which says nothing about what was installed,
    # while the count of packages sits higher up. Nothing is lost either way:
    # the file below holds every line.
    tail = condense(text, keep_last=TAIL_LINES // 2, budget=TAIL_LINES * 2,
                    width=CAPTION_LINE_CHARS,
                    tail_width=CAPTION_TAIL_CHARS).split("\n")
    while tail and len("\n".join(tail)) > CAPTION_CHARS:
        tail = tail[1:]

    size_kb = max(1, len(text.encode()) // 1024)
    caption = ([header] if header else []) + [
        f"{_status(exit_code, duration)} · <i>{len(lines)} lines, {size_kb} KB</i>"
    ]
    if tail:
        caption.append(_pre("\n".join(tail), lang))
    if exit_code != 0 and stderr:
        caption.append(f"<i>{esc(clean_output(stderr).split(chr(10))[0])}</i>")
    caption.append(prompt)

    body = text
    if len(body) > MAX_FILE_CHARS:
        body = "...beginning of output dropped...\n" + body[-MAX_FILE_CHARS:]

    return Rendered(
        "file",
        "\n".join(caption),
        file_name=_file_name(command),
        file_body=body + "\n",
        lines=len(lines),
        chars=len(text),
    )


def _host_header(state: State) -> str:
    """The machine name line above the card."""
    if not (SHOW_HOST_HEADER and state.host):
        return ""
    return f"{state.icon} <b>{esc(state.host)}</b>"


def render_running(output: str, elapsed: float, lang: str | None = None,
                   state: State | None = None) -> str:
    """An interim card for a long-running command.

    There is no exit code and no prompt yet — the command has not finished.
    We show the tail: what is happening right now is what matters.
    """
    text = clean_output(output)
    lines = text.split("\n") if text else []
    shown = lines[-STREAM_TAIL_LINES:]
    while shown and len("\n".join(shown)) > SAFE_CHARS:
        shown = shown[1:]
    header = _host_header(state) if state else ""
    parts = ([header] if header else []) + [
        f"{RUN_MARK} <i>running · {_secs(elapsed)}</i>"
    ]
    if shown:
        prefix = "…\n" if len(shown) < len(lines) else ""
        parts.append(_pre(prefix + "\n".join(shown), lang))
    return "\n".join(parts)
