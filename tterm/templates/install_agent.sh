#!/bin/sh
# tTerm — connect this machine (macOS or Linux).
#
# What this does:
#   1. puts the agent in ~/.tterm with its own Python environment;
#   2. sets up autostart (launchd on macOS, systemd --user on Linux);
#   3. starts the agent, and the machine shows up in the bot.
#
# What it does NOT do:
#   - never asks for root and refuses to run as root;
#   - never opens a port — the connection is always outbound;
#   - never touches system files, everything lives in ~/.tterm.
#
# Remove everything: ~/.tterm/uninstall.sh
#
# Source: https://github.com/tterm-net/tterm-agent

set -eu

HUB="${TTERM_HUB:-{{HUB}}}"
TOKEN="${TTERM_TOKEN:-{{TOKEN}}}"
NAME="${TTERM_NAME:-$(hostname -s 2>/dev/null || hostname)}"
DIR="$HOME/.tterm"
SRC="${TTERM_SRC:-https://raw.githubusercontent.com/tterm-net/tterm-agent/main/agent.py}"

say() { printf '  %s\n' "$1"; }
die() { printf '\n  x %s\n\n' "$1" >&2; exit 1; }

printf '\n  tTerm — connecting this machine\n\n'

# ---------------------------------------------------------------- checks

[ "$(id -u)" -ne 0 ] || die "Do not run this as root. The agent works with your
    own user's permissions — that way it can do no more than you can."

case "$(uname -s)" in
    Darwin) PLATFORM=macos ;;
    Linux)  PLATFORM=linux ;;
    *)      die "Only macOS and Linux are supported. Windows: see the bot." ;;
esac
say "System: $PLATFORM"

PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version=$("$candidate" -c 'import sys; print(sys.version_info[0]*100+sys.version_info[1])' 2>/dev/null || echo 0)
        if [ "$version" -ge 311 ]; then PY="$candidate"; break; fi
    fi
done
[ -n "$PY" ] || die "Python 3.11 or newer is required.
    macOS:  brew install python@3.12
    Linux:  sudo apt install python3 python3-venv"
say "Python: $($PY --version 2>&1)"

# ---------------------------------------------------------------- install

# Reinstalling is normal: the token changed, or the agent was updated.
# Stop the running instance so two of them do not fight over one connection,
# but keep the directory: rebuilding the virtualenv every time is slow.
if [ -f "$DIR/env" ]; then
    say "Agent already installed — updating"
    launchctl unload "$HOME/Library/LaunchAgents/ai.tterm.agent.plist" 2>/dev/null || true
    systemctl --user stop tterm-agent 2>/dev/null || true
fi

mkdir -p "$DIR"
say "Downloading the agent..."
curl -fsSL "$SRC" -o "$DIR/agent.py" || die "Could not download the agent"

if [ ! -d "$DIR/venv" ]; then
    "$PY" -m venv "$DIR/venv" || die "Could not create the Python environment"
fi
say "Installing dependencies..."
"$DIR/venv/bin/pip" install --quiet --upgrade pip websockets \
    || die "Could not install websockets"
# setproctitle is optional: without it the agent still works, it just shows up
# as "python" in the macOS list of background items instead of a clear name.
"$DIR/venv/bin/pip" install --quiet setproctitle 2>/dev/null || true

cat > "$DIR/env" <<EOF
TTERM_HUB=$HUB
TTERM_TOKEN=$TOKEN
TTERM_NAME=$NAME
EOF
chmod 600 "$DIR/env"
say "Settings written to $DIR/env"

# ---------------------------------------------------------------- autostart

if [ "$PLATFORM" = macos ]; then
    PLIST="$HOME/Library/LaunchAgents/ai.tterm.agent.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ai.tterm.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DIR/venv/bin/python</string>
    <string>$DIR/agent.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TTERM_HUB</key><string>$HUB</string>
    <key>TTERM_TOKEN</key><string>$TOKEN</string>
    <key>TTERM_NAME</key><string>$NAME</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DIR/agent.log</string>
  <key>StandardErrorPath</key><string>$DIR/agent.log</string>
</dict></plist>
EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST" || die "Could not set up autostart"
    STOP="launchctl unload $PLIST"
    say "Autostart configured (launchd)"
else
    UNIT="$HOME/.config/systemd/user/tterm-agent.service"
    mkdir -p "$HOME/.config/systemd/user"
    cat > "$UNIT" <<EOF
[Unit]
Description=tTerm agent
After=network-online.target

[Service]
Type=simple
EnvironmentFile=$DIR/env
ExecStart=$DIR/venv/bin/python $DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now tterm-agent.service || die "Could not start the service"
    STOP="systemctl --user stop tterm-agent"
    say "Autostart configured (systemd --user)"
fi

# ---------------------------------------------------------------- uninstall

cat > "$DIR/uninstall.sh" <<EOF
#!/bin/sh
set -eu
$STOP 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/ai.tterm.agent.plist" 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/tterm-agent.service" 2>/dev/null || true
systemctl --user daemon-reload 2>/dev/null || true
rm -rf "$DIR"
echo "tterm-agent removed completely."
EOF
chmod +x "$DIR/uninstall.sh"

printf '\n  Done. Open Telegram — the machine should already be online.\n'
printf '    Log:    %s/agent.log\n' "$DIR"
printf '    Remove: %s/uninstall.sh\n\n' "$DIR"
