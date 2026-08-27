#!/bin/sh
# tTerm — server access setup.
#
# What this script does:
#   1. creates a system user {{SSH_USER}} (no password);
#   2. writes a cert-authority line with our CA public key into its
#      authorized_keys;
#   3. WARNING: grants that user passwordless sudo;
#   4. tells the service the host is ready.
#
# ABOUT SUDO. Step 3 means whoever runs the bot gets root on this server.
# Without it the bot could not restart a service, install a package or read
# the system log — that is, almost nothing useful.
# To drop sudo and keep the rest:  sudo rm /etc/sudoers.d/{{SSH_USER}}
#
# What it does NOT do:
#   - never edits /etc/ssh/sshd_config and never restarts sshd, so there is
#     no risk of locking yourself out;
#   - leaves no permanent keys — access uses certificates with a {{CERT_TTL}}s
#     lifetime.
#
# Remove everything:
#   sudo userdel -r {{SSH_USER}} && sudo rm -f /etc/sudoers.d/{{SSH_USER}}
#
# The script is idempotent: running it again breaks nothing.


set -eu

SSH_USER="{{SSH_USER}}"
CA_PUBKEY="{{CA_PUBKEY}}"
API_URL="{{API_URL}}"
TOKEN="{{TOKEN}}"

say() { printf '  %s\n' "$1"; }
die() { printf '\n  x %s\n\n' "$1" >&2; exit 1; }

printf '\n  tTerm — connecting a server\n\n'

# ---------------------------------------------------------------- checks

[ "$(id -u)" -eq 0 ] || die "Root privileges are required. Run this with sudo."

command -v ssh-keygen >/dev/null 2>&1 || die "OpenSSH not found. Install openssh-server."

# User certificates are supported since OpenSSH 5.6; check just in case.
SSHD_VER=$(sshd -V 2>&1 | head -1 || true)
say "sshd: ${SSHD_VER:-unknown}"

if command -v apt-get >/dev/null 2>&1; then DISTRO=debian
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then DISTRO=rhel
elif command -v apk >/dev/null 2>&1; then DISTRO=alpine
else die "Unsupported distribution. Tell us and we will add it."
fi
say "Distribution: $DISTRO"

# ------------------------------------------------------------------ user

if id "$SSH_USER" >/dev/null 2>&1; then
    say "User $SSH_USER already exists — reusing it"
else
    case "$DISTRO" in
        alpine) adduser -D -s /bin/bash "$SSH_USER" >/dev/null ;;
        *)      useradd -m -s /bin/bash "$SSH_USER" >/dev/null ;;
    esac
    say "Created user $SSH_USER"
fi

# No password is ever set: certificate login only.
passwd -l "$SSH_USER" >/dev/null 2>&1 || true

HOME_DIR=$(getent passwd "$SSH_USER" | cut -d: -f6)
[ -n "$HOME_DIR" ] || die "Could not determine the home directory of $SSH_USER"

# -------------------------------------------------------------- CA trust

# cert-authority in authorized_keys rather than TrustedUserCAKeys in
# sshd_config: the same trust in our certificates, but local and without
# restarting the daemon.
mkdir -p "$HOME_DIR/.ssh"
AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
touch "$AUTH_KEYS"

CA_LINE="cert-authority $CA_PUBKEY"
if grep -qF "$CA_PUBKEY" "$AUTH_KEYS" 2>/dev/null; then
    say "CA key already installed"
else
    printf '%s\n' "$CA_LINE" >> "$AUTH_KEYS"
    say "CA key added"
fi

chown -R "$SSH_USER:$(id -gn "$SSH_USER")" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$AUTH_KEYS"

# ---------------------------------------------------------------- sudo

# A separate file in sudoers.d rather than editing /etc/sudoers: the change
# is visible, reverts with a single rm and does not disturb what the admin
# configured. visudo -c is mandatory — a broken file in sudoers.d breaks sudo
# for everyone, including the admin, and is only fixable from the provider's
# console.
SUDOERS_FILE="/etc/sudoers.d/$SSH_USER"
TMP_SUDOERS="$(mktemp)"
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$SSH_USER" > "$TMP_SUDOERS"
if visudo -c -f "$TMP_SUDOERS" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
    rm -f "$TMP_SUDOERS"
    say "Passwordless sudo granted (to remove: rm $SUDOERS_FILE)"
else
    rm -f "$TMP_SUDOERS"
    die "Could not validate the sudo rule — nothing was changed"
fi

# ---------------------------------------------------------- registration

SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
[ -n "${SSH_PORT:-}" ] || SSH_PORT=22

HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
OS_INFO=$(. /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME" || uname -s)
HOST_KEY=$(cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true)

say "Registering the host..."

PAYLOAD=$(printf '{"token":"%s","hostname":"%s","os":"%s","ssh_port":%s,"ssh_user":"%s","host_pubkey":"%s"}' \
    "$TOKEN" "$HOSTNAME_VAL" "$OS_INFO" "$SSH_PORT" "$SSH_USER" "$HOST_KEY")

HTTP_CODE=$(curl -sS -o /tmp/tterm_reg.$$ -w '%{http_code}' \
    -X POST "$API_URL/enroll" \
    -H 'Content-Type: application/json' \
    --max-time 20 \
    -d "$PAYLOAD" 2>/dev/null) || HTTP_CODE=000

if [ "$HTTP_CODE" = "200" ]; then
    rm -f /tmp/tterm_reg.$$
    printf '\n  Done. Open Telegram — a confirmation is waiting there.\n\n'
else
    REASON=$(cat /tmp/tterm_reg.$$ 2>/dev/null || true)
    rm -f /tmp/tterm_reg.$$
    printf '\n  x Could not reach the service (code %s).\n' "$HTTP_CODE"
    printf '    %s\n' "${REASON:-no response}"
    printf '\n    The user and key are already set up. If outbound traffic\n'
    printf '    is blocked, register the host manually with the command\n'
    printf '    /addhost manual in the bot.\n\n'
    exit 1
fi
