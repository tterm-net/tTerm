# tTerm

**Terminal in Telegram with multi-user access.**

[tterm.net](https://tterm.net) · [open the bot](https://t.me/tTermNetBot) ·
[updates](https://t.me/tTermBlog) · [agent](https://github.com/tterm-net/tterm-agent)

Type `ls -la` into the chat — the command runs on your machine and the reply
comes back as a message with the exit code, the working directory and how long
it took. The directory and environment variables are kept between messages,
just like in a real terminal.

## One bot, any number of machines

This is worth saying plainly, because the shape is not obvious: **you run one
bot and connect as many machines to it as you like.** `/use` lists them,
tapping one makes it active, and each can hold several terminals — separate
shells on the same machine, the way you keep more than one window open.

```
                    ┌─ server web-01        ← SSH, certificate per connection
  you ─ Telegram ─ bot ─ server db-02
                    └─ laptop               ← agent dials out, no open ports
```

There is no bot per server, and nothing to install per machine beyond the
one-line enrolment below.

## How it connects

**To a server: over SSH.** That is the transport, and it is ordinary SSH — the
difference is only in how the key is handled.

1. You run a single command on the server.
2. It creates a separate user and adds trust for our certificate authority to
   that user's `authorized_keys` — **without touching `sshd_config`**, so there
   is no way to lock yourself out.
3. That user gets passwordless sudo, otherwise the bot could not restart
   a service or read the system log.
4. Every connection uses a freshly issued certificate valid for 15 minutes.
   Nothing long-lived is stored: there is no private key of yours anywhere in
   the system, and none is ever asked for.
5. The server's own host key is recorded at enrolment and checked on every
   connection afterwards.

**To a computer: through an agent.** A laptop cannot be reached from the
outside, so the direction is reversed: a small
[agent](https://github.com/tterm-net/tterm-agent) opens the connection itself
and keeps it alive. No port is ever opened on your machine, and SSH is not
involved at all.

## What it can do

- run commands and keep the shell state between messages — `cd` in one message,
  and the next one starts there;
- several terminals per machine, each with its own shell;
- show the exit code, duration, current directory, git branch and whether the
  working tree is dirty;
- stream the output as it arrives, with a Stop button that actually interrupts
  the command;
- notice a command that is waiting for an answer — `Username for`, `[y/N]` —
  and offer buttons instead of hanging silently;
- ask before something irreversible: `rm -rf`, `mkfs`, `DROP DATABASE`,
  stopping `sshd`;
- send long output as a file, with a summary in the caption rather than the
  last few lines;
- share a machine with someone else, with or without a time limit, and show
  the owner everything they ran.

**bash and zsh** are both supported. Full-screen programs — `htop`, `vim` —
are only half-supported: the keys work, the screen is not redrawn.

## What is in this repository

| | |
|---|---|
| `tterm/core/` | sessions, the SSH and agent transports, the CA, the database |
| `tterm/bot/` | everything you see in Telegram |
| `tterm/api/` | the HTTP side: enrolment, the install script, the agent socket |
| `tterm/templates/` | the install scripts handed to a server or a computer |
| `tterm/tests/` | one file, run it against a real shell |

The agent that runs on a computer lives in its own repository,
[tterm-agent](https://github.com/tterm-net/tterm-agent) — it is a single file
and is meant to be read before it is run.

## Security

**Whoever controls the bot controls your machine.** With sudo granted, that
means root on a server and your own user's permissions on a computer.

Traffic goes through Telegram's servers and they can see its contents:
conversations with bots are not end-to-end encrypted. Do not print private
keys or passwords into the chat.

The install script never edits `sshd_config` and never restarts `sshd`.
Removing everything is one command, shown in the bot.

## Self-hosting

The bot is a single Python process with an SQLite database. It needs:

- Python 3.11+;
- a public HTTPS address — the install script is fetched from it, and agents
  connect to it over WebSocket;
- a Telegram bot token from [@BotFather](https://t.me/BotFather).

```bash
git clone https://github.com/tterm-net/tTerm.git && cd tTerm
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # set BOT_TOKEN and PUBLIC_URL
python -m tterm.main
```

`PUBLIC_URL` must be reachable from the outside: your servers download the
install script from it, and agents keep a WebSocket connection to it. For
a quick trial a tunnel works; for anything permanent use a real domain.

Run `python -m tterm.tests.test_flow` to check the setup — the tests spawn
a real shell and verify the whole round trip.

## Donations

tTerm is free. If it saves you time, you can support it — the link lives on
[tterm.net](https://tterm.net).

Never take a wallet address from a fork or a mirror. The canonical one is
published on the site only.

## Links

- [tterm.net](https://tterm.net) — the site, with release notes
- [@tTermNetBot](https://t.me/tTermNetBot) — the bot itself
- [@tTermBlog](https://t.me/tTermBlog) — updates and news
- [tterm-agent](https://github.com/tterm-net/tterm-agent) — the agent for
  computers

## License

MIT
