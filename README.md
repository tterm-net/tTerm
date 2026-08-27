# tTerm

**Terminal in Telegram with multi-user access.**

[tterm.net](https://tterm.net) · [open the bot](https://t.me/tTermNetBot) ·
[updates](https://t.me/tTermBlog) · [agent](https://github.com/tterm-net/tterm-agent)

Type `ls -la` into the chat — the command runs on your machine and the reply
comes back as a message with the exit code, the working directory and how long
it took. The directory and environment variables are kept between messages,
just like in a real terminal.

Works with Linux servers over SSH and with macOS or Linux computers through
a small [agent](https://github.com/tterm-net/tterm-agent).

## How it works

1. You run a single command on your server.
2. It creates a separate user and trusts our certificate authority —
   **without touching `sshd_config`**, so there is no way to lock yourself out.
3. That user gets passwordless sudo, otherwise the bot could not restart
   a service or read the system log.
4. Every connection uses a fresh certificate valid for 15 minutes. We never
   store your SSH keys.

A laptop cannot be reached from the outside, so the direction is reversed
there: a small agent opens the connection itself and keeps it alive. No port
is ever opened on your machine.

## What it can do

- run commands and keep the shell state between messages;
- show the exit code, duration, current directory, git branch and whether
  the working tree is dirty;
- send long output as a file instead of flooding the chat;
- share a machine with someone else, with or without a time limit;
- show the owner everything others ran on their machines.

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
