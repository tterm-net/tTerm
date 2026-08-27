"""Configuration. Everything comes from the environment, nothing is hardcoded."""
from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    return os.environ.get(name, default) or ""


class Config:
    # --- Telegram ---
    # Validated in validate() at startup rather than on import, so modules
    # stay importable in tests without a configured environment.
    BOT_TOKEN: str = _env("BOT_TOKEN")

    # --- Public address the install script is fetched from ---
    # Must be https and reachable from the outside. For local work use
    # a tunnel such as cloudflared.
    PUBLIC_URL: str = _env("PUBLIC_URL", "http://localhost:8080").rstrip("/")

    # --- HTTP API ---
    API_HOST: str = _env("API_HOST", "0.0.0.0")
    API_PORT: int = int(_env("API_PORT", "8080"))

    # --- Storage ---
    DATA_DIR: Path = Path(_env("DATA_DIR", "./data"))

    # --- SSH ---
    # The user the install script creates on the client's server.
    SSH_USER: str = _env("SSH_USER", "tterm")
    # Lifetime of a signed certificate. Deliberately short.
    CERT_TTL_SECONDS: int = int(_env("CERT_TTL_SECONDS", "900"))
    # A session is closed after this much idle time.
    SESSION_IDLE_SECONDS: int = int(_env("SESSION_IDLE_SECONDS", "1800"))
    # Hard limit on how long a single command may run.
    COMMAND_TIMEOUT_SECONDS: int = int(_env("COMMAND_TIMEOUT_SECONDS", "300"))

    # --- Onboarding ---
    ENROLL_TOKEN_TTL_SECONDS: int = int(_env("ENROLL_TOKEN_TTL_SECONDS", "600"))

    # --- Output ---
    # Layout thresholds (when to fall back to a file, how many tail lines)
    # live in core/formatter.py next to the layout itself. Only bot behaviour
    # belongs here, not the look of a message.
    #: How often the message is edited while streaming a long command.
    STREAM_EDIT_INTERVAL: float = 1.5

    @property
    def db_path(self) -> Path:
        return self.DATA_DIR / "tterm.db"

    @property
    def ca_key_path(self) -> Path:
        return self.DATA_DIR / "ca" / "ca_ed25519"

    def ensure_dirs(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        (self.DATA_DIR / "ca").mkdir(parents=True, exist_ok=True)
        (self.DATA_DIR / "recordings").mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        """Called at startup. Fails loudly and clearly rather than silently."""
        problems = []
        if not self.BOT_TOKEN:
            problems.append("BOT_TOKEN is not set — get one from @BotFather")
        if not self.PUBLIC_URL.startswith(("http://", "https://")):
            problems.append("PUBLIC_URL must start with http:// or https://")
        if self.PUBLIC_URL.startswith("http://") and "localhost" not in self.PUBLIC_URL:
            problems.append(
                "PUBLIC_URL over http is unsafe: the install script would travel in the clear"
            )
        if problems:
            raise RuntimeError("Configuration problems:\n  - " + "\n  - ".join(problems))


config = Config()
