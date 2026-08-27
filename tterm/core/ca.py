"""SSH Certificate Authority.

Instead of storing clients' private keys we keep one CA key and use it to
sign a short-lived certificate for every connection.

On the client's server the install script writes a cert-authority line into
authorized_keys. That trusts our certificates locally, without editing
sshd_config and without restarting the daemon, so nobody can be locked out.

In production the CA key belongs in a KMS or HSM, not on disk.
"""
from __future__ import annotations

import time
from pathlib import Path

import asyncssh

from .config import config


class CertificateAuthority:
    def __init__(self, key_path: Path | None = None) -> None:
        self.key_path = key_path or config.ca_key_path
        self._ca_key: asyncssh.SSHKey | None = None

    def load_or_create(self) -> None:
        """Loads the CA key, creating it on first run."""
        config.ensure_dirs()
        if self.key_path.exists():
            self._ca_key = asyncssh.read_private_key(str(self.key_path))
            return

        key = asyncssh.generate_private_key("ssh-ed25519", comment="tterm-ca")
        self.key_path.write_bytes(key.export_private_key())
        self.key_path.chmod(0o600)
        pub_path = self.key_path.with_suffix(".pub")
        pub_path.write_bytes(key.export_public_key())
        self._ca_key = key

    @property
    def ca_key(self) -> asyncssh.SSHKey:
        if self._ca_key is None:
            self.load_or_create()
        assert self._ca_key is not None
        return self._ca_key

    def public_key_line(self) -> str:
        """The CA public key line, as written by the install script."""
        return self.ca_key.export_public_key().decode().strip()

    def issue_client_cert(
        self, principal: str, ttl: int | None = None
    ) -> tuple[asyncssh.SSHKey, asyncssh.SSHCertificate]:
        """Issues a throwaway key pair and a signed certificate.

        The private key exists only in memory for the duration of the
        connection and is never written anywhere. Default TTL is 15 minutes.
        """
        ttl = ttl or config.CERT_TTL_SECONDS
        client_key = asyncssh.generate_private_key("ssh-ed25519")
        now = int(time.time())

        # Argument order matters and is easy to get wrong: the method is
        # called on the CA key, and the key being certified comes first.
        # The reverse silently produces a certificate for the CA key signed
        # by the throwaway one; the server rejects it and asyncssh fails with
        # "Certificate key mismatch" at connect time.
        cert = self.ca_key.generate_user_certificate(
            client_key,
            f"tterm-{principal}",
            principals=[principal],
            valid_after=now - 60,  # slack for clock skew
            valid_before=now + ttl,
            # Everything unnecessary is off: only a shell and a pty.
            permit_pty=True,
            permit_agent_forwarding=False,
            permit_port_forwarding=False,
            permit_x11_forwarding=False,
            permit_user_rc=False,
        )
        return client_key, cert


ca = CertificateAuthority()
