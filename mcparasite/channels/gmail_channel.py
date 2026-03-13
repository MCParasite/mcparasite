"""Gmail/SMTP propagation channel."""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("gmail")
class GmailChannel(PropagationChannel):
    """Gmail/SMTP/IMAP as a worm propagation medium.

    Worm spreads via email: Agent A sends infected email,
    Agent B reads inbox and executes worm instructions.
    """

    def _email(self) -> str:
        return self.config.params.get("email") or os.environ.get("GMAIL_EMAIL", "")

    def _app_password(self) -> str:
        return self.config.params.get("app_password") or os.environ.get("GMAIL_APP_PASSWORD", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/gmail_mcp.py"]
        email = self._email()
        if email:
            cmd.extend(["--email", email])
        app_password = self._app_password()
        if app_password:
            cmd.extend(["--password", app_password])
        p = self.config.params
        if p.get("imap_server"):
            cmd.extend(["--imap-server", p["imap_server"]])
        if p.get("smtp_server"):
            cmd.extend(["--smtp-server", p["smtp_server"]])
        if p.get("folder"):
            cmd.extend(["--folder", p["folder"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "gmail"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        email = self._email()
        if email:
            env["GMAIL_EMAIL"] = email
        app_password = self._app_password()
        if app_password:
            env["GMAIL_APP_PASSWORD"] = app_password
        return env

    def get_send_tool_name(self) -> str:
        return "send_email_message"

    def get_read_tool_name(self) -> str:
        return "read_email_messages"

    def get_channel_description(self) -> str:
        email = self._email() or "inbox"
        return f"Email inbox ({email})"

    def validate_config(self) -> tuple[bool, str]:
        if not self._email():
            return False, "Gmail requires 'email' param or GMAIL_EMAIL env var."
        if not self._app_password():
            return False, "Gmail requires 'app_password' param or GMAIL_APP_PASSWORD env var."
        return True, ""
