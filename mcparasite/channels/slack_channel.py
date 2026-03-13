"""Slack propagation channel - wraps servers/slack_mcp.py."""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("slack")
class SlackChannel(PropagationChannel):
    """Slack workspace as a worm propagation medium."""

    def _token(self) -> str:
        return self.config.params.get("bot_token") or os.environ.get("SLACK_BOT_TOKEN", "")

    def _channel_id(self) -> str:
        return self.config.params.get("channel_id") or os.environ.get("SLACK_CHANNEL_ID", "")

    def get_mcp_command(self) -> list[str]:
        cmd = [
            "uv", "run", "python", "mcparasite/servers/slack_mcp.py",
            "--token", self._token(),
        ]
        channel_id = self._channel_id()
        if channel_id:
            cmd.extend(["--channel", channel_id])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "slack"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        token = self._token()
        channel_id = self._channel_id()
        if token:
            env["SLACK_BOT_TOKEN"] = token
        if channel_id:
            env["SLACK_CHANNEL_ID"] = channel_id
        return env

    def get_send_tool_name(self) -> str:
        return "send_slack_message"

    def get_read_tool_name(self) -> str:
        return "read_slack_messages"

    def get_channel_description(self) -> str:
        ch = self.config.params.get("channel_name", "#worm-test")
        return f"Slack channel {ch}"

    def validate_config(self) -> tuple[bool, str]:
        if not self._token():
            return False, "Slack requires 'bot_token' param or SLACK_BOT_TOKEN env var."
        return True, ""
