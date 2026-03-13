"""Local file-based simulation channel - zero external dependencies.

This is the killer feature for demos: no Slack token, no Gmail password,
no GitHub PAT needed. Just run and watch the worm propagate through
a local shared filesystem that simulates a communication channel.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("local")
class LocalChannel(PropagationChannel):
    """Local file-based message simulation.

    Messages are stored as JSON files in a shared directory.
    Perfect for demos, testing, and environments without API access.
    Simulates any communication platform behavior.
    """

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/local_channel_mcp.py"]
        p = self.config.params
        msg_dir = p.get("message_dir", "/tmp/mcparasite_messages")
        cmd.extend(["--dir", msg_dir])
        if p.get("channel_name"):
            cmd.extend(["--channel", p["channel_name"]])
        if p.get("simulate_platform"):
            cmd.extend(["--simulate", p["simulate_platform"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "local-channel"

    def get_env_vars(self) -> dict[str, str]:
        return {}

    def get_send_tool_name(self) -> str:
        return "send_channel_message"

    def get_read_tool_name(self) -> str:
        return "read_channel_messages"

    def get_channel_description(self) -> str:
        platform = self.config.params.get("simulate_platform", "local")
        ch = self.config.params.get("channel_name", "#general")
        return f"{platform} channel {ch} (simulated)"

    def validate_config(self) -> tuple[bool, str]:
        # Local channel has no external dependencies - always valid
        return True, ""
