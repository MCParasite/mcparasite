"""Linear propagation channel - modern engineering team ticket system.

Linear is used by high-growth startups and engineering teams.
AI agents increasingly read Linear issues for sprint planning,
standup summaries, and automated triage. A worm in a Linear issue
can propagate through any agent reading the project board.
"""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("linear")
class LinearChannel(PropagationChannel):
    """Linear issues/comments as worm propagation medium."""

    def _api_key(self) -> str:
        return self.config.params.get("api_key") or os.environ.get("LINEAR_API_KEY", "")

    def _team_id(self) -> str:
        return self.config.params.get("team_id") or os.environ.get("LINEAR_TEAM_ID", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/linear_mcp.py"]
        api_key = self._api_key()
        if api_key:
            cmd.extend(["--token", api_key])
        team_id = self._team_id()
        if team_id:
            cmd.extend(["--team", team_id])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "linear"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        api_key = self._api_key()
        if api_key:
            env["LINEAR_API_KEY"] = api_key
        team_id = self._team_id()
        if team_id:
            env["LINEAR_TEAM_ID"] = team_id
        return env

    def get_send_tool_name(self) -> str:
        return "create_linear_comment"

    def get_read_tool_name(self) -> str:
        return "read_linear_issues"

    def get_channel_description(self) -> str:
        team = self.config.params.get("team_name", "Engineering")
        return f"Linear {team} board"

    def validate_config(self) -> tuple[bool, str]:
        if not self._api_key():
            return False, "Linear requires 'api_key' param or LINEAR_API_KEY env var."
        return True, ""
