"""Jira propagation channel - enterprise ticket workflow injection.

Attack scenario: Agent A creates/comments on a Jira ticket with hidden
worm payload. Agent B (sprint planning bot, status reporter) reads
the ticket and executes worm instructions.

This is particularly dangerous in enterprise environments where
AI agents are used for sprint automation, standup summaries, and
ticket triage.
"""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("jira")
class JiraChannel(PropagationChannel):
    """Jira/Atlassian tickets as worm propagation medium."""

    def _url(self) -> str:
        return self.config.params.get("url") or os.environ.get("JIRA_URL", "")

    def _email(self) -> str:
        return self.config.params.get("email") or os.environ.get("JIRA_EMAIL", "")

    def _api_token(self) -> str:
        return self.config.params.get("api_token") or os.environ.get("JIRA_API_TOKEN", "")

    def _project_key(self) -> str:
        return self.config.params.get("project_key") or os.environ.get("JIRA_PROJECT", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/jira_mcp.py"]
        url = self._url()
        if url:
            cmd.extend(["--url", url])
        email = self._email()
        if email:
            cmd.extend(["--email", email])
        api_token = self._api_token()
        if api_token:
            cmd.extend(["--token", api_token])
        project_key = self._project_key()
        if project_key:
            cmd.extend(["--project", project_key])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "jira"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        url = self._url()
        if url:
            env["JIRA_URL"] = url
        email = self._email()
        if email:
            env["JIRA_EMAIL"] = email
        api_token = self._api_token()
        if api_token:
            env["JIRA_API_TOKEN"] = api_token
        project_key = self._project_key()
        if project_key:
            env["JIRA_PROJECT"] = project_key
        return env

    def get_send_tool_name(self) -> str:
        return "create_jira_comment"

    def get_read_tool_name(self) -> str:
        return "read_jira_tickets"

    def get_channel_description(self) -> str:
        proj = self._project_key() or "PROJECT"
        return f"Jira project {proj} tickets"

    def validate_config(self) -> tuple[bool, str]:
        if not self._url():
            return False, "Jira requires 'url' param or JIRA_URL env var."
        if not self._email() or not self._api_token():
            return False, "Jira requires 'email'/'api_token' params or JIRA_EMAIL/JIRA_API_TOKEN env vars."
        return True, ""
