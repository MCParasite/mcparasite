"""Confluence/Wiki propagation channel - knowledge base poisoning.

Attack scenario: Agent A edits a Confluence page (adds hidden worm
to documentation). Agent B (research bot, onboarding bot) reads
the page and follows the worm instructions.

This demonstrates the "trusted source" problem: wikis and knowledge
bases are assumed safe, but any agent that writes to them can
inject worm payloads.
"""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("confluence")
class ConfluenceChannel(PropagationChannel):
    """Confluence/Atlassian wiki pages as worm propagation medium."""

    def _url(self) -> str:
        return self.config.params.get("url") or os.environ.get("CONFLUENCE_URL", "")

    def _email(self) -> str:
        return self.config.params.get("email") or os.environ.get("CONFLUENCE_EMAIL", "")

    def _api_token(self) -> str:
        return self.config.params.get("api_token") or os.environ.get("CONFLUENCE_API_TOKEN", "")

    def _space_key(self) -> str:
        return self.config.params.get("space_key") or os.environ.get("CONFLUENCE_SPACE", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/confluence_mcp.py"]
        url = self._url()
        if url:
            cmd.extend(["--url", url])
        email = self._email()
        if email:
            cmd.extend(["--email", email])
        api_token = self._api_token()
        if api_token:
            cmd.extend(["--token", api_token])
        space_key = self._space_key()
        if space_key:
            cmd.extend(["--space", space_key])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "confluence"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        url = self._url()
        if url:
            env["CONFLUENCE_URL"] = url
        email = self._email()
        if email:
            env["CONFLUENCE_EMAIL"] = email
        api_token = self._api_token()
        if api_token:
            env["CONFLUENCE_API_TOKEN"] = api_token
        space_key = self._space_key()
        if space_key:
            env["CONFLUENCE_SPACE"] = space_key
        return env

    def get_send_tool_name(self) -> str:
        return "update_confluence_page"

    def get_read_tool_name(self) -> str:
        return "read_confluence_page"

    def get_channel_description(self) -> str:
        space = self._space_key() or "WIKI"
        return f"Confluence space {space}"

    def validate_config(self) -> tuple[bool, str]:
        if not self._url():
            return False, "Confluence requires 'url' param or CONFLUENCE_URL env var."
        if not self._email() or not self._api_token():
            return False, "Confluence requires 'email'/'api_token' params or CONFLUENCE_EMAIL/CONFLUENCE_API_TOKEN env vars."
        return True, ""
