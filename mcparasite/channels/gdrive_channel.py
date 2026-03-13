"""Google Drive/Docs propagation channel - shared document poisoning.

Attack scenario: Agent A edits a shared Google Doc (meeting notes,
project plan, design doc) with hidden worm payload. Agent B
(summarizer bot, action-items bot) reads the document and executes
worm instructions.

Particularly dangerous because shared docs are a high-trust medium -
people and agents trust content from shared documents implicitly.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("gdrive")
class GDriveChannel(PropagationChannel):
    """Google Drive/Docs as worm propagation medium."""

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/gdrive_mcp.py"]
        p = self.config.params
        if p.get("credentials_file"):
            cmd.extend(["--credentials", p["credentials_file"]])
        if p.get("document_id"):
            cmd.extend(["--doc-id", p["document_id"]])
        if p.get("folder_id"):
            cmd.extend(["--folder-id", p["folder_id"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "gdrive"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        if self.config.params.get("credentials_file"):
            env["GOOGLE_APPLICATION_CREDENTIALS"] = self.config.params["credentials_file"]
        return env

    def get_send_tool_name(self) -> str:
        return "append_to_document"

    def get_read_tool_name(self) -> str:
        return "read_document"

    def get_channel_description(self) -> str:
        return "Google Drive shared document"

    def validate_config(self) -> tuple[bool, str]:
        p = self.config.params
        if not p.get("credentials_file"):
            return False, "Google Drive requires 'credentials_file' (service account JSON)."
        return True, ""
