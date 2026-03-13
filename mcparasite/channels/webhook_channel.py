"""Generic webhook propagation channel.

Allows custom integrations - any platform with a webhook API
can be used as a propagation medium.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("webhook")
class WebhookChannel(PropagationChannel):
    """Generic HTTP webhook as propagation medium.

    Send: POST to webhook URL
    Read: GET from polling URL

    Works with: Zapier, Make, n8n, custom endpoints,
    Microsoft Power Automate, IFTTT, etc.
    """

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/webhook_mcp.py"]
        p = self.config.params
        if p.get("send_url"):
            cmd.extend(["--send-url", p["send_url"]])
        if p.get("read_url"):
            cmd.extend(["--read-url", p["read_url"]])
        if p.get("auth_header"):
            cmd.extend(["--auth", p["auth_header"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "webhook"

    def get_env_vars(self) -> dict[str, str]:
        return {}

    def get_send_tool_name(self) -> str:
        return "send_webhook_message"

    def get_read_tool_name(self) -> str:
        return "read_webhook_messages"

    def get_channel_description(self) -> str:
        return "Webhook endpoint"

    def validate_config(self) -> tuple[bool, str]:
        p = self.config.params
        if not p.get("send_url"):
            return False, "Webhook requires 'send_url' (POST endpoint)."
        return True, ""
