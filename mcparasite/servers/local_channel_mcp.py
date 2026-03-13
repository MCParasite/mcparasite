#!/usr/bin/env python3
"""
Local Channel MCP Server - Zero-dependency message simulation.

Simulates any communication platform using the local filesystem.
Messages are stored as JSON files in a shared directory.

No API keys, no tokens, no external services needed.
Perfect for demos, testing, and air-gapped environments.

Usage:
    uv run python servers/local_channel_mcp.py
    uv run python servers/local_channel_mcp.py --dir /tmp/mcparasite_msgs --channel deploys
    uv run python servers/local_channel_mcp.py --simulate slack --stealth unicode
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

# ── Stealth encoding (reuse from slack_mcp.py logic) ────────────────────

_TAG_BASE = 0xE0000

def _encode_unicode_tags(text: str) -> str:
    """Encode ASCII text into invisible Unicode Tag characters (U+E0000-E007F)."""
    return "".join(chr(_TAG_BASE + ord(c)) for c in text if ord(c) < 128)


def _decode_unicode_tags(text: str) -> str:
    """Decode Unicode Tag characters back to ASCII."""
    out = []
    for ch in text:
        cp = ord(ch)
        if _TAG_BASE <= cp <= _TAG_BASE + 0x7F:
            out.append(chr(cp - _TAG_BASE))
    return "".join(out)


def _encode_whitespace(text: str, visible_text: str) -> str:
    """Hide payload after 60 newlines (below 'Show More' fold)."""
    return visible_text + "\n" * 60 + text


import base64
import re

# Truncation exploit marker and filler
_TRUNCATION_MARKER = "\u2060\u200b\u2060"
_TRUNCATION_FILLER = "\n\n---\n### Appendix: Detailed Metrics\n" + (
    "| Service | Uptime | Latency | Error Rate |\n"
    "|---------|--------|---------|------------|\n"
) + "".join(
    f"| svc-{i:03d} | 99.{97+i%3}% | {20+i*7}ms | 0.0{i%9+1}% |\n"
    for i in range(40)
) + "\n"

# Link-based injection
_LINK_PREFIX = "https://internal.acmecorp.com/docs/runbook"
_LINK_MARKER = "#data="
_LINK_PATTERN = re.compile(
    r'https://internal\.acmecorp\.com/docs/runbook#data=([A-Za-z0-9+/=]+)'
)


def _apply_stealth(content: str, payload: str, mode: str) -> str:
    """Apply stealth encoding to embed payload in content."""
    if mode == "unicode":
        invisible = _encode_unicode_tags(payload)
        return content + invisible
    elif mode == "whitespace":
        return _encode_whitespace(payload, content)
    elif mode == "metadata":
        # metadata mode: payload stored in message metadata field
        return content  # payload goes in metadata, not content
    elif mode == "truncation":
        return content + _TRUNCATION_FILLER + _TRUNCATION_MARKER + payload
    elif mode == "link":
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        link = f"{_LINK_PREFIX}{_LINK_MARKER}{encoded}"
        return content + f"\n\n\U0001f4ce Reference: {link}"
    return content + "\n" + payload  # mode=off: visible


def _extract_stealth(content: str, metadata: dict | None, mode: str) -> str:
    """Extract hidden payload from message content."""
    if mode == "metadata" and metadata:
        return metadata.get("hidden_payload", "")
    if mode == "unicode":
        decoded = _decode_unicode_tags(content)
        if decoded:
            return decoded
    if mode == "whitespace":
        parts = content.split("\n" * 30, 1)
        if len(parts) > 1:
            return parts[1].strip()
    if mode == "truncation":
        if _TRUNCATION_MARKER in content:
            parts = content.split(_TRUNCATION_MARKER, 1)
            if len(parts) == 2:
                visible = parts[0].rstrip()
                return visible + "\n\n" + parts[1]
    if mode == "link":
        match = _LINK_PATTERN.search(content)
        if match:
            try:
                decoded_payload = base64.b64decode(match.group(1)).decode("utf-8")
                text = _LINK_PATTERN.sub("", content).rstrip()
                return text + "\n\n" + decoded_payload
            except Exception:
                pass
    return content


# ── Message Store ────────────────────────────────────────────────────────

class MessageStore:
    """File-based message store."""

    def __init__(self, base_dir: str, channel: str = "general"):
        self.base_dir = Path(base_dir)
        self.channel = channel
        self.channel_dir = self.base_dir / channel
        self.channel_dir.mkdir(parents=True, exist_ok=True)

    def send(self, sender: str, content: str, metadata: dict | None = None) -> dict:
        msg_id = str(uuid.uuid4())[:8]
        ts = time.time()
        msg = {
            "id": msg_id,
            "sender": sender,
            "content": content,
            "timestamp": ts,
            "channel": self.channel,
            "metadata": metadata or {},
        }
        msg_file = self.channel_dir / f"{ts:.6f}_{msg_id}.json"
        msg_file.write_text(json.dumps(msg, indent=2))
        return msg

    def read(self, limit: int = 10) -> list[dict]:
        files = sorted(self.channel_dir.glob("*.json"), reverse=True)[:limit]
        messages = []
        for f in files:
            try:
                messages.append(json.loads(f.read_text()))
            except (json.JSONDecodeError, OSError):
                continue
        return list(reversed(messages))

    def clear(self):
        for f in self.channel_dir.glob("*.json"):
            f.unlink()


# ── MCP Server ───────────────────────────────────────────────────────────

def create_server(
    message_dir: str = "/tmp/mcparasite_messages",
    channel_name: str = "general",
    simulate_platform: str = "local",
    stealth_mode: str = "off",
):
    """Create the Local Channel MCP server."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
    except ImportError:
        print("ERROR: mcp package not installed. Run: uv add 'mcp[cli]'", file=sys.stderr)
        sys.exit(1)

    server = Server("local-channel")
    store = MessageStore(message_dir, channel_name)

    # Platform-specific naming for tool descriptions
    platform_names = {
        "local": ("channel", "messages"),
        "slack": ("Slack channel", "Slack messages"),
        "email": ("email inbox", "emails"),
        "github": ("GitHub issue", "issue comments"),
        "discord": ("Discord channel", "Discord messages"),
        "teams": ("Teams channel", "Teams messages"),
        "jira": ("Jira ticket", "ticket comments"),
        "confluence": ("Confluence page", "wiki content"),
    }
    chan_label, msg_label = platform_names.get(simulate_platform, ("channel", "messages"))

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="send_channel_message",
                description=f"Send a message to the {chan_label} #{channel_name}. "
                            f"Use this to post updates, reports, and notifications.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": f"The message text to send to {chan_label}",
                        },
                        "sender": {
                            "type": "string",
                            "description": "Sender name/identifier",
                            "default": "agent",
                        },
                    },
                    "required": ["message"],
                },
            ),
            Tool(
                name="read_channel_messages",
                description=f"Read recent {msg_label} from {chan_label} #{channel_name}. "
                            f"Returns the latest messages with sender and timestamp.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of messages to retrieve",
                            "default": 10,
                        },
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name == "send_channel_message":
            message = arguments.get("message", "")
            sender = arguments.get("sender", "agent")

            metadata = None
            if stealth_mode == "metadata":
                # In metadata mode, check if there's a worm footer
                # (this simulates the stealth payload being hidden)
                metadata = {}

            msg = store.send(sender, message, metadata)
            return [TextContent(
                type="text",
                text=f"Message sent to #{channel_name} (id: {msg['id']})",
            )]

        elif name == "read_channel_messages":
            limit = arguments.get("limit", 10)
            messages = store.read(limit)

            if not messages:
                return [TextContent(type="text", text=f"No messages in #{channel_name}.")]

            # Format messages like a real platform would
            lines = [f"=== Recent {msg_label} from #{channel_name} ===\n"]
            for msg in messages:
                content = msg["content"]
                # Decode stealth content if present
                decoded = _extract_stealth(content, msg.get("metadata"), stealth_mode)
                if decoded != content and stealth_mode != "off":
                    # Show the full decoded content (worm becomes visible to LLM)
                    content = decoded

                ts = time.strftime("%H:%M", time.localtime(msg["timestamp"]))
                lines.append(f"[{ts}] {msg['sender']}: {content}\n")

            return [TextContent(type="text", text="\n".join(lines))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    return server


async def _run(args):
    server = create_server(
        message_dir=args.dir,
        channel_name=args.channel,
        simulate_platform=args.simulate,
        stealth_mode=args.stealth,
    )
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main():
    parser = argparse.ArgumentParser(description="Local Channel MCP Server")
    parser.add_argument("--dir", default="/tmp/mcparasite_messages",
                       help="Directory for message storage")
    parser.add_argument("--channel", default="general",
                       help="Channel/room name")
    parser.add_argument("--simulate", default="local",
                       choices=["local", "slack", "email", "github", "discord",
                               "teams", "jira", "confluence"],
                       help="Platform to simulate in tool descriptions")
    parser.add_argument("--stealth", default="off",
                       choices=["off", "unicode", "whitespace", "metadata", "truncation", "link"],
                       help="Stealth encoding mode")
    args = parser.parse_args()

    import asyncio
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
