"""
Base classes for propagation channels.

Every channel must implement send_message and read_messages as MCP tools.
This gives us a unified interface while keeping the MCP architecture.
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChannelMessage:
    """A message in a propagation channel."""
    id: str
    sender: str
    content: str
    timestamp: float = field(default_factory=time.time)
    channel_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sender": self.sender,
            "content": self.content,
            "timestamp": self.timestamp,
            "channel_type": self.channel_type,
            "metadata": self.metadata,
        }


@dataclass
class ChannelConfig:
    """Configuration for a propagation channel."""
    channel_type: str
    name: str
    params: dict[str, Any] = field(default_factory=dict)
    stealth_mode: str = "off"  # off, unicode, whitespace, metadata, truncation, link


class PropagationChannel(ABC):
    """
    Abstract base for all propagation channels.

    Each channel wraps a communication platform (Slack, Gmail, GitHub, etc.)
    and exposes it as an MCP server with standardized tool interfaces.
    """

    def __init__(self, config: ChannelConfig):
        self.config = config
        self.name = config.name
        self.stealth_mode = config.stealth_mode

    @abstractmethod
    def get_mcp_command(self) -> list[str]:
        """Return the command to start this channel's MCP server."""
        ...

    @abstractmethod
    def get_server_name(self) -> str:
        """Return the MCP server name for this channel."""
        ...

    @abstractmethod
    def get_env_vars(self) -> dict[str, str]:
        """Return environment variables needed for this channel."""
        ...

    @abstractmethod
    def get_send_tool_name(self) -> str:
        """Return the tool name used to send messages (e.g., 'send_slack_message')."""
        ...

    @abstractmethod
    def get_read_tool_name(self) -> str:
        """Return the tool name used to read messages (e.g., 'read_slack_messages')."""
        ...

    @abstractmethod
    def get_channel_description(self) -> str:
        """Human-readable description for prompts (e.g., 'Slack channel #deploys')."""
        ...

    @abstractmethod
    def validate_config(self) -> tuple[bool, str]:
        """Check if all required config params are present. Returns (ok, error_msg)."""
        ...

    def get_stealth_flag(self) -> list[str]:
        """Return CLI flags for stealth mode."""
        if self.stealth_mode and self.stealth_mode != "off":
            return ["--stealth", self.stealth_mode]
        return []

    @staticmethod
    def get_available_channels() -> list[str]:
        """List all supported channel types."""
        return [
            "slack",
            "gmail",
            "github",
            "discord",
            "teams",
            "local",
            "webhook",
        ]
