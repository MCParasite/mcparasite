"""
MCParasite Propagation Channels

Abstraction layer for worm propagation across different communication platforms.
Each channel is an MCP server that provides send/read message capabilities.
"""

from mcparasite.channels.base import PropagationChannel, ChannelMessage
from mcparasite.channels.registry import ChannelRegistry

__all__ = ["PropagationChannel", "ChannelMessage", "ChannelRegistry"]
