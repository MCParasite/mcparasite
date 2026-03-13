"""
Channel registry - factory for creating propagation channels from config.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcparasite.channels.base import ChannelConfig, PropagationChannel

if TYPE_CHECKING:
    pass


_CHANNEL_CLASSES: dict[str, type[PropagationChannel]] = {}


def register_channel(channel_type: str):
    """Decorator to register a channel implementation."""
    def wrapper(cls: type[PropagationChannel]):
        _CHANNEL_CLASSES[channel_type] = cls
        return cls
    return wrapper


class ChannelRegistry:
    """Factory for creating channels from configuration."""

    @staticmethod
    def create(config: ChannelConfig) -> PropagationChannel:
        """Create a channel instance from config."""
        # Lazy imports to avoid circular dependencies
        _ensure_channels_loaded()

        cls = _CHANNEL_CLASSES.get(config.channel_type)
        if cls is None:
            available = ", ".join(sorted(_CHANNEL_CLASSES.keys()))
            raise ValueError(
                f"Unknown channel type: {config.channel_type!r}. "
                f"Available: {available}"
            )
        return cls(config)

    @staticmethod
    def available() -> list[str]:
        """List registered channel types."""
        _ensure_channels_loaded()
        return sorted(_CHANNEL_CLASSES.keys())

    @staticmethod
    def get_class(channel_type: str) -> type[PropagationChannel] | None:
        _ensure_channels_loaded()
        return _CHANNEL_CLASSES.get(channel_type)


_loaded = False


def _ensure_channels_loaded():
    global _loaded
    if _loaded:
        return
    _loaded = True
    # Import all channel modules to trigger @register_channel decorators
    import mcparasite.channels.slack_channel
    import mcparasite.channels.gmail_channel
    import mcparasite.channels.github_channel
    import mcparasite.channels.discord_channel
    import mcparasite.channels.local_channel
    import mcparasite.channels.webhook_channel
    import mcparasite.channels.jira_channel
    import mcparasite.channels.teams_channel
    import mcparasite.channels.confluence_channel
    import mcparasite.channels.gdrive_channel
    import mcparasite.channels.s3_channel
    import mcparasite.channels.cicd_channel
    import mcparasite.channels.notion_channel
    import mcparasite.channels.linear_channel
