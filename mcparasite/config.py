"""
MCParasite Configuration Loader

Loads config.yaml and creates channel/provider instances.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from mcparasite.channels.base import ChannelConfig
from mcparasite.channels.registry import ChannelRegistry


def _load_yaml(path: str | Path) -> dict:
    """Load YAML config file. Supports both PyYAML and a simple fallback."""
    path = Path(path)
    if not path.exists():
        print(f"Config file not found: {path}", file=sys.stderr)
        print(f"Copy config.example.yaml to config.yaml and edit it.", file=sys.stderr)
        sys.exit(1)

    text = path.read_text()

    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        # Minimal YAML-like parser for simple configs
        # (only handles flat key-value and simple nesting)
        import json
        # Try JSON as fallback
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            print("ERROR: PyYAML not installed and config is not JSON.", file=sys.stderr)
            print("Install: uv add pyyaml", file=sys.stderr)
            sys.exit(1)


class MCParasiteConfig:
    """Parsed configuration for MCParasite."""

    def __init__(self, config_path: str | Path = "config.yaml"):
        self.raw = _load_yaml(config_path)
        self.config_path = Path(config_path)

    @classmethod
    def from_dict(cls, data: dict) -> "MCParasiteConfig":
        """Create config from a dict (for programmatic use)."""
        obj = object.__new__(cls)
        obj.raw = data
        obj.config_path = Path(".")
        return obj

    # ── Providers ────────────────────────────────────────────────────

    def get_provider_config(self, name: str) -> dict[str, str]:
        """Get LLM provider config (api_key, model, etc.)."""
        providers = self.raw.get("providers", {})
        return providers.get(name, {})

    def get_available_providers(self) -> list[str]:
        """List configured providers."""
        providers = self.raw.get("providers", {})
        return [k for k, v in providers.items() if v and v.get("api_key")]

    def get_default_provider(self) -> tuple[str, str]:
        """Return (provider_name, model) for the first configured provider."""
        for name in ["openai", "anthropic", "gemini", "ollama"]:
            cfg = self.get_provider_config(name)
            if cfg.get("api_key") or name == "ollama":
                model = cfg.get("model", "")
                return name, model
        return "openai", "gpt-4o-mini"

    # ── Channels ─────────────────────────────────────────────────────

    def get_channel_configs(self) -> dict[str, ChannelConfig]:
        """Get all configured channels as ChannelConfig objects."""
        channels_raw = self.raw.get("channels", {})
        global_stealth = self.raw.get("stealth_mode", "off")

        configs = {}
        for channel_type, params in channels_raw.items():
            if params is None:
                continue  # Commented out in config
            configs[channel_type] = ChannelConfig(
                channel_type=channel_type,
                name=channel_type,
                params=params if isinstance(params, dict) else {},
                stealth_mode=global_stealth,
            )
        return configs

    def get_channel(self, channel_type: str):
        """Create a channel instance from config."""
        configs = self.get_channel_configs()
        if channel_type not in configs:
            available = ", ".join(configs.keys()) or "none"
            raise ValueError(
                f"Channel '{channel_type}' not configured. "
                f"Available: {available}. Check config.yaml."
            )
        return ChannelRegistry.create(configs[channel_type])

    def get_default_channel_type(self) -> str:
        """Return the first configured channel type."""
        channels = self.get_channel_configs()
        if not channels:
            return "local"
        return next(iter(channels))

    def get_available_channels(self) -> list[str]:
        """List configured channel types."""
        return list(self.get_channel_configs().keys())

    # ── Stealth ──────────────────────────────────────────────────────

    def get_stealth_mode(self) -> str:
        return self.raw.get("stealth_mode", "off")

    # ── Corporate Server ─────────────────────────────────────────────

    def get_corporate_mode(self) -> str:
        corp = self.raw.get("corporate", {})
        return corp.get("mode", "sandbox")

    # ── Exfil ────────────────────────────────────────────────────────

    def get_exfil_webhook(self) -> str:
        exfil = self.raw.get("exfil", {})
        return exfil.get("webhook_url", "")

    # ── Benchmark ────────────────────────────────────────────────────

    def get_benchmark_config(self) -> dict:
        return self.raw.get("benchmark", {})

    # ── Scenarios ────────────────────────────────────────────────────

    def get_scenario_dir(self) -> Path:
        return Path(__file__).parent / "scenarios"

    # ── Env vars for subprocess ──────────────────────────────────────

    def get_env_for_provider(self, provider_name: str) -> dict[str, str]:
        """Get environment variables for a provider."""
        cfg = self.get_provider_config(provider_name)
        env = {}
        key_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GOOGLE_API_KEY",
        }
        env_key = key_map.get(provider_name)
        if env_key and cfg.get("api_key"):
            env[env_key] = cfg["api_key"]
        return env
