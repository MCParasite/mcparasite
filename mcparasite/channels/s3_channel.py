"""AWS S3 Shared Bucket propagation channel - cloud infra poisoning.

Attack scenario: Agent A writes a config file / status report to a
shared S3 bucket with hidden worm payload. Agent B (infra monitoring
bot, deployment bot) reads the file and executes worm instructions.

This demonstrates that ANY shared data store can be a worm propagation
vector. S3 buckets are used for: deployment configs, log aggregation,
data pipelines, model artifacts, shared secrets.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("s3")
class S3Channel(PropagationChannel):
    """AWS S3 shared buckets as worm propagation medium."""

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/s3_mcp.py"]
        p = self.config.params
        if p.get("bucket"):
            cmd.extend(["--bucket", p["bucket"]])
        if p.get("prefix"):
            cmd.extend(["--prefix", p["prefix"]])
        if p.get("region"):
            cmd.extend(["--region", p["region"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "s3"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        for key in ("aws_access_key_id", "aws_secret_access_key", "aws_region"):
            if self.config.params.get(key):
                env[key.upper()] = self.config.params[key]
        return env

    def get_send_tool_name(self) -> str:
        return "write_s3_object"

    def get_read_tool_name(self) -> str:
        return "read_s3_object"

    def get_channel_description(self) -> str:
        bucket = self.config.params.get("bucket", "shared-bucket")
        return f"S3 bucket s3://{bucket}"

    def validate_config(self) -> tuple[bool, str]:
        p = self.config.params
        if not p.get("bucket"):
            return False, "S3 requires 'bucket' name."
        return True, ""
