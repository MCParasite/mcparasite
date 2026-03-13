"""CI/CD Pipeline propagation channel - build system injection.

Attack scenario: Agent A writes build logs / pipeline comments with
hidden worm payload. Agent B (SRE bot monitoring builds, deployment
automation bot) reads the logs and executes worm instructions.

Supports: GitHub Actions (via API), Jenkins (via REST API),
GitLab CI (via API), or local simulation.

This is the software supply chain nightmare scenario: a compromised
CI/CD pipeline agent can backdoor every build it touches.
"""

from __future__ import annotations

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("cicd")
class CICDChannel(PropagationChannel):
    """CI/CD pipeline logs and artifacts as worm propagation medium."""

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/cicd_mcp.py"]
        p = self.config.params
        platform = p.get("platform", "github_actions")
        cmd.extend(["--platform", platform])
        if p.get("token"):
            cmd.extend(["--token", p["token"]])
        if p.get("repo"):
            cmd.extend(["--repo", p["repo"]])
        if p.get("url"):
            cmd.extend(["--url", p["url"]])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "cicd"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        if self.config.params.get("token"):
            env["CICD_TOKEN"] = self.config.params["token"]
        return env

    def get_send_tool_name(self) -> str:
        return "write_pipeline_log"

    def get_read_tool_name(self) -> str:
        return "read_pipeline_logs"

    def get_channel_description(self) -> str:
        platform = self.config.params.get("platform", "CI/CD")
        return f"{platform} pipeline logs"

    def validate_config(self) -> tuple[bool, str]:
        p = self.config.params
        platform = p.get("platform", "github_actions")
        if platform != "local" and not p.get("token"):
            return False, f"CI/CD ({platform}) requires 'token' for API access."
        return True, ""
