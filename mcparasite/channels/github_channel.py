"""GitHub Issues/PRs propagation channel."""

from __future__ import annotations

import os

from mcparasite.channels.base import ChannelConfig, PropagationChannel
from mcparasite.channels.registry import register_channel


@register_channel("github")
class GitHubChannel(PropagationChannel):
    """GitHub Issues and PR comments as a worm propagation medium.

    Attack scenario: Agent A creates/comments on a GitHub issue with
    hidden worm payload. Agent B (code review bot, CI/CD bot) reads
    the issue and executes worm instructions.

    Supply chain angle: Developer tools that read GitHub issues/PRs
    are increasingly common (Copilot Workspace, Cursor, Devin, etc.)
    """

    def _token(self) -> str:
        return self.config.params.get("token") or os.environ.get("GITHUB_TOKEN", "")

    def _owner(self) -> str:
        return self.config.params.get("owner") or os.environ.get("GITHUB_OWNER", "")

    def _repo(self) -> str:
        return self.config.params.get("repo") or os.environ.get("GITHUB_REPO", "")

    def get_mcp_command(self) -> list[str]:
        cmd = ["uv", "run", "python", "mcparasite/servers/github_mcp.py"]
        token = self._token()
        if token:
            cmd.extend(["--token", token])
        repo = self._repo()
        if repo:
            cmd.extend(["--repo", repo])
        owner = self._owner()
        if owner:
            cmd.extend(["--owner", owner])
        cmd.extend(self.get_stealth_flag())
        return cmd

    def get_server_name(self) -> str:
        return "github"

    def get_env_vars(self) -> dict[str, str]:
        env = {}
        token = self._token()
        if token:
            env["GITHUB_TOKEN"] = token
        owner = self._owner()
        if owner:
            env["GITHUB_OWNER"] = owner
        repo = self._repo()
        if repo:
            env["GITHUB_REPO"] = repo
        return env

    def get_send_tool_name(self) -> str:
        return "create_github_comment"

    def get_read_tool_name(self) -> str:
        return "read_github_issues"

    def get_channel_description(self) -> str:
        repo = self._repo() or "repo"
        owner = self._owner() or "owner"
        return f"GitHub repo {owner}/{repo} issues"

    def validate_config(self) -> tuple[bool, str]:
        if not self._token():
            return False, "GitHub requires 'token' param or GITHUB_TOKEN env var."
        if not self._repo() or not self._owner():
            return False, "GitHub requires 'repo'/'owner' params or GITHUB_REPO/GITHUB_OWNER env vars."
        return True, ""
