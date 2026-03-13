#!/usr/bin/env python3
"""MCParasite Connection Tester - Validates all platform credentials before running kill chains.

Usage:
    uv run python tests/test_connections.py                    # Test all configured platforms
    uv run python tests/test_connections.py --platform slack   # Test specific platform
    uv run python tests/test_connections.py --llm              # Test LLM providers only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ──────────────────────────────────────────────
# LLM Provider Tests
# ──────────────────────────────────────────────

def test_openai() -> dict:
    """Test OpenAI API connection."""
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return {"status": "skip", "msg": "OPENAI_API_KEY not set"}
    try:
        import openai
        client = openai.OpenAI(api_key=key)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'OK' in one word."}],
            max_tokens=5,
        )
        text = resp.choices[0].message.content.strip()
        return {"status": "ok", "msg": f"GPT-4o-mini responded: '{text}'"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_anthropic() -> dict:
    """Test Anthropic Claude API connection."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return {"status": "skip", "msg": "ANTHROPIC_API_KEY not set"}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        # Try models in order of preference
        for model_name in ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"]:
            try:
                resp = client.messages.create(
                    model=model_name,
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Say 'OK' in one word."}],
                )
                text = resp.content[0].text.strip()
                return {"status": "ok", "msg": f"{model_name} responded: '{text}'"}
            except Exception:
                continue
        return {"status": "fail", "msg": "All Claude models failed"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_gemini() -> dict:
    """Test Google Gemini API connection."""
    key = os.environ.get("GOOGLE_API_KEY", "")
    if not key:
        return {"status": "skip", "msg": "GOOGLE_API_KEY not set"}
    try:
        from google import genai
        client = genai.Client(api_key=key)
        # Try multiple models in case some are not available
        errors = []
        for model_name in ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents="Say 'OK' in one word.",
                )
                text = resp.text.strip()
                return {"status": "ok", "msg": f"{model_name} responded: '{text}'"}
            except Exception as me:
                errors.append(f"{model_name}: {str(me)[:40]}")
                continue
        return {"status": "fail", "msg": f"All models failed: {'; '.join(errors[:2])}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_ollama() -> dict:
    """Test Ollama local server."""
    try:
        import httpx
        r = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return {"status": "ok", "msg": f"Ollama running, {len(models)} models: {', '.join(models[:5])}"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "fail", "msg": f"Ollama not running: {str(e)[:80]}"}


# ──────────────────────────────────────────────
# Channel Platform Tests
# ──────────────────────────────────────────────

def test_slack() -> dict:
    """Test Slack Bot Token - calls auth.test API."""
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    if not token:
        return {"status": "skip", "msg": "SLACK_BOT_TOKEN not set"}
    try:
        import httpx
        r = httpx.get("https://slack.com/api/auth.test",
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
        data = r.json()
        if data.get("ok"):
            return {"status": "ok", "msg": f"Bot: {data.get('user', '?')} in workspace: {data.get('team', '?')}"}
        return {"status": "fail", "msg": data.get("error", "unknown error")}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_slack_channel() -> dict:
    """Test Slack channel access - can we read/write?"""
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL_ID", "")
    if not token or not channel:
        return {"status": "skip", "msg": "SLACK_BOT_TOKEN or SLACK_CHANNEL_ID not set"}
    try:
        import httpx
        r = httpx.get(f"https://slack.com/api/conversations.info?channel={channel}",
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
        data = r.json()
        if data.get("ok"):
            ch = data.get("channel", {})
            name = ch.get("name", "?")
            return {"status": "ok", "msg": f"Channel #{name} accessible, is_member={ch.get('is_member', '?')}"}
        return {"status": "fail", "msg": f"Cannot access channel: {data.get('error', '?')}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_github() -> dict:
    """Test GitHub token - calls /user API."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        # Try gh CLI
        try:
            import subprocess
            result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                token = result.stdout.strip()
                os.environ["GITHUB_TOKEN"] = token
        except Exception:
            pass
    if not token:
        return {"status": "skip", "msg": "GITHUB_TOKEN not set (and gh CLI not available)"}
    try:
        import httpx
        r = httpx.get("https://api.github.com/user",
                      headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
                      timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "msg": f"Authenticated as: {data.get('login', '?')} ({data.get('name', '?')})"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_github_repo() -> dict:
    """Test GitHub repo access for supply chain scenario."""
    token = os.environ.get("GITHUB_TOKEN", "")
    owner = os.environ.get("GITHUB_OWNER", "")
    repo = os.environ.get("GITHUB_REPO", "")
    if not token or not owner or not repo:
        return {"status": "skip", "msg": "GITHUB_TOKEN, GITHUB_OWNER, or GITHUB_REPO not set"}
    try:
        import httpx
        r = httpx.get(f"https://api.github.com/repos/{owner}/{repo}",
                      headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
                      timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "msg": f"Repo: {data.get('full_name', '?')} (private={data.get('private', '?')})"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_gmail() -> dict:
    """Test Gmail IMAP/SMTP connection."""
    email = os.environ.get("GMAIL_EMAIL", "")
    password = os.environ.get("GMAIL_APP_PASSWORD", "")
    if not email or not password:
        return {"status": "skip", "msg": "GMAIL_EMAIL or GMAIL_APP_PASSWORD not set"}
    try:
        import imaplib
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        status, _ = imap.login(email, password)
        if status == "OK":
            # Check inbox count
            imap.select("INBOX", readonly=True)
            _, msgs = imap.search(None, "ALL")
            count = len(msgs[0].split()) if msgs[0] else 0
            imap.logout()
            return {"status": "ok", "msg": f"IMAP login OK for {email}, {count} messages in INBOX"}
        imap.logout()
        return {"status": "fail", "msg": f"IMAP login failed: {status}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_discord() -> dict:
    """Test Discord Bot Token."""
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    if not token:
        return {"status": "skip", "msg": "DISCORD_BOT_TOKEN not set"}
    try:
        import httpx
        r = httpx.get("https://discord.com/api/v10/users/@me",
                      headers={"Authorization": f"Bot {token}"}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "msg": f"Bot: {data.get('username', '?')}#{data.get('discriminator', '?')}"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_jira() -> dict:
    """Test Jira API Token."""
    url = os.environ.get("JIRA_URL", "")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_API_TOKEN", "")
    if not url or not email or not token:
        return {"status": "skip", "msg": "JIRA_URL, JIRA_EMAIL, or JIRA_API_TOKEN not set"}
    try:
        import httpx
        import base64
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        r = httpx.get(f"{url.rstrip('/')}/rest/api/3/myself",
                      headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
                      timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "msg": f"Jira user: {data.get('displayName', '?')} ({data.get('emailAddress', '?')})"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_notion() -> dict:
    """Test Notion API Key."""
    key = os.environ.get("NOTION_API_KEY", "")
    if not key:
        return {"status": "skip", "msg": "NOTION_API_KEY not set"}
    try:
        import httpx
        r = httpx.get("https://api.notion.com/v1/users/me",
                      headers={"Authorization": f"Bearer {key}", "Notion-Version": "2022-06-28"},
                      timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "msg": f"Notion bot: {data.get('name', '?')} (type={data.get('type', '?')})"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


def test_confluence() -> dict:
    """Test Confluence API."""
    url = os.environ.get("CONFLUENCE_URL", "")
    email = os.environ.get("CONFLUENCE_EMAIL", "")
    token = os.environ.get("CONFLUENCE_API_TOKEN", "")
    if not url or not email or not token:
        return {"status": "skip", "msg": "CONFLUENCE_URL, CONFLUENCE_EMAIL, or CONFLUENCE_API_TOKEN not set"}
    try:
        import httpx
        import base64
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        r = httpx.get(f"{url.rstrip('/')}/wiki/api/v2/spaces?limit=1",
                      headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
                      timeout=10)
        if r.status_code == 200:
            data = r.json()
            spaces = data.get("results", [])
            return {"status": "ok", "msg": f"Confluence OK, {len(spaces)} space(s) found"}
        return {"status": "fail", "msg": f"HTTP {r.status_code}: {r.text[:80]}"}
    except Exception as e:
        return {"status": "fail", "msg": str(e)[:120]}


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

LLM_TESTS = {
    "openai": test_openai,
    "anthropic": test_anthropic,
    "gemini": test_gemini,
    "ollama": test_ollama,
}

PLATFORM_TESTS = {
    "slack": [("Slack Auth", test_slack), ("Slack Channel", test_slack_channel)],
    "github": [("GitHub Auth", test_github), ("GitHub Repo", test_github_repo)],
    "gmail": [("Gmail IMAP/SMTP", test_gmail)],
    "discord": [("Discord Bot", test_discord)],
    "jira": [("Jira API", test_jira)],
    "notion": [("Notion API", test_notion)],
    "confluence": [("Confluence API", test_confluence)],
}

ENV_VARS_GUIDE = {
    "slack": {
        "vars": ["SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID"],
        "setup": [
            "1. Go to https://api.slack.com/apps → Create New App",
            "2. 'From scratch' → name it 'MCParasite Test Bot'",
            "3. OAuth & Permissions → Bot Token Scopes: channels:history, channels:read, chat:write",
            "4. Install to Workspace → Copy 'Bot User OAuth Token' (xoxb-...)",
            "5. Create a test channel #mcparasite-test → invite the bot → copy Channel ID from URL",
        ],
    },
    "github": {
        "vars": ["GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO"],
        "setup": [
            "1. Create a test repo: gh repo create mcparasite-test-arena --private --clone",
            "2. Token: gh auth token (or Settings → Developer → Personal Access Tokens → repo scope)",
            "3. Set GITHUB_OWNER=your-org GITHUB_REPO=your-test-repo",
        ],
    },
    "gmail": {
        "vars": ["GMAIL_EMAIL", "GMAIL_APP_PASSWORD"],
        "setup": [
            "1. Google Account → Security → 2-Step Verification (must be ON)",
            "2. Search 'App Passwords' in Google Account settings",
            "3. Create app password for 'Mail' → Copy the 16-char password",
            "4. Set GMAIL_EMAIL=your@gmail.com GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx",
        ],
    },
    "discord": {
        "vars": ["DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID"],
        "setup": [
            "1. https://discord.com/developers/applications → New Application → 'MCParasite Test'",
            "2. Bot tab → Reset Token → Copy token",
            "3. Bot tab → Enable 'Message Content Intent'",
            "4. OAuth2 → URL Generator → bot scope → Send Messages + Read Message History",
            "5. Use generated URL to invite bot to your test server",
            "6. Copy channel ID (Developer Mode → right-click channel → Copy Channel ID)",
        ],
    },
    "jira": {
        "vars": ["JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT"],
        "setup": [
            "1. https://id.atlassian.com/manage-profile/security/api-tokens → Create API Token",
            "2. Set JIRA_URL=https://yourworkspace.atlassian.net",
            "3. Set JIRA_EMAIL=your@email.com JIRA_API_TOKEN=your-token",
            "4. Create test project → Set JIRA_PROJECT=MCPTEST",
        ],
    },
    "notion": {
        "vars": ["NOTION_API_KEY", "NOTION_PAGE_ID"],
        "setup": [
            "1. https://www.notion.so/my-integrations → New Integration → 'MCParasite Test'",
            "2. Copy 'Internal Integration Secret' (ntn_...)",
            "3. Create a test page in Notion → Share → Add your integration",
            "4. Copy page ID from URL (last 32 chars after the page title)",
        ],
    },
    "confluence": {
        "vars": ["CONFLUENCE_URL", "CONFLUENCE_EMAIL", "CONFLUENCE_API_TOKEN", "CONFLUENCE_SPACE"],
        "setup": [
            "1. Same Atlassian API token as Jira (shared across products)",
            "2. Set CONFLUENCE_URL=https://yourworkspace.atlassian.net",
            "3. Set CONFLUENCE_SPACE=MCPTEST",
        ],
    },
}


def load_env_file():
    """Load .env file if it exists."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value:
                    # Override empty env vars too (e.g. ANTHROPIC_API_KEY="" in shell)
                    if not os.environ.get(key):
                        os.environ[key] = value
        console.print(f"[dim]Loaded .env from {env_path}[/dim]")


def main():
    parser = argparse.ArgumentParser(description="MCParasite Connection Tester")
    parser.add_argument("--platform", "-p", help="Test specific platform (slack, github, gmail, discord, jira, notion)")
    parser.add_argument("--llm", action="store_true", help="Test LLM providers only")
    parser.add_argument("--setup", "-s", help="Show setup guide for a platform")
    parser.add_argument("--all", "-a", action="store_true", help="Test everything")
    args = parser.parse_args()

    load_env_file()

    # Show setup guide
    if args.setup:
        platform = args.setup.lower()
        if platform not in ENV_VARS_GUIDE:
            console.print(f"[red]Unknown platform: {platform}[/red]")
            console.print(f"Available: {', '.join(ENV_VARS_GUIDE.keys())}")
            return
        guide = ENV_VARS_GUIDE[platform]
        console.print(Panel(
            f"[bold]{platform.upper()} Setup Guide[/bold]\n\n"
            f"[cyan]Required ENV vars:[/cyan] {', '.join(guide['vars'])}\n\n"
            + "\n".join(f"  {step}" for step in guide["setup"]),
            title=f"🔧 {platform.upper()} Setup",
            style="blue",
        ))
        return

    console.print(Panel(
        "[bold red]MCParasite Connection Tester[/bold red]\n"
        "Validates all platform credentials before running kill chains.",
        style="red",
    ))

    # LLM Tests
    if args.llm or args.all or not args.platform:
        table = Table(title="🧠 LLM Providers", show_header=True)
        table.add_column("Provider", style="cyan", width=12)
        table.add_column("Status", width=6)
        table.add_column("Details", style="dim")

        for name, test_fn in LLM_TESTS.items():
            result = test_fn()
            icon = {"ok": "✅", "fail": "❌", "skip": "⏭️"}[result["status"]]
            color = {"ok": "green", "fail": "red", "skip": "yellow"}[result["status"]]
            table.add_row(name, f"[{color}]{icon}[/{color}]", result["msg"])

        console.print(table)
        console.print()

    if args.llm:
        return

    # Platform Tests
    platforms_to_test = PLATFORM_TESTS.keys() if (args.all or not args.platform) else [args.platform]

    table = Table(title="📡 Channel Platforms", show_header=True)
    table.add_column("Platform", style="cyan", width=16)
    table.add_column("Status", width=6)
    table.add_column("Details", style="dim")

    for platform in platforms_to_test:
        if platform not in PLATFORM_TESTS:
            table.add_row(platform, "[red]❓[/red]", "Unknown platform")
            continue
        for test_name, test_fn in PLATFORM_TESTS[platform]:
            result = test_fn()
            icon = {"ok": "✅", "fail": "❌", "skip": "⏭️"}[result["status"]]
            color = {"ok": "green", "fail": "red", "skip": "yellow"}[result["status"]]
            table.add_row(test_name, f"[{color}]{icon}[/{color}]", result["msg"])

    console.print(table)

    # Show missing credentials help
    console.print()
    missing = []
    for platform in platforms_to_test:
        if platform in ENV_VARS_GUIDE:
            guide = ENV_VARS_GUIDE[platform]
            for var in guide["vars"]:
                if not os.environ.get(var):
                    missing.append((platform, var))

    if missing:
        console.print("[yellow]Missing credentials:[/yellow]")
        for platform, var in missing:
            console.print(f"  [dim]export {var}=...[/dim]  (run: [cyan]uv run python test_connections.py --setup {platform}[/cyan])")


if __name__ == "__main__":
    main()
