"""
MCParasite - Auth Auditor: OAuth & Authentication Flow Analyzer for MCP Servers

Audits MCP server authentication implementations for:
- OAuth 2.0 misconfigurations (missing PKCE, weak redirect validation, token exposure)
- Transport layer security issues (no TLS, missing auth on SSE/streamable HTTP)
- Token handling vulnerabilities (tokens in URLs, missing expiry, no rotation)
- mcp-remote proxy risks (CVE-2025-6514 pattern: wildcard redirect_uri)

Based on MCP OAuth 2.1 spec (2025-03-26) and known CVEs.

FOR AUTHORIZED SECURITY RESEARCH ONLY.
"""

import json
import re
import sys
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse, parse_qs

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("auth_auditor")


class AuthRisk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuthFinding:
    """A single authentication/authorization finding."""
    server_url: str
    risk: AuthRisk
    category: str
    title: str
    description: str
    evidence: str = ""
    cve_ref: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "server_url": self.server_url,
            "risk": self.risk.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:300],
            "cve_ref": self.cve_ref,
            "remediation": self.remediation,
        }


@dataclass
class OAuthConfig:
    """Discovered OAuth configuration for an MCP server."""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    registration_endpoint: str = ""
    revocation_endpoint: str = ""
    supported_grant_types: list[str] = field(default_factory=list)
    supported_response_types: list[str] = field(default_factory=list)
    supported_code_challenge_methods: list[str] = field(default_factory=list)
    supported_scopes: list[str] = field(default_factory=list)
    requires_pkce: bool = False
    raw_metadata: dict = field(default_factory=dict)


@dataclass
class AuthAuditReport:
    """Complete authentication audit report."""
    server_url: str = ""
    oauth_config: OAuthConfig | None = None
    transport_type: str = ""  # stdio, sse, streamable_http
    findings: list[AuthFinding] = field(default_factory=list)
    scan_time: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == AuthRisk.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == AuthRisk.HIGH)

    def to_dict(self) -> dict:
        return {
            "server_url": self.server_url,
            "transport_type": self.transport_type,
            "oauth_discovered": self.oauth_config is not None,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time": self.scan_time,
        }


# ─── Known MCP Auth Vulnerability Patterns ───

MCP_AUTH_CVES = {
    "CVE-2025-6514": {
        "title": "mcp-remote wildcard redirect_uri",
        "pattern": "redirect_uri validation bypass via localhost wildcards",
        "severity": AuthRisk.CRITICAL,
        "cvss": 9.6,
    },
    "CVE-2025-49596": {
        "title": "MCP Inspector SSRF via callback",
        "pattern": "OAuth callback endpoint SSRF",
        "severity": AuthRisk.CRITICAL,
        "cvss": 9.4,
    },
}


class AuthAuditor:
    """Audits MCP server authentication implementations."""

    def __init__(self, timeout: float = 10.0):
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)
        self.console = Console(stderr=True)

    def close(self):
        self.client.close()

    # ─── OAuth Discovery ───

    def discover_oauth(self, server_url: str) -> OAuthConfig | None:
        """Attempt to discover OAuth configuration from MCP server.

        Checks:
        1. .well-known/oauth-authorization-server
        2. .well-known/openid-configuration
        3. Common OAuth endpoint patterns
        """
        parsed = urlparse(server_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Try well-known endpoints
        discovery_paths = [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ]

        for path in discovery_paths:
            url = base + path
            try:
                resp = self.client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    logger.info(f"OAuth discovery found at {url}")
                    return self._parse_oauth_metadata(data)
            except (httpx.HTTPError, json.JSONDecodeError):
                continue

        return None

    def _parse_oauth_metadata(self, data: dict) -> OAuthConfig:
        """Parse OAuth server metadata document."""
        return OAuthConfig(
            authorization_endpoint=data.get("authorization_endpoint", ""),
            token_endpoint=data.get("token_endpoint", ""),
            registration_endpoint=data.get("registration_endpoint", ""),
            revocation_endpoint=data.get("revocation_endpoint", ""),
            supported_grant_types=data.get("grant_types_supported", []),
            supported_response_types=data.get("response_types_supported", []),
            supported_code_challenge_methods=data.get("code_challenge_methods_supported", []),
            supported_scopes=data.get("scopes_supported", []),
            requires_pkce="S256" in data.get("code_challenge_methods_supported", []),
            raw_metadata=data,
        )

    # ─── Transport Security Checks ───

    def check_transport_security(self, server_url: str) -> list[AuthFinding]:
        """Check transport-layer security of the MCP server."""
        findings = []
        parsed = urlparse(server_url)

        # 1. No TLS
        if parsed.scheme == "http":
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.HIGH,
                category="transport",
                title="No TLS encryption",
                description=(
                    "Server uses HTTP instead of HTTPS. MCP tool calls, "
                    "including potentially sensitive data, are transmitted in plaintext."
                ),
                evidence=f"Scheme: {parsed.scheme}",
                remediation="Enable TLS/HTTPS for all MCP server endpoints.",
            ))

        # 2. Check if SSE/streamable-http endpoint responds without auth
        try:
            resp = self.client.get(server_url, headers={"Accept": "text/event-stream"})
            if resp.status_code == 200:
                findings.append(AuthFinding(
                    server_url=server_url,
                    risk=AuthRisk.HIGH,
                    category="transport",
                    title="SSE endpoint accessible without authentication",
                    description=(
                        "The server's SSE endpoint responds to unauthenticated requests. "
                        "Anyone who can reach this endpoint can connect as an MCP client."
                    ),
                    evidence=f"Status: {resp.status_code}, Content-Type: {resp.headers.get('content-type', '')}",
                    remediation="Require authentication tokens for all SSE connections.",
                ))
        except httpx.HTTPError:
            pass

        # 3. Check for token in URL query params
        if "token" in parsed.query.lower() or "key" in parsed.query.lower():
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.HIGH,
                category="transport",
                title="Authentication token in URL",
                description=(
                    "Server URL contains authentication token in query parameters. "
                    "Tokens in URLs are logged in browser history, server logs, "
                    "and referrer headers."
                ),
                evidence=f"Query: {parsed.query[:100]}",
                remediation="Use Authorization headers instead of URL query parameters.",
            ))

        return findings

    # ─── OAuth Configuration Audit ───

    def audit_oauth_config(self, config: OAuthConfig, server_url: str) -> list[AuthFinding]:
        """Audit OAuth configuration for security issues."""
        findings = []

        # 1. Missing PKCE support
        if "S256" not in config.supported_code_challenge_methods:
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.CRITICAL,
                category="oauth",
                title="PKCE not supported",
                description=(
                    "OAuth server does not support PKCE (Proof Key for Code Exchange). "
                    "MCP OAuth 2.1 spec requires PKCE with S256. Without it, "
                    "authorization codes can be intercepted and replayed."
                ),
                evidence=f"Supported methods: {config.supported_code_challenge_methods}",
                remediation="Enable PKCE with S256 code challenge method.",
            ))

        # 1b. Plain PKCE method is insecure
        if "plain" in config.supported_code_challenge_methods:
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.HIGH,
                category="oauth",
                title="PKCE plain method supported",
                description=(
                    "OAuth server supports 'plain' PKCE method which provides "
                    "no security benefit. Only S256 should be supported."
                ),
                evidence=f"Methods: {config.supported_code_challenge_methods}",
                remediation="Remove 'plain' from supported code challenge methods.",
            ))

        # 2. Implicit grant still supported
        if "implicit" in config.supported_grant_types or "token" in config.supported_response_types:
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.HIGH,
                category="oauth",
                title="Implicit grant type supported",
                description=(
                    "OAuth server supports the implicit grant type which exposes "
                    "access tokens in URL fragments. OAuth 2.1 deprecates implicit grant."
                ),
                evidence=f"Grant types: {config.supported_grant_types}, Response types: {config.supported_response_types}",
                remediation="Remove implicit grant support. Use authorization_code with PKCE.",
            ))

        # 3. Password grant supported
        if "password" in config.supported_grant_types:
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.HIGH,
                category="oauth",
                title="Resource owner password grant supported",
                description=(
                    "OAuth server supports password grant type. This is deprecated "
                    "in OAuth 2.1 and exposes user credentials to the client."
                ),
                evidence=f"Grant types: {config.supported_grant_types}",
                remediation="Remove password grant support.",
            ))

        # 4. No revocation endpoint
        if not config.revocation_endpoint:
            findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.MEDIUM,
                category="oauth",
                title="No token revocation endpoint",
                description=(
                    "OAuth server does not expose a revocation endpoint. "
                    "Users cannot revoke compromised tokens."
                ),
                remediation="Implement RFC 7009 token revocation endpoint.",
            ))

        # 5. Dynamic client registration without auth
        if config.registration_endpoint:
            try:
                resp = self.client.post(
                    config.registration_endpoint,
                    json={"redirect_uris": ["http://localhost:12345/callback"]},
                )
                if resp.status_code in (200, 201):
                    findings.append(AuthFinding(
                        server_url=server_url,
                        risk=AuthRisk.HIGH,
                        category="oauth",
                        title="Open dynamic client registration",
                        description=(
                            "OAuth server allows unauthenticated dynamic client registration. "
                            "Attackers can register malicious clients with arbitrary redirect URIs."
                        ),
                        evidence=f"Registration endpoint: {config.registration_endpoint}, Status: {resp.status_code}",
                        cve_ref="CVE-2025-6514",
                        remediation="Require authentication for dynamic client registration.",
                    ))
            except httpx.HTTPError:
                pass

        return findings

    # ─── Redirect URI Validation ───

    def check_redirect_uri_validation(
        self,
        authorization_endpoint: str,
        server_url: str,
    ) -> list[AuthFinding]:
        """Test redirect_uri validation strength.

        Tests various bypass techniques:
        - Open redirects
        - Subdomain wildcards
        - Path traversal
        - Port wildcards (CVE-2025-6514 pattern)
        """
        findings = []

        # Test payloads for redirect_uri validation bypass
        test_redirects = [
            {
                "uri": "http://localhost:0/callback",
                "technique": "Port 0 (CVE-2025-6514 pattern)",
                "risk": AuthRisk.CRITICAL,
                "cve": "CVE-2025-6514",
            },
            {
                "uri": "http://localhost:99999/callback",
                "technique": "Arbitrary port on localhost",
                "risk": AuthRisk.HIGH,
                "cve": "",
            },
            {
                "uri": "http://127.0.0.1:8080/callback",
                "technique": "IP instead of hostname",
                "risk": AuthRisk.MEDIUM,
                "cve": "",
            },
            {
                "uri": "http://localhost/callback/../../../etc/passwd",
                "technique": "Path traversal in redirect",
                "risk": AuthRisk.HIGH,
                "cve": "",
            },
            {
                "uri": "http://attacker.com/callback",
                "technique": "External domain redirect",
                "risk": AuthRisk.CRITICAL,
                "cve": "",
            },
            {
                "uri": "http://localhost@attacker.com/callback",
                "technique": "Credential section bypass",
                "risk": AuthRisk.CRITICAL,
                "cve": "",
            },
            {
                "uri": "javascript:alert(1)",
                "technique": "JavaScript scheme injection",
                "risk": AuthRisk.CRITICAL,
                "cve": "",
            },
        ]

        for test in test_redirects:
            try:
                resp = self.client.get(
                    authorization_endpoint,
                    params={
                        "response_type": "code",
                        "client_id": "test-audit-client",
                        "redirect_uri": test["uri"],
                        "state": "mcparasite-audit-state",
                    },
                )

                # If server doesn't reject with 400/403, the redirect may be accepted
                if resp.status_code in (200, 302, 303, 307):
                    location = resp.headers.get("location", "")
                    if test["uri"] in location or resp.status_code == 200:
                        findings.append(AuthFinding(
                            server_url=server_url,
                            risk=test["risk"],
                            category="redirect_uri",
                            title=f"Redirect URI bypass: {test['technique']}",
                            description=(
                                f"Authorization endpoint accepted redirect_uri '{test['uri']}'. "
                                f"Technique: {test['technique']}. "
                                "This could allow authorization code interception."
                            ),
                            evidence=f"Status: {resp.status_code}, Location: {location[:100]}",
                            cve_ref=test["cve"],
                            remediation="Implement strict redirect_uri validation with exact match.",
                        ))

            except httpx.HTTPError as e:
                logger.debug(f"Redirect test failed for {test['uri']}: {e}")

        return findings

    # ─── MCP-Specific Auth Checks ───

    def check_mcp_auth_patterns(self, server_url: str) -> list[AuthFinding]:
        """Check for MCP-specific authentication anti-patterns."""
        findings = []
        parsed = urlparse(server_url)

        # 1. Check for tool-level auth bypass
        # MCP spec allows per-tool auth, but most implementations don't enforce it
        findings.append(AuthFinding(
            server_url=server_url,
            risk=AuthRisk.INFO,
            category="mcp_auth",
            title="Per-tool authorization check recommended",
            description=(
                "MCP spec supports per-tool authorization but most servers "
                "only check auth at connection time. Consider adding tool-level "
                "auth checks for sensitive operations."
            ),
            remediation="Implement tool-level authorization checks.",
        ))

        # 2. Check if server exposes tool definitions to unauthenticated clients
        try:
            # Try tools/list without auth
            resp = self.client.post(
                server_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                },
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "result" in data and "tools" in data.get("result", {}):
                        findings.append(AuthFinding(
                            server_url=server_url,
                            risk=AuthRisk.MEDIUM,
                            category="mcp_auth",
                            title="Tool list accessible without authentication",
                            description=(
                                "Server exposes tool definitions to unauthenticated clients. "
                                "Attackers can enumerate available tools for reconnaissance."
                            ),
                            evidence=f"Found {len(data['result']['tools'])} tools without auth",
                            remediation="Require authentication before exposing tool definitions.",
                        ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except httpx.HTTPError:
            pass

        return findings

    # ─── Full Audit Pipeline ───

    def audit(self, server_url: str) -> AuthAuditReport:
        """Run complete authentication audit on an MCP server."""
        report = AuthAuditReport(
            server_url=server_url,
            scan_time=datetime.now().isoformat(),
        )

        logger.info(f"Starting auth audit: {server_url}")

        # 1. Transport security
        transport_findings = self.check_transport_security(server_url)
        report.findings.extend(transport_findings)

        # 2. OAuth discovery
        oauth_config = self.discover_oauth(server_url)
        report.oauth_config = oauth_config

        if oauth_config:
            # 3. OAuth config audit
            oauth_findings = self.audit_oauth_config(oauth_config, server_url)
            report.findings.extend(oauth_findings)

            # 4. Redirect URI validation
            if oauth_config.authorization_endpoint:
                redirect_findings = self.check_redirect_uri_validation(
                    oauth_config.authorization_endpoint,
                    server_url,
                )
                report.findings.extend(redirect_findings)
        else:
            report.findings.append(AuthFinding(
                server_url=server_url,
                risk=AuthRisk.INFO,
                category="oauth",
                title="No OAuth discovery endpoint found",
                description=(
                    "Server does not expose OAuth metadata at standard well-known paths. "
                    "This may indicate no OAuth support or custom auth implementation."
                ),
            ))

        # 5. MCP-specific checks
        mcp_findings = self.check_mcp_auth_patterns(server_url)
        report.findings.extend(mcp_findings)

        return report

    def audit_config_file(self, config: dict) -> list[AuthFinding]:
        """Audit an MCP client configuration (e.g., claude_desktop_config.json).

        Checks for common misconfigurations in how clients are configured
        to connect to MCP servers.
        """
        findings = []

        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            # Check for env vars with secrets
            env = server_config.get("env", {})
            for key, value in env.items():
                if any(secret in key.upper() for secret in ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]):
                    if value and not value.startswith("${") and value != "***":
                        findings.append(AuthFinding(
                            server_url=f"config:{name}",
                            risk=AuthRisk.HIGH,
                            category="config",
                            title=f"Hardcoded secret in config: {key}",
                            description=(
                                f"MCP server '{name}' has hardcoded secret '{key}' in config. "
                                "Secrets should use environment variable references."
                            ),
                            evidence=f"Key: {key}, Value: {value[:5]}{'*' * 10}",
                            remediation=f"Use environment variable reference: ${{{key}}}",
                        ))

            # Check for HTTP (non-TLS) server URLs
            url = server_config.get("url", "")
            if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                findings.append(AuthFinding(
                    server_url=f"config:{name}",
                    risk=AuthRisk.HIGH,
                    category="config",
                    title=f"Remote MCP server without TLS: {name}",
                    description=f"Server '{name}' uses HTTP for remote connection.",
                    evidence=f"URL: {url}",
                    remediation="Use HTTPS for remote MCP server connections.",
                ))

            # Check command args for inline secrets
            args = server_config.get("args", [])
            for arg in args:
                if isinstance(arg, str) and any(
                    pattern in arg for pattern in ["--api-key=", "--token=", "--password=", "--secret="]
                ):
                    findings.append(AuthFinding(
                        server_url=f"config:{name}",
                        risk=AuthRisk.HIGH,
                        category="config",
                        title=f"Secret in command args: {name}",
                        description=(
                            f"Server '{name}' has secrets passed via command line arguments. "
                            "These are visible in process listings."
                        ),
                        evidence=f"Arg: {arg[:30]}...",
                        remediation="Use environment variables instead of command-line args for secrets.",
                    ))

        return findings

    def print_report(self, report: AuthAuditReport) -> None:
        """Print formatted auth audit report."""
        console = Console()

        color = "red" if report.critical_count > 0 else "yellow" if report.high_count > 0 else "green"
        console.print(Panel(
            f"MCParasite Auth Audit: {report.server_url}",
            style=f"bold {color}",
        ))

        console.print(f"OAuth: {'discovered' if report.oauth_config else 'not found'}")
        console.print(f"Findings: {len(report.findings)}")
        console.print(f"  CRITICAL: {report.critical_count}", style="bold red")
        console.print(f"  HIGH: {report.high_count}", style="bold yellow")

        if report.oauth_config:
            console.print(f"\n[bold]OAuth Config:[/bold]")
            console.print(f"  Auth endpoint: {report.oauth_config.authorization_endpoint}")
            console.print(f"  Token endpoint: {report.oauth_config.token_endpoint}")
            console.print(f"  PKCE required: {report.oauth_config.requires_pkce}")
            console.print(f"  Grant types: {report.oauth_config.supported_grant_types}")

        if not report.findings:
            console.print("\n[green]No authentication issues found.[/green]")
            return

        table = Table(title="Auth Findings", show_lines=True)
        table.add_column("Risk", width=10)
        table.add_column("Category", width=15)
        table.add_column("Title", width=40)
        table.add_column("CVE", width=16)
        table.add_column("Evidence", width=40)

        styles = {
            AuthRisk.CRITICAL: "bold red",
            AuthRisk.HIGH: "bold yellow",
            AuthRisk.MEDIUM: "yellow",
            AuthRisk.LOW: "dim",
            AuthRisk.INFO: "dim cyan",
        }

        for finding in sorted(report.findings, key=lambda f: list(AuthRisk).index(f.risk)):
            style = styles.get(finding.risk, "")
            table.add_row(
                f"[{style}]{finding.risk.value}[/]",
                finding.category,
                finding.title,
                finding.cve_ref or "-",
                finding.evidence[:40] if finding.evidence else "-",
            )

        console.print(table)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCParasite Auth Auditor")
    parser.add_argument("target", help="MCP server URL or config file path")
    parser.add_argument("--config", "-c", action="store_true", help="Audit a config file instead of a server")
    args = parser.parse_args()

    auditor = AuthAuditor()

    try:
        if args.config:
            with open(args.target) as f:
                config = json.load(f)
            findings = auditor.audit_config_file(config)
            report = AuthAuditReport(
                server_url=args.target,
                findings=findings,
                scan_time=datetime.now().isoformat(),
            )
        else:
            report = auditor.audit(args.target)

        auditor.print_report(report)
        print(f"\nJSON: {json.dumps(report.to_dict(), indent=2)}")
    finally:
        auditor.close()
