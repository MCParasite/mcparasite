"""Tests for MCParasite auth auditor module."""

import json
import pytest
from mcparasite.scanner.auth_auditor import (
    AuthAuditor,
    AuthAuditReport,
    AuthFinding,
    AuthRisk,
    OAuthConfig,
    MCP_AUTH_CVES,
)


class TestOAuthConfig:
    """Tests for OAuth configuration parsing and analysis."""

    def test_parse_full_config(self):
        auditor = AuthAuditor()
        config = auditor._parse_oauth_metadata({
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
            "revocation_endpoint": "https://auth.example.com/revoke",
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["read", "write"],
        })
        assert config.authorization_endpoint == "https://auth.example.com/authorize"
        assert config.requires_pkce is True
        assert "S256" in config.supported_code_challenge_methods
        auditor.close()

    def test_pkce_detection(self):
        auditor = AuthAuditor()
        # With PKCE
        config_with = auditor._parse_oauth_metadata({
            "code_challenge_methods_supported": ["S256"],
        })
        assert config_with.requires_pkce is True

        # Without PKCE
        config_without = auditor._parse_oauth_metadata({
            "code_challenge_methods_supported": [],
        })
        assert config_without.requires_pkce is False
        auditor.close()


class TestOAuthAudit:
    """Tests for OAuth configuration auditing."""

    def setup_method(self):
        self.auditor = AuthAuditor()

    def teardown_method(self):
        self.auditor.close()

    def test_missing_pkce(self):
        config = OAuthConfig(
            supported_code_challenge_methods=[],
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        pkce_findings = [f for f in findings if "PKCE" in f.title]
        assert len(pkce_findings) > 0
        assert pkce_findings[0].risk == AuthRisk.CRITICAL

    def test_plain_pkce_warning(self):
        config = OAuthConfig(
            supported_code_challenge_methods=["plain", "S256"],
            requires_pkce=True,
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        plain_findings = [f for f in findings if "plain" in f.title.lower()]
        assert len(plain_findings) > 0

    def test_implicit_grant_warning(self):
        config = OAuthConfig(
            supported_grant_types=["authorization_code", "implicit"],
            supported_code_challenge_methods=["S256"],
            requires_pkce=True,
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        implicit_findings = [f for f in findings if "implicit" in f.title.lower()]
        assert len(implicit_findings) > 0

    def test_password_grant_warning(self):
        config = OAuthConfig(
            supported_grant_types=["authorization_code", "password"],
            supported_code_challenge_methods=["S256"],
            requires_pkce=True,
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        pw_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(pw_findings) > 0

    def test_missing_revocation(self):
        config = OAuthConfig(
            revocation_endpoint="",
            supported_code_challenge_methods=["S256"],
            requires_pkce=True,
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        revoke_findings = [f for f in findings if "revocation" in f.title.lower()]
        assert len(revoke_findings) > 0

    def test_secure_config_minimal_findings(self):
        config = OAuthConfig(
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            revocation_endpoint="https://auth.example.com/revoke",
            supported_grant_types=["authorization_code"],
            supported_response_types=["code"],
            supported_code_challenge_methods=["S256"],
            requires_pkce=True,
        )
        findings = self.auditor.audit_oauth_config(config, "https://test.com")
        high_findings = [f for f in findings if f.risk in (AuthRisk.CRITICAL, AuthRisk.HIGH)]
        assert len(high_findings) == 0


class TestTransportSecurity:
    """Tests for transport layer security checks."""

    def setup_method(self):
        self.auditor = AuthAuditor()

    def teardown_method(self):
        self.auditor.close()

    def test_http_no_tls(self):
        findings = self.auditor.check_transport_security("http://mcp-server.example.com/mcp")
        tls_findings = [f for f in findings if "TLS" in f.title]
        assert len(tls_findings) > 0
        assert tls_findings[0].risk == AuthRisk.HIGH

    def test_token_in_url(self):
        findings = self.auditor.check_transport_security(
            "https://mcp-server.example.com/mcp?token=abc123&key=secret"
        )
        token_findings = [f for f in findings if "token" in f.title.lower()]
        assert len(token_findings) > 0

    def test_https_no_token_minimal_findings(self):
        findings = self.auditor.check_transport_security("https://secure-server.example.com/mcp")
        # HTTPS with no token in URL should have minimal transport findings
        transport_critical = [f for f in findings if f.risk == AuthRisk.CRITICAL and f.category == "transport"]
        assert len(transport_critical) == 0


class TestConfigAudit:
    """Tests for MCP client config file auditing."""

    def setup_method(self):
        self.auditor = AuthAuditor()

    def teardown_method(self):
        self.auditor.close()

    def test_hardcoded_secrets(self):
        config = {
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-1234567890abcdef",
                        "NORMAL_VAR": "safe_value",
                    },
                },
            },
        }
        findings = self.auditor.audit_config_file(config)
        secret_findings = [f for f in findings if "secret" in f.category.lower() or "Hardcoded" in f.title]
        assert len(secret_findings) > 0

    def test_remote_http_server(self):
        config = {
            "mcpServers": {
                "remote-server": {
                    "url": "http://remote.example.com:8080/mcp",
                },
            },
        }
        findings = self.auditor.audit_config_file(config)
        tls_findings = [f for f in findings if "TLS" in f.title]
        assert len(tls_findings) > 0

    def test_secret_in_args(self):
        config = {
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js", "--api-key=sk-secret123"],
                },
            },
        }
        findings = self.auditor.audit_config_file(config)
        arg_findings = [f for f in findings if "command" in f.title.lower() or "args" in f.title.lower()]
        assert len(arg_findings) > 0

    def test_clean_config(self):
        config = {
            "mcpServers": {
                "local-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "NODE_ENV": "production",
                    },
                },
            },
        }
        findings = self.auditor.audit_config_file(config)
        high_findings = [f for f in findings if f.risk in (AuthRisk.CRITICAL, AuthRisk.HIGH)]
        assert len(high_findings) == 0


class TestAuthReport:
    """Tests for auth audit report."""

    def test_report_counts(self):
        report = AuthAuditReport()
        report.findings = [
            AuthFinding("url", AuthRisk.CRITICAL, "cat", "title", "desc"),
            AuthFinding("url", AuthRisk.HIGH, "cat", "title", "desc"),
            AuthFinding("url", AuthRisk.LOW, "cat", "title", "desc"),
        ]
        assert report.critical_count == 1
        assert report.high_count == 1

    def test_report_to_dict(self):
        report = AuthAuditReport(
            server_url="https://test.com",
            scan_time="2025-01-01T00:00:00",
        )
        d = report.to_dict()
        assert d["server_url"] == "https://test.com"
        assert d["findings_count"] == 0

    def test_known_cves_defined(self):
        assert "CVE-2025-6514" in MCP_AUTH_CVES
        assert "CVE-2025-49596" in MCP_AUTH_CVES
