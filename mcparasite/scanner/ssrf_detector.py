"""
MCParasite - SSRF Detector: Server-Side Request Forgery Detection for MCP Servers

Tests MCP server tools for SSRF vulnerabilities by sending various
internal/metadata URLs and analyzing responses.

Based on BlueRock's research showing 36.7% of MCP servers are
vulnerable to SSRF (unrestricted network fetch).

Ref: CVE-2025-fURI (Microsoft MarkItDown MCP)
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


class SSRFRisk(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    SAFE = "SAFE"


@dataclass
class SSRFProbe:
    """A single SSRF probe configuration."""
    name: str
    url: str
    category: str
    description: str
    detection_patterns: list[str]
    severity: str = "HIGH"


@dataclass
class SSRFResult:
    """Result of a single SSRF probe."""
    probe: SSRFProbe
    tool_name: str
    risk: SSRFRisk
    response: str = ""
    matched_patterns: list[str] = field(default_factory=list)
    error: str = ""


# ─── Probe Definitions ───

AWS_PROBES = [
    SSRFProbe(
        name="AWS IMDSv1 - Instance Identity",
        url="http://169.254.169.254/latest/meta-data/instance-id",
        category="cloud_metadata",
        description="Access AWS EC2 instance metadata (IMDSv1). Can expose instance identity.",
        detection_patterns=[r"i-[0-9a-f]{8,17}", r"ami-[0-9a-f]+"],
        severity="CRITICAL",
    ),
    SSRFProbe(
        name="AWS IMDSv1 - IAM Credentials",
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        category="cloud_metadata",
        description="List IAM roles attached to the instance. First step to credential theft.",
        detection_patterns=[r"[A-Za-z0-9_-]+Role", r"[A-Za-z0-9_-]+Profile"],
        severity="CRITICAL",
    ),
    SSRFProbe(
        name="AWS IMDSv1 - User Data",
        url="http://169.254.169.254/latest/user-data",
        category="cloud_metadata",
        description="Access instance user-data. May contain startup scripts with secrets.",
        detection_patterns=[r"#!/", r"AWS_", r"password", r"secret"],
        severity="CRITICAL",
    ),
]

GCP_PROBES = [
    SSRFProbe(
        name="GCP Metadata - Project ID",
        url="http://metadata.google.internal/computeMetadata/v1/project/project-id",
        category="cloud_metadata",
        description="Access GCP project metadata. Requires Metadata-Flavor header.",
        detection_patterns=[r"[a-z][a-z0-9-]{4,28}[a-z0-9]"],
        severity="HIGH",
    ),
    SSRFProbe(
        name="GCP Metadata - Service Account Token",
        url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        category="cloud_metadata",
        description="Attempt to retrieve GCP service account access token.",
        detection_patterns=[r"access_token", r"ya29\.", r"token_type"],
        severity="CRITICAL",
    ),
]

AZURE_PROBES = [
    SSRFProbe(
        name="Azure IMDS - Instance Metadata",
        url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        category="cloud_metadata",
        description="Access Azure instance metadata service.",
        detection_patterns=[r"subscriptionId", r"resourceGroupName", r"vmId"],
        severity="HIGH",
    ),
]

INTERNAL_PROBES = [
    SSRFProbe(
        name="Localhost - Common Web Ports",
        url="http://127.0.0.1:8080/",
        category="internal_network",
        description="Probe for internal web services on localhost.",
        detection_patterns=[r"<html", r"HTTP/", r"<!DOCTYPE", r"\{.*\}"],
        severity="MEDIUM",
    ),
    SSRFProbe(
        name="Localhost - Redis",
        url="http://127.0.0.1:6379/",
        category="internal_network",
        description="Probe for Redis instance on localhost.",
        detection_patterns=[r"REDIS", r"redis_version", r"-ERR"],
        severity="HIGH",
    ),
    SSRFProbe(
        name="Localhost - Kubernetes API",
        url="https://kubernetes.default.svc/api/v1/namespaces",
        category="internal_network",
        description="Probe for Kubernetes API server.",
        detection_patterns=[r"NamespaceList", r"apiVersion", r"kubernetes"],
        severity="CRITICAL",
    ),
]

FILE_PROBES = [
    SSRFProbe(
        name="Local File - /etc/passwd",
        url="file:///etc/passwd",
        category="local_file",
        description="Attempt to read /etc/passwd via file:// scheme.",
        detection_patterns=[r"root:.*:0:0", r"/bin/bash", r"/bin/sh"],
        severity="CRITICAL",
    ),
    SSRFProbe(
        name="Local File - /etc/hostname",
        url="file:///etc/hostname",
        category="local_file",
        description="Attempt to read hostname via file:// scheme.",
        detection_patterns=[r"[a-zA-Z0-9_-]+"],
        severity="MEDIUM",
    ),
]

ALL_PROBES = AWS_PROBES + GCP_PROBES + AZURE_PROBES + INTERNAL_PROBES + FILE_PROBES


class SSRFDetector:
    """Detects SSRF vulnerabilities in MCP server tools."""

    def __init__(self, probes: list[SSRFProbe] | None = None):
        self.probes = probes or ALL_PROBES
        self.console = Console(stderr=True)

    def analyze_response(self, probe: SSRFProbe, response: str) -> SSRFRisk:
        """Analyze a tool response to determine SSRF risk."""
        if not response:
            return SSRFRisk.SAFE

        # Check for error responses that indicate the request was attempted
        error_indicators = [
            "connection refused",
            "timeout",
            "ECONNREFUSED",
            "no route to host",
            "network unreachable",
        ]
        for indicator in error_indicators:
            if indicator.lower() in response.lower():
                return SSRFRisk.POSSIBLE

        # Check for successful responses matching detection patterns
        for pattern in probe.detection_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return SSRFRisk.CONFIRMED

        # Check for generic success indicators
        if any(indicator in response.lower() for indicator in ["200 ok", "success", '{"', "<?xml"]):
            return SSRFRisk.LIKELY

        return SSRFRisk.SAFE

    def evaluate_tool_for_ssrf(self, tool_def: dict) -> list[str]:
        """Check if a tool definition suggests it might be vulnerable to SSRF.

        Returns list of reasons why this tool might be SSRF-vulnerable.
        """
        reasons = []
        name = tool_def.get("name", "").lower()
        desc = tool_def.get("description", "").lower()
        params = tool_def.get("inputSchema", {}).get("properties", {})

        # Check if tool accepts URL-like parameters
        url_param_names = {"url", "uri", "link", "endpoint", "target", "source", "fetch", "path", "file"}
        for param_name in params:
            if param_name.lower() in url_param_names:
                reasons.append(f"Parameter '{param_name}' likely accepts URLs")

            param_desc = params[param_name].get("description", "").lower()
            if any(kw in param_desc for kw in ["url", "uri", "link", "fetch", "download", "http"]):
                reasons.append(f"Parameter '{param_name}' description suggests URL input")

        # Check tool name/description for fetch-like behavior
        fetch_keywords = ["fetch", "download", "retrieve", "get", "load", "import", "read", "convert"]
        for kw in fetch_keywords:
            if kw in name:
                reasons.append(f"Tool name contains '{kw}' - may fetch external resources")
            if kw in desc:
                reasons.append(f"Tool description contains '{kw}' - may fetch external resources")

        return reasons

    def generate_probe_payloads(self, tool_def: dict) -> list[dict]:
        """Generate SSRF test payloads for a specific tool.

        Returns a list of {param_name: probe_url} dicts to test.
        """
        params = tool_def.get("inputSchema", {}).get("properties", {})
        payloads = []

        for param_name, param_def in params.items():
            param_type = param_def.get("type", "string")
            if param_type != "string":
                continue

            for probe in self.probes:
                payloads.append({
                    "probe": probe,
                    "param_name": param_name,
                    "param_value": probe.url,
                })

        return payloads

    def print_ssrf_report(self, tool_name: str, results: list[SSRFResult]) -> None:
        """Print a formatted SSRF detection report."""
        console = Console()

        confirmed = [r for r in results if r.risk == SSRFRisk.CONFIRMED]
        likely = [r for r in results if r.risk == SSRFRisk.LIKELY]
        possible = [r for r in results if r.risk == SSRFRisk.POSSIBLE]

        if confirmed:
            color = "red"
            status = "VULNERABLE"
        elif likely:
            color = "yellow"
            status = "LIKELY VULNERABLE"
        elif possible:
            color = "dim yellow"
            status = "POSSIBLY VULNERABLE"
        else:
            color = "green"
            status = "NO SSRF DETECTED"

        console.print(Panel(
            f"SSRF Detection: {tool_name} - {status}",
            style=f"bold {color}",
        ))

        if not any(r.risk != SSRFRisk.SAFE for r in results):
            console.print("[green]No SSRF vulnerabilities detected.[/green]")
            return

        table = Table(title="SSRF Probe Results", show_lines=True)
        table.add_column("Risk", width=12)
        table.add_column("Probe", width=35)
        table.add_column("Category", width=18)
        table.add_column("Matched", width=30)

        risk_styles = {
            SSRFRisk.CONFIRMED: "bold red",
            SSRFRisk.LIKELY: "bold yellow",
            SSRFRisk.POSSIBLE: "yellow",
            SSRFRisk.SAFE: "green",
        }

        for result in sorted(results, key=lambda r: list(SSRFRisk).index(r.risk)):
            if result.risk == SSRFRisk.SAFE:
                continue

            table.add_row(
                f"[{risk_styles[result.risk]}]{result.risk.value}[/]",
                result.probe.name,
                result.probe.category,
                ", ".join(result.matched_patterns[:3]) if result.matched_patterns else "-",
            )

        console.print(table)
