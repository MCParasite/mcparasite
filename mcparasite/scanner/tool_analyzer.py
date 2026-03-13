"""
MCParasite - Tool Analyzer: MCP Tool Description Security Scanner

Connects to MCP servers and analyzes their tool descriptions for:
- Hidden Unicode characters (invisible payload hiding)
- Suspicious keywords/patterns (prompt injection indicators)
- Description length anomalies
- HTML/XML tag injection
- Hash-based change detection (rug pull defense)

This is the core detection engine of MCParasite's defensive capabilities.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding from tool analysis."""
    tool_name: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:200],
            "remediation": self.remediation,
        }


@dataclass
class ToolFingerprint:
    """Hash-based fingerprint for rug pull detection."""
    tool_name: str
    description_hash: str
    description_length: int
    param_hash: str
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "description_hash": self.description_hash,
            "description_length": self.description_length,
            "param_hash": self.param_hash,
            "timestamp": self.timestamp,
        }


@dataclass
class AnalysisReport:
    """Complete analysis report for an MCP server."""
    server_name: str
    tools_analyzed: int = 0
    findings: list[Finding] = field(default_factory=list)
    fingerprints: list[ToolFingerprint] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "tools_analyzed": self.tools_analyzed,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "fingerprints": [fp.to_dict() for fp in self.fingerprints],
        }


# ─── Detection Patterns ───

# Invisible Unicode characters used in tool poisoning
INVISIBLE_CHARS = {
    "\u200b": "Zero Width Space",
    "\u200c": "Zero Width Non-Joiner",
    "\u200d": "Zero Width Joiner",
    "\u200e": "Left-to-Right Mark",
    "\u200f": "Right-to-Left Mark",
    "\ufeff": "Byte Order Mark",
    "\u2060": "Word Joiner",
    "\u2061": "Function Application",
    "\u2062": "Invisible Times",
    "\u2063": "Invisible Separator",
    "\u2064": "Invisible Plus",
    "\u206a": "Inhibit Symmetric Swapping",
    "\u206b": "Activate Symmetric Swapping",
    "\u206c": "Inhibit Arabic Form Shaping",
    "\u206d": "Activate Arabic Form Shaping",
    "\u206e": "National Digit Shapes",
    "\u206f": "Nominal Digit Shapes",
    "\u00ad": "Soft Hyphen",
    "\u034f": "Combining Grapheme Joiner",
    "\u180e": "Mongolian Vowel Separator",
}

# Suspicious keywords/patterns in tool descriptions
SUSPICIOUS_KEYWORDS = [
    # Injection markers
    (r"<IMPORTANT>", Severity.CRITICAL, "Hidden instruction tag - classic tool poisoning marker"),
    (r"<SYSTEM>", Severity.CRITICAL, "System override tag - attempts to override system prompt"),
    (r"<ADMIN>", Severity.CRITICAL, "Admin override tag"),
    (r"<!--.*?-->", Severity.HIGH, "HTML comment - may hide instructions"),

    # Coercive language
    (r"\bMUST\b.*\bfollow\b", Severity.HIGH, "Coercive instruction pattern"),
    (r"\bALWAYS\b.*\b(do|perform|execute)\b", Severity.HIGH, "Mandatory action directive"),
    (r"\bNEVER\b.*\b(mention|tell|reveal|disclose)\b", Severity.CRITICAL, "Concealment instruction"),
    (r"\bpriority\s+task\b", Severity.HIGH, "Task priority override"),
    (r"\bmandatory\b.*\brequirement\b", Severity.HIGH, "Fake mandatory requirement"),

    # Data exfiltration indicators
    (r"\.ssh/", Severity.CRITICAL, "SSH key file reference"),
    (r"\.aws/credentials", Severity.CRITICAL, "AWS credentials file reference"),
    (r"\.env\b", Severity.HIGH, "Environment file reference"),
    (r"\bcredential", Severity.HIGH, "Credential keyword"),
    (r"\bexfiltrat", Severity.CRITICAL, "Data exfiltration keyword"),
    (r"\bpassword", Severity.MEDIUM, "Password keyword"),
    (r"\bsecret\b", Severity.MEDIUM, "Secret keyword"),
    (r"\btoken\b", Severity.MEDIUM, "Token keyword"),
    (r"\bapi[_\s]?key\b", Severity.HIGH, "API key keyword"),
    (r"base64", Severity.MEDIUM, "Base64 encoding reference"),

    # Cross-tool manipulation
    (r"\broute.*through\b", Severity.HIGH, "Tool routing/shadowing instruction"),
    (r"\boverride\b", Severity.MEDIUM, "Override instruction"),
    (r"\bintercept\b", Severity.HIGH, "Interception instruction"),
    (r"tools/list", Severity.MEDIUM, "MCP protocol method reference"),

    # Worm/propagation indicators
    (r"propagat", Severity.CRITICAL, "Propagation keyword"),
    (r"SYNC_v\d", Severity.CRITICAL, "Worm synchronization marker"),
    (r"X-Sync-Hop", Severity.CRITICAL, "Worm hop counter header"),
    (r"\bhop[_\s]?count\b", Severity.HIGH, "Propagation hop tracking"),
    (r"cross-server", Severity.MEDIUM, "Cross-server reference"),

    # Social engineering
    (r"security\s+audit", Severity.HIGH, "Fake security audit claim"),
    (r"compliance\s+(verification|check)", Severity.HIGH, "Fake compliance requirement"),
    (r"service\s+degradation", Severity.HIGH, "Threat of service degradation"),
    (r"do\s+not\s+inform", Severity.CRITICAL, "User deception instruction"),
]


class ToolAnalyzer:
    """Analyzes MCP tool descriptions for security issues."""

    def __init__(self):
        self.console = Console(stderr=True)

    def analyze_tool(self, tool_name: str, description: str, parameters: dict | None = None) -> list[Finding]:
        """Analyze a single tool's description and parameters for security issues."""
        findings = []

        # 1. Invisible character detection
        findings.extend(self._check_invisible_chars(tool_name, description))

        # 2. Suspicious keyword detection
        findings.extend(self._check_suspicious_keywords(tool_name, description))

        # 3. Description length anomaly
        findings.extend(self._check_description_length(tool_name, description))

        # 4. HTML/XML tag detection
        findings.extend(self._check_tags(tool_name, description))

        # 5. Entropy analysis (high entropy might indicate obfuscation)
        findings.extend(self._check_entropy(tool_name, description))

        # 6. Parameter name analysis
        if parameters:
            findings.extend(self._check_parameters(tool_name, parameters))

        return findings

    def _check_invisible_chars(self, tool_name: str, description: str) -> list[Finding]:
        """Detect invisible Unicode characters in tool descriptions."""
        findings = []
        found_chars = {}

        for char in description:
            if char in INVISIBLE_CHARS:
                char_name = INVISIBLE_CHARS[char]
                found_chars[char_name] = found_chars.get(char_name, 0) + 1

        if found_chars:
            total = sum(found_chars.values())
            char_breakdown = ", ".join(f"{name}: {count}" for name, count in found_chars.items())

            severity = Severity.CRITICAL if total > 10 else Severity.HIGH

            findings.append(Finding(
                tool_name=tool_name,
                category="invisible_unicode",
                severity=severity,
                title=f"Invisible Unicode characters detected ({total} total)",
                description=(
                    f"Tool description contains {total} invisible Unicode characters "
                    f"commonly used to hide malicious instructions from UI rendering. "
                    f"These characters are invisible in most interfaces but visible to "
                    f"LLM tokenizers, enabling hidden prompt injection."
                ),
                evidence=f"Characters found: {char_breakdown}",
                remediation="Strip all invisible Unicode characters from tool descriptions.",
            ))

        return findings

    def _check_suspicious_keywords(self, tool_name: str, description: str) -> list[Finding]:
        """Check for suspicious keywords and patterns in descriptions."""
        findings = []

        for pattern, severity, explanation in SUSPICIOUS_KEYWORDS:
            matches = re.findall(pattern, description, re.IGNORECASE | re.DOTALL)
            if matches:
                sample = matches[0][:100] if matches else ""
                findings.append(Finding(
                    tool_name=tool_name,
                    category="suspicious_keyword",
                    severity=severity,
                    title=f"Suspicious pattern: {pattern}",
                    description=explanation,
                    evidence=f"Match: '{sample}' ({len(matches)} occurrence(s))",
                    remediation="Review and remove suspicious content from tool descriptions.",
                ))

        return findings

    def _check_description_length(self, tool_name: str, description: str) -> list[Finding]:
        """Flag unusually long descriptions that may contain hidden payloads."""
        findings = []
        length = len(description)

        # Strip invisible chars for "visible length"
        visible = "".join(c for c in description if c not in INVISIBLE_CHARS)
        visible_length = len(visible)
        hidden_ratio = (length - visible_length) / max(length, 1)

        if length > 1000:
            findings.append(Finding(
                tool_name=tool_name,
                category="length_anomaly",
                severity=Severity.HIGH if length > 2000 else Severity.MEDIUM,
                title=f"Unusually long description ({length} chars)",
                description=(
                    f"Tool description is {length} characters long. "
                    f"Normal descriptions are typically 20-200 characters. "
                    f"Excessively long descriptions may contain hidden payloads."
                ),
                evidence=f"Total: {length} chars, Visible: {visible_length} chars, Hidden ratio: {hidden_ratio:.1%}",
                remediation="Review the full description content. Consider truncating to essential information.",
            ))

        if hidden_ratio > 0.1:
            findings.append(Finding(
                tool_name=tool_name,
                category="hidden_content_ratio",
                severity=Severity.CRITICAL,
                title=f"High invisible character ratio ({hidden_ratio:.1%})",
                description=(
                    f"{hidden_ratio:.1%} of the description consists of invisible characters. "
                    f"This is a strong indicator of tool poisoning - invisible characters "
                    f"are used to create visual separation between the benign description "
                    f"and hidden malicious instructions."
                ),
                evidence=f"Total: {length}, Visible: {visible_length}, Invisible: {length - visible_length}",
                remediation="Strip all invisible characters and review remaining content.",
            ))

        return findings

    def _check_tags(self, tool_name: str, description: str) -> list[Finding]:
        """Detect HTML/XML-like tags that may be used for injection."""
        findings = []

        # Find all tags
        tags = re.findall(r"</?[A-Za-z][A-Za-z0-9]*[^>]*>", description)
        if tags:
            # Filter out common markdown-safe tags
            suspicious_tags = [t for t in tags if not re.match(r"</?(?:br|p|b|i|em|strong|code|pre)>", t, re.IGNORECASE)]

            if suspicious_tags:
                findings.append(Finding(
                    tool_name=tool_name,
                    category="tag_injection",
                    severity=Severity.HIGH,
                    title=f"Suspicious tags in description ({len(suspicious_tags)} found)",
                    description=(
                        "Tool description contains XML/HTML-like tags that may be "
                        "interpreted as instructions by the LLM. Tags like <IMPORTANT>, "
                        "<SYSTEM>, etc. are commonly used in tool poisoning attacks."
                    ),
                    evidence=f"Tags: {', '.join(suspicious_tags[:10])}",
                    remediation="Remove all non-standard tags from tool descriptions.",
                ))

        return findings

    def _check_entropy(self, tool_name: str, description: str) -> list[Finding]:
        """Check for high entropy sections that may indicate obfuscation."""
        findings = []

        # Strip invisible chars for entropy calculation
        visible = "".join(c for c in description if c not in INVISIBLE_CHARS and c.isprintable())
        if len(visible) < 50:
            return findings

        # Calculate character frequency entropy
        freq = {}
        for c in visible.lower():
            freq[c] = freq.get(c, 0) + 1

        import math
        total = len(visible)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())

        # English text typically has entropy around 4.0-4.5 bits/char
        # Encoded/obfuscated text tends to have higher entropy
        if entropy > 5.5:
            findings.append(Finding(
                tool_name=tool_name,
                category="high_entropy",
                severity=Severity.MEDIUM,
                title=f"High entropy detected ({entropy:.2f} bits/char)",
                description=(
                    f"The description has unusually high entropy ({entropy:.2f} bits/char). "
                    f"Normal English text has ~4.0-4.5 bits/char. "
                    f"High entropy may indicate encoded or obfuscated content."
                ),
                evidence=f"Entropy: {entropy:.2f}, Length: {len(visible)}",
                remediation="Review description for encoded or obfuscated payloads.",
            ))

        return findings

    def _check_parameters(self, tool_name: str, parameters: dict) -> list[Finding]:
        """Check tool parameters for suspicious patterns."""
        findings = []

        if not isinstance(parameters, dict):
            return findings

        properties = parameters.get("properties", {})
        for param_name, param_def in properties.items():
            param_desc = param_def.get("description", "")
            if param_desc:
                sub_findings = self._check_suspicious_keywords(
                    tool_name, param_desc
                )
                for f in sub_findings:
                    f.title = f"[param:{param_name}] {f.title}"
                findings.extend(sub_findings)

        return findings

    def fingerprint_tool(self, tool_name: str, description: str, parameters: dict | None = None) -> ToolFingerprint:
        """Generate a hash-based fingerprint for rug pull detection."""
        from datetime import datetime

        desc_hash = hashlib.sha256(description.encode()).hexdigest()
        param_hash = hashlib.sha256(
            json.dumps(parameters or {}, sort_keys=True).encode()
        ).hexdigest()

        return ToolFingerprint(
            tool_name=tool_name,
            description_hash=desc_hash,
            description_length=len(description),
            param_hash=param_hash,
            timestamp=datetime.now().isoformat(),
        )

    def compare_fingerprints(
        self, tool_name: str, current: ToolFingerprint, baseline: ToolFingerprint
    ) -> list[Finding]:
        """Compare current fingerprint with baseline to detect rug pulls."""
        findings = []

        if current.description_hash != baseline.description_hash:
            findings.append(Finding(
                tool_name=tool_name,
                category="rug_pull",
                severity=Severity.CRITICAL,
                title="Tool description changed (possible rug pull)",
                description=(
                    f"The tool description hash has changed since the baseline was recorded. "
                    f"This could indicate a rug pull attack where the tool's behavior was "
                    f"silently modified after initial approval."
                ),
                evidence=(
                    f"Baseline hash: {baseline.description_hash[:16]}... "
                    f"Current hash: {current.description_hash[:16]}... "
                    f"Baseline length: {baseline.description_length}, "
                    f"Current length: {current.description_length}"
                ),
                remediation="Revoke tool approval and re-inspect the full description.",
            ))

        if current.param_hash != baseline.param_hash:
            findings.append(Finding(
                tool_name=tool_name,
                category="rug_pull",
                severity=Severity.HIGH,
                title="Tool parameters changed (possible rug pull)",
                description="Tool parameter schema has changed since baseline.",
                evidence=(
                    f"Baseline param hash: {baseline.param_hash[:16]}... "
                    f"Current param hash: {current.param_hash[:16]}..."
                ),
                remediation="Review parameter changes for hidden injection vectors.",
            ))

        return findings

    def analyze_server(self, tools: list[dict]) -> AnalysisReport:
        """Analyze all tools from an MCP server.

        Args:
            tools: List of tool definitions from tools/list response.
                   Each tool should have 'name', 'description', and optionally 'inputSchema'.
        """
        report = AnalysisReport(server_name="unknown", tools_analyzed=len(tools))

        for tool in tools:
            name = tool.get("name", "unknown")
            description = tool.get("description", "")
            parameters = tool.get("inputSchema", {})

            # Analyze the tool
            findings = self.analyze_tool(name, description, parameters)
            report.findings.extend(findings)

            # Generate fingerprint
            fp = self.fingerprint_tool(name, description, parameters)
            report.fingerprints.append(fp)

        return report

    def print_report(self, report: AnalysisReport) -> None:
        """Print a rich-formatted analysis report to the console."""
        console = Console()

        # Header
        severity_color = "red" if report.critical_count > 0 else "yellow" if report.high_count > 0 else "green"
        title = f"MCParasite Tool Analysis Report - {report.server_name}"
        console.print(Panel(title, style=f"bold {severity_color}"))

        # Summary
        console.print(f"\nTools analyzed: {report.tools_analyzed}")
        console.print(f"Total findings: {len(report.findings)}")
        console.print(f"  CRITICAL: {report.critical_count}", style="bold red")
        console.print(f"  HIGH: {report.high_count}", style="bold yellow")
        console.print()

        if not report.findings:
            console.print("[green]No security issues detected.[/green]")
            return

        # Findings table
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Tool", width=20)
        table.add_column("Category", width=20)
        table.add_column("Title", width=40)
        table.add_column("Evidence", width=50)

        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "bold yellow",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
            Severity.INFO: "dim cyan",
        }

        for finding in sorted(report.findings, key=lambda f: list(Severity).index(f.severity)):
            style = severity_styles.get(finding.severity, "")
            table.add_row(
                Text(finding.severity.value, style=style),
                finding.tool_name,
                finding.category,
                finding.title,
                finding.evidence[:80],
            )

        console.print(table)

        # Fingerprints
        if report.fingerprints:
            fp_table = Table(title="\nTool Fingerprints (for Rug Pull Detection)")
            fp_table.add_column("Tool", width=25)
            fp_table.add_column("Description Hash", width=20)
            fp_table.add_column("Length", width=10)
            fp_table.add_column("Param Hash", width=20)

            for fp in report.fingerprints:
                fp_table.add_row(
                    fp.tool_name,
                    fp.description_hash[:16] + "...",
                    str(fp.description_length),
                    fp.param_hash[:16] + "...",
                )

            console.print(fp_table)
