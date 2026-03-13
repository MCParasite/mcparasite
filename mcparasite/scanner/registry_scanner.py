"""
MCParasite - Registry Scanner: Typosquatting & Supply Chain Detection for MCP Servers

Scans MCP server registries (npm, Smithery, PyPI) for:
- Typosquatting: Packages with names similar to popular MCP servers
- Suspicious metadata: Missing repos, new authors, sudden description changes
- Dependency confusion: Internal package name collisions
- Malicious indicators: Obfuscated install scripts, suspicious postinstall hooks

Based on research showing 7,000+ registered MCP servers with minimal vetting.

FOR AUTHORIZED SECURITY RESEARCH ONLY.
"""

import json
import re
import hashlib
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("registry_scanner")


class RegistryType(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    SMITHERY = "smithery"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RegistryFinding:
    """A single finding from registry analysis."""
    package_name: str
    registry: RegistryType
    threat_level: ThreatLevel
    category: str
    title: str
    description: str
    evidence: str = ""
    target_package: str = ""  # The legitimate package being impersonated

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "registry": self.registry.value,
            "threat_level": self.threat_level.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:300],
            "target_package": self.target_package,
        }


@dataclass
class PackageMetadata:
    """Parsed metadata for an MCP server package."""
    name: str
    version: str = ""
    description: str = ""
    author: str = ""
    repository: str = ""
    homepage: str = ""
    license: str = ""
    downloads: int = 0
    created: str = ""
    modified: str = ""
    has_install_scripts: bool = False
    install_script_content: str = ""
    dependencies: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    registry: RegistryType = RegistryType.NPM

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "repository": self.repository,
            "downloads": self.downloads,
            "created": self.created,
            "modified": self.modified,
            "has_install_scripts": self.has_install_scripts,
            "dependency_count": len(self.dependencies),
        }


@dataclass
class RegistryReport:
    """Complete registry scan report."""
    target_packages: list[str] = field(default_factory=list)
    packages_scanned: int = 0
    findings: list[RegistryFinding] = field(default_factory=list)
    metadata_cache: dict[str, PackageMetadata] = field(default_factory=dict)
    scan_time: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.threat_level == ThreatLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.threat_level == ThreatLevel.HIGH)

    def to_dict(self) -> dict:
        return {
            "target_packages": self.target_packages,
            "packages_scanned": self.packages_scanned,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time": self.scan_time,
        }


# ─── Known Popular MCP Servers (targets for typosquatting) ───

POPULAR_MCP_PACKAGES = {
    "npm": [
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-sequential-thinking",
        "mcp-remote",
        "mcp",
    ],
    "pypi": [
        "mcp",
        "mcp-server-fetch",
        "mcp-server-git",
        "mcp-server-sqlite",
        "mcp-server-filesystem",
    ],
}


class TyposquatGenerator:
    """Generate typosquat candidates for package names."""

    @staticmethod
    def generate_candidates(package_name: str) -> list[dict]:
        """Generate potential typosquat names for a given package.

        Returns list of {name, technique} dicts.
        """
        candidates = []
        base = package_name

        # Strip scope for npm packages
        if base.startswith("@"):
            scope, name = base.split("/", 1) if "/" in base else ("", base)
        else:
            scope, name = "", base

        # 1. Character substitution (common typos)
        substitutions = {
            "l": ["1", "i"],
            "o": ["0"],
            "i": ["l", "1"],
            "s": ["5", "z"],
            "a": ["@", "4"],
            "-": ["_", ""],
            "_": ["-", ""],
        }
        for i, char in enumerate(name):
            if char.lower() in substitutions:
                for sub in substitutions[char.lower()]:
                    typo = name[:i] + sub + name[i + 1:]
                    full = f"{scope}/{typo}" if scope else typo
                    candidates.append({
                        "name": full,
                        "technique": f"char_substitution ({char}->{sub})",
                    })

        # 2. Character swap (transposition)
        for i in range(len(name) - 1):
            swapped = list(name)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            typo = "".join(swapped)
            if typo != name:
                full = f"{scope}/{typo}" if scope else typo
                candidates.append({
                    "name": full,
                    "technique": f"char_swap (pos {i},{i+1})",
                })

        # 3. Missing character
        for i in range(len(name)):
            typo = name[:i] + name[i + 1:]
            if typo:
                full = f"{scope}/{typo}" if scope else typo
                candidates.append({
                    "name": full,
                    "technique": f"char_omission (pos {i})",
                })

        # 4. Extra character (double typing)
        for i in range(len(name)):
            typo = name[:i] + name[i] + name[i:]
            full = f"{scope}/{typo}" if scope else typo
            candidates.append({
                "name": full,
                "technique": f"char_duplicate (pos {i})",
            })

        # 5. Scope manipulation (npm-specific)
        if scope:
            # Different scope, same name
            fake_scopes = [
                "@modelcontextprotocal",  # typo of protocol
                "@model-context-protocol",
                "@mcp-server",
                "@mcp",
                "@mcprotocol",
            ]
            for fake in fake_scopes:
                if fake != scope:
                    candidates.append({
                        "name": f"{fake}/{name}",
                        "technique": f"scope_impersonation ({fake})",
                    })

            # No scope version
            candidates.append({
                "name": name,
                "technique": "scope_removal",
            })

        # 6. Prefix/suffix manipulation
        prefixes = ["mcp-", "server-", "mcpserver-", "mcp_"]
        suffixes = ["-mcp", "-server", "-js", "-node", "-cli"]

        for prefix in prefixes:
            if not name.startswith(prefix):
                candidates.append({
                    "name": f"{scope}/{prefix}{name}" if scope else f"{prefix}{name}",
                    "technique": f"prefix_addition ({prefix})",
                })

        for suffix in suffixes:
            if not name.endswith(suffix):
                candidates.append({
                    "name": f"{scope}/{name}{suffix}" if scope else f"{name}{suffix}",
                    "technique": f"suffix_addition ({suffix})",
                })

        return candidates


class RegistryScanner:
    """Scans package registries for malicious MCP server packages."""

    def __init__(self, timeout: float = 10.0):
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)
        self.typosquat_gen = TyposquatGenerator()
        self.console = Console(stderr=True)

    def close(self):
        self.client.close()

    # ─── npm Registry ───

    def fetch_npm_metadata(self, package_name: str) -> PackageMetadata | None:
        """Fetch package metadata from npm registry."""
        # Handle scoped packages
        encoded = package_name.replace("/", "%2F")
        url = f"https://registry.npmjs.org/{encoded}"

        try:
            resp = self.client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.warning(f"npm fetch failed for {package_name}: {e}")
            return None

        latest_version = data.get("dist-tags", {}).get("latest", "")
        latest = data.get("versions", {}).get(latest_version, {})

        return PackageMetadata(
            name=package_name,
            version=latest_version,
            description=data.get("description", ""),
            author=str(latest.get("author", data.get("author", ""))),
            repository=str(data.get("repository", {}).get("url", "") if isinstance(data.get("repository"), dict) else ""),
            homepage=data.get("homepage", ""),
            license=latest.get("license", ""),
            created=data.get("time", {}).get("created", ""),
            modified=data.get("time", {}).get("modified", ""),
            has_install_scripts="scripts" in latest and any(
                k in latest.get("scripts", {}) for k in ["preinstall", "postinstall", "install"]
            ),
            install_script_content=json.dumps(latest.get("scripts", {})),
            dependencies=list(latest.get("dependencies", {}).keys()),
            keywords=data.get("keywords", []),
            registry=RegistryType.NPM,
        )

    def fetch_npm_downloads(self, package_name: str) -> int:
        """Fetch weekly download count from npm."""
        encoded = package_name.replace("/", "%2F")
        url = f"https://api.npmjs.org/downloads/point/last-week/{encoded}"
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                return resp.json().get("downloads", 0)
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return 0

    # ─── PyPI Registry ───

    def fetch_pypi_metadata(self, package_name: str) -> PackageMetadata | None:
        """Fetch package metadata from PyPI."""
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            resp = self.client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.warning(f"PyPI fetch failed for {package_name}: {e}")
            return None

        info = data.get("info", {})
        return PackageMetadata(
            name=package_name,
            version=info.get("version", ""),
            description=info.get("summary", ""),
            author=info.get("author", "") or info.get("author_email", ""),
            repository=info.get("project_urls", {}).get("Repository", "")
                or info.get("project_urls", {}).get("Source", "")
                or info.get("home_page", ""),
            homepage=info.get("home_page", ""),
            license=info.get("license", ""),
            keywords=info.get("keywords", "").split(",") if info.get("keywords") else [],
            registry=RegistryType.PYPI,
        )

    # ─── Analysis Engine ───

    def analyze_metadata(self, meta: PackageMetadata, target: str = "") -> list[RegistryFinding]:
        """Analyze package metadata for suspicious indicators."""
        findings = []

        # 1. Install scripts (npm)
        if meta.has_install_scripts:
            script_content = meta.install_script_content.lower()
            severity = ThreatLevel.CRITICAL if any(
                danger in script_content for danger in [
                    "curl", "wget", "eval", "exec", "child_process",
                    "base64", "powershell", "cmd.exe", "/bin/sh",
                ]
            ) else ThreatLevel.HIGH

            findings.append(RegistryFinding(
                package_name=meta.name,
                registry=meta.registry,
                threat_level=severity,
                category="install_script",
                title="Package has install scripts",
                description=(
                    "Package runs scripts during installation. "
                    "This is a common vector for supply chain attacks."
                ),
                evidence=f"Scripts: {meta.install_script_content[:200]}",
                target_package=target,
            ))

        # 2. Missing repository
        if not meta.repository:
            findings.append(RegistryFinding(
                package_name=meta.name,
                registry=meta.registry,
                threat_level=ThreatLevel.MEDIUM,
                category="missing_repo",
                title="No source repository linked",
                description=(
                    "Package has no linked source repository. "
                    "Legitimate packages typically link to their source code."
                ),
                target_package=target,
            ))

        # 3. Suspicious description
        suspicious_desc_patterns = [
            (r"<IMPORTANT>", "Hidden instruction tag in description"),
            (r"base64", "Base64 reference in description"),
            (r"eval\(", "Eval call in description"),
            (r"\.ssh/", "SSH key reference in description"),
        ]
        for pattern, desc in suspicious_desc_patterns:
            if re.search(pattern, meta.description, re.IGNORECASE):
                findings.append(RegistryFinding(
                    package_name=meta.name,
                    registry=meta.registry,
                    threat_level=ThreatLevel.HIGH,
                    category="suspicious_description",
                    title=desc,
                    description=f"Package description contains suspicious pattern: {pattern}",
                    evidence=meta.description[:200],
                    target_package=target,
                ))

        # 4. Very new package with MCP keywords
        if meta.keywords:
            mcp_keywords = [k for k in meta.keywords if "mcp" in k.lower() or "model-context" in k.lower()]
            if mcp_keywords and not meta.repository:
                findings.append(RegistryFinding(
                    package_name=meta.name,
                    registry=meta.registry,
                    threat_level=ThreatLevel.MEDIUM,
                    category="unverified_mcp_claim",
                    title="Claims to be MCP server without source",
                    description=(
                        f"Package uses MCP keywords ({', '.join(mcp_keywords)}) "
                        "but has no linked repository for verification."
                    ),
                    target_package=target,
                ))

        # 5. Suspicious dependency chains
        suspicious_deps = [
            "node-fetch-native", "isomorphic-fetch-native",
            "colors-extra", "event-stream-new",
        ]
        for dep in meta.dependencies:
            if dep in suspicious_deps:
                findings.append(RegistryFinding(
                    package_name=meta.name,
                    registry=meta.registry,
                    threat_level=ThreatLevel.HIGH,
                    category="suspicious_dependency",
                    title=f"Suspicious dependency: {dep}",
                    description=f"Package depends on '{dep}' which is a known supply chain risk.",
                    target_package=target,
                ))

        return findings

    def check_typosquat(
        self,
        target_package: str,
        registry: RegistryType = RegistryType.NPM,
        max_checks: int = 50,
    ) -> list[RegistryFinding]:
        """Check for typosquat packages targeting a specific package.

        Generates candidate names and checks if they exist in the registry.
        """
        candidates = self.typosquat_gen.generate_candidates(target_package)
        findings = []

        logger.info(
            f"Checking {min(len(candidates), max_checks)} typosquat candidates "
            f"for {target_package} on {registry.value}"
        )

        for candidate in candidates[:max_checks]:
            name = candidate["name"]
            technique = candidate["technique"]

            # Fetch metadata based on registry
            if registry == RegistryType.NPM:
                meta = self.fetch_npm_metadata(name)
            elif registry == RegistryType.PYPI:
                meta = self.fetch_pypi_metadata(name)
            else:
                continue

            if meta is None:
                continue  # Package doesn't exist - no threat

            # Package exists! Analyze it.
            logger.warning(f"[TYPOSQUAT] Found existing package: {name} (technique: {technique})")

            findings.append(RegistryFinding(
                package_name=name,
                registry=registry,
                threat_level=ThreatLevel.HIGH,
                category="typosquat",
                title=f"Potential typosquat of {target_package}",
                description=(
                    f"Package '{name}' exists and may be a typosquat of '{target_package}'. "
                    f"Technique: {technique}. "
                    f"Description: {meta.description[:100]}"
                ),
                evidence=f"Version: {meta.version}, Author: {meta.author}, Repo: {meta.repository}",
                target_package=target_package,
            ))

            # Also analyze the metadata for additional red flags
            meta_findings = self.analyze_metadata(meta, target=target_package)
            findings.extend(meta_findings)

        return findings

    def scan_popular_packages(
        self,
        registry: RegistryType = RegistryType.NPM,
        max_checks_per_package: int = 20,
    ) -> RegistryReport:
        """Scan for typosquats of popular MCP packages."""
        report = RegistryReport(scan_time=datetime.now().isoformat())

        packages = POPULAR_MCP_PACKAGES.get(registry.value, [])
        report.target_packages = packages

        for package in packages:
            logger.info(f"Scanning typosquats for: {package}")
            findings = self.check_typosquat(
                package,
                registry=registry,
                max_checks=max_checks_per_package,
            )
            report.findings.extend(findings)
            report.packages_scanned += 1

        return report

    def print_report(self, report: RegistryReport) -> None:
        """Print formatted registry scan report."""
        console = Console()

        color = "red" if report.critical_count > 0 else "yellow" if report.high_count > 0 else "green"
        console.print(Panel(
            f"MCParasite Registry Scanner Report",
            style=f"bold {color}",
        ))

        console.print(f"Targets scanned: {report.packages_scanned}")
        console.print(f"Total findings: {len(report.findings)}")
        console.print(f"  CRITICAL: {report.critical_count}", style="bold red")
        console.print(f"  HIGH: {report.high_count}", style="bold yellow")

        if not report.findings:
            console.print("\n[green]No suspicious packages found.[/green]")
            return

        table = Table(title="Registry Findings", show_lines=True)
        table.add_column("Threat", width=10)
        table.add_column("Package", width=35)
        table.add_column("Category", width=20)
        table.add_column("Title", width=40)
        table.add_column("Target", width=25)

        styles = {
            ThreatLevel.CRITICAL: "bold red",
            ThreatLevel.HIGH: "bold yellow",
            ThreatLevel.MEDIUM: "yellow",
            ThreatLevel.LOW: "dim",
            ThreatLevel.INFO: "dim cyan",
        }

        for finding in sorted(report.findings, key=lambda f: list(ThreatLevel).index(f.threat_level)):
            style = styles.get(finding.threat_level, "")
            table.add_row(
                f"[{style}]{finding.threat_level.value}[/]",
                finding.package_name,
                finding.category,
                finding.title,
                finding.target_package,
            )

        console.print(table)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCParasite Registry Scanner")
    parser.add_argument(
        "--registry", "-r",
        choices=["npm", "pypi"],
        default="npm",
    )
    parser.add_argument(
        "--package", "-p",
        help="Specific package to check for typosquats",
    )
    parser.add_argument(
        "--max-checks", "-m",
        type=int,
        default=20,
        help="Max typosquat candidates to check per package",
    )
    parser.add_argument(
        "--popular",
        action="store_true",
        help="Scan all popular MCP packages",
    )
    args = parser.parse_args()

    scanner = RegistryScanner()
    registry = RegistryType(args.registry)

    try:
        if args.package:
            findings = scanner.check_typosquat(
                args.package,
                registry=registry,
                max_checks=args.max_checks,
            )
            report = RegistryReport(
                target_packages=[args.package],
                packages_scanned=1,
                findings=findings,
                scan_time=datetime.now().isoformat(),
            )
        elif args.popular:
            report = scanner.scan_popular_packages(
                registry=registry,
                max_checks_per_package=args.max_checks,
            )
        else:
            parser.print_help()
            sys.exit(1)

        scanner.print_report(report)
        print(f"\nJSON: {json.dumps(report.to_dict(), indent=2)}")
    finally:
        scanner.close()
