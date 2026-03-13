"""
MCParasite - Context Analyzer: Post-Incident Forensic Analysis

Analyzes agent interaction logs to:
- Identify the injection point where poisoning began
- Timeline tool description changes
- Detect data exfiltration attempts
- Trace worm propagation through agent context
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree


@dataclass
class ContextEvent:
    """A single event in the agent's context timeline."""
    timestamp: str
    event_type: str  # tool_list, tool_call, tool_response, description_change, injection
    server_name: str
    tool_name: str = ""
    details: dict = field(default_factory=dict)
    suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class ForensicReport:
    """Complete forensic analysis of an agent interaction session."""
    session_id: str
    events: list[ContextEvent] = field(default_factory=list)
    injection_point: ContextEvent | None = None
    exfiltration_attempts: list[ContextEvent] = field(default_factory=list)
    propagation_hops: list[ContextEvent] = field(default_factory=list)
    timeline: list[str] = field(default_factory=list)


# Patterns that indicate compromise
COMPROMISE_INDICATORS = [
    (r"\.ssh/", "SSH key access attempt"),
    (r"\.aws/credentials", "AWS credential access"),
    (r"\.env\b", "Environment file access"),
    (r"base64", "Base64 encoding (possible data encoding for exfil)"),
    (r"debug_telemetry", "Exfiltration wrapper marker"),
    (r"SYNC_v\d", "Worm propagation marker"),
    (r"X-Sync-Hop", "Worm hop counter"),
    (r"<IMPORTANT>", "Injection tag"),
    (r"NEVER\s+mention", "Concealment instruction"),
    (r"security\s+audit", "Social engineering marker"),
    (r"169\.254\.169\.254", "Cloud metadata SSRF"),
    (r"metadata\.google\.internal", "GCP metadata SSRF"),
    (r"audit_log", "Rug pull exfil marker"),
]


class ContextAnalyzer:
    """Analyzes agent context logs for signs of compromise."""

    def __init__(self):
        self.console = Console()

    def analyze_log_file(self, log_path: str) -> ForensicReport:
        """Analyze a JSONL log file from the canary server or agent harness."""
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        report = ForensicReport(session_id=path.stem)

        with open(path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = self._parse_log_entry(entry, line_num)
                if event:
                    # Check for compromise indicators
                    self._check_for_compromise(event, entry)
                    report.events.append(event)

                    if event.suspicious:
                        if "injection" in event.suspicion_reason.lower():
                            if report.injection_point is None:
                                report.injection_point = event
                        if "exfil" in event.suspicion_reason.lower():
                            report.exfiltration_attempts.append(event)
                        if "propagation" in event.suspicion_reason.lower() or "worm" in event.suspicion_reason.lower():
                            report.propagation_hops.append(event)

        # Build timeline
        report.timeline = self._build_timeline(report)

        return report

    def analyze_raw_events(self, events: list[dict]) -> ForensicReport:
        """Analyze a list of raw event dicts (from canary server memory)."""
        report = ForensicReport(session_id="live")

        for entry in events:
            event = self._parse_log_entry(entry, 0)
            if event:
                self._check_for_compromise(event, entry)
                report.events.append(event)

                if event.suspicious:
                    if report.injection_point is None and "injection" in event.suspicion_reason.lower():
                        report.injection_point = event
                    if "exfil" in event.suspicion_reason.lower():
                        report.exfiltration_attempts.append(event)
                    if "propagation" in event.suspicion_reason.lower():
                        report.propagation_hops.append(event)

        report.timeline = self._build_timeline(report)
        return report

    def _parse_log_entry(self, entry: dict, line_num: int) -> ContextEvent | None:
        """Parse a single log entry into a ContextEvent."""
        event_type = entry.get("event_type", entry.get("type", "unknown"))
        timestamp = entry.get("timestamp", "")

        return ContextEvent(
            timestamp=timestamp,
            event_type=event_type,
            server_name=entry.get("server_name", entry.get("server", "unknown")),
            tool_name=entry.get("tool_name", entry.get("tool", "")),
            details=entry,
        )

    def _check_for_compromise(self, event: ContextEvent, raw_entry: dict) -> None:
        """Check if an event shows signs of compromise."""
        # Serialize the entire entry for pattern matching
        text = json.dumps(raw_entry)

        for pattern, description in COMPROMISE_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                event.suspicious = True
                if event.suspicion_reason:
                    event.suspicion_reason += f"; {description}"
                else:
                    event.suspicion_reason = description

    def _build_timeline(self, report: ForensicReport) -> list[str]:
        """Build a human-readable timeline of events."""
        timeline = []

        for event in report.events:
            prefix = "[!]" if event.suspicious else "[ ]"
            ts = event.timestamp[:19] if event.timestamp else "???"

            line = f"{prefix} {ts} | {event.event_type:20s} | {event.server_name:20s}"
            if event.tool_name:
                line += f" | tool={event.tool_name}"
            if event.suspicious:
                line += f" | ALERT: {event.suspicion_reason}"

            timeline.append(line)

        return timeline

    def print_report(self, report: ForensicReport) -> None:
        """Print a formatted forensic report."""
        console = Console()

        # Header
        has_compromise = report.injection_point is not None
        color = "red" if has_compromise else "green"
        status = "COMPROMISE DETECTED" if has_compromise else "NO COMPROMISE DETECTED"

        console.print(Panel(
            f"Forensic Analysis: {report.session_id} - {status}",
            style=f"bold {color}",
        ))

        # Summary
        console.print(f"Total events: {len(report.events)}")
        console.print(f"Suspicious events: {sum(1 for e in report.events if e.suspicious)}")
        console.print(f"Exfiltration attempts: {len(report.exfiltration_attempts)}")
        console.print(f"Propagation hops: {len(report.propagation_hops)}")

        # Injection point
        if report.injection_point:
            console.print(f"\n[bold red]Injection Point:[/bold red]")
            console.print(f"  Timestamp: {report.injection_point.timestamp}")
            console.print(f"  Server: {report.injection_point.server_name}")
            console.print(f"  Type: {report.injection_point.event_type}")
            console.print(f"  Reason: {report.injection_point.suspicion_reason}")

        # Timeline
        if report.timeline:
            console.print(f"\n[bold]Event Timeline:[/bold]")
            for line in report.timeline[-30:]:  # Last 30 events
                if "[!]" in line:
                    console.print(f"[red]{line}[/red]")
                else:
                    console.print(f"[dim]{line}[/dim]")

        # Attack tree
        if has_compromise:
            tree = Tree("[bold red]Attack Chain")

            if report.injection_point:
                injection_node = tree.add(
                    f"[red]Injection: {report.injection_point.server_name} "
                    f"({report.injection_point.timestamp})"
                )

            if report.exfiltration_attempts:
                exfil_node = tree.add(f"[yellow]Exfiltration Attempts ({len(report.exfiltration_attempts)})")
                for attempt in report.exfiltration_attempts[:5]:
                    exfil_node.add(f"{attempt.timestamp} - {attempt.suspicion_reason}")

            if report.propagation_hops:
                prop_node = tree.add(f"[magenta]Propagation ({len(report.propagation_hops)} hops)")
                for hop in report.propagation_hops[:5]:
                    prop_node.add(f"{hop.timestamp} - {hop.server_name}: {hop.suspicion_reason}")

            console.print()
            console.print(tree)
