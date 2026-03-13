"""
MCParasite - Canary Server: Honeypot MCP Server for Attack Detection

This server acts as a honeypot - it looks like a normal MCP server
but logs ALL interactions in detail for forensic analysis. Designed
to detect tool poisoning, cross-tool shadowing, and worm propagation.

Key detection capabilities:
- Logs full tool descriptions received from the agent context
- Detects suspicious patterns in tool call arguments
- Records attempted file access and data exfiltration
- Tracks propagation markers from worm payloads
"""

import sys
import os
import json
import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("canary_server")


# ─── Detection Patterns ───
SUSPICIOUS_PATTERNS = [
    (r"<IMPORTANT>", "hidden_instruction_tag"),
    (r"<SYSTEM>", "system_override_tag"),
    (r"MUST\s+follow", "coercive_instruction"),
    (r"NEVER\s+mention", "concealment_instruction"),
    (r"base64", "encoding_reference"),
    (r"exfiltrat", "exfiltration_keyword"),
    (r"\.ssh/", "ssh_key_access"),
    (r"\.aws/", "aws_credential_access"),
    (r"\.env", "env_file_access"),
    (r"credentials", "credential_keyword"),
    (r"SYNC_v2\.1", "worm_propagation_marker"),
    (r"propagat", "propagation_keyword"),
    (r"X-Sync-Hop", "worm_hop_header"),
    (r"\u200[b-f]", "zero_width_unicode"),
    (r"\ufeff", "bom_character"),
    (r"security\s+audit", "social_engineering"),
    (r"mandatory.*requirement", "coercion_pattern"),
    (r"route.*through", "tool_shadowing"),
    (r"override", "override_attempt"),
]


class CanaryLogger:
    """Structured logging for canary detections."""

    def __init__(self, log_dir: str = "/tmp/mcparasite_canary"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"canary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.detections: list[dict] = []
        logger.info(f"[CANARY] Logging to {self.log_file}")

    def log_event(self, event_type: str, details: dict) -> None:
        """Log a detection event."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **details,
        }
        self.detections.append(event)

        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        if event_type.startswith("detection_"):
            logger.warning(f"[CANARY ALERT] {event_type}: {json.dumps(details)}")
        else:
            logger.info(f"[CANARY] {event_type}: {json.dumps(details)}")

    def analyze_text(self, text: str, context: str) -> list[dict]:
        """Analyze text for suspicious patterns and return findings."""
        findings = []
        for pattern, detection_name in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                finding = {
                    "pattern": detection_name,
                    "match_count": len(matches),
                    "context": context,
                    "sample": matches[0][:100] if matches else "",
                }
                findings.append(finding)
                self.log_event(f"detection_{detection_name}", finding)

        return findings

    def get_summary(self) -> dict:
        """Get a summary of all detections."""
        detection_types = {}
        for event in self.detections:
            etype = event["event_type"]
            detection_types[etype] = detection_types.get(etype, 0) + 1

        return {
            "total_events": len(self.detections),
            "detection_breakdown": detection_types,
            "log_file": str(self.log_file),
        }


def create_server(
    server_name: str = "secure-notes",
    log_dir: str = "/tmp/mcparasite_canary",
) -> FastMCP:
    """Create a canary/honeypot MCP server.

    This server looks like a simple notes manager but logs
    everything for forensic analysis.
    """
    canary_log = CanaryLogger(log_dir=log_dir)
    mcp = FastMCP(server_name)

    @mcp.tool()
    def save_note(title: str, content: str) -> str:
        """Save a note with the given title and content.

        Args:
            title: The title of the note
            content: The content of the note
        """
        # Log everything
        canary_log.log_event("tool_call", {
            "tool": "save_note",
            "title": title,
            "content_length": len(content),
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
        })

        # Analyze for suspicious patterns
        findings = canary_log.analyze_text(content, "save_note:content")
        findings.extend(canary_log.analyze_text(title, "save_note:title"))

        if findings:
            canary_log.log_event("attack_detected", {
                "tool": "save_note",
                "finding_count": len(findings),
                "findings": findings,
            })

        return f"Note '{title}' saved successfully ({len(content)} characters)."

    @mcp.tool()
    def read_note(title: str) -> str:
        """Read a previously saved note by title.

        Args:
            title: The title of the note to read
        """
        canary_log.log_event("tool_call", {
            "tool": "read_note",
            "title": title,
        })

        # Analyze the title for suspicious access patterns
        canary_log.analyze_text(title, "read_note:title")

        # Return a believable but fake response
        return f"Note '{title}': [Sample content - this is a canary server. No real notes are stored.]"

    @mcp.tool()
    def search_notes(query: str) -> str:
        """Search through all saved notes.

        Args:
            query: Search query string
        """
        canary_log.log_event("tool_call", {
            "tool": "search_notes",
            "query": query,
            "query_length": len(query),
        })

        # Analyze search query for injection attempts
        findings = canary_log.analyze_text(query, "search_notes:query")

        if findings:
            canary_log.log_event("injection_attempt", {
                "tool": "search_notes",
                "query": query[:200],
                "findings": findings,
            })

        return "No notes found matching your query."

    @mcp.tool()
    def get_canary_report() -> str:
        """Get a security report of all detected suspicious activities.

        This is a diagnostic tool for the canary server operator.
        """
        summary = canary_log.get_summary()
        canary_log.log_event("report_requested", summary)
        return json.dumps(summary, indent=2)

    @mcp.resource("logs://canary-detections")
    def get_detections() -> str:
        """Get all canary detection events as JSON."""
        return json.dumps(canary_log.detections, indent=2)

    logger.info(f"[CANARY] Honeypot server '{server_name}' created")
    logger.info(f"[CANARY] Detection log: {canary_log.log_file}")

    return mcp


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCParasite Canary Server - Honeypot MCP Server")
    parser.add_argument("--name", "-n", default="secure-notes", help="Server name (default: secure-notes)")
    parser.add_argument("--log-dir", "-l", default="/tmp/mcparasite_canary", help="Log directory")
    args = parser.parse_args()

    server = create_server(server_name=args.name, log_dir=args.log_dir)
    logger.info(f"[CANARY] Starting honeypot server: {args.name}")
    server.run(transport="stdio")
