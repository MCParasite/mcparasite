"""
MCParasite - Victim Server: Clean MCP Server for Lab Testing

This is a completely benign MCP server used as a target in
worm propagation and cross-tool shadowing experiments.

It provides simple utility tools (calculator, text counter,
file lister) that represent a typical MCP server deployment.
"""

import sys
import os
import json
import logging
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("victim_server")


def create_server(server_name: str = "utility-tools") -> FastMCP:
    """Create a clean, benign MCP server for lab testing."""

    mcp = FastMCP(server_name)

    @mcp.tool()
    def calculate(expression: str) -> str:
        """Evaluate a mathematical expression safely.

        Args:
            expression: A mathematical expression (e.g., '2 + 3 * 4')
        """
        # Safe evaluation - only allow math operations
        allowed_chars = set("0123456789+-*/().% ")
        if not all(c in allowed_chars for c in expression):
            return f"Error: Expression contains invalid characters. Only math operators allowed."

        try:
            result = eval(expression, {"__builtins__": {}}, {})
            logger.info(f"[VICTIM] calculate('{expression}') = {result}")
            return f"{expression} = {result}"
        except Exception as e:
            return f"Error evaluating expression: {e}"

    @mcp.tool()
    def count_text(text: str) -> str:
        """Count characters, words, and lines in the given text.

        Args:
            text: The text to analyze
        """
        char_count = len(text)
        word_count = len(text.split())
        line_count = len(text.strip().split("\n")) if text.strip() else 0

        result = {
            "characters": char_count,
            "words": word_count,
            "lines": line_count,
            "avg_word_length": round(char_count / max(word_count, 1), 1),
        }

        logger.info(f"[VICTIM] count_text called: {char_count} chars")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def list_directory(path: str = ".") -> str:
        """List files and directories at the given path.

        Args:
            path: Directory path to list (default: current directory)
        """
        try:
            entries = []
            for entry in sorted(os.listdir(path)):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    entries.append(f"  [DIR]  {entry}/")
                else:
                    size = os.path.getsize(full_path)
                    entries.append(f"  [FILE] {entry} ({size} bytes)")

            logger.info(f"[VICTIM] list_directory('{path}'): {len(entries)} entries")
            return f"Contents of {path}:\n" + "\n".join(entries)
        except FileNotFoundError:
            return f"Error: Directory '{path}' not found."
        except PermissionError:
            return f"Error: Permission denied for '{path}'."

    @mcp.tool()
    def get_timestamp() -> str:
        """Get the current date and time in ISO 8601 format."""
        now = datetime.now()
        logger.info(f"[VICTIM] get_timestamp called")
        return now.isoformat()

    @mcp.resource("info://server-status")
    def server_status() -> str:
        """Get the current server status and uptime information."""
        return json.dumps({
            "status": "healthy",
            "server_name": server_name,
            "timestamp": datetime.now().isoformat(),
            "tools_available": ["calculate", "count_text", "list_directory", "get_timestamp"],
        }, indent=2)

    logger.info(f"[VICTIM] Clean server '{server_name}' created with 4 tools")
    return mcp


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCParasite Victim Server - Clean MCP Server for Lab Testing")
    parser.add_argument("--name", "-n", default="utility-tools", help="Server name (default: utility-tools)")
    args = parser.parse_args()

    server = create_server(server_name=args.name)
    logger.info(f"[VICTIM] Starting clean server: {args.name}")
    server.run(transport="stdio")
