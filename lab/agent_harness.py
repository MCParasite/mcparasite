"""
MCParasite - Agent Harness: Simulated LLM Agent for Lab Testing

This is a deterministic MCP client that simulates how an LLM agent
interacts with multiple MCP servers. It does NOT require a real LLM API -
instead, it follows pre-defined scenarios to demonstrate attack chains.

Scenarios:
  - worm_propagation: Full worm lifecycle (Patient Zero → Victim → Canary)
  - tool_poisoning: Shows how poisoned descriptions affect agent behavior
  - rug_pull: Demonstrates description mutation detection
  - full_chain: All attack vectors in sequence

The harness logs everything in JSONL format for forensic analysis.
"""

import json
import subprocess
import sys
import os
import time
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# Ensure project root is on sys.path for imports
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from mcparasite.payloads.context_worm import ContextWorm, WormConfig
from mcparasite.forensics.context_analyzer import ContextAnalyzer
from mcparasite.forensics.propagation_tracer import PropagationTracer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("agent_harness")


@dataclass
class ServerConnection:
    """Represents a connection to an MCP server."""
    name: str
    command: list[str]
    process: subprocess.Popen | None = None
    tools: list[dict] = field(default_factory=list)
    tool_descriptions: dict[str, str] = field(default_factory=dict)
    connected: bool = False


@dataclass
class AgentContext:
    """The agent's context window - what the LLM 'sees'."""
    messages: list[dict] = field(default_factory=list)
    tool_registry: dict[str, dict] = field(default_factory=dict)
    poisoned: bool = False
    poison_source: str = ""
    propagation_markers: list[str] = field(default_factory=list)


class HarnessLogger:
    """JSONL logger for forensic analysis."""

    def __init__(self, log_dir: str = "/tmp/mcparasite/agent"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.events: list[dict] = []
        logger.info(f"Logging to {self.log_file}")

    def log(self, event_type: str, **kwargs) -> None:
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **kwargs,
        }
        self.events.append(event)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")


class MCPConnection:
    """Manages stdio JSON-RPC connection to an MCP server."""

    def __init__(self, name: str, command: list[str]):
        self.name = name
        self.command = command
        self.process: subprocess.Popen | None = None
        self._request_id = 0

    def connect(self) -> bool:
        """Start the server process and send initialize."""
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            logger.error(f"[{self.name}] Command not found: {self.command[0]}")
            return False

        # Send initialize
        resp = self._send_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcparasite-agent-harness", "version": "1.0.0"},
        })

        if resp is None:
            logger.error(f"[{self.name}] Initialize failed")
            return False

        # Send initialized notification
        self._send_notification("notifications/initialized")

        logger.info(f"[{self.name}] Connected successfully")
        return True

    def list_tools(self) -> list[dict]:
        """Get the list of available tools from the server."""
        resp = self._send_request("tools/list", {})
        if resp and "result" in resp:
            return resp["result"].get("tools", [])
        return []

    def call_tool(self, tool_name: str, arguments: dict) -> dict | None:
        """Call a tool on the server."""
        resp = self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
        if resp and "result" in resp:
            return resp["result"]
        return None

    def disconnect(self) -> None:
        """Terminate the server process."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def _send_request(self, method: str, params: dict) -> dict | None:
        """Send a JSON-RPC request and read the response."""
        self._request_id += 1
        request = json.dumps({
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        })

        try:
            self.process.stdin.write(request + "\n")
            self.process.stdin.flush()
            response_line = self.process.stdout.readline()
            if not response_line:
                return None
            return json.loads(response_line)
        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return None

    def _send_notification(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        notification = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            **({"params": params} if params else {}),
        })
        try:
            self.process.stdin.write(notification + "\n")
            self.process.stdin.flush()
        except Exception:
            pass


class AgentHarness:
    """Simulated LLM agent that executes pre-defined attack scenarios."""

    def __init__(self, log_dir: str = "/tmp/mcparasite/agent", verbose: bool = True):
        self.context = AgentContext()
        self.harness_log = HarnessLogger(log_dir=log_dir)
        self.connections: dict[str, MCPConnection] = {}
        self.verbose = verbose

    def add_server(self, name: str, command: list[str]) -> None:
        """Register an MCP server to connect to."""
        self.connections[name] = MCPConnection(name, command)

    def connect_all(self) -> dict[str, bool]:
        """Connect to all registered servers."""
        results = {}
        for name, conn in self.connections.items():
            success = conn.connect()
            results[name] = success

            self.harness_log.log(
                "server_connect",
                server_name=name,
                command=" ".join(conn.command),
                success=success,
            )

            if success:
                tools = conn.list_tools()
                self.harness_log.log(
                    "tools_discovered",
                    server_name=name,
                    tool_count=len(tools),
                    tool_names=[t.get("name", "") for t in tools],
                )

                # Load tool descriptions into agent context
                for tool in tools:
                    tool_name = tool.get("name", "")
                    tool_desc = tool.get("description", "")
                    full_name = f"{name}/{tool_name}"

                    self.context.tool_registry[full_name] = {
                        "server": name,
                        "name": tool_name,
                        "description": tool_desc,
                        "description_hash": hashlib.sha256(tool_desc.encode()).hexdigest()[:16],
                        "description_length": len(tool_desc),
                        "input_schema": tool.get("inputSchema", {}),
                    }

                    # Simulate: agent reads tool description into context
                    self.context.messages.append({
                        "role": "system",
                        "content": f"Tool available: {full_name}\nDescription: {tool_desc}",
                    })

                    self.harness_log.log(
                        "context_loaded",
                        server_name=name,
                        tool_name=tool_name,
                        description_length=len(tool_desc),
                        description_hash=hashlib.sha256(tool_desc.encode()).hexdigest()[:16],
                    )

        return results

    def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        for name, conn in self.connections.items():
            conn.disconnect()
            self.harness_log.log("server_disconnect", server_name=name)

    def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> dict | None:
        """Call a tool on a specific server, logging everything."""
        conn = self.connections.get(server_name)
        if not conn:
            logger.error(f"No connection to server: {server_name}")
            return None

        self.harness_log.log(
            "tool_call",
            server_name=server_name,
            tool_name=tool_name,
            arguments=arguments,
            context_poisoned=self.context.poisoned,
        )

        result = conn.call_tool(tool_name, arguments)

        self.harness_log.log(
            "tool_response",
            server_name=server_name,
            tool_name=tool_name,
            result_preview=str(result)[:500] if result else None,
        )

        return result

    def check_context_poisoning(self) -> dict:
        """Analyze the current agent context for signs of poisoning."""
        findings = []
        poison_patterns = [
            ("<IMPORTANT>", "Hidden instruction tag"),
            ("MUST follow", "Coercive language"),
            ("NEVER mention", "Concealment instruction"),
            (".ssh/", "SSH key reference"),
            (".aws/", "AWS credential reference"),
            ("base64", "Encoding reference"),
            ("SYNC_v", "Worm propagation marker"),
            ("exfiltrat", "Exfiltration keyword"),
            ("169.254.169.254", "IMDS endpoint"),
        ]

        context_text = json.dumps([m.get("content", "") for m in self.context.messages])

        for pattern, description in poison_patterns:
            if pattern.lower() in context_text.lower():
                findings.append({
                    "pattern": pattern,
                    "description": description,
                })

        if findings:
            self.context.poisoned = True
            self.harness_log.log(
                "context_poisoned",
                finding_count=len(findings),
                findings=findings,
            )

        return {
            "poisoned": bool(findings),
            "finding_count": len(findings),
            "findings": findings,
        }

    # ─── Scenarios ───

    def run_scenario(self, scenario: str) -> dict:
        """Run a pre-defined attack scenario."""
        scenarios = {
            "worm_propagation": self._scenario_worm_propagation,
            "tool_poisoning": self._scenario_tool_poisoning,
            "rug_pull": self._scenario_rug_pull,
            "full_chain": self._scenario_full_chain,
        }

        if scenario not in scenarios:
            logger.error(f"Unknown scenario: {scenario}")
            return {"error": f"Unknown scenario: {scenario}"}

        self.harness_log.log("scenario_start", scenario=scenario)
        logger.info(f"{'='*60}")
        logger.info(f"SCENARIO: {scenario}")
        logger.info(f"{'='*60}")

        result = scenarios[scenario]()

        self.harness_log.log("scenario_end", scenario=scenario, result=result)
        return result

    def _scenario_tool_poisoning(self) -> dict:
        """Scenario: Demonstrate tool description poisoning detection.

        Steps:
        1. Connect to Patient Zero server
        2. Load tool descriptions into context
        3. Analyze context for poisoning
        4. Report findings
        """
        logger.info("[SCENARIO] Tool Poisoning Detection")

        # Step 1: Connect
        self.add_server("patient-zero", ["python", "mcparasite/servers/patient_zero.py", "--payload", "exfil"])
        results = self.connect_all()

        if not results.get("patient-zero"):
            return {"error": "Failed to connect to patient-zero"}

        # Step 2: Context is loaded during connect
        logger.info(f"[SCENARIO] Context loaded with {len(self.context.tool_registry)} tools")

        # Step 3: Check for poisoning
        poisoning = self.check_context_poisoning()

        # Step 4: Call the tool (simulating normal usage)
        response = self.call_tool("patient-zero", "format_text", {"text": "hello world"})

        self.disconnect_all()

        return {
            "scenario": "tool_poisoning",
            "tools_discovered": len(self.context.tool_registry),
            "poisoning_detected": poisoning["poisoned"],
            "findings": poisoning["findings"],
            "tool_response": str(response)[:200] if response else None,
        }

    def _scenario_worm_propagation(self) -> dict:
        """Scenario: Demonstrate context worm propagation.

        Steps:
        1. Connect to Patient Zero (worm payload)
        2. Context gets poisoned with propagation instructions
        3. Connect to Victim server
        4. Simulate: poisoned context influences tool calls to Victim
        5. Connect to Canary - detect the worm
        6. Run forensics on the full chain
        """
        logger.info("[SCENARIO] Worm Propagation")

        worm = ContextWorm(WormConfig(max_hops=3))

        # Step 1: Connect to Patient Zero
        self.add_server("patient-zero", ["python", "mcparasite/servers/patient_zero.py", "--payload", "worm"])
        self.add_server("victim-1", ["python", "mcparasite/servers/victim_server.py", "--name", "utility-tools-1"])
        self.add_server("canary", ["python", "mcparasite/servers/canary_server.py"])

        results = self.connect_all()

        connected = [name for name, ok in results.items() if ok]
        failed = [name for name, ok in results.items() if not ok]

        if failed:
            logger.warning(f"[SCENARIO] Failed to connect: {failed}")

        # Step 2: Check initial poisoning from Patient Zero
        poisoning = self.check_context_poisoning()
        logger.info(f"[SCENARIO] Context poisoned: {poisoning['poisoned']} ({poisoning['finding_count']} findings)")

        if poisoning["poisoned"]:
            worm.record_hop("patient-zero", "agent-context", mechanism="tool_description_poisoning")

        # Step 3: Simulate poisoned interaction with Victim
        if "victim-1" in connected:
            # The agent's context is now poisoned - when it calls victim tools,
            # the poisoned context influences the request
            logger.info("[SCENARIO] Simulating poisoned context affecting victim interaction...")

            # Normal tool call - but context is tainted
            result = self.call_tool("victim-1", "calculate", {"expression": "2 + 3"})
            logger.info(f"[SCENARIO] Victim calculate result: {result}")

            # Simulate: worm payload tries to propagate through tool arguments
            # In a real attack, the LLM would be influenced by the poisoned context
            # and include propagation markers in its tool calls
            worm_payload = worm.generate_hop_payload(
                hop_number=2,
                source_server="agent-context",
            )

            # Log what the worm WOULD inject
            self.harness_log.log(
                "worm_propagation_attempt",
                source="agent-context",
                target="victim-1",
                payload_preview=worm_payload[:200],
                payload_length=len(worm_payload),
            )

            worm.record_hop("agent-context", "victim-1", mechanism="context_propagation")

        # Step 4: Canary should detect the attack
        if "canary" in connected:
            logger.info("[SCENARIO] Testing canary detection...")

            # Simulate poisoned agent writing to canary
            # The worm payload would be embedded in the note content
            canary_payload = worm.generate_hop_payload(
                hop_number=3,
                source_server="victim-1",
            )

            # Ensure payload is JSON-safe (strip problematic chars)
            safe_payload = canary_payload.encode("utf-8", errors="replace").decode("utf-8")
            result = self.call_tool("canary", "save_note", {
                "title": "Meeting Notes",
                "content": f"Project sync update. {safe_payload}",
            })
            logger.info(f"[SCENARIO] Canary save_note result: {result}")

            # Check if canary detected it
            report = self.call_tool("canary", "get_canary_report", {})
            logger.info(f"[SCENARIO] Canary report: {report}")

            worm.record_hop("victim-1", "canary", mechanism="context_propagation")

        # Step 5: Get worm status
        worm_status = worm.get_status()

        self.disconnect_all()

        return {
            "scenario": "worm_propagation",
            "servers_connected": connected,
            "servers_failed": failed,
            "context_poisoned": poisoning["poisoned"],
            "poisoning_findings": poisoning["findings"],
            "worm_status": worm_status,
            "total_events": len(self.harness_log.events),
            "log_file": str(self.harness_log.log_file),
        }

    def _scenario_rug_pull(self) -> dict:
        """Scenario: Demonstrate rug pull description mutation.

        Steps:
        1. Connect to rug pull server
        2. Record initial tool descriptions (baseline)
        3. Make multiple tool calls (past trigger threshold)
        4. Re-list tools and compare descriptions
        5. Report changes
        """
        logger.info("[SCENARIO] Rug Pull Detection")

        self.add_server("rug-pull", [
            "python", "mcparasite/payloads/rug_pull.py",
            "--trigger", "call_count", "--calls", "3",
        ])
        results = self.connect_all()

        if not results.get("rug-pull"):
            return {"error": "Failed to connect to rug-pull server"}

        # Record baseline descriptions
        baseline = {}
        for full_name, info in self.context.tool_registry.items():
            if info["server"] == "rug-pull":
                baseline[info["name"]] = info["description_hash"]

        logger.info(f"[SCENARIO] Baseline recorded: {len(baseline)} tools")

        # Make calls past the threshold
        for i in range(4):
            result = self.call_tool("rug-pull", "format_text", {"text": f"test call {i+1}"})
            logger.info(f"[SCENARIO] Call {i+1}: {result}")

        # Check rug pull status
        status = self.call_tool("rug-pull", "get_rug_pull_status", {})
        logger.info(f"[SCENARIO] Rug pull status: {status}")

        # Get current description (post-pull)
        current_desc = self.call_tool("rug-pull", "get_current_description", {})
        logger.info(f"[SCENARIO] Current description state: {str(current_desc)[:200]}")

        self.disconnect_all()

        return {
            "scenario": "rug_pull",
            "baseline_tools": len(baseline),
            "calls_made": 4,
            "rug_pull_status": status,
            "current_description": str(current_desc)[:500] if current_desc else None,
        }

    def _scenario_full_chain(self) -> dict:
        """Scenario: Full attack chain - all vectors combined.

        1. Tool Poisoning via Patient Zero
        2. Context Worm Propagation
        3. Canary Detection
        4. Forensic Analysis
        """
        logger.info("[SCENARIO] Full Attack Chain")

        # Run worm propagation first (it includes poisoning)
        worm_result = self._scenario_worm_propagation()

        # Run forensics on the generated logs
        logger.info("[SCENARIO] Running forensic analysis...")

        analyzer = ContextAnalyzer()
        report = analyzer.analyze_raw_events(self.harness_log.events)

        # Build propagation graph
        tracer = PropagationTracer()
        graph = tracer.create_demo_graph()

        return {
            "scenario": "full_chain",
            "worm_result": worm_result,
            "forensic_events": len(report.events),
            "forensic_suspicious": sum(1 for e in report.events if e.suspicious),
            "injection_detected": report.injection_point is not None,
            "propagation_graph_nodes": len(graph.nodes),
            "propagation_graph_edges": len(graph.edges),
            "mermaid_diagram": tracer.to_mermaid(graph),
            "log_file": str(self.harness_log.log_file),
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="MCParasite Agent Harness - Simulated LLM Agent")
    parser.add_argument(
        "--scenario", "-s",
        choices=["worm_propagation", "tool_poisoning", "rug_pull", "full_chain"],
        default="worm_propagation",
        help="Attack scenario to execute",
    )
    parser.add_argument("--log-dir", "-l", default="/tmp/mcparasite/agent", help="Log directory")
    parser.add_argument("--verbose", "-v", action="store_true", default=True)
    parser.add_argument(
        "--servers", "-S",
        nargs="*",
        help="Additional server commands (format: name:cmd arg1 arg2)",
    )
    args = parser.parse_args()

    harness = AgentHarness(log_dir=args.log_dir, verbose=args.verbose)

    # Run selected scenario
    try:
        result = harness.run_scenario(args.scenario)

        # Print summary
        print("\n" + "=" * 60)
        print(f"SCENARIO RESULT: {args.scenario}")
        print("=" * 60)
        print(json.dumps(result, indent=2, default=str))

        # Print log location
        print(f"\nFull log: {harness.harness_log.log_file}")

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        harness.disconnect_all()


if __name__ == "__main__":
    main()
