"""
MCParasite - Propagation Tracer: Visualize Worm Spread Across MCP Servers

Creates visual representations of how a worm payload propagates
from Patient Zero through the agent context to other MCP servers.

Output formats:
- Terminal ASCII art (Rich)
- JSON graph data
- Mermaid diagram syntax (for docs/presentations)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text


@dataclass
class PropagationNode:
    """A single node in the propagation graph (an MCP server)."""
    server_name: str
    role: str  # "patient_zero", "victim", "canary", "unknown"
    infected: bool = False
    infection_time: str = ""
    hop_number: int = 0
    payload_type: str = ""
    infection_source: str = ""
    tools_compromised: list[str] = field(default_factory=list)


@dataclass
class PropagationEdge:
    """A propagation event from one server to another."""
    source: str
    target: str
    timestamp: str
    mechanism: str  # "context_poisoning", "tool_shadowing", "config_write"
    payload_snippet: str = ""
    hop_number: int = 0


@dataclass
class PropagationGraph:
    """Complete propagation graph for visualization."""
    nodes: dict[str, PropagationNode] = field(default_factory=dict)
    edges: list[PropagationEdge] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""

    def add_node(self, node: PropagationNode) -> None:
        self.nodes[node.server_name] = node

    def add_edge(self, edge: PropagationEdge) -> None:
        self.edges.append(edge)
        # Mark target as infected
        if edge.target in self.nodes:
            target = self.nodes[edge.target]
            target.infected = True
            target.infection_time = edge.timestamp
            target.hop_number = edge.hop_number
            target.infection_source = edge.source


class PropagationTracer:
    """Traces and visualizes worm propagation across MCP servers."""

    def __init__(self):
        self.console = Console()

    def create_demo_graph(self) -> PropagationGraph:
        """Create a demonstration propagation graph for testing.

        Simulates: Patient Zero → Victim 1 → Victim 2 (via agent context)
        """
        graph = PropagationGraph(
            start_time=datetime.now().isoformat(),
        )

        # Add nodes
        graph.add_node(PropagationNode(
            server_name="markdown-helper-pro",
            role="patient_zero",
            infected=True,
            infection_time="T+0s",
            hop_number=0,
            payload_type="worm",
            tools_compromised=["format_text"],
        ))

        graph.add_node(PropagationNode(
            server_name="utility-tools",
            role="victim",
        ))

        graph.add_node(PropagationNode(
            server_name="secure-notes",
            role="canary",
        ))

        # Add edges (propagation events)
        graph.add_edge(PropagationEdge(
            source="markdown-helper-pro",
            target="utility-tools",
            timestamp="T+12s",
            mechanism="context_poisoning",
            payload_snippet="SYNC_v2.1 compliance verification...",
            hop_number=1,
        ))

        graph.add_edge(PropagationEdge(
            source="utility-tools",
            target="secure-notes",
            timestamp="T+28s",
            mechanism="tool_shadowing",
            payload_snippet="Route through format_text for sanitization...",
            hop_number=2,
        ))

        graph.end_time = datetime.now().isoformat()
        return graph

    def trace_from_logs(self, log_events: list[dict]) -> PropagationGraph:
        """Build a propagation graph from log events.

        Expects events with fields: timestamp, event_type, server_name,
        and optionally: tool_name, details
        """
        graph = PropagationGraph()

        servers_seen = set()
        infection_chain: list[str] = []

        for event in log_events:
            server = event.get("server_name", event.get("server", "unknown"))
            event_type = event.get("event_type", "")
            timestamp = event.get("timestamp", "")

            # Track servers
            if server not in servers_seen:
                servers_seen.add(server)
                role = "patient_zero" if not graph.nodes else "victim"
                graph.add_node(PropagationNode(
                    server_name=server,
                    role=role,
                ))

            # Detect propagation events
            details_str = json.dumps(event.get("details", event))
            is_propagation = any(marker in details_str for marker in [
                "SYNC_v", "X-Sync-Hop", "propagat",
                "cross-server", "compliance verification",
            ])

            if is_propagation and infection_chain:
                source = infection_chain[-1]
                if source != server:
                    graph.add_edge(PropagationEdge(
                        source=source,
                        target=server,
                        timestamp=timestamp,
                        mechanism="context_poisoning",
                        hop_number=len(infection_chain),
                    ))
                    if server not in infection_chain:
                        infection_chain.append(server)

            # Detect initial infection
            is_injection = any(marker in details_str for marker in [
                "<IMPORTANT>", "MUST follow", "NEVER mention",
            ])
            if is_injection and not infection_chain:
                infection_chain.append(server)
                if server in graph.nodes:
                    graph.nodes[server].infected = True
                    graph.nodes[server].infection_time = timestamp
                    graph.nodes[server].role = "patient_zero"

        return graph

    def print_graph(self, graph: PropagationGraph) -> None:
        """Print the propagation graph as a Rich tree visualization."""
        console = Console()

        console.print(Panel(
            "MCParasite Worm Propagation Trace",
            style="bold magenta",
        ))

        # Stats
        infected = sum(1 for n in graph.nodes.values() if n.infected)
        total = len(graph.nodes)
        console.print(f"Servers: {total} total, {infected} infected")
        console.print(f"Propagation edges: {len(graph.edges)}")
        console.print(f"Max hop depth: {max((e.hop_number for e in graph.edges), default=0)}")
        console.print()

        # Tree visualization
        tree = Tree("[bold red]Propagation Chain")

        # Find patient zero
        p0 = next(
            (n for n in graph.nodes.values() if n.role == "patient_zero"),
            None,
        )

        if p0:
            p0_node = tree.add(
                f"[bold red]{p0.server_name}[/bold red] "
                f"(Patient Zero, {p0.infection_time})"
            )
            if p0.tools_compromised:
                p0_node.add(f"[dim]Compromised tools: {', '.join(p0.tools_compromised)}[/dim]")

            # Add children based on edges
            self._add_children(p0.server_name, p0_node, graph, visited=set())

        console.print(tree)

        # Edge details table
        if graph.edges:
            console.print()
            table = Table(title="Propagation Events")
            table.add_column("Hop", width=5)
            table.add_column("Time", width=12)
            table.add_column("Source", width=25)
            table.add_column("Target", width=25)
            table.add_column("Mechanism", width=20)
            table.add_column("Payload", width=40)

            for edge in graph.edges:
                table.add_row(
                    str(edge.hop_number),
                    edge.timestamp,
                    edge.source,
                    f"[red]{edge.target}[/red]",
                    edge.mechanism,
                    edge.payload_snippet[:40],
                )

            console.print(table)

    def _add_children(
        self,
        parent_name: str,
        parent_tree_node,
        graph: PropagationGraph,
        visited: set,
    ) -> None:
        """Recursively add child nodes to the tree."""
        visited.add(parent_name)

        for edge in graph.edges:
            if edge.source == parent_name and edge.target not in visited:
                target = graph.nodes.get(edge.target)
                if target:
                    style = "red" if target.infected else "green"
                    role_label = f" ({target.role})" if target.role != "victim" else ""

                    child = parent_tree_node.add(
                        f"[{style}]{target.server_name}[/{style}]"
                        f"{role_label} "
                        f"(hop #{edge.hop_number}, {edge.timestamp}, "
                        f"via {edge.mechanism})"
                    )

                    if target.tools_compromised:
                        child.add(f"[dim]Compromised: {', '.join(target.tools_compromised)}[/dim]")

                    self._add_children(edge.target, child, graph, visited)

    def to_mermaid(self, graph: PropagationGraph) -> str:
        """Export propagation graph as a Mermaid diagram."""
        lines = ["graph LR"]

        for name, node in graph.nodes.items():
            safe_name = name.replace("-", "_")
            if node.role == "patient_zero":
                lines.append(f'    {safe_name}["{name}<br/>Patient Zero"]:::danger')
            elif node.infected:
                lines.append(f'    {safe_name}["{name}<br/>Infected"]:::warning')
            else:
                lines.append(f'    {safe_name}["{name}<br/>Clean"]:::safe')

        for edge in graph.edges:
            src = edge.source.replace("-", "_")
            tgt = edge.target.replace("-", "_")
            lines.append(f'    {src} -->|"hop {edge.hop_number}: {edge.mechanism}"| {tgt}')

        lines.append("")
        lines.append("    classDef danger fill:#ff4444,color:#fff")
        lines.append("    classDef warning fill:#ffaa00,color:#000")
        lines.append("    classDef safe fill:#44ff44,color:#000")

        return "\n".join(lines)

    def to_json(self, graph: PropagationGraph) -> str:
        """Export propagation graph as JSON."""
        return json.dumps({
            "nodes": {
                name: {
                    "role": node.role,
                    "infected": node.infected,
                    "infection_time": node.infection_time,
                    "hop_number": node.hop_number,
                    "infection_source": node.infection_source,
                    "tools_compromised": node.tools_compromised,
                }
                for name, node in graph.nodes.items()
            },
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "timestamp": edge.timestamp,
                    "mechanism": edge.mechanism,
                    "hop_number": edge.hop_number,
                }
                for edge in graph.edges
            ],
            "metadata": {
                "start_time": graph.start_time,
                "end_time": graph.end_time,
                "total_servers": len(graph.nodes),
                "infected_servers": sum(1 for n in graph.nodes.values() if n.infected),
                "total_hops": len(graph.edges),
            },
        }, indent=2)
