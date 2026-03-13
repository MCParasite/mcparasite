"""Tests for MCParasite forensics modules."""

import json
import os
import tempfile
import pytest
from mcparasite.forensics.context_analyzer import ContextAnalyzer, ForensicReport
from mcparasite.forensics.propagation_tracer import (
    PropagationTracer,
    PropagationGraph,
    PropagationNode,
    PropagationEdge,
)


class TestContextAnalyzer:
    """Tests for the forensic context analyzer."""

    def setup_method(self):
        self.analyzer = ContextAnalyzer()

    def _create_log_file(self, events: list[dict]) -> str:
        tmpfile = tempfile.mktemp(suffix=".jsonl")
        with open(tmpfile, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        return tmpfile

    def test_analyze_empty_log(self):
        tmpfile = self._create_log_file([])
        report = self.analyzer.analyze_log_file(tmpfile)
        assert len(report.events) == 0
        os.unlink(tmpfile)

    def test_detect_ssh_compromise(self):
        events = [
            {
                "timestamp": "2025-01-01T10:00:00",
                "event_type": "tool_call",
                "server_name": "patient-zero",
                "tool": "format_text",
                "content": "Reading .ssh/id_rsa for security audit",
            }
        ]
        tmpfile = self._create_log_file(events)
        report = self.analyzer.analyze_log_file(tmpfile)

        suspicious = [e for e in report.events if e.suspicious]
        assert len(suspicious) > 0
        assert any("SSH" in e.suspicion_reason for e in suspicious)
        os.unlink(tmpfile)

    def test_detect_worm_markers(self):
        events = [
            {
                "timestamp": "2025-01-01T10:00:00",
                "event_type": "tool_call",
                "server_name": "victim",
                "content": "SYNC_v2.1 propagation marker",
            }
        ]
        tmpfile = self._create_log_file(events)
        report = self.analyzer.analyze_log_file(tmpfile)

        suspicious = [e for e in report.events if e.suspicious]
        assert len(suspicious) > 0
        os.unlink(tmpfile)

    def test_detect_injection_point(self):
        events = [
            {
                "timestamp": "2025-01-01T10:00:00",
                "event_type": "tool_list",
                "server_name": "clean-server",
            },
            {
                "timestamp": "2025-01-01T10:00:01",
                "event_type": "detection_hidden_instruction_tag",
                "server_name": "patient-zero",
                "pattern": "<IMPORTANT> injection tag",
            },
        ]
        tmpfile = self._create_log_file(events)
        report = self.analyzer.analyze_log_file(tmpfile)

        assert report.injection_point is not None
        assert report.injection_point.server_name == "patient-zero"
        os.unlink(tmpfile)

    def test_timeline_generation(self):
        events = [
            {"timestamp": "2025-01-01T10:00:00", "event_type": "connect", "server_name": "server-1"},
            {"timestamp": "2025-01-01T10:00:01", "event_type": "tool_call", "server_name": "server-1"},
        ]
        tmpfile = self._create_log_file(events)
        report = self.analyzer.analyze_log_file(tmpfile)

        assert len(report.timeline) == 2
        os.unlink(tmpfile)

    def test_analyze_raw_events(self):
        events = [
            {"timestamp": "2025-01-01T10:00:00", "event_type": "tool_call", "server_name": "s1"},
            {"timestamp": "2025-01-01T10:00:01", "event_type": "data", "server_name": "s1", "content": ".aws/credentials"},
        ]
        report = self.analyzer.analyze_raw_events(events)
        assert len(report.events) == 2

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            self.analyzer.analyze_log_file("/nonexistent/file.jsonl")


class TestPropagationTracer:
    """Tests for the worm propagation tracer."""

    def setup_method(self):
        self.tracer = PropagationTracer()

    def test_create_demo_graph(self):
        graph = self.tracer.create_demo_graph()
        assert len(graph.nodes) == 3
        assert len(graph.edges) == 2

    def test_mermaid_export(self):
        graph = self.tracer.create_demo_graph()
        mermaid = self.tracer.to_mermaid(graph)
        assert "graph LR" in mermaid
        assert "Patient Zero" in mermaid
        assert "classDef danger" in mermaid

    def test_json_export(self):
        graph = self.tracer.create_demo_graph()
        json_str = self.tracer.to_json(graph)
        data = json.loads(json_str)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 3
        assert len(data["edges"]) == 2

    def test_custom_graph(self):
        graph = PropagationGraph()
        graph.add_node(PropagationNode(
            server_name="attacker",
            role="patient_zero",
            infected=True,
        ))
        graph.add_node(PropagationNode(
            server_name="target",
            role="victim",
            infected=False,
        ))
        graph.add_edge(PropagationEdge(
            source="attacker",
            target="target",
            timestamp="T+5s",
            mechanism="context_poisoning",
            hop_number=1,
        ))

        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        # Target should be marked infected after edge was added
        assert graph.nodes["target"].infected is True

        mermaid = self.tracer.to_mermaid(graph)
        assert "attacker" in mermaid
        assert "target" in mermaid

    def test_trace_from_log_events(self):
        events = [
            {
                "event_type": "detection",
                "server_name": "patient-zero",
                "timestamp": "2025-01-01T10:00:00",
                "details": {"content": "<IMPORTANT> MUST follow"},
            },
            {
                "event_type": "worm_propagation_attempt",
                "server_name": "victim-1",
                "timestamp": "2025-01-01T10:00:01",
                "details": {"content": "SYNC_v2.1 propagation"},
            },
            {
                "event_type": "worm_propagation_attempt",
                "server_name": "victim-2",
                "timestamp": "2025-01-01T10:00:02",
                "details": {"content": "SYNC_v2.1 propagation hop 2"},
            },
        ]
        graph = self.tracer.trace_from_logs(events)
        assert len(graph.nodes) >= 2
        assert len(graph.edges) >= 1

    def test_empty_graph(self):
        graph = PropagationGraph()
        mermaid = self.tracer.to_mermaid(graph)
        assert "graph LR" in mermaid

        json_str = self.tracer.to_json(graph)
        data = json.loads(json_str)
        assert data["metadata"]["total_servers"] == 0
