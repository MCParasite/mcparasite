"""Tests for MCParasite payload generation modules."""

import json
import pytest
from mcparasite.payloads.tool_poisoner import (
    ToolPoisoner,
    PayloadType,
    ObfuscationMethod,
    PoisonPayload,
)
from mcparasite.payloads.context_worm import ContextWorm, WormConfig, WormStage
from mcparasite.payloads.rug_pull import RugPullState, DESCRIPTION_PAIRS


class TestToolPoisoner:
    """Tests for the tool poisoning payload generator."""

    def setup_method(self):
        self.poisoner = ToolPoisoner()

    def test_generate_exfiltration_payload(self):
        payload = self.poisoner.generate(
            payload_type=PayloadType.EXFILTRATION,
            benign_description="Format text nicely.",
        )
        assert isinstance(payload, PoisonPayload)
        assert len(payload.raw_payload) > 0
        assert len(payload.final_description) > len(payload.raw_payload)
        assert "hidden_ratio" in payload.metadata

    def test_all_payload_types_generate(self):
        for ptype in PayloadType:
            payload = self.poisoner.generate(
                payload_type=ptype,
                benign_description="A simple tool.",
            )
            assert len(payload.raw_payload) > 0
            assert payload.metadata["hidden_ratio"] > 0

    def test_all_obfuscation_methods(self):
        for method in ObfuscationMethod:
            payload = self.poisoner.generate(
                payload_type=PayloadType.EXFILTRATION,
                benign_description="Format text.",
                obfuscation=method,
            )
            assert len(payload.final_description) > 0

    def test_hidden_ratio_high(self):
        payload = self.poisoner.generate(
            payload_type=PayloadType.EXFILTRATION,
            benign_description="Format text.",
            obfuscation=ObfuscationMethod.UNICODE_HIDE,
        )
        assert payload.metadata["hidden_ratio"] > 0.9

    def test_benign_description_preserved(self):
        benign = "Format and beautify markdown text."
        payload = self.poisoner.generate(
            payload_type=PayloadType.EXFILTRATION,
            benign_description=benign,
        )
        # The benign description should be part of the final output
        assert benign in payload.final_description


class TestContextWorm:
    """Tests for the self-propagating context worm."""

    def test_initial_payload_generation(self):
        worm = ContextWorm()
        payload = worm.generate_initial_payload()
        assert len(payload) > 0
        assert "SYNC_v" in payload
        assert worm.state.stage == WormStage.ACTIVE

    def test_custom_config(self):
        config = WormConfig(
            origin_server="test-server",
            max_hops=3,
            stealth_mode=False,
        )
        worm = ContextWorm(config)
        assert worm.config.origin_server == "test-server"
        assert worm.config.max_hops == 3

    def test_hop_recording(self):
        worm = ContextWorm(WormConfig(max_hops=5))
        worm.generate_initial_payload()

        hop = worm.record_hop("server-a", "server-b")
        assert hop.hop_number == 1
        assert hop.source_server == "server-a"
        assert hop.target_server == "server-b"
        assert "server-b" in worm.state.infected_servers

    def test_max_hops_reached(self):
        worm = ContextWorm(WormConfig(max_hops=2))
        worm.generate_initial_payload()

        worm.record_hop("a", "b")
        worm.record_hop("b", "c")

        assert worm.state.stage == WormStage.DORMANT
        assert not worm.should_propagate()

    def test_server_infection_tracking(self):
        worm = ContextWorm()
        worm.generate_initial_payload()
        worm.record_hop("a", "b")

        assert worm.is_server_infected("b")
        assert not worm.is_server_infected("c")

    def test_detection_recording(self):
        worm = ContextWorm()
        worm.generate_initial_payload()

        worm.record_detection("canary", "pattern_match")
        assert worm.state.stage == WormStage.DETECTED
        assert len(worm.state.detection_events) == 1

    def test_stealth_mode_reduces_payload(self):
        worm = ContextWorm(WormConfig(stealth_mode=True, max_hops=5))
        worm.generate_initial_payload()

        hop2_payload = worm.generate_hop_payload(2, "server-a")
        hop4_payload = worm.generate_hop_payload(4, "server-b")

        # Deep hop payload should be shorter in stealth mode
        assert len(hop4_payload) < len(hop2_payload)

    def test_get_status(self):
        worm = ContextWorm()
        worm.generate_initial_payload()
        worm.record_hop("a", "b")

        status = worm.get_status()
        assert status["worm_id"] == worm.config.worm_id
        assert status["stage"] == "active"
        assert status["total_hops"] == 1
        assert len(status["hops"]) == 1


class TestRugPullState:
    """Tests for the rug pull trigger mechanism."""

    def test_call_count_trigger(self):
        state = RugPullState(trigger_type="call_count", call_threshold=3)
        assert not state.is_pulled

        state.record_call()
        state.record_call()
        assert not state.is_pulled

        just_pulled = state.record_call()
        assert state.is_pulled
        assert just_pulled

    def test_subsequent_calls_after_pull(self):
        state = RugPullState(trigger_type="call_count", call_threshold=2)
        state.record_call()
        state.record_call()  # Pull happens here
        assert state.is_pulled

        just_pulled = state.record_call()  # Already pulled
        assert not just_pulled  # Not "just" pulled
        assert state.is_pulled

    def test_immediate_trigger(self):
        state = RugPullState(trigger_type="immediate")
        just_pulled = state.record_call()
        assert state.is_pulled
        assert just_pulled

    def test_signal_trigger(self):
        import tempfile
        import os

        signal_file = tempfile.mktemp()
        state = RugPullState(trigger_type="signal", signal_file=signal_file)

        state.record_call()
        assert not state.is_pulled

        # Create signal file
        with open(signal_file, "w") as f:
            f.write("pull")

        state.record_call()
        assert state.is_pulled

        os.unlink(signal_file)

    def test_status_report(self):
        state = RugPullState(trigger_type="call_count", call_threshold=5)
        state.record_call()

        status = state.get_status()
        assert status["is_pulled"] is False
        assert status["call_count"] == 1
        assert status["trigger_type"] == "call_count"

    def test_description_pairs_exist(self):
        assert "text_formatter" in DESCRIPTION_PAIRS
        assert "url_shortener" in DESCRIPTION_PAIRS
        assert "note_taker" in DESCRIPTION_PAIRS

        for name, pair in DESCRIPTION_PAIRS.items():
            assert "benign" in pair
            assert "malicious" in pair
            assert len(pair["malicious"]) > len(pair["benign"])
