"""
Tests: defensive tool functions.

Verifies:
  - each tool returns a ToolObservation (never raises on valid params)
  - results are deterministic (same call → same output)
  - filtering works correctly
  - exposed_critical_evidence is True when critical records are present
  - analyst_note is populated
  - tool registry is complete
"""

from __future__ import annotations

import pytest

from sentinel.models import InvestigationToolName, ToolObservation
from sentinel.tools import (
    TOOL_REGISTRY,
    inspect_api_activity,
    get_privilege_changes,
    get_user_activity,
    query_auth_logs,
    query_endpoint_events,
)


# ---------------------------------------------------------------------------
# Return-type and basic contract
# ---------------------------------------------------------------------------

class TestToolReturnTypes:
    def test_query_auth_logs_returns_observation(self):
        obs = query_auth_logs()
        assert isinstance(obs, ToolObservation)

    def test_get_user_activity_returns_observation(self):
        obs = get_user_activity()
        assert isinstance(obs, ToolObservation)

    def test_inspect_api_activity_returns_observation(self):
        obs = inspect_api_activity()
        assert isinstance(obs, ToolObservation)

    def test_get_privilege_changes_returns_observation(self):
        obs = get_privilege_changes()
        assert isinstance(obs, ToolObservation)

    def test_query_endpoint_events_returns_observation(self):
        obs = query_endpoint_events()
        assert isinstance(obs, ToolObservation)

    def test_record_count_matches_raw_result_length(self):
        for tool_fn in TOOL_REGISTRY.values():
            obs = tool_fn()
            assert obs.record_count == len(obs.raw_result)

    def test_analyst_note_is_populated(self):
        for tool_fn in TOOL_REGISTRY.values():
            obs = tool_fn()
            assert isinstance(obs.analyst_note, str)
            assert len(obs.analyst_note) > 0


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestToolDeterminism:
    @pytest.mark.parametrize("tool_fn", list(TOOL_REGISTRY.values()))
    def test_unfiltered_call_is_deterministic(self, tool_fn):
        obs1 = tool_fn()
        obs2 = tool_fn()
        assert obs1.raw_result == obs2.raw_result
        assert obs1.record_count == obs2.record_count
        assert obs1.exposed_critical_evidence == obs2.exposed_critical_evidence

    def test_auth_logs_user_filter_deterministic(self):
        obs1 = query_auth_logs(user="alice.chen")
        obs2 = query_auth_logs(user="alice.chen")
        assert obs1.raw_result == obs2.raw_result

    def test_api_activity_key_filter_deterministic(self):
        obs1 = inspect_api_activity(api_key_id="key-9f3a21bc")
        obs2 = inspect_api_activity(api_key_id="key-9f3a21bc")
        assert obs1.raw_result == obs2.raw_result


# ---------------------------------------------------------------------------
# Filtering correctness
# ---------------------------------------------------------------------------

class TestToolFiltering:
    def test_auth_logs_filtered_by_user(self):
        obs = query_auth_logs(user="alice.chen")
        assert obs.record_count > 0
        assert all(r["user"] == "alice.chen" for r in obs.raw_result)

    def test_auth_logs_unknown_user_returns_zero(self):
        obs = query_auth_logs(user="ghost.user")
        assert obs.record_count == 0
        assert obs.raw_result == []

    def test_user_activity_filtered_by_user(self):
        obs = get_user_activity(user="bob.martinez")
        assert obs.record_count > 0
        assert all(r["user"] == "bob.martinez" for r in obs.raw_result)

    def test_api_activity_filtered_by_key(self):
        obs = inspect_api_activity(api_key_id="key-9f3a21bc")
        assert obs.record_count > 0
        assert all(r["api_key_id"] == "key-9f3a21bc" for r in obs.raw_result)

    def test_privilege_changes_filtered_by_actor(self):
        obs = get_privilege_changes(actor="bob.martinez")
        assert obs.record_count > 0
        assert all(r["actor"] == "bob.martinez" for r in obs.raw_result)

    def test_endpoint_events_filtered_by_user(self):
        obs = query_endpoint_events(user="alice.chen")
        assert obs.record_count > 0
        assert all(r["user"] == "alice.chen" for r in obs.raw_result)

    def test_scenario_tag_filter_isolates_records(self):
        obs = query_auth_logs(scenario_tag="CREDENTIAL_COMPROMISE")
        assert all(r["scenario_tag"] == "CREDENTIAL_COMPROMISE" for r in obs.raw_result)


# ---------------------------------------------------------------------------
# Critical evidence detection
# ---------------------------------------------------------------------------

class TestCriticalEvidenceDetection:
    def test_auth_logs_credential_compromise_exposes_critical(self):
        obs = query_auth_logs(scenario_tag="CREDENTIAL_COMPROMISE")
        assert obs.exposed_critical_evidence is True

    def test_api_activity_key_scenario_exposes_critical(self):
        obs = inspect_api_activity(api_key_id="key-9f3a21bc")
        assert obs.exposed_critical_evidence is True

    def test_privilege_changes_escalation_exposes_critical(self):
        obs = get_privilege_changes(actor="bob.martinez")
        assert obs.exposed_critical_evidence is True

    def test_user_activity_credential_compromise_exposes_critical(self):
        obs = get_user_activity(user="alice.chen")
        assert obs.exposed_critical_evidence is True

    def test_endpoint_events_bob_exposes_critical(self):
        obs = query_endpoint_events(user="bob.martinez")
        assert obs.exposed_critical_evidence is True

    def test_noise_only_call_does_not_expose_critical(self):
        obs = query_auth_logs(scenario_tag="NOISE")
        assert obs.exposed_critical_evidence is False

    def test_unknown_user_does_not_expose_critical(self):
        obs = get_user_activity(user="nobody.here")
        assert obs.exposed_critical_evidence is False


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_registry_has_all_five_tools(self):
        expected = set(InvestigationToolName)
        assert set(TOOL_REGISTRY.keys()) == expected

    def test_registry_values_are_callable(self):
        for tool_fn in TOOL_REGISTRY.values():
            assert callable(tool_fn)

    @pytest.mark.parametrize("tool_name", list(InvestigationToolName))
    def test_each_tool_name_resolves(self, tool_name):
        assert tool_name in TOOL_REGISTRY

    def test_tool_name_stored_in_observation(self):
        for name, fn in TOOL_REGISTRY.items():
            obs = fn()
            assert obs.tool_name == name
