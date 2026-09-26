"""
Tests: incident scenario definitions.

Verifies:
  - all three scenarios exist in the SCENARIOS registry
  - each has a valid SecurityAlert
  - ground_truth_type matches the registry key
  - critical_evidence_ids lists are non-empty and reference real event_ids
  - alert timestamps, severities, and affected entities are set correctly
"""

from __future__ import annotations

import pytest
from datetime import datetime

from sentinel.models import IncidentType, Severity, SecurityAlert
from sentinel.scenarios import SCENARIOS
from sentinel.environment import (
    AUTH_LOGS, USER_ACTIVITY, API_ACTIVITY, PRIVILEGE_CHANGES, ENDPOINT_EVENTS
)

# Flat set of all event_ids across every log store
ALL_EVENT_IDS: set[str] = {
    r["event_id"]
    for r in AUTH_LOGS + USER_ACTIVITY + API_ACTIVITY + PRIVILEGE_CHANGES + ENDPOINT_EVENTS
}

EXPECTED_TYPES = [
    IncidentType.CREDENTIAL_COMPROMISE,
    IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
    IncidentType.PRIVILEGE_ESCALATION,
    IncidentType.CREDENTIAL_COMPROMISE_VARIANT,
]


class TestScenarioRegistry:
    def test_all_scenarios_present(self):
        for it in EXPECTED_TYPES:
            assert it in SCENARIOS, f"Missing scenario: {it.value}"

    def test_no_unexpected_scenarios(self):
        assert set(SCENARIOS.keys()) == set(EXPECTED_TYPES)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_scenario_has_required_keys(self, incident_type):
        scenario = SCENARIOS[incident_type]
        assert "alert" in scenario
        assert "ground_truth_type" in scenario
        assert "critical_evidence_ids" in scenario
        assert "description" in scenario

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_alert_is_security_alert(self, incident_type):
        alert = SCENARIOS[incident_type]["alert"]
        assert isinstance(alert, SecurityAlert)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_ground_truth_matches_key(self, incident_type):
        scenario = SCENARIOS[incident_type]
        if incident_type == IncidentType.CREDENTIAL_COMPROMISE_VARIANT:
            assert scenario["ground_truth_type"] == IncidentType.CREDENTIAL_COMPROMISE
        else:
            assert scenario["ground_truth_type"] == incident_type

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_critical_evidence_ids_nonempty(self, incident_type):
        ids = SCENARIOS[incident_type]["critical_evidence_ids"]
        assert len(ids) > 0, f"{incident_type.value} has no critical evidence IDs"

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_critical_evidence_ids_exist_in_environment(self, incident_type):
        ids = SCENARIOS[incident_type]["critical_evidence_ids"]
        for eid in ids:
            assert eid in ALL_EVENT_IDS, (
                f"critical evidence ID '{eid}' in {incident_type.value} "
                "not found in any environment log store"
            )

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_alert_has_valid_timestamp(self, incident_type):
        alert = SCENARIOS[incident_type]["alert"]
        assert isinstance(alert.timestamp, datetime)
        assert alert.timestamp.year == 2026

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_alert_has_nonempty_raw_message(self, incident_type):
        alert = SCENARIOS[incident_type]["alert"]
        assert len(alert.raw_message) > 20

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_alert_has_affected_entity(self, incident_type):
        alert = SCENARIOS[incident_type]["alert"]
        assert alert.affected_entity, "affected_entity must be a non-empty string"


class TestScenarioGroundTruths:
    def test_credential_compromise_severity_is_critical(self):
        alert = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]["alert"]
        assert alert.severity == Severity.CRITICAL

    def test_api_key_severity_is_high_or_above(self):
        alert = SCENARIOS[IncidentType.SUSPICIOUS_API_KEY_ACTIVITY]["alert"]
        assert alert.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_privilege_escalation_severity_is_critical(self):
        alert = SCENARIOS[IncidentType.PRIVILEGE_ESCALATION]["alert"]
        assert alert.severity == Severity.CRITICAL

    def test_credential_compromise_affected_entity(self):
        alert = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]["alert"]
        assert alert.affected_entity == "alice.chen"

    def test_api_key_affected_entity(self):
        alert = SCENARIOS[IncidentType.SUSPICIOUS_API_KEY_ACTIVITY]["alert"]
        assert alert.affected_entity == "key-9f3a21bc"

    def test_privilege_escalation_affected_entity(self):
        alert = SCENARIOS[IncidentType.PRIVILEGE_ESCALATION]["alert"]
        assert alert.affected_entity == "bob.martinez"

    def test_scenario_descriptions_are_nonempty(self):
        for it in EXPECTED_TYPES:
            desc = SCENARIOS[it]["description"]
            assert isinstance(desc, str) and len(desc) > 10
