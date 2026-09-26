"""
Tests: simulated environment datasets.

Verifies:
  - all log stores return deterministic, non-empty results
  - filtering by user / actor / api_key_id / scenario_tag works correctly
  - critical evidence exists in every store
  - scenario_tag=NOISE records carry no critical evidence
"""

from __future__ import annotations

import pytest

from sentinel.environment import (
    AUTH_LOGS,
    USER_ACTIVITY,
    API_ACTIVITY,
    PRIVILEGE_CHANGES,
    ENDPOINT_EVENTS,
    ENV,
)


# ---------------------------------------------------------------------------
# Dataset completeness
# ---------------------------------------------------------------------------

class TestDatasetCompleteness:
    def test_auth_logs_not_empty(self):
        assert len(AUTH_LOGS) > 0

    def test_user_activity_not_empty(self):
        assert len(USER_ACTIVITY) > 0

    def test_api_activity_not_empty(self):
        assert len(API_ACTIVITY) > 0

    def test_privilege_changes_not_empty(self):
        assert len(PRIVILEGE_CHANGES) > 0

    def test_endpoint_events_not_empty(self):
        assert len(ENDPOINT_EVENTS) > 0

    def test_all_records_have_event_id(self):
        all_records = AUTH_LOGS + USER_ACTIVITY + API_ACTIVITY + PRIVILEGE_CHANGES + ENDPOINT_EVENTS
        for record in all_records:
            assert "event_id" in record, f"Missing event_id in {record}"

    def test_all_records_have_scenario_tag(self):
        all_records = AUTH_LOGS + USER_ACTIVITY + API_ACTIVITY + PRIVILEGE_CHANGES + ENDPOINT_EVENTS
        for record in all_records:
            assert "scenario_tag" in record, f"Missing scenario_tag in {record}"


# ---------------------------------------------------------------------------
# Determinism — calling ENV twice returns identical results
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_auth_logs_deterministic(self):
        first = ENV.get_auth_logs()
        second = ENV.get_auth_logs()
        assert first == second

    def test_user_activity_deterministic(self):
        first = ENV.get_user_activity()
        second = ENV.get_user_activity()
        assert first == second

    def test_api_activity_deterministic(self):
        first = ENV.get_api_activity()
        second = ENV.get_api_activity()
        assert first == second

    def test_privilege_changes_deterministic(self):
        first = ENV.get_privilege_changes()
        second = ENV.get_privilege_changes()
        assert first == second

    def test_endpoint_events_deterministic(self):
        first = ENV.get_endpoint_events()
        second = ENV.get_endpoint_events()
        assert first == second


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

class TestFiltering:
    def test_auth_logs_filter_by_user(self):
        results = ENV.get_auth_logs(user="alice.chen")
        assert all(r["user"] == "alice.chen" for r in results)
        assert len(results) > 0

    def test_auth_logs_filter_by_scenario_tag(self):
        results = ENV.get_auth_logs(scenario_tag="CREDENTIAL_COMPROMISE")
        assert all(r["scenario_tag"] == "CREDENTIAL_COMPROMISE" for r in results)

    def test_user_activity_filter_by_user(self):
        results = ENV.get_user_activity(user="bob.martinez")
        assert all(r["user"] == "bob.martinez" for r in results)
        assert len(results) > 0

    def test_api_activity_filter_by_key(self):
        results = ENV.get_api_activity(api_key_id="key-9f3a21bc")
        assert all(r["api_key_id"] == "key-9f3a21bc" for r in results)
        assert len(results) > 0

    def test_privilege_changes_filter_by_actor(self):
        results = ENV.get_privilege_changes(actor="bob.martinez")
        assert all(r["actor"] == "bob.martinez" for r in results)
        assert len(results) > 0

    def test_endpoint_events_filter_by_user(self):
        results = ENV.get_endpoint_events(user="alice.chen")
        assert all(r["user"] == "alice.chen" for r in results)
        assert len(results) > 0

    def test_unknown_user_returns_empty(self):
        assert ENV.get_auth_logs(user="nobody.exists") == []

    def test_noise_tag_filter(self):
        noise_auth = ENV.get_auth_logs(scenario_tag="NOISE")
        assert len(noise_auth) > 0
        assert all(r["scenario_tag"] == "NOISE" for r in noise_auth)


# ---------------------------------------------------------------------------
# Critical evidence presence in each scenario
# ---------------------------------------------------------------------------

class TestCriticalEvidence:
    def test_credential_compromise_has_critical_auth(self):
        records = ENV.get_auth_logs(scenario_tag="CREDENTIAL_COMPROMISE")
        critical = [r for r in records if r.get("is_critical_evidence")]
        assert len(critical) >= 1, "CREDENTIAL_COMPROMISE needs critical auth evidence"

    def test_credential_compromise_has_critical_user_activity(self):
        records = ENV.get_user_activity(scenario_tag="CREDENTIAL_COMPROMISE")
        critical = [r for r in records if r.get("is_critical_evidence")]
        assert len(critical) >= 1

    def test_credential_compromise_has_critical_endpoint(self):
        records = ENV.get_endpoint_events(scenario_tag="CREDENTIAL_COMPROMISE")
        critical = [r for r in records if r.get("is_critical_evidence")]
        assert len(critical) >= 1

    def test_api_key_scenario_has_critical_api_records(self):
        records = ENV.get_api_activity(scenario_tag="SUSPICIOUS_API_KEY_ACTIVITY")
        critical = [r for r in records if r.get("is_critical_evidence")]
        assert len(critical) >= 2, "API key scenario needs at least 2 critical API records"

    def test_privilege_escalation_has_critical_priv_changes(self):
        records = ENV.get_privilege_changes(scenario_tag="PRIVILEGE_ESCALATION")
        critical = [r for r in records if r.get("is_critical_evidence")]
        assert len(critical) >= 3, "Privilege escalation needs at least 3 critical changes"

    def test_noise_records_have_no_critical_evidence(self):
        stores = [
            ENV.get_auth_logs(scenario_tag="NOISE"),
            ENV.get_user_activity(scenario_tag="NOISE"),
            ENV.get_api_activity(scenario_tag="NOISE"),
            ENV.get_privilege_changes(scenario_tag="NOISE"),
            ENV.get_endpoint_events(scenario_tag="NOISE"),
        ]
        for store in stores:
            for record in store:
                assert not record.get("is_critical_evidence"), (
                    f"NOISE record {record['event_id']} must not be critical"
                )
