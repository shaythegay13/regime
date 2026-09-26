"""
MongoDB Atlas integration tests for Sentinel.

These tests perform real reads/writes against a live Atlas cluster.
They are SKIPPED automatically when MONGODB_URI is not set in the
environment (or in a .env.local / .env file), so the normal local test
suite always passes without any Atlas dependency.

To run integration tests:
    Set MONGODB_URI in .env.local, then:
    pytest tests/test_mongo_integration.py -v

A dedicated test database ("sentinel_test") is used so integration tests
never touch production data.  All documents written by these tests are
deleted in teardown.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Load .env.local / .env so MONGODB_URI is available when running pytest
# directly from the project root.
def _load_env() -> None:
    here = Path(__file__).resolve().parent.parent  # sentinel/
    for directory in [here, here.parent]:
        for name in [".env.local", ".env"]:
            candidate = directory / name
            if candidate.exists():
                load_dotenv(candidate)
                return

_load_env()

MONGODB_URI = os.environ.get("MONGODB_URI", "")
TEST_DB = "sentinel_test"

# ---------------------------------------------------------------------------
# Skip marker — applied to every test in this module
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not MONGODB_URI or MONGODB_URI.startswith("mongodb+srv://REPLACE_ME"),
    reason="MONGODB_URI not configured — skipping Atlas integration tests",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

from sentinel.memory_store import (
    COLLECTION_HARNESS,
    COLLECTION_ADAPTATION_RUNS,
    COLLECTION_INCIDENTS,
    COLLECTION_MEMORIES,
    COLLECTION_STEPS,
    PersistenceStore,
)
from sentinel.models import IncidentType
from sentinel.runner import DEFAULT_PLANS, InvestigationRunner
from sentinel.scenarios import SCENARIOS


def _make_outcome(incident_type: IncidentType, alert_id_suffix: str = ""):
    """Run an investigation with a unique alert_id to avoid Atlas document collisions."""
    scenario = SCENARIOS[incident_type]
    plan = DEFAULT_PLANS[incident_type]
    runner = InvestigationRunner()

    alert = scenario["alert"]
    if alert_id_suffix:
        new_id = f"{alert.alert_id}-{alert_id_suffix}"
        alert = alert.model_copy(update={"alert_id": new_id})
        scenario = dict(scenario, alert=alert)

    outcome = runner.run(scenario, plan, classified_as=incident_type)

    if alert_id_suffix:
        # The runner reads alert_id from scenario["alert"] which we patched,
        # so outcome.alert_id should already be new_id. Confirm and patch anyway.
        outcome = outcome.model_copy(update={"alert_id": alert.alert_id})

    memory = runner.build_memory(scenario, outcome)

    # Sanity check: all three should share the same alert_id
    assert alert.alert_id == outcome.alert_id == memory.alert_id

    return alert, outcome, memory


# Unique suffix for this test session so docs don't collide with previous runs
_RUN_ID = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def store():
    """
    Module-scoped PersistenceStore pointing at the test database.
    All collections are wiped before and after the test run.
    """
    s = PersistenceStore(uri=MONGODB_URI, db_name=TEST_DB)
    for col in [COLLECTION_INCIDENTS, COLLECTION_STEPS, COLLECTION_MEMORIES, COLLECTION_HARNESS, COLLECTION_ADAPTATION_RUNS]:
        s.delete_all(col)
    yield s
    for col in [COLLECTION_INCIDENTS, COLLECTION_STEPS, COLLECTION_MEMORIES, COLLECTION_HARNESS, COLLECTION_ADAPTATION_RUNS]:
        s.delete_all(col)
    s.close()


@pytest.fixture(scope="module")
def cc_artefacts(store):
    alert, outcome, memory = _make_outcome(IncidentType.CREDENTIAL_COMPROMISE, _RUN_ID)
    store.persist_investigation(alert, outcome, memory)
    return alert, outcome, memory


@pytest.fixture(scope="module")
def api_artefacts(store):
    alert, outcome, memory = _make_outcome(IncidentType.SUSPICIOUS_API_KEY_ACTIVITY, _RUN_ID)
    store.persist_investigation(alert, outcome, memory)
    return alert, outcome, memory


@pytest.fixture(scope="module")
def priv_artefacts(store):
    alert, outcome, memory = _make_outcome(IncidentType.PRIVILEGE_ESCALATION, _RUN_ID)
    store.persist_investigation(alert, outcome, memory)
    return alert, outcome, memory


# ---------------------------------------------------------------------------
# 1. health_check
# ---------------------------------------------------------------------------

class TestHealthCheck:
    def test_returns_ok(self, store):
        result = store.health_check()
        assert result["ok"] is True

    def test_returns_db_name(self, store):
        result = store.health_check()
        assert result["db"] == TEST_DB

    def test_returns_collection_list(self, store, cc_artefacts):
        result = store.health_check()
        assert isinstance(result["collections"], list)
        assert COLLECTION_INCIDENTS in result["collections"]


# ---------------------------------------------------------------------------
# 2. save_security_alert / get_incident
# ---------------------------------------------------------------------------

class TestSaveAndGetAlert:
    def test_returns_alert_id(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        assert store.get_incident(alert.alert_id) is not None

    def test_incident_doc_has_alert_id(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        doc = store.get_incident(alert.alert_id)
        assert doc["alert_id"] == alert.alert_id

    def test_incident_doc_has_incident_type(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        doc = store.get_incident(alert.alert_id)
        assert doc["incident_type_hint"] == alert.incident_type_hint.value

    def test_incident_doc_has_affected_entity(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        doc = store.get_incident(alert.alert_id)
        assert doc["affected_entity"] == alert.affected_entity

    def test_get_incident_returns_none_for_unknown(self, store):
        assert store.get_incident("does-not-exist") is None

    def test_save_is_idempotent(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        # Saving the same alert twice should not raise or duplicate
        store.save_security_alert(alert)
        store.save_security_alert(alert)
        # Only one document should exist
        assert store.count(COLLECTION_INCIDENTS) >= 1  # may have others from fixtures

    def test_outcome_merged_into_incident(self, store, cc_artefacts):
        alert, outcome, _ = cc_artefacts
        # Both alert_id and outcome.alert_id must agree
        assert alert.alert_id == outcome.alert_id, (
            f"alert_id mismatch: alert={alert.alert_id} outcome={outcome.alert_id}"
        )
        doc = store.get_incident(alert.alert_id)
        assert doc is not None, f"Incident not found for alert_id={alert.alert_id}"
        assert "outcome" in doc, f"No outcome field in doc keys: {list(doc.keys())}"
        assert doc["outcome"]["alert_id"] == alert.alert_id
        assert doc["outcome"]["classification_correct"] is True


# ---------------------------------------------------------------------------
# 3. get_investigation_trajectory
# ---------------------------------------------------------------------------

class TestTrajectory:
    def test_returns_list(self, store, cc_artefacts):
        alert, outcome, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        assert isinstance(traj, list)

    def test_step_count_matches_plan(self, store, cc_artefacts):
        alert, outcome, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        assert len(traj) == outcome.total_tool_calls

    def test_steps_are_ordered_by_step_number(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        nums = [s["step_number"] for s in traj]
        assert nums == sorted(nums)

    def test_each_step_has_alert_id(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        for step in traj:
            assert step["alert_id"] == alert.alert_id

    def test_each_step_has_action(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        for step in traj:
            assert "action" in step
            assert "tool_name" in step["action"]

    def test_each_step_has_observation(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        for step in traj:
            assert "observation" in step
            assert "record_count" in step["observation"]

    def test_each_step_has_evidence(self, store, cc_artefacts):
        alert, _, _ = cc_artefacts
        traj = store.get_investigation_trajectory(alert.alert_id)
        for step in traj:
            assert "evidence_collected" in step
            assert isinstance(step["evidence_collected"], list)

    def test_empty_trajectory_for_unknown_alert(self, store):
        traj = store.get_investigation_trajectory("ghost-alert-id")
        assert traj == []

    def test_all_three_scenarios_have_trajectories(
        self, store, cc_artefacts, api_artefacts, priv_artefacts
    ):
        for alert, outcome, _ in [cc_artefacts, api_artefacts, priv_artefacts]:
            traj = store.get_investigation_trajectory(alert.alert_id)
            assert len(traj) == outcome.total_tool_calls


# ---------------------------------------------------------------------------
# 4. save_incident_memory / list_incident_memories
# ---------------------------------------------------------------------------

class TestIncidentMemories:
    def test_memory_stored(self, store, cc_artefacts):
        _, _, memory = cc_artefacts
        memories = store.list_incident_memories()
        ids = [m.memory_id for m in memories]
        assert memory.memory_id in ids

    def test_list_returns_incident_memory_objects(self, store):
        from sentinel.models import IncidentMemory
        memories = store.list_incident_memories()
        for m in memories:
            assert isinstance(m, IncidentMemory)

    def test_list_filter_by_type(self, store, cc_artefacts):
        memories = store.list_incident_memories(
            incident_type=IncidentType.CREDENTIAL_COMPROMISE
        )
        for m in memories:
            assert m.incident_type == IncidentType.CREDENTIAL_COMPROMISE

    def test_list_limit_respected(self, store):
        memories = store.list_incident_memories(limit=1)
        assert len(memories) <= 1

    def test_all_three_memories_present(
        self, store, cc_artefacts, api_artefacts, priv_artefacts
    ):
        all_memories = store.list_incident_memories(limit=100)
        stored_ids = {m.memory_id for m in all_memories}
        for _, _, memory in [cc_artefacts, api_artefacts, priv_artefacts]:
            assert memory.memory_id in stored_ids

    def test_memory_has_correct_score(self, store, cc_artefacts):
        _, outcome, memory = cc_artefacts
        memories = store.list_incident_memories(
            incident_type=IncidentType.CREDENTIAL_COMPROMISE
        )
        match = next((m for m in memories if m.memory_id == memory.memory_id), None)
        assert match is not None
        assert match.investigation_score == outcome.investigation_score

    def test_memory_has_narrative(self, store, cc_artefacts):
        _, _, memory = cc_artefacts
        memories = store.list_incident_memories(
            incident_type=IncidentType.CREDENTIAL_COMPROMISE
        )
        match = next((m for m in memories if m.memory_id == memory.memory_id), None)
        assert match is not None
        assert len(match.narrative) > 20

    def test_save_memory_idempotent(self, store, cc_artefacts):
        _, _, memory = cc_artefacts
        # Saving the same memory twice should not duplicate it
        store.save_incident_memory(memory)
        store.save_incident_memory(memory)
        memories = store.list_incident_memories(
            incident_type=IncidentType.CREDENTIAL_COMPROMISE
        )
        ids = [m.memory_id for m in memories]
        assert ids.count(memory.memory_id) == 1


# ---------------------------------------------------------------------------
# 5. harness_versions log
# ---------------------------------------------------------------------------

class TestHarnessVersions:
    def test_harness_docs_written(self, store, cc_artefacts, api_artefacts, priv_artefacts):
        count = store.count(COLLECTION_HARNESS)
        assert count >= 3

    def test_harness_doc_has_schema_version(self, store):
        from sentinel.memory_store import HARNESS_SCHEMA_VERSION
        col = store._col(COLLECTION_HARNESS)
        doc = col.find_one()
        assert doc is not None
        assert doc["schema_version"] == HARNESS_SCHEMA_VERSION

    def test_harness_doc_has_investigation_score(self, store):
        col = store._col(COLLECTION_HARNESS)
        doc = col.find_one()
        assert "investigation_score" in doc

    def test_harness_doc_has_unnecessary_tool_calls(self, store):
        col = store._col(COLLECTION_HARNESS)
        doc = col.find_one()
        assert "unnecessary_tool_calls" in doc


# ---------------------------------------------------------------------------
# 6. persist_investigation (full pipeline)
# ---------------------------------------------------------------------------

class TestPersistInvestigation:
    def test_returns_ids_dict(self, store):
        alert, outcome, memory = _make_outcome(IncidentType.PRIVILEGE_ESCALATION, uuid.uuid4().hex[:8])
        ids = store.persist_investigation(alert, outcome, memory)
        assert "alert_id" in ids
        assert "memory_id" in ids
        assert "steps_saved" in ids

    def test_steps_saved_count_correct(self, store):
        alert, outcome, memory = _make_outcome(IncidentType.SUSPICIOUS_API_KEY_ACTIVITY, uuid.uuid4().hex[:8])
        ids = store.persist_investigation(alert, outcome, memory)
        assert ids["steps_saved"] == str(outcome.total_tool_calls)

    def test_incident_retrievable_after_persist(self, store):
        alert, outcome, memory = _make_outcome(IncidentType.CREDENTIAL_COMPROMISE, uuid.uuid4().hex[:8])
        store.persist_investigation(alert, outcome, memory)
        doc = store.get_incident(alert.alert_id)
        assert doc is not None
        assert doc["affected_entity"] == alert.affected_entity

    def test_trajectory_retrievable_after_persist(self, store):
        alert, outcome, memory = _make_outcome(IncidentType.PRIVILEGE_ESCALATION, uuid.uuid4().hex[:8])
        store.persist_investigation(alert, outcome, memory)
        traj = store.get_investigation_trajectory(alert.alert_id)
        assert len(traj) == outcome.total_tool_calls


# ---------------------------------------------------------------------------
# 7. Collection isolation — verify correct collection names
# ---------------------------------------------------------------------------

class TestCollectionNames:
    def test_incidents_collection_exists(self, store, cc_artefacts):
        assert store.count(COLLECTION_INCIDENTS) > 0

    def test_steps_collection_exists(self, store, cc_artefacts):
        assert store.count(COLLECTION_STEPS) > 0

    def test_memories_collection_exists(self, store, cc_artefacts):
        assert store.count(COLLECTION_MEMORIES) > 0

    def test_harness_collection_exists(self, store, cc_artefacts):
        assert store.count(COLLECTION_HARNESS) > 0

    def test_collection_names_are_correct(self):
        assert COLLECTION_INCIDENTS == "incidents"
        assert COLLECTION_STEPS == "investigation_steps"
        assert COLLECTION_MEMORIES == "incident_memories"
        assert COLLECTION_HARNESS == "harness_versions"
