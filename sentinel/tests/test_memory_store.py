"""
Tests: PersistenceStore (aliased as MemoryStore) — MongoDB persistence layer.

All tests use unittest.mock to patch the MongoClient so no live Atlas
cluster is required.  The tests verify:

  - PersistenceStore is importable and constructable without a URI
  - save_incident_memory() / store() calls replace_one correctly
  - store() uses memory_id as _id
  - store() is idempotent (upsert=True)
  - list_incident_memories() / list_all() sorts and filters correctly
  - count(collection) delegates to count_documents
  - delete_all(collection) delegates to delete_many
  - ping() / health_check() calls admin.command("ping")
  - _memory_to_doc() serialises all enum fields to strings
  - _doc_to_memory() strips _id and reconstructs a valid IncidentMemory
  - RuntimeError is raised when no URI is configured
  - close() resets the internal client reference
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call
import pytest
from pymongo.errors import OperationFailure

from sentinel.memory_store import (
    MemoryStore,
    PersistenceStore,
    COLLECTION_MEMORIES,
    COLLECTION_ADAPTATION_RUNS,
    _doc_to_memory,
    _memory_to_doc,
)
from sentinel.models import AdaptationRun, ComparisonResult, IncidentMemory, IncidentType, OutcomeStatus, Severity
from sentinel.runner import DEFAULT_PLANS, InvestigationRunner
from sentinel.scenarios import SCENARIOS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_memory(incident_type: IncidentType = IncidentType.CREDENTIAL_COMPROMISE) -> IncidentMemory:
    """Build a real IncidentMemory via the runner — no manual construction."""
    scenario = SCENARIOS[incident_type]
    plan = DEFAULT_PLANS[incident_type]
    runner = InvestigationRunner()
    outcome = runner.run(scenario, plan, classified_as=incident_type)
    return runner.build_memory(scenario, outcome)


@pytest.fixture
def cc_memory() -> IncidentMemory:
    return _make_memory(IncidentType.CREDENTIAL_COMPROMISE)


@pytest.fixture
def api_memory() -> IncidentMemory:
    return _make_memory(IncidentType.SUSPICIOUS_API_KEY_ACTIVITY)


@pytest.fixture
def priv_memory() -> IncidentMemory:
    return _make_memory(IncidentType.PRIVILEGE_ESCALATION)


def _mock_store(uri: str = "mongodb+srv://fake:fake@cluster.example.mongodb.net/") -> tuple[PersistenceStore, MagicMock]:
    """
    Return (PersistenceStore, mock_collection pointing at incident_memories).

    The MongoClient is patched so no real connection is attempted.
    """
    store = PersistenceStore(uri=uri)

    mock_col = MagicMock()
    mock_col.replace_one.return_value = MagicMock(upserted_id=None)
    mock_col.insert_one.return_value = MagicMock()
    mock_col.update_one.return_value = MagicMock()
    mock_col.delete_many.return_value = MagicMock(deleted_count=3)
    mock_col.count_documents.return_value = 7
    mock_col.find.return_value = MagicMock()
    mock_col.find.return_value.sort.return_value = MagicMock()
    mock_col.find.return_value.sort.return_value.limit.return_value = []

    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_col)
    mock_db.list_collection_names.return_value = [COLLECTION_MEMORIES]

    mock_client = MagicMock()
    mock_client.__getitem__ = MagicMock(return_value=mock_db)
    mock_client.admin.command.return_value = {"ok": 1}

    mock_client.__getitem__.return_value = mock_db
    mock_db.__getitem__.return_value = mock_col

    # Inject directly — bypass lazy _connect()
    store._client = mock_client

    return store, mock_col


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_memory_to_doc_sets_id_from_memory_id(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        assert doc["_id"] == cc_memory.memory_id

    def test_memory_to_doc_keeps_memory_id_field(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        assert doc["memory_id"] == cc_memory.memory_id

    def test_memory_to_doc_enums_are_strings(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        assert isinstance(doc["incident_type"], str)
        assert isinstance(doc["severity"], str)
        assert isinstance(doc["outcome_status"], str)
        assert all(isinstance(t, str) for t in doc["tool_sequence"])
        assert all(isinstance(t, str) for t in doc["useful_tools"])

    def test_memory_to_doc_created_at_is_datetime(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        assert isinstance(doc["created_at"], datetime)

    def test_memory_to_doc_created_at_is_timezone_aware(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        assert doc["created_at"].tzinfo is not None

    def test_doc_to_memory_roundtrip(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        restored = _doc_to_memory(doc)
        assert restored.memory_id == cc_memory.memory_id
        assert restored.incident_type == cc_memory.incident_type
        assert restored.investigation_score == cc_memory.investigation_score
        assert restored.narrative == cc_memory.narrative

    def test_doc_to_memory_strips_id(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        # Should not raise even though _id is not a IncidentMemory field
        restored = _doc_to_memory(doc)
        assert isinstance(restored, IncidentMemory)

    def test_doc_to_memory_strips_embedding_field(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        doc["embedding"] = [0.1] * 1024  # simulate Phase 3 field
        restored = _doc_to_memory(doc)
        assert isinstance(restored, IncidentMemory)


# ---------------------------------------------------------------------------
# Construction and configuration
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_constructable_without_uri(self):
        store = PersistenceStore()
        assert store._client is None

    def test_constructable_with_uri(self):
        store = PersistenceStore(uri="mongodb+srv://fake:fake@cluster.example.mongodb.net/")
        assert store._uri.startswith("mongodb")

    def test_custom_db_name(self):
        store = PersistenceStore(uri="mongodb://localhost", db_name="testdb")
        assert store._db_name == "testdb"

    def test_default_db_name(self):
        store = PersistenceStore(uri="mongodb://localhost")
        assert store._db_name == "sentinel"

    def test_no_uri_raises_runtime_error_on_use(self):
        store = PersistenceStore(uri="")
        with pytest.raises(RuntimeError, match="MONGODB_URI is not set"):
            store._connect()


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------


class TestPing:
    def test_ping_returns_true(self, cc_memory):
        store, mock_col = _mock_store()
        result = store.ping()
        assert result is True

    def test_health_check_calls_admin_ping(self, cc_memory):
        store, mock_col = _mock_store()
        store.health_check()
        # health_check() calls db.client.admin.command("ping")
        # db = _client[db_name], client = db.client
        store._client[store._db_name].client.admin.command.assert_called_once_with("ping")

    def test_health_check_returns_ok(self, cc_memory):
        store, mock_col = _mock_store()
        result = store.health_check()
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


class TestStore:
    def test_store_calls_replace_one(self, cc_memory):
        store, mock_col = _mock_store()
        store.store(cc_memory)
        mock_col.replace_one.assert_called_once()

    def test_store_uses_memory_id_as_filter(self, cc_memory):
        store, mock_col = _mock_store()
        store.store(cc_memory)
        filter_arg = mock_col.replace_one.call_args[0][0]
        assert filter_arg == {"_id": cc_memory.memory_id}

    def test_store_upsert_true(self, cc_memory):
        store, mock_col = _mock_store()
        store.store(cc_memory)
        kwargs = mock_col.replace_one.call_args[1]
        assert kwargs.get("upsert") is True

    def test_store_returns_memory_id(self, cc_memory):
        store, mock_col = _mock_store()
        returned = store.store(cc_memory)
        assert returned == cc_memory.memory_id

    def test_store_document_has_id(self, cc_memory):
        store, mock_col = _mock_store()
        store.store(cc_memory)
        doc_arg = mock_col.replace_one.call_args[0][1]
        assert doc_arg["_id"] == cc_memory.memory_id

    def test_store_document_incident_type_is_string(self, cc_memory):
        store, mock_col = _mock_store()
        store.store(cc_memory)
        doc_arg = mock_col.replace_one.call_args[0][1]
        assert isinstance(doc_arg["incident_type"], str)

    def test_store_idempotent_on_second_call(self, cc_memory):
        """Calling store twice should call replace_one twice (upsert handles idempotency)."""
        store, mock_col = _mock_store()
        store.store(cc_memory)
        store.store(cc_memory)
        assert mock_col.replace_one.call_count == 2


class TestSaveSecurityAlert:
    def test_alert_upsert_preserves_completed_outcome(self):
        store, mock_col = _mock_store()
        alert = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]["alert"]

        store.save_security_alert(alert)

        filter_arg, update_arg = mock_col.update_one.call_args[0]
        assert filter_arg == {"_id": alert.alert_id}
        assert update_arg["$set"]["alert_id"] == alert.alert_id
        assert "_id" not in update_arg["$set"]
        assert mock_col.update_one.call_args[1]["upsert"] is True


class TestSemanticMemoryRetrieval:
    def test_search_parses_vector_result_and_excludes_current_incident(self):
        store, mock_col = _mock_store()
        mock_col.aggregate.return_value = [{
            "memory_id": "memory-1", "alert_id": "INC-2026-001", "narrative": "Useful lesson.",
            "incident_type": "CREDENTIAL_COMPROMISE", "useful_tools": ["query_auth_logs"],
            "wasteful_tools": ["inspect_api_activity"], "critical_evidence": ["auth-001"],
            "tool_call_count": 5, "similarity_score": 0.93,
        }]

        results = store.search_similar_memories("unusual login", exclude_incident_id="INC-2026-004")

        assert results[0].memory_id == "memory-1"
        pipeline = mock_col.aggregate.call_args[0][0]
        assert pipeline[0]["$vectorSearch"]["index"] == "incident_memory_vector"
        assert pipeline[0]["$vectorSearch"]["limit"] == 4

    def test_search_returns_empty_when_vector_index_is_unavailable(self):
        store, mock_col = _mock_store()
        mock_col.aggregate.side_effect = OperationFailure("vector index not found")
        assert store.search_similar_memories("unusual login") == []

    def test_search_deduplicates_by_incident_and_keeps_highest_score(self):
        store, mock_col = _mock_store()
        base = {
            "alert_id": "INC-2026-001", "narrative": "Useful lesson.",
            "incident_type": "CREDENTIAL_COMPROMISE", "useful_tools": ["query_auth_logs"],
            "wasteful_tools": [], "critical_evidence": ["auth-001"], "tool_call_count": 5,
        }
        mock_col.aggregate.return_value = [
            {**base, "memory_id": "older", "similarity_score": 0.81},
            {**base, "memory_id": "newer", "similarity_score": 0.92},
        ]
        results = store.search_similar_memories("unusual login")
        assert [item.memory_id for item in results] == ["newer"]


class TestAdaptationRunPersistence:
    def test_save_adaptation_run_upserts_the_new_collection(self):
        store, mock_col = _mock_store()
        run = AdaptationRun(
            run_id="run-1", incident_id="INC-2026-004", minimum_similarity=0.80,
            retrieved_memories=[],
            comparison=ComparisonResult(
                baseline_tool_calls=5, memory_tool_calls=3, tool_calls_saved=2,
                baseline_calls_before_critical=3, memory_calls_before_critical=1,
                unnecessary_calls_avoided=2, classification_correct=True,
                critical_evidence_found=5, top_memory_similarity=0.829,
            ),
        )
        assert store.save_adaptation_run(run) == "run-1"
        mock_col.replace_one.assert_called_once()
        assert mock_col.replace_one.call_args[0][0] == {"_id": "run-1"}
        assert mock_col.replace_one.call_args[1]["upsert"] is True


# ---------------------------------------------------------------------------
# retrieve_similar (via list_incident_memories)
# ---------------------------------------------------------------------------


class TestRetrieveSimilar:
    def _store_with_results(self, results: list[dict]) -> tuple[PersistenceStore, MagicMock]:
        store, mock_col = _mock_store()
        chain = MagicMock()
        chain.sort.return_value.limit.return_value = results
        mock_col.find.return_value = chain
        return store, mock_col

    def test_retrieve_type_only_uses_incident_type_filter(self, cc_memory):
        store, mock_col = self._store_with_results([])
        store.list_incident_memories(IncidentType.CREDENTIAL_COMPROMISE, limit=5)
        call_filter = mock_col.find.call_args[0][0]
        assert call_filter["incident_type"] == "CREDENTIAL_COMPROMISE"

    def test_retrieve_no_filter_returns_all(self):
        store, mock_col = self._store_with_results([])
        store.list_incident_memories(limit=5)
        call_filter = mock_col.find.call_args[0][0]
        assert call_filter == {}

    def test_retrieve_returns_list_of_incident_memory(self, cc_memory):
        doc = _memory_to_doc(cc_memory)
        store, mock_col = self._store_with_results([doc])
        results = store.list_incident_memories(IncidentType.CREDENTIAL_COMPROMISE)
        assert isinstance(results, list)
        assert all(isinstance(r, IncidentMemory) for r in results)

    def test_retrieve_empty_when_no_matches(self):
        store, mock_col = self._store_with_results([])
        results = store.list_incident_memories(IncidentType.PRIVILEGE_ESCALATION)
        assert results == []


# ---------------------------------------------------------------------------
# list_all
# ---------------------------------------------------------------------------


class TestListAll:
    def test_list_all_calls_find_with_empty_filter(self):
        store, mock_col = _mock_store()
        store.list_all(limit=10)
        mock_col.find.assert_called_once_with({})

    def test_list_all_respects_limit(self):
        store, mock_col = _mock_store()
        store.list_all(limit=7)
        limit_call = mock_col.find.return_value.sort.return_value.limit
        limit_call.assert_called_once_with(7)

    def test_list_all_returns_list(self):
        store, mock_col = _mock_store()
        results = store.list_all()
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# count / delete_all
# ---------------------------------------------------------------------------


class TestCountAndDelete:
    def test_count_delegates_to_count_documents(self):
        store, mock_col = _mock_store()
        result = store.count(COLLECTION_MEMORIES)
        mock_col.count_documents.assert_called_once_with({})
        assert result == 7

    def test_delete_all_delegates_to_delete_many(self):
        store, mock_col = _mock_store()
        deleted = store.delete_all(COLLECTION_MEMORIES)
        mock_col.delete_many.assert_called_once_with({})
        assert deleted == 3


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_resets_client_to_none(self):
        store, _ = _mock_store()
        assert store._client is not None
        store.close()
        assert store._client is None

    def test_close_calls_client_close(self):
        store, _ = _mock_store()
        client = store._client
        store.close()
        client.close.assert_called_once()

    def test_close_on_uninitialised_store_is_safe(self):
        store = PersistenceStore(uri="mongodb://localhost")
        store.close()  # should not raise


# ---------------------------------------------------------------------------
# Integration: real IncidentMemory round-trips through serialisation
# ---------------------------------------------------------------------------


class TestRealMemoryRoundtrip:
    @pytest.mark.parametrize("incident_type", [
        IncidentType.CREDENTIAL_COMPROMISE,
        IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
        IncidentType.PRIVILEGE_ESCALATION,
    ])
    def test_serialise_deserialise_all_scenarios(self, incident_type):
        memory = _make_memory(incident_type)
        doc = _memory_to_doc(memory)
        restored = _doc_to_memory(doc)

        assert restored.memory_id == memory.memory_id
        assert restored.incident_type == memory.incident_type
        assert restored.severity == memory.severity
        assert restored.affected_entity == memory.affected_entity
        assert restored.investigation_score == memory.investigation_score
        assert restored.outcome_status == memory.outcome_status
        assert restored.classification_correct == memory.classification_correct
        assert restored.narrative == memory.narrative
        assert len(restored.tool_sequence) == len(memory.tool_sequence)
        assert len(restored.outcome.steps) == len(memory.outcome.steps)

    @pytest.mark.parametrize("incident_type", [
        IncidentType.CREDENTIAL_COMPROMISE,
        IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
        IncidentType.PRIVILEGE_ESCALATION,
    ])
    def test_created_at_is_timezone_aware_after_roundtrip(self, incident_type):
        memory = _make_memory(incident_type)
        doc = _memory_to_doc(memory)
        restored = _doc_to_memory(doc)
        assert restored.created_at.tzinfo is not None
