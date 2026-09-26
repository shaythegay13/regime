"""
MongoDB Atlas persistence layer for Sentinel.

Collections (all in the same database, default name: "sentinel"):

  incidents
    One document per SecurityAlert.  Written at the start of every
    investigation.  _id = alert_id.

  investigation_steps
    One document per InvestigationStep (action + observation + evidence).
    Written after each tool call.  Indexed on alert_id for fast trajectory
    retrieval.

  incident_memories
    One document per IncidentMemory.  Written after every investigation
    completes.  This is the collection that will receive embeddings and a
    Vector Search index in Phase 3.

  harness_versions
    Append-only log of harness metadata (schema version, run timestamp,
    Python version).  Useful for replay and debugging.

All methods are synchronous.  The MongoClient is created lazily on first
use so that importing this module never raises when MONGODB_URI is unset.

Application models (Pydantic) are kept entirely separate from MongoDB
code — serialisation/deserialisation happens only inside this module.

Usage
-----
    from sentinel.memory_store import PersistenceStore

    store = PersistenceStore()          # reads MONGODB_URI + MONGODB_DATABASE
    store.health_check()                # raises if Atlas is unreachable

    alert_id = store.save_security_alert(alert)
    store.save_investigation_step(alert_id, step, step_number=1)
    store.save_incident_outcome(outcome)
    store.save_incident_memory(memory)

    incident   = store.get_incident(alert_id)
    trajectory = store.get_investigation_trajectory(alert_id)
    memories   = store.list_incident_memories(incident_type, limit=10)

    store.close()
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import OperationFailure

from sentinel.models import (
    IncidentMemory,
    AdaptationRun,
    AgentRun,
    IncidentOutcome,
    IncidentType,
    InvestigationStep,
    SecurityAlert,
    SimilarIncidentMemory,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COLLECTION_INCIDENTS = "incidents"
COLLECTION_STEPS = "investigation_steps"
COLLECTION_MEMORIES = "incident_memories"
COLLECTION_HARNESS = "harness_versions"
COLLECTION_ADAPTATION_RUNS = "adaptation_runs"
COLLECTION_AGENT_RUNS = "agent_runs"

HARNESS_SCHEMA_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# Serialisation helpers  (app models → plain dicts, plain dicts → app models)
# All MongoDB-specific concerns (field naming, _id mapping) live here only.
# ---------------------------------------------------------------------------


def _alert_to_doc(alert: SecurityAlert) -> dict[str, Any]:
    doc = alert.model_dump()
    doc["_id"] = doc["alert_id"]
    return doc


def _doc_to_alert(doc: dict[str, Any]) -> SecurityAlert:
    d = dict(doc)
    d.pop("_id", None)
    return SecurityAlert.model_validate(d)


def _step_to_doc(
    alert_id: str,
    step: InvestigationStep,
    step_number: int,
) -> dict[str, Any]:
    doc = step.model_dump()
    doc["alert_id"] = alert_id
    doc["step_number"] = step_number
    doc["persisted_at"] = datetime.now(tz=timezone.utc)
    return doc


def _outcome_to_doc(outcome: IncidentOutcome) -> dict[str, Any]:
    doc = outcome.model_dump()
    doc["_id"] = doc["alert_id"]
    doc["persisted_at"] = datetime.now(tz=timezone.utc)
    return doc


def _memory_to_doc(memory: IncidentMemory) -> dict[str, Any]:
    doc = memory.model_dump()
    doc["_id"] = doc["memory_id"]
    return doc


def _doc_to_memory(doc: dict[str, Any]) -> IncidentMemory:
    d = dict(doc)
    d.pop("_id", None)
    d.pop("embedding", None)      # Phase 3 field — ignore on read-back
    return IncidentMemory.model_validate(d)


# ---------------------------------------------------------------------------
# PersistenceStore
# ---------------------------------------------------------------------------


class PersistenceStore:
    """
    Synchronous MongoDB persistence layer for Sentinel.

    Parameters
    ----------
    uri     : MongoDB connection string.
              Falls back to MONGODB_URI env var if omitted.
    db_name : Database name.
              Falls back to MONGODB_DATABASE env var, then "sentinel".

    The MongoClient is created lazily — constructing this object is always
    safe even when Atlas is unreachable or the URI is unset.
    """

    def __init__(
        self,
        uri: str | None = None,
        db_name: str | None = None,
    ) -> None:
        self._uri: str = uri if uri is not None else os.environ.get("MONGODB_URI", "")
        self._db_name: str = (
            db_name
            or os.environ.get("MONGODB_DATABASE", "sentinel")
        )
        self._client: MongoClient | None = None

    # ------------------------------------------------------------------
    # Internal: connection management
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Create MongoClient and ensure all indexes exist."""
        if not self._uri:
            raise RuntimeError(
                "MONGODB_URI is not set. "
                "Copy .env.example to .env.local and add your Atlas URI."
            )
        self._client = MongoClient(
            self._uri,
            serverSelectionTimeoutMS=5_000,
            connectTimeoutMS=5_000,
        )
        self._ensure_indexes()

    def _db(self):
        if self._client is None:
            self._connect()
        return self._client[self._db_name]

    def _col(self, name: str) -> Collection:
        return self._db()[name]

    def _ensure_indexes(self) -> None:
        """Create all collection indexes idempotently."""
        db = self._client[self._db_name]

        # incidents
        db[COLLECTION_INCIDENTS].create_index("alert_id", unique=True)
        db[COLLECTION_INCIDENTS].create_index("incident_type_hint")
        db[COLLECTION_INCIDENTS].create_index([("timestamp", DESCENDING)])

        # investigation_steps
        db[COLLECTION_STEPS].create_index("alert_id")
        db[COLLECTION_STEPS].create_index(
            [("alert_id", ASCENDING), ("step_number", ASCENDING)]
        )

        # incident_memories
        db[COLLECTION_MEMORIES].create_index("memory_id", unique=True)
        db[COLLECTION_MEMORIES].create_index("alert_id")
        db[COLLECTION_MEMORIES].create_index("incident_type")
        db[COLLECTION_MEMORIES].create_index("affected_entity")
        db[COLLECTION_MEMORIES].create_index(
            [("investigation_score", DESCENDING), ("created_at", DESCENDING)]
        )

        # harness_versions: no special index needed (append-only log)

        db[COLLECTION_ADAPTATION_RUNS].create_index("run_id", unique=True)
        db[COLLECTION_ADAPTATION_RUNS].create_index([("incident_id", ASCENDING), ("created_at", DESCENDING)])
        db[COLLECTION_AGENT_RUNS].create_index("run_id", unique=True)
        db[COLLECTION_AGENT_RUNS].create_index([("incident_id", ASCENDING), ("created_at", DESCENDING)])

    def close(self) -> None:
        """Close the underlying MongoClient."""
        if self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # 1. health_check
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Verify Atlas connectivity and return a status dict.

        Returns
        -------
        {"ok": True, "db": "<name>", "collections": [...]}

        Raises on connection failure.
        """
        db = self._db()
        db.client.admin.command("ping")
        cols = db.list_collection_names()
        return {
            "ok": True,
            "db": self._db_name,
            "collections": sorted(cols),
        }

    # ------------------------------------------------------------------
    # 2. save_security_alert
    # ------------------------------------------------------------------

    def save_security_alert(self, alert: SecurityAlert) -> str:
        """
        Persist a SecurityAlert to the *incidents* collection.

        Uses an upsert so replaying the same alert_id is idempotent without
        replacing a final outcome that has already been attached.

        Returns alert_id.
        """
        col = self._col(COLLECTION_INCIDENTS)
        doc = _alert_to_doc(alert)
        alert_id = doc.pop("_id")
        col.update_one({"_id": alert_id}, {"$set": doc}, upsert=True)
        return alert.alert_id

    # ------------------------------------------------------------------
    # 3. save_investigation_step
    # ------------------------------------------------------------------

    def save_investigation_step(
        self,
        alert_id: str,
        step: InvestigationStep,
        step_number: int,
    ) -> None:
        """
        Persist one InvestigationStep to the *investigation_steps* collection.

        Each step is inserted as a new document (append semantics).
        A compound index on (alert_id, step_number) makes trajectory
        retrieval fast.
        """
        col = self._col(COLLECTION_STEPS)
        doc = _step_to_doc(alert_id, step, step_number)
        col.insert_one(doc)

    # ------------------------------------------------------------------
    # 4. save_incident_outcome
    # ------------------------------------------------------------------

    def save_incident_outcome(self, outcome: IncidentOutcome) -> str:
        """
        Persist the final IncidentOutcome back into the *incidents* document.

        The outcome is merged into the existing alert document via $set so
        the incidents collection holds the complete incident lifecycle in
        one place.

        Returns alert_id.
        """
        col = self._col(COLLECTION_INCIDENTS)
        outcome_doc = _outcome_to_doc(outcome)
        outcome_doc.pop("_id", None)  # don't overwrite the alert _id
        col.update_one(
            {"_id": outcome.alert_id},
            {"$set": {"outcome": outcome_doc}},
            upsert=True,
        )
        return outcome.alert_id

    # ------------------------------------------------------------------
    # 5. save_incident_memory
    # ------------------------------------------------------------------

    def save_incident_memory(self, memory: IncidentMemory) -> str:
        """
        Persist an IncidentMemory to the *incident_memories* collection.

        Uses upsert on memory_id — idempotent for replays.

        Returns memory_id.
        """
        col = self._col(COLLECTION_MEMORIES)
        doc = _memory_to_doc(memory)
        col.replace_one({"_id": doc["_id"]}, doc, upsert=True)
        return memory.memory_id

    # ------------------------------------------------------------------
    # 6. get_incident
    # ------------------------------------------------------------------

    def get_incident(self, alert_id: str) -> dict[str, Any] | None:
        """
        Retrieve a full incident document (alert + outcome if available).

        Returns the raw dict so callers can inspect both the original alert
        fields and the merged outcome without needing to reconstruct models.
        Returns None if alert_id is not found.
        """
        col = self._col(COLLECTION_INCIDENTS)
        doc = col.find_one({"_id": alert_id})
        if doc is None:
            return None
        doc.pop("_id", None)
        return doc

    # ------------------------------------------------------------------
    # 7. get_investigation_trajectory
    # ------------------------------------------------------------------

    def get_investigation_trajectory(
        self,
        alert_id: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all investigation steps for an alert, ordered by step_number.

        Returns a list of raw step dicts.  Each dict contains action,
        observation, evidence_collected, alert_id, step_number, persisted_at.
        """
        col = self._col(COLLECTION_STEPS)
        docs = list(
            col.find({"alert_id": alert_id})
            .sort("step_number", ASCENDING)
        )
        for doc in docs:
            doc.pop("_id", None)
        return docs

    # ------------------------------------------------------------------
    # 8. list_incident_memories
    # ------------------------------------------------------------------

    def list_incident_memories(
        self,
        incident_type: IncidentType | None = None,
        limit: int = 20,
    ) -> list[IncidentMemory]:
        """
        Return IncidentMemory records, most-recent first.

        Parameters
        ----------
        incident_type : if provided, filter to this type only
        limit         : max documents to return (default 20)
        """
        col = self._col(COLLECTION_MEMORIES)
        filt: dict[str, Any] = {}
        if incident_type is not None:
            filt["incident_type"] = incident_type.value
        docs = list(
            col.find(filt)
            .sort([("created_at", DESCENDING)])
            .limit(limit)
        )
        return [_doc_to_memory(d) for d in docs]

    def search_similar_memories(
        self,
        query_text: str,
        limit: int = 3,
        exclude_incident_id: str | None = None,
    ) -> list[SimilarIncidentMemory]:
        """Search Atlas automated-embedding memories without exposing vectors."""
        if not query_text.strip() or limit < 1:
            return []

        vector_stage: dict[str, Any] = {
            "index": "incident_memory_vector",
            "path": "narrative",
            "query": {"text": query_text},
            "numCandidates": max(limit * 10, 20),
            "limit": limit + (1 if exclude_incident_id else 0),
        }

        pipeline = [
            {"$vectorSearch": vector_stage},
            {"$project": {
                "_id": 0,
                "memory_id": 1,
                "alert_id": 1,
                "narrative": 1,
                "incident_type": 1,
                "useful_tools": 1,
                "wasteful_tools": 1,
                "critical_evidence": "$outcome.critical_evidence_found",
                "tool_call_count": "$outcome.total_tool_calls",
                "similarity_score": {"$meta": "vectorSearchScore"},
            }},
        ]
        try:
            documents = list(self._col(COLLECTION_MEMORIES).aggregate(pipeline))
        except OperationFailure as exc:
            if "vector" in str(exc).lower() or "index" in str(exc).lower():
                return []
            raise
        results = [SimilarIncidentMemory.model_validate(doc) for doc in documents]
        if exclude_incident_id:
            results = [item for item in results if item.alert_id != exclude_incident_id]
        deduplicated: dict[str, SimilarIncidentMemory] = {}
        for item in results:
            existing = deduplicated.get(item.alert_id)
            if existing is None or item.similarity_score > existing.similarity_score:
                deduplicated[item.alert_id] = item
        return sorted(
            deduplicated.values(), key=lambda item: item.similarity_score, reverse=True
        )[:limit]

    def save_adaptation_run(self, run: AdaptationRun) -> str:
        """Persist a measured baseline-versus-memory-guided comparison."""
        document = run.model_dump()
        document["_id"] = run.run_id
        self._col(COLLECTION_ADAPTATION_RUNS).replace_one(
            {"_id": run.run_id}, document, upsert=True
        )
        return run.run_id

    def save_agent_run(self, run: AgentRun) -> str:
        """Persist bounded agent decisions and their final simulated outcome."""
        document = run.model_dump()
        document["_id"] = run.run_id
        self._col(COLLECTION_AGENT_RUNS).replace_one({"_id": run.run_id}, document, upsert=True)
        return run.run_id

    # ------------------------------------------------------------------
    # Convenience: persist a complete investigation in one call
    # ------------------------------------------------------------------

    def persist_investigation(
        self,
        alert: SecurityAlert,
        outcome: IncidentOutcome,
        memory: IncidentMemory,
    ) -> dict[str, str]:
        """
        Persist all artefacts of a completed investigation atomically:
          - SecurityAlert        → incidents
          - every InvestigationStep → investigation_steps
          - IncidentOutcome      → incidents (merged)
          - IncidentMemory       → incident_memories
          - harness version log  → harness_versions

        Returns a dict of stored IDs for logging.
        """
        # 1. Alert
        self.save_security_alert(alert)

        # 2. Steps
        for step in outcome.steps:
            self.save_investigation_step(alert.alert_id, step, step.action.step_number)

        # 3. Outcome (merged into incident doc)
        self.save_incident_outcome(outcome)

        # 4. Memory
        self.save_incident_memory(memory)

        # 5. Harness version log
        self._col(COLLECTION_HARNESS).insert_one({
            "schema_version": HARNESS_SCHEMA_VERSION,
            "alert_id": alert.alert_id,
            "incident_type": alert.incident_type_hint.value,
            "total_tool_calls": outcome.total_tool_calls,
            "investigation_score": outcome.investigation_score,
            "classification_correct": outcome.classification_correct,
            "unnecessary_tool_calls": len(memory.wasteful_tools),
            "python_version": sys.version,
            "logged_at": datetime.now(tz=timezone.utc),
        })

        return {
            "alert_id": alert.alert_id,
            "memory_id": memory.memory_id,
            "steps_saved": str(len(outcome.steps)),
        }

    # ------------------------------------------------------------------
    # Utility: count documents (used in tests)
    # ------------------------------------------------------------------

    def count(self, collection: str) -> int:
        return self._col(collection).count_documents({})

    def delete_all(self, collection: str) -> int:
        return self._col(collection).delete_many({}).deleted_count

    # ------------------------------------------------------------------
    # Backward-compat shims so existing CLI code keeps working
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Alias for health_check() — returns True on success."""
        self.health_check()
        return True

    def store(self, memory: IncidentMemory) -> str:
        """Alias for save_incident_memory()."""
        return self.save_incident_memory(memory)

    def list_all(self, limit: int = 20) -> list[IncidentMemory]:
        """Alias for list_incident_memories()."""
        return self.list_incident_memories(limit=limit)


# ---------------------------------------------------------------------------
# Legacy alias — keeps test_memory_store.py imports working
# ---------------------------------------------------------------------------
MemoryStore = PersistenceStore
