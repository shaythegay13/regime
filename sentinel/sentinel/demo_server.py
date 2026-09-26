"""Read-only demo API for rendering the latest persisted Sentinel run."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from sentinel.memory_store import PersistenceStore


def _load_env() -> None:
    package_root = Path(__file__).resolve().parent.parent
    for directory in (package_root, package_root.parent):
        candidate = directory / ".env.local"
        if candidate.exists():
            load_dotenv(candidate)
            return


def _severity(value: str) -> str:
    return value.lower() if value.lower() in {"low", "medium", "high", "critical"} else "medium"


def build_demo_payload() -> dict[str, Any]:
    """Map one completed memory-enabled agent run into the frontend contract."""
    store = PersistenceStore()
    try:
        agent_run = store._col("agent_runs").find_one(
            {"memory_enabled": True}, sort=[("created_at", -1)]
        )
        if agent_run is None:
            raise LookupError("No completed memory-enabled agent run is available.")

        incident = store._col("incidents").find_one({"_id": agent_run["incident_id"]})
        adaptation = store._col("adaptation_runs").find_one(
            {"incident_id": agent_run["incident_id"]}, sort=[("created_at", -1)]
        )
        baseline_agent_run = store._col("agent_runs").find_one(
            {"incident_id": agent_run["incident_id"], "memory_enabled": False},
            sort=[("created_at", -1)],
        )
        if incident is None or adaptation is None:
            raise LookupError("The selected agent run is missing its alert or adaptation result.")

        memory_id = next(iter(agent_run.get("retrieved_memory_ids", [])), None)
        recalled = next(
            (memory for memory in adaptation.get("retrieved_memories", []) if memory["memory_id"] == memory_id),
            None,
        )
        memory_doc = store._col("incident_memories").find_one({"_id": memory_id}) if memory_id else None
        comparison = adaptation["comparison"]
        decisions = [decision for decision in agent_run["decisions"] if decision["action"] != "RESOLVE"]
        resolve = next((decision for decision in reversed(agent_run["decisions"]) if decision["action"] == "RESOLVE"), {})
        outcome = agent_run["outcome"]
        baseline_unnecessary = sum(
            not decision.get("observation", {}).get("exposed_critical_evidence", False)
            for decision in (baseline_agent_run or {}).get("decisions", [])
            if decision["action"] != "RESOLVE"
        )
        memory_unnecessary = sum(
            not decision.get("observation", {}).get("exposed_critical_evidence", False)
            for decision in agent_run["decisions"]
            if decision["action"] != "RESOLVE"
        )

        return {
            "runId": agent_run["run_id"],
            "source": "backend",
            "memoryStore": {"provider": "MongoDB Atlas", "status": "connected", "collection": "sentinel.agent_runs"},
            "alert": {
                "id": incident["alert_id"], "entity": incident["affected_entity"], "entityType": "Affected entity",
                "text": incident["raw_message"], "severity": _severity(incident["severity"]),
                "timestamp": incident["timestamp"].isoformat(), "source": incident["source_system"],
            },
            "memory": None if recalled is None else {
                "incidentId": recalled["alert_id"], "similarity": recalled["similarity_score"],
                "incidentType": recalled["incident_type"], "usefulTools": recalled["useful_tools"],
                "lesson": memory_doc["narrative"] if memory_doc else recalled["narrative"],
                "influence": "This recalled incident promoted its useful tools and deprioritized its low-value checks.",
                "resolvedAt": (memory_doc or recalled).get("created_at", adaptation["created_at"]).isoformat(),
            },
            "steps": [{
                "id": f"step-{decision['step_number']}", "thought": decision["reason"], "tool": decision["action"],
                "reason": decision["reason"], "observation": decision["observation"]["analyst_note"],
                "critical": decision["observation"]["exposed_critical_evidence"],
                "memoryGuided": bool(decision.get("memory_ids")),
            } for decision in decisions],
            "verdict": {
                "classification": agent_run["final_classification"], "confidence": resolve.get("confidence", 0),
                "status": outcome["status"], "summary": outcome["summary"],
            },
            "adaptation": {
                "withoutMemory": {"toolCalls": comparison["baseline_tool_calls"], "callsBeforeCriticalEvidence": comparison["baseline_calls_before_critical"], "unnecessaryCalls": baseline_unnecessary},
                "withMemory": {"toolCalls": comparison["memory_tool_calls"], "callsBeforeCriticalEvidence": comparison["memory_calls_before_critical"], "unnecessaryCalls": memory_unnecessary},
                "correctClassification": comparison["classification_correct"], "criticalEvidenceFound": comparison["critical_evidence_found"] > 0,
            },
        }
    finally:
        store.close()


class DemoRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/api/demo":
            self.send_error(404)
            return
        try:
            payload = build_demo_payload()
            body = json.dumps(payload, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    _load_env()
    host, port = "127.0.0.1", int(os.environ.get("SENTINEL_DEMO_PORT", "8000"))
    print(f"Sentinel demo API listening at http://{host}:{port}/api/demo")
    ThreadingHTTPServer((host, port), DemoRequestHandler).serve_forever()


if __name__ == "__main__":
    main()
