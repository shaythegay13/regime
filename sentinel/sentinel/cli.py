"""
Sentinel CLI — run a simulated incident investigation from the terminal.

Usage
-----
    # Run without persistence (local only)
    python -m sentinel.cli --incident CREDENTIAL_COMPROMISE

    # Run with full MongoDB persistence
    python -m sentinel.cli --incident CREDENTIAL_COMPROMISE --persist

    # Run all three scenarios with persistence
    python -m sentinel.cli --incident all --persist

    # List stored memories from Atlas
    python -m sentinel.cli --list-memories

Environment
-----------
    MONGODB_URI      : Atlas connection string (required for --persist)
    MONGODB_DATABASE : database name (default: sentinel)

    Both can be set in a .env or .env.local file in the project root.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv

from sentinel.models import AdaptationRun, IncidentType
from sentinel.memory_guidance import adapt_plan, build_alert_search_description, comparison_metrics
from sentinel.runner import DEFAULT_PLANS, InvestigationRunner
from sentinel.scenarios import SCENARIOS


# ---------------------------------------------------------------------------
# Environment loading — walks up from package dir to find .env.local / .env
# ---------------------------------------------------------------------------

def _load_env() -> None:
    here = Path(__file__).resolve().parent   # sentinel/sentinel/
    for directory in [here, here.parent, here.parent.parent]:
        for name in [".env.local", ".env"]:
            candidate = directory / name
            if candidate.exists():
                load_dotenv(candidate)
                return

_load_env()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_outcome(outcome_dict: dict) -> None:
    print("\n" + "=" * 70)
    print(f"  INCIDENT  : {outcome_dict['alert_id']}")
    print(f"  STATUS    : {outcome_dict['status']}")
    print(f"  VERDICT   : {outcome_dict['classified_as']}"
          f"  (ground truth: {outcome_dict['ground_truth_type']})")
    print(f"  CORRECT   : {outcome_dict['classification_correct']}")
    print(f"  SCORE     : {outcome_dict['investigation_score']:.0%}")
    print(f"  TOOL CALLS: {outcome_dict['total_tool_calls']}")
    print(f"  FOUND     : {outcome_dict['critical_evidence_found']}")
    print(f"  MISSED    : {outcome_dict['critical_evidence_missed']}")
    print(f"\n  SUMMARY   : {outcome_dict['summary']}")
    print("=" * 70 + "\n")


def _print_memory_summary(memory) -> None:
    print(json.dumps(
        {
            "memory_id": memory.memory_id,
            "incident_type": memory.incident_type.value,
            "affected_entity": memory.affected_entity,
            "tool_sequence": [t.value for t in memory.tool_sequence],
            "useful_tools": [t.value for t in memory.useful_tools],
            "wasteful_tools": [t.value for t in memory.wasteful_tools],
            "investigation_score": memory.investigation_score,
            "narrative": memory.narrative,
        },
        indent=2,
        ensure_ascii=False,
    ))


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------

def _persist(alert, outcome, memory) -> None:
    """
    Persist the full investigation to MongoDB Atlas.

    Writes to four collections:
      incidents            — initial alert + merged outcome
      investigation_steps  — one doc per tool call
      incident_memories    — structured memory record
      harness_versions     — run metadata log

    Skips silently if MONGODB_URI is not configured.
    Prints a clear error (never raises) so the CLI stays usable offline.
    """
    uri = os.environ.get("MONGODB_URI", "")
    if not uri or uri.startswith("mongodb+srv://REPLACE_ME"):
        print("[sentinel] --persist: MONGODB_URI not configured, skipping.")
        return

    try:
        from sentinel.memory_store import PersistenceStore
        store = PersistenceStore()
        store.health_check()

        ids = store.persist_investigation(alert, outcome, memory)
        store.close()

        print(
            f"[sentinel] Persisted to Atlas:"
            f"\n           alert_id  = {ids['alert_id']}"
            f"\n           memory_id = {ids['memory_id']}"
            f"\n           steps     = {ids['steps_saved']}"
        )
    except Exception as exc:
        print(
            f"[sentinel] Persistence failed ({type(exc).__name__}: {exc})",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Core investigation command
# ---------------------------------------------------------------------------

def _retrieve_memories(alert):
    try:
        from sentinel.memory_store import PersistenceStore
        store = PersistenceStore()
        memories = store.search_similar_memories(
            build_alert_search_description(alert), exclude_incident_id=alert.alert_id
        )
        store.close()
        return memories
    except Exception as exc:
        print(f"[sentinel] Semantic memory unavailable ({type(exc).__name__}: {exc})", file=sys.stderr)
        return []


def _print_memories_and_adaptations(memories, adaptations) -> None:
    print("\nSIMILAR INCIDENT MEMORIES RETRIEVED")
    if not memories:
        print("  None available; using the static plan.")
    for memory in memories:
        print(f"  {memory.memory_id}  score={memory.similarity_score:.3f}")
        print(f"  Lesson: {memory.narrative}")
    print("\nINVESTIGATION PLAN ADAPTED")
    if not adaptations:
        print("  No promotions or demotions.")
    for adaptation in adaptations:
        print(f"  {adaptation.tool_name.value}: {adaptation.direction} - {adaptation.reason}")


def run_incident(incident_type: IncidentType, persist: bool = False, memory: bool = False, minimum_similarity: float = 0.80):
    scenario = SCENARIOS[incident_type]
    plan = DEFAULT_PLANS[incident_type]
    runner = InvestigationRunner()

    print(f"\n[sentinel] Starting investigation: {incident_type.value}")
    print(f"[sentinel] Alert: {scenario['alert'].raw_message}\n")

    memories = _retrieve_memories(scenario["alert"]) if memory else []
    adapted_plan, adaptations = adapt_plan(plan, memories, minimum_similarity) if memory else (plan, [])
    if memory:
        _print_memories_and_adaptations(memories, adaptations)

    for action in adapted_plan:
        print(
            f"  Step {action.step_number}: "
            f"{action.tool_name.value}({action.parameters})"
        )

    outcome = runner.run(scenario, adapted_plan, classified_as=scenario["alert"].incident_type_hint)
    memory = runner.build_memory(scenario, outcome)

    _print_outcome(outcome.model_dump())

    print("[sentinel] Memory record:")
    _print_memory_summary(memory)

    if persist:
        _persist(scenario["alert"], outcome, memory)
    return outcome, memories


def compare_incident(incident_type: IncidentType, minimum_similarity: float = 0.80) -> None:
    scenario = SCENARIOS[incident_type]
    runner = InvestigationRunner()
    baseline = runner.run(scenario, DEFAULT_PLANS[incident_type], scenario["alert"].incident_type_hint)
    memories = _retrieve_memories(scenario["alert"])
    guided_plan, adaptations = adapt_plan(DEFAULT_PLANS[incident_type], memories, minimum_similarity)
    guided = runner.run(scenario, guided_plan, scenario["alert"].incident_type_hint)
    comparison = comparison_metrics(baseline, guided, memories, minimum_similarity)
    run = AdaptationRun(
        run_id=str(uuid.uuid4()), incident_id=scenario["alert"].alert_id,
        minimum_similarity=minimum_similarity, retrieved_memories=memories, comparison=comparison,
    )
    try:
        from sentinel.memory_store import PersistenceStore
        store = PersistenceStore()
        store.save_adaptation_run(run)
        store.close()
    except Exception as exc:
        print(f"[sentinel] Adaptation result not persisted ({type(exc).__name__}: {exc})", file=sys.stderr)
    _print_memories_and_adaptations(memories, adaptations)
    print("\nADAPTATION RESULT")
    print(f"  Baseline tool calls: {comparison.baseline_tool_calls}")
    print(f"  Memory-guided tool calls: {comparison.memory_tool_calls}")
    print(f"  Tool calls saved: {comparison.tool_calls_saved}")
    print(f"  Critical evidence: {comparison.critical_evidence_found}/{len(scenario['critical_evidence_ids'])}")
    print(f"  Correct classification: {str(comparison.classification_correct).lower()}")
    print(f"  Top memory similarity: {comparison.top_memory_similarity:.3f}" if comparison.top_memory_similarity is not None else "  Top memory similarity: none")


def run_agent(incident_type: IncidentType, memory_enabled: bool, minimum_similarity: float) -> None:
    from sentinel.agent import BoundedInvestigationAgent
    from sentinel.memory_guidance import select_influential_memories
    scenario = SCENARIOS[incident_type]
    memories = _retrieve_memories(scenario["alert"]) if memory_enabled else []
    run = BoundedInvestigationAgent().investigate(
        scenario, DEFAULT_PLANS[incident_type], memories, memory_enabled, minimum_similarity
    )
    print("\nAGENT DECISIONS")
    for decision in run.decisions:
        print(f"  Selected tool: {decision.action}\n  Reason: {decision.reason}\n  Memory influencing decision: {decision.memory_ids}")
        if decision.observation:
            print(f"  Observation: {decision.observation.analyst_note}")
    try:
        from sentinel.memory_store import PersistenceStore
        store = PersistenceStore()
        store.save_agent_run(run)
        store.close()
    except Exception as exc:
        print(f"[sentinel] Agent run not persisted ({type(exc).__name__}: {exc})", file=sys.stderr)
    _print_outcome(run.outcome.model_dump())


# ---------------------------------------------------------------------------
# list-memories command
# ---------------------------------------------------------------------------

def list_memories(limit: int = 20) -> None:
    uri = os.environ.get("MONGODB_URI", "")
    if not uri or uri.startswith("mongodb+srv://REPLACE_ME"):
        print("[sentinel] MONGODB_URI not configured.")
        return

    try:
        from sentinel.memory_store import PersistenceStore
        store = PersistenceStore()
        memories = store.list_incident_memories(limit=limit)
        store.close()

        if not memories:
            print("[sentinel] No memories stored yet.")
            return

        print(f"\n[sentinel] {len(memories)} memory record(s) in Atlas:\n")
        for m in memories:
            print(
                f"  {m.memory_id[:8]}...  "
                f"{m.incident_type.value:<35}  "
                f"score={m.investigation_score:.0%}  "
                f"entity={m.affected_entity}"
            )
        print()
    except Exception as exc:
        print(f"[sentinel] Retrieval failed ({type(exc).__name__}: {exc})", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel — adaptive cybersecurity investigation agent"
    )
    parser.add_argument(
        "--incident",
        choices=[t.value for t in IncidentType if t != IncidentType.UNKNOWN] + ["all"],
        default=None,
        help="Incident type to investigate (default: all)",
    )
    parser.add_argument(
        "--persist",
        action="store_true",
        default=False,
        help="Persist investigation to MongoDB Atlas (requires MONGODB_URI)",
    )
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Use Atlas semantic incident memories to reprioritize the plan",
    )
    parser.add_argument("--agent", action="store_true", help="Use the bounded LLM agent with safe fallback")
    parser.add_argument("--no-memory", action="store_true", help="Disable memories for --agent")
    parser.add_argument(
        "--compare",
        choices=[IncidentType.CREDENTIAL_COMPROMISE_VARIANT.value],
        help="Compare static and memory-guided plans for an incident",
    )
    parser.add_argument(
        "--minimum-similarity",
        type=float,
        default=0.80,
        help="Minimum similarity for memory-guided ordering (default: 0.80)",
    )
    parser.add_argument(
        "--list-memories",
        action="store_true",
        default=False,
        help="List recently stored memories from Atlas",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max memories to list with --list-memories (default: 20)",
    )
    args = parser.parse_args()

    if args.list_memories:
        list_memories(limit=args.limit)
        return

    if args.compare:
        compare_incident(IncidentType(args.compare), args.minimum_similarity)
        return

    if args.agent:
        if not args.incident or args.incident == "all":
            parser.error("--agent requires one specific --incident")
        run_agent(IncidentType(args.incident), not args.no_memory and args.memory, args.minimum_similarity)
        return

    incident_arg = args.incident or "all"

    targets = (
        [
            IncidentType.CREDENTIAL_COMPROMISE,
            IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
            IncidentType.PRIVILEGE_ESCALATION,
        ]
        if incident_arg == "all"
        else [IncidentType(incident_arg)]
    )

    for it in targets:
        run_incident(it, persist=args.persist, memory=args.memory, minimum_similarity=args.minimum_similarity)


if __name__ == "__main__":
    main()
