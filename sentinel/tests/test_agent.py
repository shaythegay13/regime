"""Mocked tests for the bounded LLM investigation agent."""

from sentinel.agent import BoundedInvestigationAgent, build_agent_context
from sentinel.memory_store import PersistenceStore
from sentinel.models import IncidentType, InvestigationToolName, SimilarIncidentMemory
from sentinel.runner import DEFAULT_PLANS
from sentinel.scenarios import SCENARIOS


def _memory(score: float = 0.91) -> SimilarIncidentMemory:
    return SimilarIncidentMemory(memory_id="memory-1", alert_id="INC-2026-001", narrative="Prior credential lesson.", incident_type=IncidentType.CREDENTIAL_COMPROMISE, useful_tools=[InvestigationToolName.QUERY_AUTH_LOGS], wasteful_tools=[], critical_evidence=["auth-001"], tool_call_count=5, similarity_score=score)


def test_rejects_actions_outside_allowlist_and_falls_back():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    agent = BoundedInvestigationAgent(lambda _: {"action": "shell", "reason": "bad", "confidence": 0.9})
    run = agent.investigate(scenario, DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [], False)
    assert all(decision.action != "shell" for decision in run.decisions)
    assert len(run.tool_sequence) <= 5


def test_structured_resolve_output_is_validated():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    agent = BoundedInvestigationAgent(lambda _: {"action": "RESOLVE", "reason": "Enough alert context.", "confidence": 0.8, "classification": "CREDENTIAL_COMPROMISE"})
    run = agent.investigate(scenario, DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [], False)
    assert run.decisions[0].action == "RESOLVE"
    assert run.tool_sequence == []


def test_no_memory_context_excludes_memories_and_ground_truth():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    context = build_agent_context(scenario["alert"], [_memory()], False, [])
    assert "RETRIEVED INCIDENT MEMORIES" not in context
    assert "auth-v001" not in context
    assert "ground_truth_type" not in context
    assert "critical_evidence_ids" not in context


def test_memory_context_includes_only_threshold_qualified_memories():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    agent = BoundedInvestigationAgent(lambda _: {"action": "RESOLVE", "reason": "done", "confidence": 0.8})
    run = agent.investigate(scenario, DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [_memory(0.81), _memory(0.79).model_copy(update={"memory_id": "weak", "alert_id": "INC-OTHER"})], True)
    assert run.retrieved_memory_ids == ["memory-1"]


def test_agent_decisions_are_persistable():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    run = BoundedInvestigationAgent(lambda _: {"action": "RESOLVE", "reason": "done", "confidence": 0.8}).investigate(
        scenario, DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [], False
    )
    store = PersistenceStore(uri="mongodb://example")
    class Collection:
        def replace_one(self, *args, **kwargs):
            self.args, self.kwargs = args, kwargs
    collection = Collection()
    store._col = lambda _: collection
    assert store.save_agent_run(run) == run.run_id
    assert collection.args[1]["decisions"][0]["action"] == "RESOLVE"
