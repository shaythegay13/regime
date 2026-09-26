"""Tests for non-leaking semantic-memory guidance."""

from sentinel.memory_guidance import adapt_plan, build_alert_search_description, comparison_metrics, select_influential_memories
from sentinel.models import IncidentType, InvestigationToolName, SimilarIncidentMemory
from sentinel.runner import DEFAULT_PLANS, InvestigationRunner
from sentinel.scenarios import SCENARIOS


def _credential_memory() -> SimilarIncidentMemory:
    return SimilarIncidentMemory(
        memory_id="memory-1", alert_id="INC-2026-001", narrative="Prior credential compromise lesson.",
        incident_type=IncidentType.CREDENTIAL_COMPROMISE,
        useful_tools=[InvestigationToolName.QUERY_AUTH_LOGS, InvestigationToolName.GET_USER_ACTIVITY, InvestigationToolName.QUERY_ENDPOINT_EVENTS],
        wasteful_tools=[InvestigationToolName.GET_PRIVILEGE_CHANGES, InvestigationToolName.INSPECT_API_ACTIVITY],
        critical_evidence=["auth-001"], tool_call_count=5, similarity_score=0.91,
    )


def test_alert_query_contains_alert_facts_but_not_hidden_ground_truth():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    description = build_alert_search_description(scenario["alert"])
    assert "maya.patel" in description
    assert "auth-v001" not in description
    assert scenario["ground_truth_type"].value not in description


def test_memory_guidance_promotes_useful_tools_and_omits_low_value_tools():
    plan, changes = adapt_plan(DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [_credential_memory()])
    assert [action.tool_name for action in plan] == [
        InvestigationToolName.QUERY_AUTH_LOGS,
        InvestigationToolName.GET_USER_ACTIVITY,
        InvestigationToolName.QUERY_ENDPOINT_EVENTS,
    ]
    assert any(change.direction == "promoted" for change in changes)


def test_no_memories_leaves_static_plan_unchanged():
    original = DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    plan, changes = adapt_plan(original, [])
    assert plan == original
    assert changes == []


def test_comparison_metrics_are_correct():
    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    runner = InvestigationRunner()
    baseline = runner.run(scenario, DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], scenario["alert"].incident_type_hint)
    guided_plan, _ = adapt_plan(DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [_credential_memory()])
    guided = runner.run(scenario, guided_plan, scenario["alert"].incident_type_hint)
    metrics = comparison_metrics(baseline, guided, [_credential_memory()])
    assert metrics.baseline_tool_calls == 5
    assert metrics.memory_tool_calls == 3
    assert metrics.tool_calls_saved == 2
    assert metrics.baseline_calls_before_critical == 3
    assert metrics.memory_calls_before_critical == 1
    assert metrics.unnecessary_calls_avoided == 2
    assert metrics.classification_correct is True
    assert metrics.critical_evidence_found == 5
    assert metrics.top_memory_similarity == 0.91


def test_duplicate_incidents_keep_only_the_highest_scoring_memory():
    lower = _credential_memory().model_copy(update={"memory_id": "older", "similarity_score": 0.81})
    higher = _credential_memory().model_copy(update={"memory_id": "newer", "similarity_score": 0.92})
    selected = select_influential_memories([lower, higher])
    assert [memory.memory_id for memory in selected] == ["newer"]


def test_memories_below_similarity_threshold_do_not_change_ordering():
    weak = _credential_memory().model_copy(update={"similarity_score": 0.79})
    original = DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT]
    adapted, changes = adapt_plan(original, [weak])
    assert adapted == original
    assert changes == []


def test_higher_similarity_memory_has_more_influence_on_tool_ordering():
    weak_auth = _credential_memory().model_copy(update={
        "alert_id": "INC-A", "similarity_score": 0.81,
        "useful_tools": [InvestigationToolName.QUERY_AUTH_LOGS], "wasteful_tools": [],
    })
    strong_endpoint = _credential_memory().model_copy(update={
        "alert_id": "INC-B", "similarity_score": 0.95,
        "useful_tools": [InvestigationToolName.QUERY_ENDPOINT_EVENTS], "wasteful_tools": [],
    })
    adapted, _ = adapt_plan(DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE_VARIANT], [weak_auth, strong_endpoint])
    assert adapted[0].tool_name == InvestigationToolName.QUERY_ENDPOINT_EVENTS
