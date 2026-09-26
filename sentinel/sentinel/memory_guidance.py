"""Deterministic semantic-memory guidance for bounded Sentinel tools."""

from __future__ import annotations

from collections import defaultdict

from sentinel.models import (
    ComparisonResult,
    IncidentOutcome,
    InvestigationAction,
    PlanAdaptation,
    SecurityAlert,
    SimilarIncidentMemory,
)


def build_alert_search_description(alert: SecurityAlert) -> str:
    """Describe only alert-visible facts; never scenario ground truth or evidence."""
    metadata = ", ".join(f"{key}={value}" for key, value in sorted(alert.metadata.items()))
    return (
        f"Security alert from {alert.source_system}. Severity: {alert.severity.value}. "
        f"Affected entity: {alert.affected_entity}. Timestamp: {alert.timestamp.isoformat()}. "
        f"Alert details: {alert.raw_message} Metadata: {metadata}"
    )


def adapt_plan(
    plan: list[InvestigationAction],
    memories: list[SimilarIncidentMemory],
    minimum_similarity: float = 0.80,
) -> tuple[list[InvestigationAction], list[PlanAdaptation]]:
    """Promote tools that repeatedly exposed evidence and omit repeated low-value tools."""
    memories = select_influential_memories(memories, minimum_similarity)
    if not memories:
        return plan, []

    useful: defaultdict = defaultdict(float)
    wasteful: defaultdict = defaultdict(float)
    for memory in memories:
        for tool in memory.useful_tools:
            useful[tool] += memory.similarity_score
        for tool in memory.wasteful_tools:
            wasteful[tool] += memory.similarity_score
    ranked = sorted(
        plan,
        key=lambda action: (-useful[action.tool_name], wasteful[action.tool_name], action.step_number),
    )
    selected = [action for action in ranked if useful[action.tool_name] > wasteful[action.tool_name]]
    selected = selected or ranked
    adaptations: list[PlanAdaptation] = []
    for position, action in enumerate(selected, start=1):
        original = next(index for index, item in enumerate(plan, start=1) if item.tool_name == action.tool_name)
        if position < original:
            adaptations.append(PlanAdaptation(tool_name=action.tool_name, direction="promoted", reason="Prior similar incidents exposed critical evidence with this tool."))
        elif action.tool_name in wasteful:
            adaptations.append(PlanAdaptation(tool_name=action.tool_name, direction="demoted", reason="Prior similar incidents found this tool low-value."))
    return [action.model_copy(update={"step_number": number}) for number, action in enumerate(selected, start=1)], adaptations


def select_influential_memories(
    memories: list[SimilarIncidentMemory], minimum_similarity: float = 0.80,
) -> list[SimilarIncidentMemory]:
    """Keep one highest-scoring qualified memory for each prior incident."""
    selected: dict[str, SimilarIncidentMemory] = {}
    for memory in memories:
        if memory.similarity_score < minimum_similarity:
            continue
        existing = selected.get(memory.alert_id)
        if existing is None or memory.similarity_score > existing.similarity_score:
            selected[memory.alert_id] = memory
    return sorted(selected.values(), key=lambda memory: memory.similarity_score, reverse=True)


def _outcome_metrics(outcome: IncidentOutcome) -> tuple[int | None, int]:
    first = next((index for index, step in enumerate(outcome.steps, start=1) if step.observation.exposed_critical_evidence), None)
    unnecessary = sum(not step.observation.exposed_critical_evidence for step in outcome.steps)
    return first, unnecessary


def comparison_metrics(
    baseline: IncidentOutcome,
    memory_guided: IncidentOutcome,
    memories: list[SimilarIncidentMemory],
    minimum_similarity: float = 0.80,
) -> ComparisonResult:
    """Build a measured comparison from two executions and qualified memories."""
    baseline_first, baseline_unnecessary = _outcome_metrics(baseline)
    memory_first, memory_unnecessary = _outcome_metrics(memory_guided)
    influential = select_influential_memories(memories, minimum_similarity)
    return ComparisonResult(
        baseline_tool_calls=baseline.total_tool_calls,
        memory_tool_calls=memory_guided.total_tool_calls,
        tool_calls_saved=baseline.total_tool_calls - memory_guided.total_tool_calls,
        baseline_calls_before_critical=baseline_first,
        memory_calls_before_critical=memory_first,
        unnecessary_calls_avoided=baseline_unnecessary - memory_unnecessary,
        classification_correct=memory_guided.classification_correct,
        critical_evidence_found=len(memory_guided.critical_evidence_found),
        top_memory_similarity=influential[0].similarity_score if influential else None,
    )
