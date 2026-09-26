"""Bounded LLM-directed investigation loop with deterministic safe fallback."""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import uuid
from typing import Callable

from pydantic import BaseModel, Field, ValidationError

from sentinel.memory_guidance import adapt_plan, select_influential_memories
from sentinel.models import AgentDecision, AgentRun, IncidentType, InvestigationAction, InvestigationToolName, SimilarIncidentMemory
from sentinel.runner import InvestigationRunner
from sentinel.tools import TOOL_REGISTRY

MAX_TOOL_CALLS = 5
ALLOWED_ACTIONS = {tool.value for tool in InvestigationToolName} | {"RESOLVE"}


class ModelDecision(BaseModel):
    action: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    classification: IncidentType | None = None


def build_agent_context(alert, memories: list[SimilarIncidentMemory], memory_enabled: bool, observations: list[str]) -> str:
    context = [f"CURRENT ALERT\n{alert.model_dump_json()}", "AVAILABLE TOOLS\nquery_auth_logs, get_user_activity, inspect_api_activity, get_privilege_changes, query_endpoint_events, RESOLVE", "OBJECTIVE\nDetermine the incident class and identify critical evidence using as few unnecessary investigative actions as possible."]
    if memory_enabled:
        lessons = [{"id": memory.memory_id, "score": memory.similarity_score, "useful_tools": [tool.value for tool in memory.useful_tools], "wasteful_tools": [tool.value for tool in memory.wasteful_tools], "lesson": memory.narrative} for memory in memories]
        context.append(f"RETRIEVED INCIDENT MEMORIES\n{json.dumps(lessons)}")
    if observations:
        context.append(f"OBSERVATIONS\n{json.dumps(observations)}")
    return "\n\n".join(context)


def _openrouter_decision(context: str) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")
    model = os.environ.get("SENTINEL_MODEL", "openai/gpt-4o-mini")
    payload = {"model": model, "messages": [{"role": "system", "content": "Return JSON only: action, reason, confidence, optional classification."}, {"role": "user", "content": context}], "response_format": {"type": "json_object"}}
    request = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=json.dumps(payload).encode(), headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(json.loads(response.read())["choices"][0]["message"]["content"])


class BoundedInvestigationAgent:
    def __init__(self, decision_provider: Callable[[str], dict] | None = None) -> None:
        self._provider = decision_provider or _openrouter_decision

    def investigate(self, scenario: dict, plan: list[InvestigationAction], memories: list[SimilarIncidentMemory], memory_enabled: bool, minimum_similarity: float = 0.80) -> AgentRun:
        alert = scenario["alert"]
        qualified = select_influential_memories(memories, minimum_similarity) if memory_enabled else []
        fallback_plan, _ = adapt_plan(plan, qualified, minimum_similarity) if memory_enabled else (plan, [])
        actions_by_name = {action.tool_name.value: action for action in plan}
        fallback_actions = iter(fallback_plan)
        decisions: list[AgentDecision] = []
        selected: list[InvestigationAction] = []
        observations: list[str] = []
        classification = alert.incident_type_hint
        for step_number in range(1, MAX_TOOL_CALLS + 1):
            context = build_agent_context(alert, qualified, memory_enabled, observations)
            try:
                raw = ModelDecision.model_validate(self._provider(context))
                if raw.action not in ALLOWED_ACTIONS:
                    raise ValueError("action outside allowlist")
            except (
                RuntimeError,
                ValidationError,
                ValueError,
                json.JSONDecodeError,
                urllib.error.HTTPError,
                urllib.error.URLError,
            ):
                fallback_action = next(fallback_actions, None)
                raw = ModelDecision(
                    action=fallback_action.tool_name.value if fallback_action else "RESOLVE",
                    reason="Safe deterministic fallback.",
                    confidence=0.0,
                )
            if raw.action == "RESOLVE":
                classification = raw.classification or classification
                decisions.append(AgentDecision(step_number=step_number, action="RESOLVE", reason=raw.reason, confidence=raw.confidence, memory_ids=[memory.memory_id for memory in qualified]))
                break
            action = actions_by_name.get(raw.action)
            if action is None or any(previous.tool_name == action.tool_name for previous in selected):
                action = next((item for item in fallback_plan if item.tool_name not in {chosen.tool_name for chosen in selected}), None)
            if action is None:
                break
            action = action.model_copy(update={"step_number": step_number, "rationale": raw.reason})
            observation = TOOL_REGISTRY[action.tool_name](**action.parameters)
            selected.append(action)
            observations.append(observation.analyst_note)
            decisions.append(AgentDecision(step_number=step_number, action=action.tool_name.value, reason=raw.reason, confidence=raw.confidence, memory_ids=[memory.memory_id for memory in qualified], observation=observation))
        outcome = InvestigationRunner().run(scenario, selected, classification)
        return AgentRun(run_id=str(uuid.uuid4()), incident_id=alert.alert_id, model=os.environ.get("SENTINEL_MODEL", "deterministic-fallback"), memory_enabled=memory_enabled, retrieved_memory_ids=[memory.memory_id for memory in qualified], decisions=decisions, tool_sequence=[action.tool_name for action in selected], final_classification=classification, outcome=outcome)
