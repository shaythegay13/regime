"""
Investigation runner.

The runner is the execution harness that:
  1. Loads an incident scenario
  2. Accepts a sequence of InvestigationActions from a deterministic plan
  3. Invokes the corresponding tool for each action
  4. Extracts IncidentEvidence from tool observations
  5. Records every step in full detail
  6. Produces a final IncidentOutcome with scoring

The runner is intentionally stateless between calls — it takes a scenario
and an action plan, runs them, and returns a result.  Persistence (MongoDB)
will be added in a later phase.

Usage example
-------------
    from sentinel.runner import InvestigationRunner
    from sentinel.scenarios import SCENARIOS
    from sentinel.models import IncidentType, InvestigationAction, InvestigationToolName

    scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]
    plan = [
        InvestigationAction(
            step_number=1,
            tool_name=InvestigationToolName.QUERY_AUTH_LOGS,
            parameters={"user": "alice.chen"},
            rationale="Check auth logs for anomalous logins on the affected user",
        ),
        ...
    ]
    runner = InvestigationRunner()
    outcome = runner.run(scenario, plan, classified_as=IncidentType.CREDENTIAL_COMPROMISE)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sentinel.models import (
    IncidentEvidence,
    IncidentMemory,
    IncidentOutcome,
    IncidentType,
    InvestigationAction,
    InvestigationStep,
    InvestigationToolName,
    OutcomeStatus,
    ToolObservation,
)
from sentinel.tools import TOOL_REGISTRY


class InvestigationRunner:
    """
    Executes an investigation plan against a scenario and records every step.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        scenario: dict[str, Any],
        plan: list[InvestigationAction],
        classified_as: IncidentType | None = None,
    ) -> IncidentOutcome:
        """
        Run a complete investigation.

        Parameters
        ----------
        scenario      : one of the dicts from sentinel.scenarios.SCENARIOS
        plan          : ordered list of InvestigationActions to execute
        classified_as : final incident type classification (analyst or agent)
                        defaults to the alert's hint type if omitted

        Returns
        -------
        IncidentOutcome with full step history and scoring
        """
        alert = scenario["alert"]
        ground_truth: IncidentType = scenario["ground_truth_type"]
        critical_ids: list[str] = scenario["critical_evidence_ids"]

        if classified_as is None:
            classified_as = alert.incident_type_hint

        steps: list[InvestigationStep] = []
        all_evidence: dict[str, IncidentEvidence] = {}  # evidence_id -> evidence

        for action in plan:
            obs = self._invoke_tool(action)
            evidence_list = self._extract_evidence(obs)

            for ev in evidence_list:
                all_evidence[ev.evidence_id] = ev

            steps.append(
                InvestigationStep(
                    action=action,
                    observation=obs,
                    evidence_collected=evidence_list,
                )
            )

        # Score: fraction of critical evidence IDs surfaced
        found_ids = [eid for eid in critical_ids if eid in all_evidence]
        missed_ids = [eid for eid in critical_ids if eid not in all_evidence]
        score = len(found_ids) / len(critical_ids) if critical_ids else 0.0

        status = OutcomeStatus.RESOLVED if score >= 0.6 else OutcomeStatus.UNRESOLVED

        classification_correct = classified_as == ground_truth

        summary = self._build_summary(
            alert_id=alert.alert_id,
            classified_as=classified_as,
            ground_truth=ground_truth,
            correct=classification_correct,
            found=found_ids,
            missed=missed_ids,
            total_calls=len(plan),
            score=score,
        )

        return IncidentOutcome(
            alert_id=alert.alert_id,
            status=status,
            classified_as=classified_as,
            ground_truth_type=ground_truth,
            classification_correct=classification_correct,
            total_tool_calls=len(plan),
            steps=steps,
            critical_evidence_found=found_ids,
            critical_evidence_missed=missed_ids,
            summary=summary,
            investigation_score=round(score, 4),
        )

    def build_memory(
        self,
        scenario: dict[str, Any],
        outcome: IncidentOutcome,
    ) -> IncidentMemory:
        """
        Convert a completed IncidentOutcome into an IncidentMemory record
        ready for storage in MongoDB Atlas.
        """
        alert = scenario["alert"]

        tool_sequence = [step.action.tool_name for step in outcome.steps]

        useful_tools = list(dict.fromkeys(
            step.action.tool_name for step in outcome.steps
            if step.observation.exposed_critical_evidence
        ))
        wasteful_tools = list(dict.fromkeys(
            step.action.tool_name for step in outcome.steps
            if not step.observation.exposed_critical_evidence
        ))

        narrative = (
            f"Resolved {outcome.ground_truth_type.value} for {alert.affected_entity}. "
            f"Alert signals: {alert.raw_message} "
            f"Critical evidence: {outcome.critical_evidence_found}. "
            f"Useful tools: {[tool.value for tool in useful_tools]}. "
            f"Low-value tools: {[tool.value for tool in wasteful_tools]}. "
            f"Root cause classification: {outcome.ground_truth_type.value}. "
            f"Resolution lesson: prioritize {[tool.value for tool in useful_tools]} before low-value checks."
        )

        return IncidentMemory(
            memory_id=str(uuid.uuid4()),
            alert_id=outcome.alert_id,
            incident_type=outcome.ground_truth_type,
            severity=alert.severity,
            affected_entity=alert.affected_entity,
            tool_sequence=tool_sequence,
            useful_tools=useful_tools,
            wasteful_tools=wasteful_tools,
            outcome_status=outcome.status,
            classification_correct=outcome.classification_correct,
            investigation_score=outcome.investigation_score,
            narrative=narrative,
            created_at=datetime.now(tz=timezone.utc),
            outcome=outcome,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _invoke_tool(self, action: InvestigationAction) -> ToolObservation:
        """Look up and call the tool matching action.tool_name."""
        tool_fn = TOOL_REGISTRY.get(action.tool_name)
        if tool_fn is None:
            raise ValueError(f"Unknown tool: {action.tool_name}")
        return tool_fn(**action.parameters)

    def _extract_evidence(self, obs: ToolObservation) -> list[IncidentEvidence]:
        """
        Turn each record that carries is_critical_evidence=True into an
        IncidentEvidence object.  Non-critical records are still stored in
        the raw_result but do not generate named evidence items.
        """
        evidence: list[IncidentEvidence] = []
        for record in obs.raw_result:
            ev = IncidentEvidence(
                evidence_id=record.get("event_id", str(uuid.uuid4())),
                source_tool=obs.tool_name,
                description=record.get("critical_reason", "") or f"Event from {obs.tool_name.value}",
                is_critical=record.get("is_critical_evidence", False),
                raw_data=record,
            )
            evidence.append(ev)
        return evidence

    def _build_summary(
        self,
        alert_id: str,
        classified_as: IncidentType,
        ground_truth: IncidentType,
        correct: bool,
        found: list[str],
        missed: list[str],
        total_calls: int,
        score: float,
    ) -> str:
        verdict = "CORRECT" if correct else "INCORRECT"
        return (
            f"Investigation of {alert_id} complete. "
            f"Classified as {classified_as.value} [{verdict}]. "
            f"Score: {score:.0%} ({len(found)} of {len(found) + len(missed)} critical items found). "
            f"Total tool calls: {total_calls}. "
            f"Missed evidence: {missed if missed else 'none'}."
        )


# ---------------------------------------------------------------------------
# Default investigation plans
#
# These deterministic plans are used by tests and the CLI demo.
# A future LLM agent will generate its own plan dynamically.
# ---------------------------------------------------------------------------

DEFAULT_PLANS: dict[IncidentType, list[InvestigationAction]] = {
    IncidentType.CREDENTIAL_COMPROMISE_VARIANT: [
        InvestigationAction(step_number=1, tool_name=InvestigationToolName.GET_PRIVILEGE_CHANGES, parameters={"actor": "maya.patel"}, rationale="Check for a possible permission change."),
        InvestigationAction(step_number=2, tool_name=InvestigationToolName.INSPECT_API_ACTIVITY, parameters={"scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT"}, rationale="Check for related API activity."),
        InvestigationAction(step_number=3, tool_name=InvestigationToolName.QUERY_AUTH_LOGS, parameters={"user": "maya.patel"}, rationale="Review the unusual sign-in."),
        InvestigationAction(step_number=4, tool_name=InvestigationToolName.GET_USER_ACTIVITY, parameters={"user": "maya.patel"}, rationale="Review post-login activity."),
        InvestigationAction(step_number=5, tool_name=InvestigationToolName.QUERY_ENDPOINT_EVENTS, parameters={"user": "maya.patel"}, rationale="Check endpoint activity."),
    ],
    IncidentType.CREDENTIAL_COMPROMISE: [
        InvestigationAction(
            step_number=1,
            tool_name=InvestigationToolName.QUERY_AUTH_LOGS,
            parameters={"user": "alice.chen"},
            rationale="Check auth history for the affected user — look for anomalous login times, IPs, or missing MFA.",
        ),
        InvestigationAction(
            step_number=2,
            tool_name=InvestigationToolName.GET_USER_ACTIVITY,
            parameters={"user": "alice.chen"},
            rationale="Examine what the user did after the anomalous login — look for data access or exfiltration.",
        ),
        InvestigationAction(
            step_number=3,
            tool_name=InvestigationToolName.QUERY_ENDPOINT_EVENTS,
            parameters={"user": "alice.chen"},
            rationale="Check endpoint logs for CLI commands run under this session.",
        ),
        InvestigationAction(
            step_number=4,
            tool_name=InvestigationToolName.GET_PRIVILEGE_CHANGES,
            parameters={"actor": "alice.chen"},
            rationale="Verify the attacker did not escalate privileges during the session.",
        ),
        InvestigationAction(
            step_number=5,
            tool_name=InvestigationToolName.INSPECT_API_ACTIVITY,
            parameters={"scenario_tag": "CREDENTIAL_COMPROMISE"},
            rationale="Check if API calls were made under the compromised session.",
        ),
    ],
    IncidentType.SUSPICIOUS_API_KEY_ACTIVITY: [
        InvestigationAction(
            step_number=1,
            tool_name=InvestigationToolName.INSPECT_API_ACTIVITY,
            parameters={"api_key_id": "key-9f3a21bc"},
            rationale="Primary: inspect all activity associated with the flagged API key.",
        ),
        InvestigationAction(
            step_number=2,
            tool_name=InvestigationToolName.QUERY_AUTH_LOGS,
            parameters={"user": "svc-dataexport"},
            rationale="Check auth events for the service account that owns this key.",
        ),
        InvestigationAction(
            step_number=3,
            tool_name=InvestigationToolName.GET_USER_ACTIVITY,
            parameters={"user": "svc-dataexport"},
            rationale="Review data access performed under this service account.",
        ),
        InvestigationAction(
            step_number=4,
            tool_name=InvestigationToolName.QUERY_ENDPOINT_EVENTS,
            parameters={"user": "svc-dataexport"},
            rationale="Check if any endpoint initiated the suspicious API calls.",
        ),
        InvestigationAction(
            step_number=5,
            tool_name=InvestigationToolName.GET_PRIVILEGE_CHANGES,
            parameters={"target_user": "svc-dataexport"},
            rationale="Check if this service account received any unusual privilege grants.",
        ),
    ],
    IncidentType.PRIVILEGE_ESCALATION: [
        InvestigationAction(
            step_number=1,
            tool_name=InvestigationToolName.GET_PRIVILEGE_CHANGES,
            parameters={"actor": "bob.martinez"},
            rationale="Primary: retrieve all privilege changes made by or for the flagged actor.",
        ),
        InvestigationAction(
            step_number=2,
            tool_name=InvestigationToolName.QUERY_ENDPOINT_EVENTS,
            parameters={"user": "bob.martinez"},
            rationale="Look for CLI commands used to execute the privilege changes.",
        ),
        InvestigationAction(
            step_number=3,
            tool_name=InvestigationToolName.GET_USER_ACTIVITY,
            parameters={"user": "bob.martinez"},
            rationale="Examine what the actor did after gaining elevated privileges.",
        ),
        InvestigationAction(
            step_number=4,
            tool_name=InvestigationToolName.QUERY_AUTH_LOGS,
            parameters={"user": "bob.martinez"},
            rationale="Verify login context — confirm actor was authenticated legitimately.",
        ),
        InvestigationAction(
            step_number=5,
            tool_name=InvestigationToolName.INSPECT_API_ACTIVITY,
            parameters={"scenario_tag": "PRIVILEGE_ESCALATION"},
            rationale="Check if API calls were made under the escalated privilege level.",
        ),
    ],
}
