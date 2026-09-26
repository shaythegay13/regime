"""
Tests: InvestigationRunner and investigation trajectories.

Verifies:
  - runner produces a valid IncidentOutcome for each scenario
  - classification is correct when the right incident type is supplied
  - total_tool_calls equals len(plan)
  - every step has an action, observation, and evidence list
  - critical evidence IDs from the scenario are found in the outcome
  - investigation_score is in [0.0, 1.0]
  - score is RESOLVED when ≥60% critical evidence found
  - build_memory() produces a valid IncidentMemory
  - trajectories are recorded in step order
  - a partial plan (subset of tools) scores lower than the full plan
"""

from __future__ import annotations

import pytest

from sentinel.models import (
    IncidentEvidence,
    IncidentMemory,
    IncidentOutcome,
    IncidentType,
    InvestigationAction,
    InvestigationStep,
    InvestigationToolName,
    OutcomeStatus,
)
from sentinel.runner import DEFAULT_PLANS, InvestigationRunner
from sentinel.scenarios import SCENARIOS

RUNNER = InvestigationRunner()

EXPECTED_TYPES = [
    IncidentType.CREDENTIAL_COMPROMISE,
    IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
    IncidentType.PRIVILEGE_ESCALATION,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_default(incident_type: IncidentType) -> IncidentOutcome:
    scenario = SCENARIOS[incident_type]
    plan = DEFAULT_PLANS[incident_type]
    return RUNNER.run(scenario, plan, classified_as=incident_type)


# ---------------------------------------------------------------------------
# Outcome structure
# ---------------------------------------------------------------------------

class TestOutcomeStructure:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_outcome_is_incident_outcome(self, incident_type):
        outcome = run_default(incident_type)
        assert isinstance(outcome, IncidentOutcome)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_alert_id_matches_scenario(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        assert outcome.alert_id == scenario["alert"].alert_id

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_total_tool_calls_matches_plan_length(self, incident_type):
        plan = DEFAULT_PLANS[incident_type]
        outcome = run_default(incident_type)
        assert outcome.total_tool_calls == len(plan)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_steps_count_matches_plan_length(self, incident_type):
        plan = DEFAULT_PLANS[incident_type]
        outcome = run_default(incident_type)
        assert len(outcome.steps) == len(plan)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_each_step_has_action_and_observation(self, incident_type):
        outcome = run_default(incident_type)
        for step in outcome.steps:
            assert isinstance(step, InvestigationStep)
            assert isinstance(step.action, InvestigationAction)
            assert step.observation is not None

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_each_step_has_evidence_list(self, incident_type):
        outcome = run_default(incident_type)
        for step in outcome.steps:
            assert isinstance(step.evidence_collected, list)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_summary_is_nonempty_string(self, incident_type):
        outcome = run_default(incident_type)
        assert isinstance(outcome.summary, str) and len(outcome.summary) > 10


# ---------------------------------------------------------------------------
# Classification correctness
# ---------------------------------------------------------------------------

class TestClassification:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_correct_classification_when_right_type_supplied(self, incident_type):
        outcome = run_default(incident_type)
        assert outcome.classification_correct is True

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_incorrect_classification_when_wrong_type_supplied(self, incident_type):
        scenario = SCENARIOS[incident_type]
        plan = DEFAULT_PLANS[incident_type]
        # Supply a deliberately wrong type
        wrong_type = (
            IncidentType.SUSPICIOUS_API_KEY_ACTIVITY
            if incident_type != IncidentType.SUSPICIOUS_API_KEY_ACTIVITY
            else IncidentType.CREDENTIAL_COMPROMISE
        )
        outcome = RUNNER.run(scenario, plan, classified_as=wrong_type)
        assert outcome.classification_correct is False

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_ground_truth_type_preserved_in_outcome(self, incident_type):
        outcome = run_default(incident_type)
        assert outcome.ground_truth_type == incident_type


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class TestScoring:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_score_in_valid_range(self, incident_type):
        outcome = run_default(incident_type)
        assert 0.0 <= outcome.investigation_score <= 1.0

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_default_plan_achieves_passing_score(self, incident_type):
        outcome = run_default(incident_type)
        assert outcome.investigation_score >= 0.6, (
            f"{incident_type.value} default plan scored {outcome.investigation_score:.0%} — "
            "expected ≥60%"
        )

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_default_plan_status_is_resolved(self, incident_type):
        outcome = run_default(incident_type)
        assert outcome.status == OutcomeStatus.RESOLVED

    def test_empty_plan_scores_zero(self):
        scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]
        outcome = RUNNER.run(scenario, [], classified_as=IncidentType.CREDENTIAL_COMPROMISE)
        assert outcome.investigation_score == 0.0
        assert outcome.status == OutcomeStatus.UNRESOLVED
        assert outcome.total_tool_calls == 0

    def test_partial_plan_scores_lower_than_full(self):
        scenario = SCENARIOS[IncidentType.CREDENTIAL_COMPROMISE]
        full_plan = DEFAULT_PLANS[IncidentType.CREDENTIAL_COMPROMISE]
        # Use only the first step
        partial_plan = full_plan[:1]
        full_outcome = RUNNER.run(scenario, full_plan, classified_as=IncidentType.CREDENTIAL_COMPROMISE)
        partial_outcome = RUNNER.run(scenario, partial_plan, classified_as=IncidentType.CREDENTIAL_COMPROMISE)
        assert partial_outcome.investigation_score <= full_outcome.investigation_score


# ---------------------------------------------------------------------------
# Critical evidence tracking
# ---------------------------------------------------------------------------

class TestCriticalEvidenceTracking:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_default_plan_finds_critical_evidence(self, incident_type):
        outcome = run_default(incident_type)
        assert len(outcome.critical_evidence_found) > 0

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_found_plus_missed_equals_all_critical(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        total = len(scenario["critical_evidence_ids"])
        assert len(outcome.critical_evidence_found) + len(outcome.critical_evidence_missed) == total

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_found_evidence_ids_are_from_scenario(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        valid_ids = set(scenario["critical_evidence_ids"])
        for eid in outcome.critical_evidence_found:
            assert eid in valid_ids, f"Found unexpected evidence ID: {eid}"

    def test_empty_plan_misses_all_critical_evidence(self):
        scenario = SCENARIOS[IncidentType.PRIVILEGE_ESCALATION]
        outcome = RUNNER.run(scenario, [], classified_as=IncidentType.PRIVILEGE_ESCALATION)
        assert len(outcome.critical_evidence_found) == 0
        assert len(outcome.critical_evidence_missed) == len(scenario["critical_evidence_ids"])


# ---------------------------------------------------------------------------
# Investigation trajectory (step ordering)
# ---------------------------------------------------------------------------

class TestInvestigationTrajectory:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_steps_are_in_plan_order(self, incident_type):
        plan = DEFAULT_PLANS[incident_type]
        outcome = run_default(incident_type)
        for i, (action, step) in enumerate(zip(plan, outcome.steps)):
            assert step.action.step_number == action.step_number
            assert step.action.tool_name == action.tool_name

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_step_numbers_are_sequential(self, incident_type):
        outcome = run_default(incident_type)
        for expected_num, step in enumerate(outcome.steps, start=1):
            assert step.action.step_number == expected_num

    def test_repeated_runs_produce_identical_trajectories(self):
        """Runner is deterministic — same plan always produces same steps."""
        scenario = SCENARIOS[IncidentType.SUSPICIOUS_API_KEY_ACTIVITY]
        plan = DEFAULT_PLANS[IncidentType.SUSPICIOUS_API_KEY_ACTIVITY]
        outcome1 = RUNNER.run(scenario, plan, classified_as=IncidentType.SUSPICIOUS_API_KEY_ACTIVITY)
        outcome2 = RUNNER.run(scenario, plan, classified_as=IncidentType.SUSPICIOUS_API_KEY_ACTIVITY)
        # Compare step tool names and observation results (not timestamps)
        for s1, s2 in zip(outcome1.steps, outcome2.steps):
            assert s1.action.tool_name == s2.action.tool_name
            assert s1.observation.raw_result == s2.observation.raw_result
            assert s1.observation.exposed_critical_evidence == s2.observation.exposed_critical_evidence


# ---------------------------------------------------------------------------
# IncidentMemory generation
# ---------------------------------------------------------------------------

class TestIncidentMemory:
    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_build_memory_returns_incident_memory(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert isinstance(memory, IncidentMemory)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_alert_id_matches_outcome(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert memory.alert_id == outcome.alert_id

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_incident_type_correct(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert memory.incident_type == incident_type

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_tool_sequence_length_matches_plan(self, incident_type):
        scenario = SCENARIOS[incident_type]
        plan = DEFAULT_PLANS[incident_type]
        outcome = RUNNER.run(scenario, plan, classified_as=incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert len(memory.tool_sequence) == len(plan)

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_has_useful_tools(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert len(memory.useful_tools) > 0

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_narrative_nonempty(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert isinstance(memory.narrative, str) and len(memory.narrative) > 20

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_id_is_unique_across_runs(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        m1 = RUNNER.build_memory(scenario, outcome)
        m2 = RUNNER.build_memory(scenario, outcome)
        assert m1.memory_id != m2.memory_id

    @pytest.mark.parametrize("incident_type", EXPECTED_TYPES)
    def test_memory_score_matches_outcome(self, incident_type):
        scenario = SCENARIOS[incident_type]
        outcome = run_default(incident_type)
        memory = RUNNER.build_memory(scenario, outcome)
        assert memory.investigation_score == outcome.investigation_score
