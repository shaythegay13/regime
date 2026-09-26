"""
Typed domain models for Sentinel.

All models use Pydantic v2 for strict runtime validation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IncidentType(str, Enum):
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    SUSPICIOUS_API_KEY_ACTIVITY = "SUSPICIOUS_API_KEY_ACTIVITY"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_COMPROMISE_VARIANT = "CREDENTIAL_COMPROMISE_VARIANT"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvestigationToolName(str, Enum):
    QUERY_AUTH_LOGS = "query_auth_logs"
    GET_USER_ACTIVITY = "get_user_activity"
    INSPECT_API_ACTIVITY = "inspect_api_activity"
    GET_PRIVILEGE_CHANGES = "get_privilege_changes"
    QUERY_ENDPOINT_EVENTS = "query_endpoint_events"


class OutcomeStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    ESCALATED = "ESCALATED"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class SecurityAlert(BaseModel):
    """The initial trigger that starts an investigation."""

    alert_id: str
    timestamp: datetime
    incident_type_hint: IncidentType
    severity: Severity
    source_system: str
    affected_entity: str  # user, service, or resource name
    raw_message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationAction(BaseModel):
    """A single tool invocation recorded during an investigation."""

    step_number: int
    tool_name: InvestigationToolName
    parameters: dict[str, Any]
    rationale: str  # why this tool was chosen


class ToolObservation(BaseModel):
    """The result returned by a tool, plus an analyst note."""

    tool_name: InvestigationToolName
    parameters: dict[str, Any]
    raw_result: list[dict[str, Any]]
    record_count: int
    analyst_note: str = ""
    exposed_critical_evidence: bool = False


class IncidentEvidence(BaseModel):
    """A piece of evidence extracted from a tool observation."""

    evidence_id: str
    source_tool: InvestigationToolName
    description: str
    is_critical: bool
    raw_data: dict[str, Any]


class InvestigationStep(BaseModel):
    """Pairs an action with its observation — one step in the timeline."""

    action: InvestigationAction
    observation: ToolObservation
    evidence_collected: list[IncidentEvidence] = Field(default_factory=list)


class IncidentOutcome(BaseModel):
    """Final structured result produced at the end of an investigation."""

    alert_id: str
    status: OutcomeStatus
    classified_as: IncidentType
    ground_truth_type: IncidentType
    classification_correct: bool
    total_tool_calls: int
    steps: list[InvestigationStep]
    critical_evidence_found: list[str]  # evidence_ids
    critical_evidence_missed: list[str]  # evidence_ids
    summary: str
    investigation_score: float = Field(
        ge=0.0, le=1.0,
        description="Fraction of critical evidence found (0.0–1.0)",
    )


class IncidentMemory(BaseModel):
    """
    Persistent memory record stored after an investigation completes.

    This is the unit stored in MongoDB Atlas after an investigation.
    """

    memory_id: str
    alert_id: str
    incident_type: IncidentType
    severity: Severity
    affected_entity: str

    # Investigation trajectory
    tool_sequence: list[InvestigationToolName]
    useful_tools: list[InvestigationToolName]   # tools that found critical evidence
    wasteful_tools: list[InvestigationToolName] # tools that returned nothing useful

    # Outcome
    outcome_status: OutcomeStatus
    classification_correct: bool
    investigation_score: float

    # Human-readable investigation summary
    narrative: str

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))

    # Raw outcome preserved for full replay
    outcome: IncidentOutcome


class SimilarIncidentMemory(BaseModel):
    """Application-facing semantic-memory result without database details."""

    memory_id: str
    alert_id: str
    narrative: str
    incident_type: IncidentType
    useful_tools: list[InvestigationToolName]
    wasteful_tools: list[InvestigationToolName]
    critical_evidence: list[str]
    tool_call_count: int
    similarity_score: float


class PlanAdaptation(BaseModel):
    """A deterministic reordering decision derived from retrieved memories."""

    tool_name: InvestigationToolName
    direction: str
    reason: str


class ComparisonResult(BaseModel):
    """Measured baseline versus memory-guided investigation outcome."""

    baseline_tool_calls: int
    memory_tool_calls: int
    tool_calls_saved: int
    baseline_calls_before_critical: int | None
    memory_calls_before_critical: int | None
    unnecessary_calls_avoided: int
    classification_correct: bool
    critical_evidence_found: int
    top_memory_similarity: float | None


class AdaptationRun(BaseModel):
    """Persisted audit record for one baseline versus memory-guided comparison."""

    run_id: str
    incident_id: str
    minimum_similarity: float
    retrieved_memories: list[SimilarIncidentMemory]
    comparison: ComparisonResult
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class AgentDecision(BaseModel):
    step_number: int
    action: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    memory_ids: list[str] = Field(default_factory=list)
    observation: ToolObservation | None = None


class AgentRun(BaseModel):
    run_id: str
    incident_id: str
    model: str
    memory_enabled: bool
    retrieved_memory_ids: list[str]
    decisions: list[AgentDecision]
    tool_sequence: list[InvestigationToolName]
    final_classification: IncidentType
    outcome: IncidentOutcome
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
