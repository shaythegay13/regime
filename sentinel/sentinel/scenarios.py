"""
Deterministic incident scenarios.

Each scenario is a self-contained dict that the InvestigationRunner can load.
Fields:
  - alert             : SecurityAlert that initiates the investigation
  - ground_truth_type : IncidentType the correct classification
  - critical_evidence : list of evidence_ids that must be found to resolve
  - description       : human-readable summary for README / tests

Critical evidence IDs correspond to `event_id` values in environment.py
records that carry `is_critical_evidence: True`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinel.models import IncidentType, SecurityAlert, Severity


# ---------------------------------------------------------------------------
# Scenario 1 — Credential Compromise
# ---------------------------------------------------------------------------

CREDENTIAL_COMPROMISE_ALERT = SecurityAlert(
    alert_id="INC-2026-001",
    timestamp=datetime(2026, 9, 26, 2, 15, 0, tzinfo=timezone.utc),
    incident_type_hint=IncidentType.CREDENTIAL_COMPROMISE,
    severity=Severity.CRITICAL,
    source_system="SIEM",
    affected_entity="alice.chen",
    raw_message=(
        "ALERT: Anomalous login detected for alice.chen from IP 185.220.101.42 "
        "(known Tor exit node) at 02:13 UTC. No MFA. Geo: RU. "
        "User normally authenticates from US during business hours."
    ),
    metadata={
        "source_ip": "185.220.101.42",
        "geo_country": "RU",
        "mfa_used": False,
    },
)

CREDENTIAL_COMPROMISE_SCENARIO: dict[str, Any] = {
    "alert": CREDENTIAL_COMPROMISE_ALERT,
    "ground_truth_type": IncidentType.CREDENTIAL_COMPROMISE,
    "critical_evidence_ids": [
        "auth-001",  # login from Tor exit node without MFA
        "auth-002",  # session created immediately after
        "ua-001",    # 512 MB bulk download 2 min later
        "ua-002",    # access to finance doc out of hours
        "ep-001",    # AWS CLI recursive S3 copy on jump server
    ],
    "description": (
        "alice.chen's credentials compromised. Attacker logs in from Tor exit node "
        "at 02:13 UTC without MFA, immediately begins bulk data exfiltration via "
        "S3 and AWS CLI on a jump server."
    ),
}

CREDENTIAL_COMPROMISE_VARIANT_ALERT = SecurityAlert(
    alert_id="INC-2026-004",
    timestamp=datetime(2026, 10, 3, 23, 41, 0, tzinfo=timezone.utc),
    incident_type_hint=IncidentType.CREDENTIAL_COMPROMISE,
    severity=Severity.HIGH,
    source_system="Identity-Provider",
    affected_entity="maya.patel",
    raw_message=("ALERT: Unusual password session for maya.patel from 198.51.100.84 at 23:41 UTC. "
                 "The sign-in skipped the usual MFA challenge and originated outside the normal region."),
    metadata={"source_ip": "198.51.100.84", "geo_country": "BR", "mfa_used": False},
)

CREDENTIAL_COMPROMISE_VARIANT_SCENARIO: dict[str, Any] = {
    "alert": CREDENTIAL_COMPROMISE_VARIANT_ALERT,
    "ground_truth_type": IncidentType.CREDENTIAL_COMPROMISE,
    "critical_evidence_ids": ["auth-v001", "auth-v002", "ua-v001", "ua-v002", "ep-v001"],
    "description": "A distinct employee's suspicious password session is followed by sensitive cloud-data access.",
}


# ---------------------------------------------------------------------------
# Scenario 2 — Suspicious API Key Activity
# ---------------------------------------------------------------------------

SUSPICIOUS_API_KEY_ALERT = SecurityAlert(
    alert_id="INC-2026-002",
    timestamp=datetime(2026, 9, 26, 3, 0, 30, tzinfo=timezone.utc),
    incident_type_hint=IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
    severity=Severity.HIGH,
    source_system="API-Gateway",
    affected_entity="key-9f3a21bc",
    raw_message=(
        "ALERT: API key key-9f3a21bc (owner: svc-dataexport) used from external IP "
        "203.0.113.77 at 03:00 UTC. Endpoint: /v1/export/bulk. "
        "1.2 GB returned. Key normally used only from internal 10.x.x.x range."
    ),
    metadata={
        "api_key_id": "key-9f3a21bc",
        "source_ip": "203.0.113.77",
        "endpoint": "/v1/export/bulk",
        "bytes_returned": 1_200_000_000,
    },
)

SUSPICIOUS_API_KEY_SCENARIO: dict[str, Any] = {
    "alert": SUSPICIOUS_API_KEY_ALERT,
    "ground_truth_type": IncidentType.SUSPICIOUS_API_KEY_ACTIVITY,
    "critical_evidence_ids": [
        "auth-005",  # service account authenticated from unexpected external IP
        "api-001",   # bulk export 1.2 GB from external IP
        "api-002",   # schema enumeration before bulk export
        "ua-006",    # 1.2 GB customer DB query
        "ep-004",    # curl command from unknown external host
    ],
    "description": (
        "API key key-9f3a21bc (belonging to svc-dataexport) used from external IP "
        "203.0.113.77 at 03:00 UTC. Attacker enumerates schema then bulk-exports "
        "1.2 GB of customer data. Key appears to have been leaked or stolen."
    ),
}


# ---------------------------------------------------------------------------
# Scenario 3 — Privilege Escalation
# ---------------------------------------------------------------------------

PRIVILEGE_ESCALATION_ALERT = SecurityAlert(
    alert_id="INC-2026-003",
    timestamp=datetime(2026, 9, 26, 14, 2, 30, tzinfo=timezone.utc),
    incident_type_hint=IncidentType.PRIVILEGE_ESCALATION,
    severity=Severity.CRITICAL,
    source_system="CloudTrail",
    affected_entity="bob.martinez",
    raw_message=(
        "ALERT: IAM policy AdministratorAccess attached to user bob.martinez "
        "at 14:04 UTC. No approval ticket. Actor: bob.martinez (self-modification). "
        "Previous role: developer."
    ),
    metadata={
        "actor": "bob.martinez",
        "policy_attached": "AdministratorAccess",
        "approval_ticket": None,
    },
)

PRIVILEGE_ESCALATION_SCENARIO: dict[str, Any] = {
    "alert": PRIVILEGE_ESCALATION_ALERT,
    "ground_truth_type": IncidentType.PRIVILEGE_ESCALATION,
    "critical_evidence_ids": [
        "priv-001",  # self-granted iam-admin without ticket
        "priv-002",  # escalated svc-dataexport to db-superuser
        "priv-003",  # AdministratorAccess attached
        "ua-004",    # admin panel access after escalation
        "ua-005",    # full user list exported
        "ep-003",    # AWS CLI iam attach-user-policy command
    ],
    "description": (
        "bob.martinez (developer) uses AWS CLI to attach AdministratorAccess to his "
        "own account without any approval. He then escalates a service account, "
        "accesses the admin panel, and exports the full user list."
    ),
}


# ---------------------------------------------------------------------------
# Registry — single dict used by the runner to look up scenarios by name
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, dict[str, Any]] = {
    IncidentType.CREDENTIAL_COMPROMISE: CREDENTIAL_COMPROMISE_SCENARIO,
    IncidentType.SUSPICIOUS_API_KEY_ACTIVITY: SUSPICIOUS_API_KEY_SCENARIO,
    IncidentType.PRIVILEGE_ESCALATION: PRIVILEGE_ESCALATION_SCENARIO,
    IncidentType.CREDENTIAL_COMPROMISE_VARIANT: CREDENTIAL_COMPROMISE_VARIANT_SCENARIO,
}
