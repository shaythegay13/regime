"""
Simulated security environment.

All datasets are deterministic — seeded with fixed data, no randomness.
This module is the single source of truth for every event in the simulation.

Data is organized into five log stores that mirror real SOC data sources:
  - auth_logs         : authentication events (login, MFA, session)
  - user_activity     : user behavioural events (file access, app usage)
  - api_activity      : API key / service-to-service calls
  - privilege_changes : role / permission modifications
  - endpoint_events   : host-level events (process, network, file-system)

Each record carries a `scenario_tag` so tool implementations can filter
per-incident without ambiguity during testing.  In a real deployment this
field would not exist — the agent would have to infer relevance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _ts(iso: str) -> str:
    """Normalise an ISO-8601 string — keeps data definitions readable."""
    return iso  # stored as strings; tools parse when needed


# ---------------------------------------------------------------------------
# Auth logs  (query_auth_logs)
# ---------------------------------------------------------------------------

AUTH_LOGS: list[dict[str, Any]] = [
    # ── CREDENTIAL_COMPROMISE scenario ─────────────────────────────────────
    {
        "event_id": "auth-001",
        "timestamp": "2026-09-26T02:13:00Z",
        "user": "alice.chen",
        "source_ip": "185.220.101.42",  # known Tor exit node
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "PASSWORD",
        "mfa_used": False,
        "geo_country": "RU",
        "user_agent": "python-requests/2.31.0",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": True,
        "critical_reason": "Successful login from Tor exit node without MFA at 02:13 UTC",
    },
    {
        "event_id": "auth-002",
        "timestamp": "2026-09-26T02:14:10Z",
        "user": "alice.chen",
        "source_ip": "185.220.101.42",
        "event_type": "SESSION_CREATED",
        "auth_method": "PASSWORD",
        "mfa_used": False,
        "geo_country": "RU",
        "user_agent": "python-requests/2.31.0",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": True,
        "critical_reason": "Anomalous session created immediately after suspicious login",
    },
    {
        "event_id": "auth-003",
        "timestamp": "2026-09-26T08:45:00Z",
        "user": "alice.chen",
        "source_ip": "10.0.1.55",
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "SSO",
        "mfa_used": True,
        "geo_country": "US",
        "user_agent": "Mozilla/5.0 (Macintosh)",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── PRIVILEGE_ESCALATION scenario ───────────────────────────────────────
    {
        "event_id": "auth-004",
        "timestamp": "2026-09-26T14:05:00Z",
        "user": "bob.martinez",
        "source_ip": "10.0.2.88",
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "SSO",
        "mfa_used": True,
        "geo_country": "US",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── SUSPICIOUS_API_KEY scenario ─────────────────────────────────────────
    {
        "event_id": "auth-005",
        "timestamp": "2026-09-26T03:00:00Z",
        "user": "svc-dataexport",
        "source_ip": "203.0.113.77",
        "event_type": "API_AUTH_SUCCESS",
        "auth_method": "API_KEY",
        "mfa_used": False,
        "geo_country": "CN",
        "user_agent": "curl/7.88.1",
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": True,
        "critical_reason": "Service account authenticated from unexpected external IP via raw API key",
    },
    # ── Noise / irrelevant records ───────────────────────────────────────────
    {
        "event_id": "auth-006",
        "timestamp": "2026-09-26T09:00:00Z",
        "user": "carol.williams",
        "source_ip": "10.0.1.60",
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "SSO",
        "mfa_used": True,
        "geo_country": "US",
        "user_agent": "Mozilla/5.0 (Macintosh)",
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    {
        "event_id": "auth-007",
        "timestamp": "2026-09-26T09:05:00Z",
        "user": "david.kim",
        "source_ip": "10.0.1.72",
        "event_type": "LOGIN_FAIL",
        "auth_method": "PASSWORD",
        "mfa_used": False,
        "geo_country": "US",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
]


# ---------------------------------------------------------------------------
# User activity  (get_user_activity)
# ---------------------------------------------------------------------------

USER_ACTIVITY: list[dict[str, Any]] = [
    # ── CREDENTIAL_COMPROMISE ───────────────────────────────────────────────
    {
        "event_id": "ua-001",
        "timestamp": "2026-09-26T02:15:30Z",
        "user": "alice.chen",
        "action": "BULK_DOWNLOAD",
        "resource": "s3://corp-sensitive/hr-records/",
        "bytes_transferred": 512_000_000,
        "outcome": "SUCCESS",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": True,
        "critical_reason": "512 MB bulk download 2 min after anomalous login — data exfiltration indicator",
    },
    {
        "event_id": "ua-002",
        "timestamp": "2026-09-26T02:18:00Z",
        "user": "alice.chen",
        "action": "FILE_ACCESS",
        "resource": "s3://corp-sensitive/finance/q3-projections.xlsx",
        "bytes_transferred": 2_048_000,
        "outcome": "SUCCESS",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": True,
        "critical_reason": "Access to finance document outside business hours under compromised session",
    },
    {
        "event_id": "ua-003",
        "timestamp": "2026-09-26T08:50:00Z",
        "user": "alice.chen",
        "action": "FILE_ACCESS",
        "resource": "confluence://engineering/onboarding",
        "bytes_transferred": 45_000,
        "outcome": "SUCCESS",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── PRIVILEGE_ESCALATION ────────────────────────────────────────────────
    {
        "event_id": "ua-004",
        "timestamp": "2026-09-26T14:10:00Z",
        "user": "bob.martinez",
        "action": "ADMIN_PANEL_ACCESS",
        "resource": "iam-console://admin",
        "bytes_transferred": 0,
        "outcome": "SUCCESS",
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "bob.martinez accessed admin panel shortly after unauthorized role grant",
    },
    {
        "event_id": "ua-005",
        "timestamp": "2026-09-26T14:12:00Z",
        "user": "bob.martinez",
        "action": "USER_LIST_EXPORT",
        "resource": "iam-console://users/export",
        "bytes_transferred": 150_000,
        "outcome": "SUCCESS",
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "Exported full user list — reconnaissance after privilege escalation",
    },
    # ── SUSPICIOUS_API_KEY ──────────────────────────────────────────────────
    {
        "event_id": "ua-006",
        "timestamp": "2026-09-26T03:02:00Z",
        "user": "svc-dataexport",
        "action": "DATA_QUERY",
        "resource": "db://prod-postgres/customers",
        "bytes_transferred": 1_200_000_000,
        "outcome": "SUCCESS",
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": True,
        "critical_reason": "1.2 GB customer DB query via service account outside normal window",
    },
    # ── Noise ────────────────────────────────────────────────────────────────
    {
        "event_id": "ua-007",
        "timestamp": "2026-09-26T10:00:00Z",
        "user": "carol.williams",
        "action": "FILE_ACCESS",
        "resource": "confluence://marketing/roadmap",
        "bytes_transferred": 80_000,
        "outcome": "SUCCESS",
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
]


# ---------------------------------------------------------------------------
# API activity  (inspect_api_activity)
# ---------------------------------------------------------------------------

API_ACTIVITY: list[dict[str, Any]] = [
    # ── SUSPICIOUS_API_KEY_ACTIVITY ─────────────────────────────────────────
    {
        "event_id": "api-001",
        "timestamp": "2026-09-26T03:00:05Z",
        "api_key_id": "key-9f3a21bc",
        "service": "data-export-service",
        "endpoint": "/v1/export/bulk",
        "method": "POST",
        "source_ip": "203.0.113.77",
        "response_code": 200,
        "bytes_returned": 1_200_000_000,
        "calls_in_window": 1,
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": True,
        "critical_reason": "Bulk export of 1.2 GB via API key from external IP at 03:00 UTC",
    },
    {
        "event_id": "api-002",
        "timestamp": "2026-09-26T03:01:00Z",
        "api_key_id": "key-9f3a21bc",
        "service": "data-export-service",
        "endpoint": "/v1/export/schema",
        "method": "GET",
        "source_ip": "203.0.113.77",
        "response_code": 200,
        "bytes_returned": 12_000,
        "calls_in_window": 2,
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": True,
        "critical_reason": "Schema enumeration — attacker mapping DB structure before exfiltration",
    },
    {
        "event_id": "api-003",
        "timestamp": "2026-09-26T03:05:00Z",
        "api_key_id": "key-9f3a21bc",
        "service": "data-export-service",
        "endpoint": "/v1/export/bulk",
        "method": "POST",
        "source_ip": "203.0.113.77",
        "response_code": 429,
        "bytes_returned": 0,
        "calls_in_window": 3,
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── CREDENTIAL_COMPROMISE — API call made under stolen session ──────────
    {
        "event_id": "api-004",
        "timestamp": "2026-09-26T02:20:00Z",
        "api_key_id": "session-token-alice",
        "service": "internal-hr-api",
        "endpoint": "/v2/employees/export",
        "method": "GET",
        "source_ip": "185.220.101.42",
        "response_code": 200,
        "bytes_returned": 512_000_000,
        "calls_in_window": 1,
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── Noise ────────────────────────────────────────────────────────────────
    {
        "event_id": "api-005",
        "timestamp": "2026-09-26T11:00:00Z",
        "api_key_id": "key-internal-ci",
        "service": "ci-pipeline",
        "endpoint": "/v1/build/trigger",
        "method": "POST",
        "source_ip": "10.0.3.10",
        "response_code": 202,
        "bytes_returned": 512,
        "calls_in_window": 1,
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
]


# ---------------------------------------------------------------------------
# Privilege changes  (get_privilege_changes)
# ---------------------------------------------------------------------------

PRIVILEGE_CHANGES: list[dict[str, Any]] = [
    # ── PRIVILEGE_ESCALATION ────────────────────────────────────────────────
    {
        "event_id": "priv-001",
        "timestamp": "2026-09-26T14:02:00Z",
        "actor": "bob.martinez",
        "target_user": "bob.martinez",
        "change_type": "ROLE_GRANTED",
        "role": "iam-admin",
        "previous_role": "developer",
        "approved_by": None,
        "approval_ticket": None,
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "bob.martinez granted himself iam-admin without approval ticket",
    },
    {
        "event_id": "priv-002",
        "timestamp": "2026-09-26T14:03:00Z",
        "actor": "bob.martinez",
        "target_user": "svc-dataexport",
        "change_type": "ROLE_GRANTED",
        "role": "db-superuser",
        "previous_role": "db-reader",
        "approved_by": None,
        "approval_ticket": None,
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "Escalated service account svc-dataexport to db-superuser without approval",
    },
    {
        "event_id": "priv-003",
        "timestamp": "2026-09-26T14:04:00Z",
        "actor": "bob.martinez",
        "target_user": "bob.martinez",
        "change_type": "POLICY_ATTACHED",
        "role": "AdministratorAccess",
        "previous_role": "iam-admin",
        "approved_by": None,
        "approval_ticket": None,
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "AdministratorAccess policy attached — full account takeover potential",
    },
    # ── CREDENTIAL_COMPROMISE — permission probe under stolen session ────────
    {
        "event_id": "priv-004",
        "timestamp": "2026-09-26T02:16:00Z",
        "actor": "alice.chen",
        "target_user": "alice.chen",
        "change_type": "PERMISSION_CHECK",
        "role": "s3-read",
        "previous_role": "s3-read",
        "approved_by": None,
        "approval_ticket": None,
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── Routine / noise ──────────────────────────────────────────────────────
    {
        "event_id": "priv-005",
        "timestamp": "2026-09-26T09:30:00Z",
        "actor": "hr-admin",
        "target_user": "new.employee",
        "change_type": "ROLE_GRANTED",
        "role": "employee-base",
        "previous_role": None,
        "approved_by": "hr-admin",
        "approval_ticket": "JIRA-1234",
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
]


# ---------------------------------------------------------------------------
# Endpoint events  (query_endpoint_events)
# ---------------------------------------------------------------------------

ENDPOINT_EVENTS: list[dict[str, Any]] = [
    # ── CREDENTIAL_COMPROMISE — process spawned under stolen session ─────────
    {
        "event_id": "ep-001",
        "timestamp": "2026-09-26T02:19:00Z",
        "hostname": "jump-server-01",
        "user": "alice.chen",
        "event_type": "PROCESS_LAUNCH",
        "process_name": "aws",
        "command_line": "aws s3 cp s3://corp-sensitive/hr-records/ /tmp/ --recursive",
        "parent_process": "bash",
        "outcome": "SUCCESS",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": True,
        "critical_reason": "AWS CLI recursive copy of sensitive bucket from jump server under suspicious session",
    },
    {
        "event_id": "ep-002",
        "timestamp": "2026-09-26T02:21:00Z",
        "hostname": "jump-server-01",
        "user": "alice.chen",
        "event_type": "NETWORK_CONNECTION",
        "process_name": "aws",
        "command_line": None,
        "parent_process": None,
        "destination_ip": "185.220.101.42",
        "destination_port": 443,
        "outcome": "SUCCESS",
        "scenario_tag": "CREDENTIAL_COMPROMISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
    # ── PRIVILEGE_ESCALATION — IAM CLI calls ────────────────────────────────
    {
        "event_id": "ep-003",
        "timestamp": "2026-09-26T14:02:30Z",
        "hostname": "dev-workstation-bob",
        "user": "bob.martinez",
        "event_type": "PROCESS_LAUNCH",
        "process_name": "aws",
        "command_line": "aws iam attach-user-policy --user-name bob.martinez --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "parent_process": "zsh",
        "outcome": "SUCCESS",
        "scenario_tag": "PRIVILEGE_ESCALATION",
        "is_critical_evidence": True,
        "critical_reason": "AWS CLI IAM attach-user-policy to AdministratorAccess — self-escalation confirmed",
    },
    # ── SUSPICIOUS_API_KEY — curl on anomalous host ──────────────────────────
    {
        "event_id": "ep-004",
        "timestamp": "2026-09-26T03:00:00Z",
        "hostname": "UNKNOWN-EXTERNAL",
        "user": "svc-dataexport",
        "event_type": "PROCESS_LAUNCH",
        "process_name": "curl",
        "command_line": "curl -X POST https://api.corp.internal/v1/export/bulk -H 'Authorization: Bearer key-9f3a21bc'",
        "parent_process": "bash",
        "outcome": "SUCCESS",
        "scenario_tag": "SUSPICIOUS_API_KEY_ACTIVITY",
        "is_critical_evidence": True,
        "critical_reason": "Bulk export curl command from unknown external host using service API key",
    },
    # ── Noise ────────────────────────────────────────────────────────────────
    {
        "event_id": "ep-005",
        "timestamp": "2026-09-26T10:30:00Z",
        "hostname": "build-agent-03",
        "user": "svc-ci",
        "event_type": "PROCESS_LAUNCH",
        "process_name": "pytest",
        "command_line": "pytest tests/ -q",
        "parent_process": "bash",
        "outcome": "SUCCESS",
        "scenario_tag": "NOISE",
        "is_critical_evidence": False,
        "critical_reason": "",
    },
]


# ---------------------------------------------------------------------------
# Public accessor — returns a copy so callers cannot mutate the source data
# ---------------------------------------------------------------------------

AUTH_LOGS.extend([
    {"event_id": "auth-v001", "timestamp": "2026-10-03T23:41:00Z", "user": "maya.patel", "source_ip": "198.51.100.84", "event_type": "LOGIN_SUCCESS", "auth_method": "PASSWORD", "mfa_used": False, "geo_country": "BR", "user_agent": "python-requests/2.32", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": True, "critical_reason": "Unexpected password login without MFA."},
    {"event_id": "auth-v002", "timestamp": "2026-10-03T23:42:00Z", "user": "maya.patel", "source_ip": "198.51.100.84", "event_type": "SESSION_CREATED", "auth_method": "PASSWORD", "mfa_used": False, "geo_country": "BR", "user_agent": "python-requests/2.32", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": True, "critical_reason": "Suspicious session immediately followed the login."},
    {"event_id": "auth-v003", "timestamp": "2026-10-03T09:10:00Z", "user": "maya.patel", "source_ip": "10.0.4.22", "event_type": "LOGIN_SUCCESS", "auth_method": "SSO", "mfa_used": True, "geo_country": "US", "user_agent": "Mozilla/5.0", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": False, "critical_reason": ""},
])
USER_ACTIVITY.extend([
    {"event_id": "ua-v001", "timestamp": "2026-10-03T23:43:00Z", "user": "maya.patel", "action": "BULK_DOWNLOAD", "resource": "s3://corp-sensitive/contracts/", "bytes_transferred": 640_000_000, "outcome": "SUCCESS", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": True, "critical_reason": "Large download immediately after anomalous login."},
    {"event_id": "ua-v002", "timestamp": "2026-10-03T23:46:00Z", "user": "maya.patel", "action": "FILE_ACCESS", "resource": "s3://corp-sensitive/legal/acquisitions.xlsx", "bytes_transferred": 4_096_000, "outcome": "SUCCESS", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": True, "critical_reason": "Sensitive file access outside normal hours."},
    {"event_id": "ua-v003", "timestamp": "2026-10-03T16:00:00Z", "user": "maya.patel", "action": "FILE_ACCESS", "resource": "confluence://product/releases", "bytes_transferred": 16_000, "outcome": "SUCCESS", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": False, "critical_reason": ""},
])
ENDPOINT_EVENTS.extend([
    {"event_id": "ep-v001", "timestamp": "2026-10-03T23:48:00Z", "user": "maya.patel", "hostname": "jump-02", "process": "aws", "command_line": "aws s3 sync s3://corp-sensitive/contracts /tmp/contracts", "scenario_tag": "CREDENTIAL_COMPROMISE_VARIANT", "is_critical_evidence": True, "critical_reason": "CLI copied sensitive cloud data after suspicious session."},
])


class SimulatedEnvironment:
    """
    Read-only facade over all simulated log stores.

    Tools query this object rather than touching module-level lists directly,
    making it straightforward to swap in a database-backed implementation
    later without changing tool signatures.
    """

    def get_auth_logs(
        self,
        user: str | None = None,
        scenario_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        records = list(AUTH_LOGS)
        if user:
            records = [r for r in records if r.get("user") == user]
        if scenario_tag:
            records = [r for r in records if r.get("scenario_tag") == scenario_tag]
        return records

    def get_user_activity(
        self,
        user: str | None = None,
        scenario_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        records = list(USER_ACTIVITY)
        if user:
            records = [r for r in records if r.get("user") == user]
        if scenario_tag:
            records = [r for r in records if r.get("scenario_tag") == scenario_tag]
        return records

    def get_api_activity(
        self,
        api_key_id: str | None = None,
        scenario_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        records = list(API_ACTIVITY)
        if api_key_id:
            records = [r for r in records if r.get("api_key_id") == api_key_id]
        if scenario_tag:
            records = [r for r in records if r.get("scenario_tag") == scenario_tag]
        return records

    def get_privilege_changes(
        self,
        actor: str | None = None,
        target_user: str | None = None,
        scenario_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        records = list(PRIVILEGE_CHANGES)
        if actor:
            records = [r for r in records if r.get("actor") == actor]
        if target_user:
            records = [r for r in records if r.get("target_user") == target_user]
        if scenario_tag:
            records = [r for r in records if r.get("scenario_tag") == scenario_tag]
        return records

    def get_endpoint_events(
        self,
        user: str | None = None,
        hostname: str | None = None,
        scenario_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        records = list(ENDPOINT_EVENTS)
        if user:
            records = [r for r in records if r.get("user") == user]
        if hostname:
            records = [r for r in records if r.get("hostname") == hostname]
        if scenario_tag:
            records = [r for r in records if r.get("scenario_tag") == scenario_tag]
        return records


# Singleton used by tools and tests
ENV = SimulatedEnvironment()
