"""
Bounded defensive investigation tools.

Each tool:
  - accepts typed parameters
  - queries the SimulatedEnvironment (read-only)
  - returns a ToolObservation with raw results + metadata
  - marks exposed_critical_evidence when any returned record
    carries is_critical_evidence=True

All tools are purely defensive — they READ simulated log data only.
No network access, no credential manipulation, no offensive capability.
"""

from __future__ import annotations

from typing import Any

from sentinel.environment import ENV
from sentinel.models import InvestigationToolName, ToolObservation


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _observation(
    tool_name: InvestigationToolName,
    parameters: dict[str, Any],
    records: list[dict[str, Any]],
    analyst_note: str = "",
) -> ToolObservation:
    """Build a ToolObservation, auto-detecting critical evidence."""
    has_critical = any(r.get("is_critical_evidence", False) for r in records)
    return ToolObservation(
        tool_name=tool_name,
        parameters=parameters,
        raw_result=records,
        record_count=len(records),
        analyst_note=analyst_note,
        exposed_critical_evidence=has_critical,
    )


# ---------------------------------------------------------------------------
# Tool 1 — query_auth_logs
# ---------------------------------------------------------------------------


def query_auth_logs(
    user: str | None = None,
    scenario_tag: str | None = None,
) -> ToolObservation:
    """
    Retrieve authentication log entries.

    Parameters
    ----------
    user        : filter to a specific username (optional)
    scenario_tag: internal filter used during deterministic simulation (optional)

    Returns authentication events: logins, MFA usage, session creation,
    API auth, and failures.
    """
    params: dict[str, Any] = {}
    if user:
        params["user"] = user
    if scenario_tag:
        params["scenario_tag"] = scenario_tag

    records = ENV.get_auth_logs(user=user, scenario_tag=scenario_tag)

    note = (
        f"Found {len(records)} auth event(s)"
        + (f" for user '{user}'" if user else "")
        + "."
    )
    if any(r.get("mfa_used") is False and r.get("event_type") == "LOGIN_SUCCESS" for r in records):
        note += " WARNING: Successful login(s) without MFA detected."
    if any(r.get("geo_country") not in (None, "US") for r in records):
        note += " NOTE: Login(s) from non-US geo detected."

    return _observation(InvestigationToolName.QUERY_AUTH_LOGS, params, records, note)


# ---------------------------------------------------------------------------
# Tool 2 — get_user_activity
# ---------------------------------------------------------------------------


def get_user_activity(
    user: str | None = None,
    scenario_tag: str | None = None,
) -> ToolObservation:
    """
    Retrieve user behavioural activity: file access, downloads, admin actions.

    Parameters
    ----------
    user        : filter to a specific username (optional)
    scenario_tag: internal filter for simulation (optional)
    """
    params: dict[str, Any] = {}
    if user:
        params["user"] = user
    if scenario_tag:
        params["scenario_tag"] = scenario_tag

    records = ENV.get_user_activity(user=user, scenario_tag=scenario_tag)

    total_bytes = sum(r.get("bytes_transferred", 0) for r in records)
    note = f"Found {len(records)} activity event(s)"
    note += f", {total_bytes:,} bytes transferred total." if total_bytes else "."

    bulk = [r for r in records if r.get("action") == "BULK_DOWNLOAD"]
    if bulk:
        note += f" ALERT: {len(bulk)} bulk download(s) detected."

    return _observation(InvestigationToolName.GET_USER_ACTIVITY, params, records, note)


# ---------------------------------------------------------------------------
# Tool 3 — inspect_api_activity
# ---------------------------------------------------------------------------


def inspect_api_activity(
    api_key_id: str | None = None,
    scenario_tag: str | None = None,
) -> ToolObservation:
    """
    Retrieve API gateway activity for a given key or service account.

    Parameters
    ----------
    api_key_id  : the API key identifier to inspect (optional)
    scenario_tag: internal filter for simulation (optional)
    """
    params: dict[str, Any] = {}
    if api_key_id:
        params["api_key_id"] = api_key_id
    if scenario_tag:
        params["scenario_tag"] = scenario_tag

    records = ENV.get_api_activity(api_key_id=api_key_id, scenario_tag=scenario_tag)

    total_bytes = sum(r.get("bytes_returned", 0) for r in records)
    note = f"Found {len(records)} API call(s)"
    note += f", {total_bytes:,} bytes returned total." if total_bytes else "."

    external_calls = [
        r for r in records
        if not str(r.get("source_ip", "")).startswith("10.")
    ]
    if external_calls:
        note += f" WARNING: {len(external_calls)} call(s) from external (non-RFC1918) IP(s)."

    return _observation(InvestigationToolName.INSPECT_API_ACTIVITY, params, records, note)


# ---------------------------------------------------------------------------
# Tool 4 — get_privilege_changes
# ---------------------------------------------------------------------------


def get_privilege_changes(
    actor: str | None = None,
    target_user: str | None = None,
    scenario_tag: str | None = None,
) -> ToolObservation:
    """
    Retrieve IAM / RBAC privilege change events.

    Parameters
    ----------
    actor       : who made the change (optional)
    target_user : who the change was applied to (optional)
    scenario_tag: internal filter for simulation (optional)
    """
    params: dict[str, Any] = {}
    if actor:
        params["actor"] = actor
    if target_user:
        params["target_user"] = target_user
    if scenario_tag:
        params["scenario_tag"] = scenario_tag

    records = ENV.get_privilege_changes(
        actor=actor, target_user=target_user, scenario_tag=scenario_tag
    )

    note = f"Found {len(records)} privilege change event(s)."

    unapproved = [r for r in records if r.get("approval_ticket") is None and r.get("change_type") != "PERMISSION_CHECK"]
    if unapproved:
        note += f" WARNING: {len(unapproved)} change(s) with no approval ticket."

    self_grants = [r for r in records if r.get("actor") == r.get("target_user") and r.get("change_type") == "ROLE_GRANTED"]
    if self_grants:
        note += " CRITICAL: Self-granted privilege change(s) detected."

    return _observation(InvestigationToolName.GET_PRIVILEGE_CHANGES, params, records, note)


# ---------------------------------------------------------------------------
# Tool 5 — query_endpoint_events
# ---------------------------------------------------------------------------


def query_endpoint_events(
    user: str | None = None,
    hostname: str | None = None,
    scenario_tag: str | None = None,
) -> ToolObservation:
    """
    Retrieve host-level endpoint events: process launches, network connections.

    Parameters
    ----------
    user        : filter by the user context of the process (optional)
    hostname    : filter by endpoint hostname (optional)
    scenario_tag: internal filter for simulation (optional)
    """
    params: dict[str, Any] = {}
    if user:
        params["user"] = user
    if hostname:
        params["hostname"] = hostname
    if scenario_tag:
        params["scenario_tag"] = scenario_tag

    records = ENV.get_endpoint_events(user=user, hostname=hostname, scenario_tag=scenario_tag)

    note = f"Found {len(records)} endpoint event(s)."

    iam_calls = [
        r for r in records
        if "iam" in str(r.get("command_line", "")).lower()
    ]
    if iam_calls:
        note += f" WARNING: {len(iam_calls)} IAM-related CLI command(s) detected."

    s3_exfil = [
        r for r in records
        if "s3 cp" in str(r.get("command_line", "")) or "s3 sync" in str(r.get("command_line", ""))
    ]
    if s3_exfil:
        note += f" WARNING: {len(s3_exfil)} S3 data-movement command(s) detected."

    return _observation(InvestigationToolName.QUERY_ENDPOINT_EVENTS, params, records, note)


# ---------------------------------------------------------------------------
# Tool registry — maps enum values to callables for the runner
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[InvestigationToolName, Any] = {
    InvestigationToolName.QUERY_AUTH_LOGS: query_auth_logs,
    InvestigationToolName.GET_USER_ACTIVITY: get_user_activity,
    InvestigationToolName.INSPECT_API_ACTIVITY: inspect_api_activity,
    InvestigationToolName.GET_PRIVILEGE_CHANGES: get_privilege_changes,
    InvestigationToolName.QUERY_ENDPOINT_EVENTS: query_endpoint_events,
}
