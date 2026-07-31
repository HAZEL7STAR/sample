from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Sequence


@dataclass
class PolicyDecision:
    action: str
    status: str
    reason: str


def evaluate_policy_decision(policies: Sequence[dict[str, Any]], identity: Any) -> PolicyDecision:
    """Return a policy decision for a device identity.

    The current implementation uses the existing SQLAlchemy/SQLite policy model and
    defaults to blocking unknown devices when no matching policy exists.
    """

    now = datetime.now(timezone.utc)
    fingerprint = getattr(identity, "fingerprint", None) or ""

    matching_policy = None
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        device_fingerprint = policy.get("device_fingerprint")
        if device_fingerprint and device_fingerprint != fingerprint:
            continue
        expires_at = policy.get("expires_at")
        if expires_at is not None:
            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.fromisoformat(expires_at)
                except ValueError:
                    expires_at = None
            if expires_at is not None and expires_at <= now:
                continue
        matching_policy = policy
        break

    if matching_policy is None:
        return PolicyDecision(
            action="block",
            status="blacklisted",
            reason="No matching policy found; unknown device blocking is enabled.",
        )

    rule_type = (matching_policy.get("rule_type") or "").lower()
    if rule_type in {"whitelist", "permanent_allow", "temp_allow"}:
        return PolicyDecision(
            action="allow",
            status="whitelisted" if rule_type == "whitelist" else "temp_allowed",
            reason=matching_policy.get("reason") or "Policy allowed this device.",
        )

    if rule_type in {"blacklist", "permanent_block", "temp_block"}:
        return PolicyDecision(
            action="block",
            status="blacklisted" if rule_type in {"blacklist", "permanent_block"} else "temp_blocked",
            reason=matching_policy.get("reason") or "Policy blocked this device.",
        )

    return PolicyDecision(
        action="block",
        status="blacklisted",
        reason=matching_policy.get("reason") or "Policy rule was not recognized.",
    )
