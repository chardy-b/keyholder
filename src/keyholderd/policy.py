from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class PolicyError(ValueError):
    """Raised when policy validation or authorization fails."""


def load_policy(path: str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    if data.get("version") != 1:
        raise PolicyError("policy version 1 is required")
    if "callers" not in data or not isinstance(data["callers"], dict):
        raise PolicyError("policy callers mapping is required")
    return data


def _caller(policy: dict[str, Any], uid_name: str) -> dict[str, Any] | None:
    for caller in policy.get("callers", {}).values():
        if isinstance(caller, dict) and caller.get("uid_name") == uid_name:
            return caller
    return None


def grants_for_caller(policy: dict[str, Any], uid_name: str, profile: str) -> list[dict[str, Any]]:
    caller = _caller(policy, uid_name)
    if caller is None:
        return []
    prof = caller.get("profiles", {}).get(profile)
    if not isinstance(prof, dict):
        return []
    return list(prof.get("grants", []))


def _profile_list(policy: dict[str, Any], uid_name: str, profile: str, field: str) -> list[Any]:
    caller = _caller(policy, uid_name)
    if caller is None:
        return []
    prof = caller.get("profiles", {}).get(profile)
    if not isinstance(prof, dict) or not isinstance(prof.get(field), list):
        return []
    return list(prof[field])


def operations_for_caller(policy: dict[str, Any], uid_name: str, profile: str) -> list[Any]:
    return _profile_list(policy, uid_name, profile, "operations")


def secret_creates_for_caller(policy: dict[str, Any], uid_name: str, profile: str) -> list[Any]:
    # Separate from ``grants`` so issue/run can never reach a create-only entry.
    return _profile_list(policy, uid_name, profile, "secret_creates")


def get_grant(policy: dict[str, Any], uid_name: str, profile: str, grant_name: str) -> dict[str, Any]:
    for grant in grants_for_caller(policy, uid_name, profile):
        if grant.get("name") == grant_name:
            return grant
    raise PolicyError(f"grant {grant_name!r} is not available for caller {uid_name!r} profile {profile!r}")


def validate_ttl(grant: dict[str, Any], requested_ttl: int | None) -> int:
    default = int(grant.get("ttl_seconds", 300))
    max_ttl = int(grant.get("max_ttl_seconds", default))
    ttl = default if requested_ttl is None else int(requested_ttl)
    if ttl <= 0:
        raise PolicyError("ttl_seconds must be positive")
    if ttl > max_ttl:
        raise PolicyError(f"requested ttl {ttl}s exceeds max {max_ttl}s")
    return ttl
