from __future__ import annotations

REQUIRED_EVIDENCE = (
    "change_reference",
    "owner",
    "preauth_reenabled",
    "credential_rotated",
    "privilege_reviewed",
    "post_change_validated",
)


def validate_closure(evidence: dict) -> tuple[str, list[str]]:
    missing = [key for key in REQUIRED_EVIDENCE if key not in evidence]
    if missing:
        return "invalid_closure", [f"missing field: {key}" for key in missing]
    issues: list[str] = []
    if not str(evidence["change_reference"]).strip(): issues.append("change reference is empty")
    if not str(evidence["owner"]).strip(): issues.append("owner is empty")
    for key in ("preauth_reenabled", "credential_rotated", "privilege_reviewed", "post_change_validated"):
        if type(evidence[key]) is not bool:
            issues.append(f"{key} must be boolean")
        elif not evidence[key]:
            issues.append(f"{key} is not complete")
    return ("validated", []) if not issues else ("needs_evidence", issues)
