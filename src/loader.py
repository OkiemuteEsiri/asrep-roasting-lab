from __future__ import annotations

import json
from pathlib import Path

REQUIRED = {
    "sam_account_name", "enabled", "preauth_required", "password_age_days",
    "privileged", "service_account", "managed_identity", "interactive_logon",
    "criticality", "strong_authentication"
}
CRITICALITY = {"low", "medium", "high", "critical"}


def load_accounts(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("top-level JSON must be a list")
    seen: set[str] = set()
    validated: list[dict] = []
    for index, record in enumerate(data):
        if not isinstance(record, dict):
            raise ValueError(f"record {index} must be an object")
        missing = REQUIRED - record.keys()
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        name = record["sam_account_name"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"record {index} has invalid sam_account_name")
        key = name.casefold()
        if key in seen:
            raise ValueError(f"duplicate account: {name}")
        seen.add(key)
        for field in ("enabled", "preauth_required", "privileged", "service_account", "managed_identity", "interactive_logon", "strong_authentication"):
            if type(record[field]) is not bool:
                raise ValueError(f"{name}: {field} must be boolean")
        age = record["password_age_days"]
        if type(age) is not int or age < 0:
            raise ValueError(f"{name}: password_age_days must be a non-negative integer")
        if record["criticality"] not in CRITICALITY:
            raise ValueError(f"{name}: unsupported criticality")
        validated.append(record)
    return validated
