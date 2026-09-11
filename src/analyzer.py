from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

ATTACK = ("T1558.004", "T1078")
CRIT = {"low": 0, "medium": 5, "high": 10, "critical": 15}

@dataclass(frozen=True)
class Finding:
    finding_id: str
    account: str
    score: int
    severity: str
    reasons: tuple[str, ...]
    attack: tuple[str, ...] = ATTACK


def _severity(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 70: return "high"
    if score >= 40: return "medium"
    if score > 0: return "low"
    return "informational"


def assess(record: dict) -> Finding:
    name = record["sam_account_name"]
    if record["preauth_required"]:
        score, reasons = 0, ["Kerberos pre-authentication is required"]
    else:
        score, reasons = 45, ["Kerberos pre-authentication is disabled"]
        if record["enabled"]:
            score += 10; reasons.append("account is enabled")
        else:
            score -= 25; reasons.append("account is disabled")
        if record["privileged"]:
            score += 20; reasons.append("privileged identity")
        if record["service_account"]:
            score += 8; reasons.append("service identity")
        if record["interactive_logon"]:
            score += 7; reasons.append("interactive logon allowed")
        if record["password_age_days"] >= 180:
            score += 10; reasons.append("password age >= 180 days")
        elif record["password_age_days"] >= 90:
            score += 5; reasons.append("password age >= 90 days")
        if record["managed_identity"]:
            score -= 20; reasons.append("managed identity control present")
        if record["strong_authentication"]:
            score -= 5; reasons.append("strong authentication control present")
        score += CRIT[record["criticality"]]
        reasons.append(f"business criticality: {record['criticality']}")
    score = max(0, min(100, score))
    digest = sha256(f"asrep|{name.casefold()}".encode()).hexdigest()[:12]
    return Finding(f"ASREP-{digest}", name, score, _severity(score), tuple(reasons))


def assess_all(accounts: list[dict]) -> list[Finding]:
    return sorted((assess(a) for a in accounts), key=lambda f: (-f.score, f.account.casefold()))


def metrics(findings: list[Finding]) -> dict:
    exposed = [f for f in findings if f.score > 0]
    return {
        "accounts_assessed": len(findings),
        "exposed_accounts": len(exposed),
        "critical_high": sum(f.severity in {"critical", "high"} for f in exposed),
        "highest_risk": max((f.score for f in findings), default=0),
    }
