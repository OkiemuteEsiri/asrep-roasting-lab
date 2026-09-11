from __future__ import annotations

from .analyzer import Finding, metrics


def render(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# AS-REP Exposure Assessment",
        "",
        "> Synthetic defensive assessment. No live directory or Kerberos activity was performed.",
        "",
        "## Executive summary",
        "",
        f"- Accounts assessed: **{m['accounts_assessed']}**",
        f"- Exposed accounts: **{m['exposed_accounts']}**",
        f"- Critical/High findings: **{m['critical_high']}**",
        f"- Highest risk score: **{m['highest_risk']}/100**",
        "",
        "## Prioritized findings",
        "",
        "| ID | Account | Risk | Severity | ATT&CK |",
        "|---|---|---:|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.account} | {f.score} | {f.severity} | {', '.join(f.attack)} |")
    lines.extend(["", "## Finding detail", ""])
    for f in findings:
        lines.extend([
            f"### {f.account} — {f.severity.upper()} ({f.score}/100)",
            f"Finding ID: `{f.finding_id}`",
            "",
            "Risk rationale:",
            *[f"- {reason}" for reason in f.reasons],
            "",
            "Recommended validation:",
            "- Confirm Kerberos pre-authentication is required after the change.",
            "- Confirm exposed credentials were rotated where the account remained enabled.",
            "- Review privilege and interactive logon rights.",
            "- Re-run the approved directory export and verify the finding no longer reproduces.",
            "",
        ])
    lines.extend([
        "## Closure standard",
        "",
        "A finding should not be closed solely because a change ticket exists. Closure requires accountable ownership, the configuration correction, credential rotation for exposed enabled identities, privilege review, and post-change validation evidence.",
        "",
    ])
    return "\n".join(lines)
