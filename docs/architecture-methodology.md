# Architecture and Methodology

## Objective

Assess Active Directory account metadata for Kerberos pre-authentication exposure without contacting a domain controller or retrieving authentication material. The lab demonstrates identity-risk engineering, prioritization and remediation validation.

## Trust boundaries

1. **Input boundary** — JSON is considered untrusted until validated. Required fields, booleans, password-age values, criticality and duplicate identities are checked before analysis.
2. **Analysis boundary** — only normalized records enter scoring. The analyzer has no network capability and performs no authentication operations.
3. **Reporting boundary** — findings communicate configuration exposure, not compromise. ATT&CK mappings are contextual.
4. **Closure boundary** — ticket existence is insufficient. Closure requires complete remediation evidence.

## Detection methodology

A record is exposed when `preauth_required` is false. Pre-authentication-enabled accounts remain in the assessed population with informational risk so program owners can see the denominator rather than only the exceptions.

## Contextual risk model

Base exposure begins at 45. The following controls and business factors adjust risk:

| Factor | Direction | Rationale |
|---|---:|---|
| Account enabled | +10 | Active identities have greater practical exposure |
| Account disabled | -25 | Reduces immediate usability but does not replace cleanup |
| Privileged identity | +20 | Compromise could produce disproportionate impact |
| Service identity | +8 | Often non-human and long-lived |
| Interactive logon | +7 | Broadens potential use of credentials |
| Password age >= 180d | +10 | Indicates long-lived credential material |
| Password age >= 90d | +5 | Moderate credential-age concern |
| Managed identity | -20 | Indicates automated lifecycle controls |
| Strong authentication | -5 | Compensating control, not a fix for disabled pre-authentication |
| High/Critical business criticality | +10/+15 | Reflects business impact |

Scores are clamped to 0-100 and converted into deterministic severity bands. The weights are intentionally transparent and should be calibrated before enterprise use.

## ATT&CK mapping

- **T1558.004 — AS-REP Roasting**: directly relevant to the exposed Kerberos configuration.
- **T1078 — Valid Accounts**: represents downstream identity-risk context if credentials are compromised.

These mappings do not assert technique execution.

## Remediation methodology

Preferred treatment order:

1. Determine whether the exemption has a documented technical dependency.
2. Enable Kerberos pre-authentication.
3. Rotate credentials for enabled exposed accounts.
4. Review and reduce privileged group membership.
5. Remove interactive logon rights from non-human identities.
6. Migrate service identities to managed accounts where technically suitable.
7. Produce a fresh approved directory export and rerun assessment.

## Closure evidence

A closure package must identify the accountable owner and change reference, confirm pre-authentication is enabled, confirm credential rotation, record privilege review, and include post-change validation. Missing or false evidence produces `needs_evidence`; malformed closure packages produce `invalid_closure`.

## Limitations

The lab is not an LDAP collector, Kerberos client, password auditor or exploitation framework. It cannot establish whether exposed authentication material has ever been requested or abused. It should be combined with authorized directory configuration management and security telemetry in a production program.
