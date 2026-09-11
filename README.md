# AS-REP Roasting Exposure Assessment Lab

Defensive Active Directory security project for identifying and prioritizing accounts exposed because Kerberos pre-authentication is disabled. The repository analyzes synthetic directory exports only; it does **not** request Kerberos tickets, contact domain controllers, crack credentials, or automate exploitation.

## Problem statement

Accounts configured with `DONT_REQ_PREAUTH` can expose encrypted authentication material without first proving knowledge of the password. A mature identity-security program needs to detect the configuration, assess business context, prioritize remediation, and validate closure.

## Architecture

```text
Synthetic AD export
      |
      v
src/loader.py -------- fail-closed validation
      |
      v
src/analyzer.py ------ exposure classification + 0-100 risk score
      |                         |
      |                         +--> MITRE ATT&CK context
      v
src/reporting.py ----- Markdown assessment
      |
      +--> reports/example-assessment.md

Remediation evidence --> src/remediation.py --> closure decision
```

## Controls assessed

- Kerberos pre-authentication requirement
- Account enabled/disabled state
- Password age and managed-identity status
- Privileged group membership
- Service-account classification
- Interactive logon allowance
- Business criticality
- Strong-authentication context where available

## Risk model

The analyzer produces a bounded `0-100` score. Pre-authentication disabled is the base exposure. Risk increases for enabled identities, privileged membership, old passwords, service accounts, interactive logon and high business criticality. Managed service accounts and disabled identities reduce practical exposure.

| Score | Severity |
|---:|---|
| 85-100 | Critical |
| 70-84 | High |
| 40-69 | Medium |
| 1-39 | Low |
| 0 | Informational |

## MITRE ATT&CK context

- **T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting**
- **T1078 - Valid Accounts**

Mappings describe defensive threat context only. They are not evidence that exploitation or credential compromise occurred.

## Repository structure

```text
.github/workflows/security-quality.yml
data/synthetic_accounts.json
docs/architecture-methodology.md
reports/example-assessment.md
src/analyzer.py
src/loader.py
src/remediation.py
src/reporting.py
src/cli.py
tests/test_asrep_lab.py
```

## Usage

Requires Python 3.11+ and only the standard library.

```bash
python -m src.cli data/synthetic_accounts.json --output reports/generated-assessment.md
python -m unittest discover -s tests -v
```

## Remediation workflow

1. Confirm whether the pre-authentication exemption is still required.
2. Re-enable Kerberos pre-authentication where supported.
3. Rotate the credential for exposed enabled identities.
4. Remove unnecessary privilege and interactive logon rights.
5. Migrate suitable service identities to managed accounts.
6. Validate the resulting directory state from a fresh export.
7. Close the finding only when change reference and validation evidence are complete.

## Design decisions

- **Offline by design:** consumes synthetic or pre-approved directory exports rather than querying AD.
- **Fail closed:** malformed records, duplicates and unsupported enumerations are rejected.
- **Deterministic findings:** SHA-256-derived IDs support repeatable reporting.
- **Evidence-based closure:** remediation is not complete from a ticket comment alone.
- **No fabricated telemetry:** example data is explicitly fictional.

## Skills demonstrated

Active Directory security, Kerberos security concepts, identity governance, security data validation, contextual risk scoring, remediation governance, evidence-based validation, Python engineering, unit testing, security reporting, MITRE ATT&CK mapping and CI/CD quality controls.

## Limitations

This project does not parse live LDAP, Windows event logs or domain-controller configuration. It does not validate password quality, retrieve Kerberos material, attempt authentication or prove exploitability. Risk weights are illustrative and should be calibrated to an organization's threat model and control environment.

## Roadmap

- Add snapshot-to-snapshot drift comparison.
- Add configurable risk-policy files.
- Add CSV ingestion and normalized export schema.
- Add ownership/SLA reporting.
- Add correlation with synthetic password-policy and tiering data.
- Add structured JSON report output.

## Safety and data handling

All sample identities and organizational details are fictional. Do not place production directory exports, credentials, hashes, tickets, confidential employer/client information or sensitive identity data in this public repository.
