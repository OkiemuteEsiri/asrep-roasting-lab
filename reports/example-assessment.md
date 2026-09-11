# AS-REP Exposure Assessment — Example

> Synthetic defensive assessment only. No live directory or Kerberos activity was performed.

## Executive summary

Six fictional identities were assessed. Three enabled identities were configured without Kerberos pre-authentication; one additional disabled archival identity retained the same legacy setting. The highest-priority condition is a privileged interactive identity with an old password and critical business context.

## Prioritized remediation

| Account | Risk classification | Primary issue | Recommended treatment |
|---|---|---|---|
| `ops_admin_legacy` | Critical | Pre-authentication disabled on privileged interactive identity | Enable pre-authentication, rotate credential, review privilege and validate |
| `svc_legacy_reporting` | High | Long-lived service credential with pre-authentication disabled | Enable pre-authentication and evaluate managed service identity migration |
| `app_batch_user` | Medium | Service identity retains pre-authentication exemption | Remove exemption, rotate credential and validate application compatibility |
| `contractor_archive` | Low | Disabled legacy identity retains unsafe setting | Remove exemption and complete deprovisioning review |

## ATT&CK context

- T1558.004 — AS-REP Roasting
- T1078 — Valid Accounts

The mappings describe defensive risk context, not evidence of compromise.

## Validation criteria

Closure requires a documented change reference and owner, confirmation that Kerberos pre-authentication is enabled, credential rotation for exposed enabled identities, privilege review, and a fresh post-change directory export showing that the condition no longer reproduces.

## Strategic observations

A recurring exemption should be treated as identity-configuration debt rather than an isolated finding. Program-level controls should monitor pre-authentication settings for drift, maintain explicit exception ownership, and favor managed identities for service workloads where supported.
