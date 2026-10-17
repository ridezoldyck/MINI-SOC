# Incident 001 - Brute Force Login (Simulation)

| Field | Value |
|---|---|
| Status | Closed (lab simulation) |
| Severity | HIGH |
| Detection rule | AUTH-002 Brute Force Login (supporting: AUTH-001) |
| Alert | `BRUTE_FORCE`, alert #2 (supporting `FAILED_LOGIN`, alert #1) |
| Source IP | 203.0.113.50 (documentation range, simulated) |
| Targeted account | `admin` |
| MITRE ATT&CK | T1110 - Brute Force |
| Generated with | `python scripts/simulate_events.py all` |

> This incident was produced by the built-in simulator against the local lab.
> No real system or account was involved.

## Summary

Seven failed login events for the `admin` account were received from
`203.0.113.50` within about two seconds. Mini SOC raised a `FAILED_LOGIN`
alert (MEDIUM) on the third failure and escalated to a `BRUTE_FORCE` alert
(HIGH) on the fifth failure, when the threshold of 5 failures within 5 minutes
was reached. The pattern is consistent with automated password guessing
against a single account.

## Timeline

| Time (local) | Event | Description |
|---|---|---|
| 10:56:29 | #1 `LOGIN_FAILED` | Failure 1 for `admin` |
| 10:56:30 | #2 `LOGIN_FAILED` | Failure 2 |
| 10:56:30 | #3 `LOGIN_FAILED` | Failure 3: AUTH-001 raises `FAILED_LOGIN` alert #1 (MEDIUM) |
| 10:56:30 | #4 `LOGIN_FAILED` | Failure 4 |
| 10:56:30 | #5 `LOGIN_FAILED` | Failure 5: AUTH-002 raises `BRUTE_FORCE` alert #2 (HIGH) |
| 10:56:30 | #6 `LOGIN_FAILED` | Failure 6: no new alert (deduplicated) |
| 10:56:31 | #7 `LOGIN_FAILED` | Failure 7: no new alert (deduplicated) |

All times are the Mini SOC server's local time.

## Detection

- **AUTH-001** fires at 3 failed logins from one IP within 5 minutes (MEDIUM).
- **AUTH-002** fires at 5 failed logins from one IP within 5 minutes (HIGH).
- Both rules are deduplicated: while an alert for the same type and source IP
  is OPEN or INVESTIGATING (15-minute window), further failures only update the
  existing alert instead of creating new ones. Seven failed logins therefore
  produced two alerts, not seven.

## Analysis

- Rate: 7 attempts in roughly 2 seconds is far faster than a human can type,
  which indicates automation.
- Scope: a single account (`admin`) was targeted from a single IP, which
  suggests password guessing rather than password spraying.
- Outcome: no `LOGIN_SUCCESS` event followed from the same IP, so there is no
  evidence of a successful compromise in this scenario.

## Impact assessment

Low in the lab (no successful login). In a real environment the targeted
account is privileged (`admin`), so a successful guess would grant full access.

## Recommended response

1. Block or rate-limit the source IP at the firewall or reverse proxy.
2. Enforce account lockout or progressive delays after repeated failures.
3. Require MFA for administrative accounts.
4. Review `LOGIN_SUCCESS` events from the same source for the following 24 hours.
5. Keep AUTH-001 and AUTH-002 enabled and tune thresholds if false positives appear.

## Evidence

Screenshots (add after running the scenario): `screenshots/alerts.png`,
`screenshots/incident.png`.
