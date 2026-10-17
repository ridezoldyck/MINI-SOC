# Incident 002 - SQL Injection Attempt (Simulation)

| Field | Value |
|---|---|
| Status | Closed (lab simulation) |
| Severity | HIGH |
| Detection rule | WEB-001 SQL Injection Pattern |
| Alert | `SQL_INJECTION`, alert #6 |
| Source IP | 203.0.113.50 (documentation range, simulated) |
| MITRE ATT&CK | T1190 - Exploit Public-Facing Application |
| Generated with | `python scripts/simulate_events.py sql-injection` |

> This incident was produced by the built-in simulator against the local lab.
> The request was a synthetic `WEB_REQUEST` event; no real application was attacked.

## Summary

A `WEB_REQUEST` event containing a classic authentication-bypass payload was
received from `203.0.113.50`. Rule WEB-001 matched the *tautology* pattern and
raised a HIGH `SQL_INJECTION` alert.

## Evidence

```
GET /detail.php?id=1' OR '1'='1' -- -
```

The request closes the string literal with `'`, appends an always-true
condition (`OR '1'='1'`) and comments out the rest of the query with `-- -`.
If the application concatenates `id` into SQL, the query would return every row.

## Detection

WEB-001 URL-decodes the request and checks it against a set of patterns:
tautologies, `UNION SELECT`, stacked queries, time-based functions, schema
enumeration and comment terminators after a quote. It is a heuristic and does
not replace a WAF; encoded or obfuscated payloads may evade it.

## Analysis

- The payload is a well-known test string, typical of manual testing or
  automated scanners.
- The attack surface is a single parameter (`id`) on `detail.php`.
- No follow-up `UNION SELECT` or schema enumeration requests were observed
  from the same IP in this scenario.

## Recommended response

1. Use parameterized queries (prepared statements) for every database access.
2. Validate and cast numeric parameters such as `id` server-side.
3. Run the database account with least privilege.
4. Add a WAF rule or rate limit for the source if the activity continues.
5. Review web server logs for other requests from the same IP.

## Evidence (screenshots)

Add after running the scenario: `screenshots/alerts.png`.
