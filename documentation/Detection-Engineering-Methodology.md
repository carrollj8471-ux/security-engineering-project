# Detection Engineering Methodology

## Purpose

This methodology describes the repeatable workflow used across the ATT&CK detection case studies in this portfolio.

## Workflow

1. Select a MITRE ATT&CK technique relevant to Windows enterprise risk.
2. Execute a safe Atomic Red Team test or equivalent lab simulation.
3. Confirm Sysmon and Windows logs were generated on the endpoint.
4. Verify Wazuh ingestion, indexing, and searchability.
5. Document command lines, parent-child process relationships, users, hosts, and timestamps.
6. Map observed telemetry to ATT&CK tactic and technique.
7. Write analyst investigation steps and false-positive considerations.
8. Capture screenshots for evidence.
9. Convert validated logic into durable rules, dashboards, or runbooks.
10. Report coverage, gaps, and improvement actions through the management portfolio.

## Validation Standard

A detection is considered validated when endpoint telemetry is present, Wazuh search can retrieve the event, the behavior maps to ATT&CK, and the analyst can explain what happened from available evidence.

## Documentation Standard

Each case study includes executive summary, objective, ATT&CK mapping, lab environment, simulation command, expected telemetry, Wazuh queries, detection logic, incident response, metrics, recommendations, lessons learned, and evidence placeholders.
