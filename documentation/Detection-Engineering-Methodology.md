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
7. Record observed and expected false positives, known blind spots, the tuning decision, and minimum analyst response actions.
8. Capture screenshots for evidence.
9. Convert validated logic into durable rules, dashboards, or runbooks.
10. Report coverage, gaps, lifecycle metrics, and improvement actions through the management portfolio.

## Validation Standard

A detection is considered positively validated when endpoint telemetry is present, Wazuh can retrieve the event, the intended analytic produces the expected result, the behavior maps to ATT&CK, and the analyst can explain what happened from preserved evidence.

Negative validation is tracked independently. A valid negative control must retain comparable telemetry while omitting the elevated condition. A command that produces no qualifying source event is inconclusive and must not be recorded as a pass.

Every tuning change requires a fresh positive test and comparable negative control. Lab validation demonstrates functional behavior; it does not establish a production false-positive rate, precision, or response-time metric.

## Documentation Standard

Each completed case study follows the common structure defined in [`../detections/CASE-STUDY-README-STANDARD.md`](../detections/CASE-STUDY-README-STANDARD.md). Evidence gaps must be labeled explicitly instead of represented as successful tests.

## Lifecycle measurement

The authoritative definitions, current portfolio baseline, per-detection decision register, and response-action standard are maintained in [`../metrics/detection-lifecycle-metrics.md`](../metrics/detection-lifecycle-metrics.md). Event-level validation and tuning records are appended to [`../metrics/detection-lifecycle-register.csv`](../metrics/detection-lifecycle-register.csv); historical records are not overwritten.
