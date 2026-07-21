# Security KPI Catalog

## Purpose

Define management metrics that connect security engineering activity to coverage, risk reduction, accountability, and response outcomes. Each KPI requires a stable calculation, named owner, reporting cadence, target, and documented data source.

## KPI Definitions

| Program area | KPI | Definition | Owner | Cadence | Target |
|---|---|---|---|---|---|
| Detection Engineering | Validated ATT&CK techniques | Count of techniques with current positive telemetry, alert, ATT&CK mapping, and evidence; “documented” alone does not qualify | Detection Engineer | Monthly | 25 validated priority techniques |
| Detection Engineering | Detection validation pass rate | Successful positive and negative tests divided by tests executed | Detection Engineer | Monthly | ≥95% |
| Detection Engineering | Telemetry-to-alert gap count | Collected behaviors lacking an intended analytic | Security Lead | Monthly | Downward trend; no unowned High gaps |
| Detection Engineering | Negative-control pass rate | Comparable controls collected without the elevated analytic divided by controls executed | Detection Engineer | Monthly | ≥95% |
| Detection Engineering | False-positive rate | Benign dispositions divided by all reviewed detection alerts | SOC Lead | Monthly after operational data is available | Establish baseline, then downward trend without recall loss |
| Detection Engineering | Validation freshness | Days since the most recent successful positive and negative validation | Detection Engineer | Monthly | ≤90 days or immediately after material change |
| Detection Engineering | Mean time to detect | Average alert-availability time minus source-event time for validated detections | Detection Engineer | Monthly after timestamp normalization | ≤5 minutes in the lab |
| Detection Engineering | Tuning regression rate | Tuning changes that fail positive or negative revalidation divided by tuning changes tested | Detection Engineer | Monthly | 0% |
| Vulnerability Management | Critical findings within SLA | Critical findings remediated or formally accepted before SLA divided by Critical findings due | Vulnerability Manager | Weekly/monthly | ≥90% |
| Vulnerability Management | Median remediation age | Median days from validated finding to verified closure | Vulnerability Manager | Monthly | Downward trend |
| Cloud Security | Failed High controls | Open High-severity cloud-control failures after validation | Cloud Owner | Weekly/monthly | 0 |
| DevSecOps | Repositories with security gates | In-scope repositories enforcing required security checks divided by total in-scope repositories | App/System Owners | Monthly | 100% of critical repositories |
| Compliance | Baseline controls passing | Passing validated controls divided by controls tested | Control Owners | Monthly | ≥95% |
| Incident Response | Mean time to triage | Average time from alert availability to initial analyst disposition | SOC Lead | Monthly | ≤30 minutes |
| Incident Response | Mean time to contain | Average time from confirmed incident to verified containment | Incident Commander | Quarterly | Risk-based downward trend |
| Risk Management | Open risks older than 30 days | Count of open risks older than 30 days without current approved treatment | Security Lead | Monthly | 0 |
| Risk Management | Overdue Critical/High actions | Count of Critical or High remediation items past SLA without active acceptance | Executive Sponsor | Weekly/monthly | 0 |

## Status Rules

| Status | Meaning |
|---|---|
| On Track | Target met or trend supports timely achievement |
| Needs Improvement | Below target but owned corrective plan is active |
| At Risk | Material target miss, overdue action, missing owner, or worsening trend |
| Not Measured | Data source or calculation is not yet reliable |

## Data Quality Rules

- Use a single authoritative source for each numerator and denominator.
- Record the reporting period and extraction time.
- Do not combine documented, tested, and validated detection states.
- Exclude duplicate findings only through a documented normalization rule.
- Treat accepted risk separately from remediated risk.
- Preserve prior-period values; do not rewrite history after methodology changes.
- Explain material changes, target misses, and data limitations in the notes field.

## Governance

KPI owners validate results before publication. The Security Lead reviews definitions quarterly and approves methodology changes. Executive reporting should emphasize risk, ownership, trend, and required decisions—not activity volume without outcome context.

The current monthly values are maintained in [`monthly-security-scorecard.csv`](monthly-security-scorecard.csv). Per-detection false-positive decisions, blind spots, tuning decisions, response actions, definitions, and data limitations are maintained in [`detection-lifecycle-metrics.md`](detection-lifecycle-metrics.md), with event-level records in [`detection-lifecycle-register.csv`](detection-lifecycle-register.csv).
