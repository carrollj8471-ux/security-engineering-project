# 30-60-90 Day Security Engineering Plan

## Outcome

Move the portfolio from a set of technical artifacts to an operating security program with reliable evidence, ownership, measurable coverage, and management reporting.

## Days 1–30 — Establish Control

| Deliverable | Owner | Completion evidence |
|---|---|---|
| Confirm charter, RACI, and operating cadence | Security Lead | Approved governance documents |
| Reconcile risk register and remediation backlog | Security Lead / Control Owners | Every open High/Critical item has owner and due date |
| Separate documented from validated detections | Detection Engineer | Updated scorecard with evidence-backed statuses |
| Repair duplicate Wazuh rule IDs and invalid groups | Detection Engineer | Clean `wazuh-analysisd -t` output |
| Publish initial KPI definitions and monthly scorecard | Security Lead | Reviewed catalog and scorecard |
| Complete repository link and placeholder audit | Repository Owner | Link-check results and no unexplained empty files |

## Days 31–60 — Validate and Expand

| Deliverable | Owner | Completion evidence |
|---|---|---|
| Validate highest-priority ATT&CK techniques | Detection Engineer | Positive/negative tests, JSON, screenshots, final rules |
| Add rule tests and versioned detection artifacts | Detection Engineer | Repeatable test inputs and expected rule IDs |
| Improve vulnerability and cloud prioritization | Vulnerability Manager / Cloud Owner | Risk-context fields and SLA tracking |
| Apply security gates to critical repositories | App/System Owners | Enforced checks and exception workflow |
| Run failed-logon and endpoint triage exercises | SOC Lead | Completed timelines and after-action notes |
| Review privileged and service-account access | Identity Owner | Signed access-review evidence |

## Days 61–90 — Operationalize

| Deliverable | Owner | Completion evidence |
|---|---|---|
| Produce quarterly risk review | Security Lead | Trend, decisions, overdue risks, and accepted risks |
| Validate remediation closure evidence | Independent reviewer | Sampled closures pass re-test |
| Automate scorecard inputs where reliable | Security Engineering | Documented data pipeline and reconciliation |
| Exercise recovery and incident communications | Incident Commander | After-action report and tracked improvements |
| Convert recurring gaps into annual roadmap initiatives | Security Lead | Prioritized, funded backlog |
| Publish portfolio release | Repository Owner | Reviewed, redacted, navigable GitHub content |

## Success Measures

- No unowned Critical or High risk.
- No unexplained duplicate Wazuh rule IDs.
- Detection status uses documented, telemetry-confirmed, alert-validated, and tuned states consistently.
- Every closed remediation item has validation evidence.
- Monthly reporting identifies decisions and accountable owners.
- Public artifacts contain no unintended sensitive lab data.
