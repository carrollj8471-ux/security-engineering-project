# Detection Lifecycle Metrics and Decision Register

## Purpose

This document records how validated detections are measured, tuned, investigated, and maintained. It separates lab validation results from production performance so a successful simulation is not misrepresented as an operational false-positive rate or response-time measurement.

## Current portfolio baseline

Baseline date: **2026-07-21**

| Metric | Value | Interpretation |
|---|---:|---|
| Techniques in scope | 25 | Completed and planned detection directories |
| Positively validated techniques | 15 | Endpoint telemetry and a Wazuh detection or hunt result are preserved |
| Implemented coverage | 60.0% | 15 validated techniques divided by 25 in scope |
| Positive validation pass rate | 100% | 15 successful positive paths divided by 15 completed studies |
| Preserved negative-control rate | 86.7% | 13 preserved negative controls divided by 15 completed studies |
| Negative-control evidence gaps | 2 | T1057 and T1087 retain an explicit gap rather than claiming a pass |
| Confirmed false-positive investigations | 1 | T1059.001 documents `dsregcmd.exe` incorrectly matching a broad CMD expression |
| Production false-positive rate | Not measured | Lab executions do not provide a production alert population |
| Mean time to detect/triage/respond | Not measured | The lab has not yet captured normalized alert and analyst timestamps |

## Metric definitions

| Metric | Calculation | Required fields | Target | Guardrail |
|---|---|---|---|---|
| Positive validation pass rate | Successful expected alerts ÷ positive tests executed | Detection ID, test ID, event record, expected rule, observed rule, result | ≥95% | A searchable raw event without the intended analytic is a telemetry-to-alert gap, not a pass |
| Negative-control pass rate | Controls collected without the elevated analytic ÷ controls executed | Control ID, comparable telemetry, expected baseline, elevated-rule result | ≥95% | A control that produced no qualifying telemetry is inconclusive |
| False-positive rate | Benign alerts ÷ all reviewed alerts | Alert ID, disposition, reason, reviewer, review time | Establish baseline, then trend downward | Do not estimate from simulation-only data |
| Precision | True-positive alerts ÷ all reviewed alerts | Alert disposition and review population | Risk based | Requires consistent analyst disposition criteria |
| Telemetry-to-alert gap count | Collected target behaviors lacking the intended analytic | Endpoint record, archive record, expected rule, owner | 0 unowned High gaps | Separate ingestion failures from rule-evaluation failures |
| Mean time to detect | Alert availability time − behavior time | Endpoint event time and alert/index time | ≤5 minutes in the lab | Normalize time zones and clocks before calculation |
| Mean time to triage | Initial disposition time − alert availability time | Alert time, analyst start, disposition time | ≤30 minutes | Automation timestamps are not analyst timestamps |
| Tuning effectiveness | False-positive rate after tuning compared with before tuning | Version, test window, comparable alert populations | Improvement without validation regression | Rerun positive and negative tests after every change |
| Validation freshness | Current date − last successful validation date | Detection ID, version, validation timestamp | ≤90 days or after material change | A ruleset, decoder, Sysmon, or policy change forces revalidation |
| Response completeness | Required response actions completed ÷ applicable actions | Case ID, action, owner, result, evidence | 100% for confirmed High/Critical alerts | Containment must be verified, not merely initiated |

## Detection decision register

| Technique | False-positive considerations | Expected blind spots | Tuning decision | Minimum analyst response |
|---|---|---|---|---|
| T1007 Service Discovery | Administration, monitoring, inventory, installers | PowerShell/WMI/API enumeration and renamed tools | Match `/svc` or `query` behavior; preserve separate process-discovery coverage | Validate user/parent/host role; identify clustered discovery; escalate unexpected reconnaissance |
| T1016 Network Configuration Discovery | Help desk, VPN/DNS/DHCP diagnostics, inventory | PowerShell/.NET/API discovery and alternate utilities | Extend the live parent branch; match discovery arguments; retain existing `ipconfig`/`arp` coverage | Review user, parent, adjacent discovery commands, remote logons, and maintenance context |
| T1021.002 SMB/Admin Shares | Deployment, backup, inventory, vulnerability scanning | Other remote-service protocols and access lacking process lineage | Match tested admin-share context; narrowly exclude known management systems | Confirm source/destination/account/share; correlate 5140/5145 and authentication; contain unauthorized access |
| T1047 WMI | Management agents, inventory, software deployment | WMI activity that does not spawn an interpreter; remote context not captured | Detect `WmiPrvSE.exe` spawning command/script interpreters | Review parent-child lineage, user, remote origin, command, hashes, and follow-on execution |
| T1053.005 Scheduled Task | Updaters, installers, management agents, maintenance | Modification/deletion and benign-looking actions outside interpreter list | Retain baseline task visibility; elevate interpreter-bearing task XML | Inspect task XML, principal, author, action, trigger, creator process; disable malicious task and preserve XML |
| T1057 Process Discovery | Help desk, monitoring, administration, IR tools | `Get-Process`, WMI, APIs, Task Manager, renamed binaries | Current image detection should expand to multiple enumeration paths and correlation | Confirm actor and parent; look for discovery clusters, remote logon, and credential access |
| T1059.001 PowerShell | Administrative automation and management scripts | PowerShell 7, encoded/obfuscated variants, in-memory APIs, missing script content | Anchor exact original filenames; separate baseline PowerShell from suspicious flags | Capture command/script block, parent, user, network and child activity; isolate if malicious execution is confirmed |
| T1078 Valid Accounts | RunAs, support, installers, scheduled tasks, automation | Credential use without 4648; token/cookie abuse; broad `svchost.exe` context | Extend the audit-success branch; exclude tested LSASS/consent paths; add identity and frequency context | Validate source/target identities, host, process, address, logon history; reset credentials and revoke sessions when compromised |
| T1082 System Information Discovery | Inventory, support, diagnostic scripts, installers | WMI/PowerShell/API collection and renamed tools | Match full `systeminfo.exe`/`hostname.exe` image; resolve duplicate Wazuh IDs | Review initiating user/parent and nearby discovery; escalate when paired with initial access or execution |
| T1087.001 Account Discovery | Help desk, audits, configuration management | Domain/cloud enumeration and API/PowerShell variants | Expand coverage across account-enumeration commands and correlate discovery bursts | Validate requester and business purpose; review subsequent group, privilege, and credential activity |
| T1105 Ingress Tool Transfer | Deployment, patching, approved downloads, build workflows | BITS, curl/wget, aliases, .NET clients, variables and fileless retrieval | Separate utility observation from file-output context; inherit PowerShell script-block hierarchy | Validate source reputation, destination, hash, parent/user; quarantine payload and block source when malicious |
| T1112 Modify Registry | Installers, session agents, update software, administration | Registry paths outside Sysmon scope; API changes without covered events | Scope to tested Run-key/interpreter branch; create separate analytics for other high-risk paths | Review key/value/data, modifying process/user, signature/hash; export evidence and revert unauthorized changes |
| T1218.011 Rundll32 | Control Panel, drivers, installers, vendor utilities | Other proxy binaries and untested Rundll32 syntax | Separate generic LOLBin visibility from elevated proxy-execution syntax | Inspect DLL/arguments, signature, parent, network and child activity; quarantine malicious content |
| T1547.001 Registry Run Keys | Updaters, user agents, cloud clients, approved startup software | Startup folders, services, scheduled tasks and uncovered registry paths | Reuse built-in Run-key branch; elevate interpreter-based values; narrow allowlists | Capture value/process/user, verify signer/hash and prevalence; remove unauthorized persistence and hunt fleetwide |
| T1552.001 Credentials in Files | Secret scanners, source audits, IR collections, admin searches | File access not proven; alternate tools, aliases, encodings and content APIs | Require credential-oriented keywords; enrich with paths/extensions and file/EDR telemetry | Identify searched paths and actor; determine whether secrets existed; rotate exposed credentials and review subsequent use |

## Lifecycle gates

1. **Design:** document the hypothesis, data source, expected benign activity, blind spots, severity, and response owner.
2. **Telemetry validation:** prove the endpoint record exists and reaches the manager archive before changing the analytic.
3. **Positive validation:** generate fresh benign activity and confirm the intended rule, fields, ATT&CK mapping, and evidence.
4. **Negative validation:** exercise a behaviorally similar control that retains comparable telemetry while omitting the elevated condition.
5. **Tuning:** record the observed problem, rule version, decision, expected effect, and validation results. Do not suppress an entire telemetry source to fix one false positive.
6. **Deployment:** preserve the rule artifact, owner, enablement date, severity, dependencies, and rollback path.
7. **Operations:** disposition alerts consistently and capture detection, triage, containment, and closure timestamps.
8. **Review:** reassess at least every 90 days and after decoder, ruleset, Sysmon, endpoint-policy, or threat-model changes.
9. **Retirement:** document replacement coverage, approval, effective date, and residual risk.

## Tuning decision record

Use this minimum record for every analytic change:

| Field | Required content |
|---|---|
| Detection ID and version | Stable identifier plus revision |
| Trigger | False positive, false negative, blind spot, decoder change, performance, or threat change |
| Evidence | Alert/event IDs, query window, affected hosts/users, and representative samples |
| Decision | Logic, severity, suppression, enrichment, or no-change decision |
| Risk | Expected false-negative and false-positive tradeoff |
| Test results | Fresh positive test and comparable negative control |
| Owner and date | Approver, implementer, deployment time, and next review |
| Rollback | Previous version and restoration steps |

## Response-action standard

| Stage | Required action | Evidence of completion |
|---|---|---|
| Triage | Confirm rule intent, event integrity, actor, asset, process lineage, command, and relevant ATT&CK context | Analyst disposition with supporting event IDs |
| Scope | Search for the same user, hash, command, source, destination, or persistence mechanism across the environment | Saved query and affected-asset list |
| Contain | Apply the least disruptive action appropriate to confidence and severity | Verified isolation, block, account control, or task/value removal |
| Eradicate | Remove malicious files, tasks, services, registry values, sessions, and compromised credentials | Post-action validation evidence |
| Recover | Restore service safely and monitor for recurrence | Health check and heightened-monitoring window |
| Improve | Update analytic, runbook, blind spots, and lessons learned | Versioned change with positive and negative test results |

## Data limitations and next measurement steps

- Current results come from a single-host lab and demonstrate functional validation, not production prevalence.
- Two earlier studies lack preserved negative controls; rerun T1057 and T1087 before claiming complete validation parity.
- Detection latency, analyst triage time, containment time, precision, and production false-positive rate require event-level operational timestamps and dispositions.
- Duplicate Wazuh rule IDs and order-dependent parent/child behavior identified in case studies should be remediated before using rule-level counts as authoritative operational metrics.
- Begin recording each future execution in [`detection-lifecycle-register.csv`](detection-lifecycle-register.csv), preserving historical rows rather than overwriting prior outcomes.

Coverage status is maintained in the [MITRE ATT&CK Coverage Matrix](../detections/MITRE-Matrix.md).
