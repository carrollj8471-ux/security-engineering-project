# MITRE ATT&CK Coverage Matrix

This matrix tracks implemented detection engineering coverage separately from planned work. A technique is marked **Validated** only when its case-study README contains a preserved positive-path result. Negative-control status is shown independently so evidence gaps remain visible.

## Portfolio snapshot

| Metric | Current state |
|---|---:|
| Techniques in scope | 25 |
| Completed case studies | 18 |
| Planned case studies | 7 |
| Completed studies with a preserved negative control | 16 |
| Completed studies with a documented negative-control gap | 2 |
| ATT&CK tactics represented by completed studies | 9 |

## Implemented coverage

| Tactic | Technique | Detection focus | Primary telemetry | Positive | Negative control | Rule artifact | Case study |
|---|---|---|---|---|---|---|---|
| Credential Access | T1003.001 | LSASS-style memory dumping | Sysmon 1; Sysmon 10 enrichment | Validated | Preserved | [XML](./T1003-LSASS-Credential-Dumping/detection-rules.xml) | [README](./T1003-LSASS-Credential-Dumping/README.md) |
| Discovery | T1007 | Service Discovery | Sysmon 1 | Validated | Preserved | Hunt/analytic documented | [README](./T1007-Service-Discovery/README.md) |
| Discovery | T1016 | System Network Configuration Discovery | Sysmon 1 | Validated | Preserved | Hunt/analytic documented | [README](./T1016-Network-Discovery/README.md) |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | Security 5140/5145; Sysmon 1 | Validated | Preserved | Hunt/analytic documented | [README](./T1021-Remote-Services/README.md) |
| Execution | T1047 | Windows Management Instrumentation | Sysmon 1 | Validated | Preserved | [XML](./T1047-WMI/detection-rules.xml) | [README](./T1047-WMI/README.md) |
| Execution, Persistence, Privilege Escalation | T1053.005 | Scheduled Task/Job | Sysmon 1; Task Scheduler telemetry | Validated | Preserved | [XML](./T1053-Scheduled-Task/detection-rules.xml) | [README](./T1053-Scheduled-Task/README.md) |
| Discovery | T1057 | Process Discovery | Sysmon 1 | Validated | Gap documented | Hunt/analytic documented | [README](./T1057-Process-Discovery/README.md) |
| Execution | T1059.001 | PowerShell | Sysmon 1; Security 4688 | Validated | Preserved | Wazuh rule documented | [README](./T1059.001-PowerShell/README.md) |
| Initial Access, Persistence, Privilege Escalation, Defense Evasion | T1078 | Explicit credential use/valid accounts | Security 4624/4648 | Validated | Preserved | [XML](./T1078-Valid-Accounts/detection-rules.xml) | [README](./T1078-Valid-Accounts/README.md) |
| Discovery | T1082 | System Information Discovery | Sysmon 1 | Validated | Preserved | [XML](./T1082-System-Information-Discovery/detection-rules.xml) | [README](./T1082-System-Information-Discovery/README.md) |
| Discovery | T1087.001 | Local Account Discovery | Sysmon 1 | Validated | Gap documented | Hunt/analytic documented | [README](./T1087-Account-Discovery/README.md) |
| Command and Control | T1105 | Ingress Tool Transfer | Sysmon 1/3/11 | Validated | Preserved | Hunt/analytic documented | [README](./T1105-Ingress-Tool-Transfer/README.md) |
| Defense Evasion | T1112 | Modify Registry | Sysmon 12/13 | Validated | Preserved | [XML](./T1112-Modify-Registry/detection-rules.xml) | [README](./T1112-Modify-Registry/README.md) |
| Privilege Escalation, Defense Evasion | T1548.002 | Bypass User Account Control | Sysmon 1/13; Security 4688 | Validated | Preserved | [XML](./T1548-UAC-Bypass/detection-rules.xml) | [README](./T1548-UAC-Bypass/README.md) |
| Defense Evasion | T1218.011 | Rundll32 Proxy Execution | Sysmon 1 | Validated | Preserved | Wazuh rule documented | [README](./T1218-Signed-Binary-Proxy-Execution/README.md) |
| Persistence, Privilege Escalation | T1547.001 | Registry Run Keys/Startup Folder | Sysmon 13 | Validated | Preserved | [XML](./T1547-Registry-Run-Keys/detection-rules.xml) | [README](./T1547-Registry-Run-Keys/README.md) |
| Credential Access | T1552.001 | Credentials in Files | Sysmon 1 | Validated | Preserved | [XML](./T1552-Credentials-in-Files/detection-rules.xml) | [README](./T1552-Credentials-in-Files/README.md) |
| Defense Evasion | T1562.001 | Impair Defenses | Sysmon 1; Defender 5007 | Validated | Preserved | [XML](./T1562-Impair-Defenses/detection-rules.xml) | [README](./T1562-Impair-Defenses/README.md) |

## Planned coverage and priorities

Planned rows are not counted as implemented detection coverage. Priority reflects portfolio value and the importance of closing current tactic gaps.

| Priority | Tactic | Technique | Planned focus | Target telemetry | Status |
|---|---|---|---|---|---|
| P1 | Defense Evasion | T1070 | Indicator Removal | Security 1102; Sysmon 23/26; PowerShell | Planned |
| P1 | Impact | T1486 | Data Encrypted for Impact | Sysmon 1/11/23; file-change telemetry | Planned |
| P1 | Credential Access | T1555 | Credentials from Password Stores | Sysmon 1/10; Defender | Planned |
| P2 | Discovery | T1049 | System Network Connections Discovery | Sysmon 1; PowerShell | Planned |
| P2 | Discovery | T1083 | File and Directory Discovery | Sysmon 1; PowerShell | Planned |
| P2 | Execution | T1106 | Native API | Sysmon process/access telemetry; ETW where available | Planned |
| P2 | Defense Evasion, Discovery | T1497 | Virtualization/Sandbox Evasion | Sysmon 1; WMI/registry telemetry | Planned |

## Tactic-level view

Because a technique can map to multiple tactics, totals below are non-exclusive.

| ATT&CK tactic | Validated techniques | Planned techniques | Coverage observation |
|---|---:|---:|---|
| Initial Access | 1 | 0 | Valid-account coverage only; best demonstrated in an attack chain. |
| Execution | 3 | 1 | Strong Windows execution coverage across PowerShell, WMI, and scheduled tasks. |
| Persistence | 3 | 0 | Valid accounts, scheduled tasks, and Run keys are represented. |
| Privilege Escalation | 4 | 0 | Behavioral coverage plus a validated UAC-bypass study; this tactic is well represented. |
| Defense Evasion | 5 | 2 | Impair-defenses, registry modification, Rundll32, and UAC bypass are validated; log clearing remains the priority gap. |
| Credential Access | 2 | 1 | File-search and LSASS-style dump coverage are validated; password-store telemetry remains planned. |
| Discovery | 5 | 3 | Mature coverage; additional discovery studies have lower marginal portfolio value. |
| Lateral Movement | 1 | 0 | SMB is covered, but an end-to-end remote-services chain would improve depth. |
| Command and Control | 1 | 0 | Ingress transfer is covered; network analytics remain a potential expansion. |
| Impact | 0 | 1 | No validated impact technique yet; a safe ransomware simulation is the clearest gap. |

## Coverage criteria

- **Validated:** a reproducible benign simulation generated endpoint telemetry and a preserved Wazuh detection or hunt result.
- **Preserved negative control:** a similar benign action was tested and evidence shows the detection-specific condition did not alert.
- **Gap documented:** the positive result exists, but a separate negative-control artifact was not preserved; this is not treated as a negative-test pass.
- **Planned:** a directory or roadmap entry exists, but no completed README supports a coverage claim.

## Recommended next milestone

Complete T1070 and T1486, then build one correlated attack-chain study spanning initial access, execution, credential access, lateral movement, defense evasion, and impact. This produces more portfolio value than completing every remaining discovery technique.
