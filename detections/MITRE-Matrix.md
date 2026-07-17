# MITRE ATT&CK Detection Matrix

This matrix tracks the detection engineering case studies included in this portfolio. Each folder contains a repeatable validation report with simulation steps, telemetry expectations, Wazuh hunting guidance, incident response actions, metrics, and screenshot placeholders.

| Tactic | Technique | Name | Case Study | Severity | Priority |
|---|---|---|---|---|---|
| Discovery | T1082 | System Information Discovery | [T1082-System-Information-Discovery](./T1082-System-Information-Discovery/) | Medium | P2 |
| Discovery | T1057 | Process Discovery | [T1057-Process-Discovery](./T1057-Process-Discovery/) | Medium | P2 |
| Discovery | T1087 | Account Discovery | [T1087-Account-Discovery](./T1087-Account-Discovery/) | Medium | P2 |
| Discovery | T1007 | Service Discovery | [T1007-Service-Discovery](./T1007-Service-Discovery/) | Medium | P2 |
| Discovery | T1016 | Network Discovery | [T1016-Network-Discovery](./T1016-Network-Discovery/) | Medium | P2 |
| Discovery | T1033 | System Owner/User Discovery | [T1033-User-Discovery](./T1033-User-Discovery/) | Low | P3 |
| Discovery | T1049 | System Network Connections Discovery | [T1049-Network-Connections](./T1049-Network-Connections/) | Medium | P2 |
| Discovery | T1083 | File and Directory Discovery | [T1083-File-Discovery](./T1083-File-Discovery/) | Medium | P2 |
| Execution | T1059.001 | PowerShell | [T1059.001-PowerShell](./T1059.001-PowerShell/) | High | P1 |
| Execution | T1106 | Native API | [T1106-Native-API](./T1106-Native-API/) | High | P1 |
| Defense Evasion | T1218 | Signed Binary Proxy Execution | [T1218-Signed-Binary-Proxy-Execution](./T1218-Signed-Binary-Proxy-Execution/) | High | P1 |
| Credential Access | T1003.001 | LSASS Memory | [T1003-LSASS-Credential-Dumping](./T1003-LSASS-Credential-Dumping/) | Critical | P1 |
| Credential Access | T1552 | Unsecured Credentials | [T1552-Credentials-in-Files](./T1552-Credentials-in-Files/) | High | P1 |
| Credential Access | T1555 | Credentials from Password Stores | [T1555-Credentials-from-Password-Stores](./T1555-Credentials-from-Password-Stores/) | High | P1 |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | [T1547-Registry-Run-Keys](./T1547-Registry-Run-Keys/) | High | P1 |
| Privilege Escalation | T1548.002 | Bypass User Account Control | [T1548-UAC-Bypass](./T1548-UAC-Bypass/) | High | P1 |
| Lateral Movement | T1021 | Remote Services | [T1021-Remote-Services](./T1021-Remote-Services/) | High | P1 |
| Defense Evasion, Persistence, Privilege Escalation, Initial Access | T1078 | Valid Accounts | [T1078-Valid-Accounts](./T1078-Valid-Accounts/) | High | P1 |
| Defense Evasion | T1562 | Impair Defenses | [T1562-Impair-Defenses](./T1562-Impair-Defenses/) | Critical | P1 |
| Defense Evasion | T1070 | Indicator Removal | [T1070-Indicator-Removal](./T1070-Indicator-Removal/) | High | P1 |
| Command and Control | T1105 | Ingress Tool Transfer | [T1105-Ingress-Tool-Transfer](./T1105-Ingress-Tool-Transfer/) | High | P1 |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | [T1497-Virtualization-Checks](./T1497-Virtualization-Checks/) | Medium | P2 |
| Impact | T1486 | Data Encrypted for Impact | [T1486-Data-Encrypted-for-Impact](./T1486-Data-Encrypted-for-Impact/) | Critical | P1 |
| Defense Evasion | T1112 | Modify Registry | [T1112-Modify-Registry](./T1112-Modify-Registry/) | High | P1 |
| Execution | T1047 | Windows Management Instrumentation | [T1047-WMI](./T1047-WMI/) | High | P1 |

## Coverage Summary

| ATT&CK Area | Techniques Included |
|---|---:|
| Discovery | 8 |
| Execution | 3 |
| Credential Access | 3 |
| Persistence | 1 |
| Privilege Escalation | 1 |
| Lateral Movement | 1 |
| Defense Evasion | 6 |
| Command and Control | 1 |
| Impact | 1 |

## Operating Model

The portfolio is designed to be updated as screenshots, rule files, and false-positive notes are added. A mature version of the matrix should include owner, last validation date, detection status, rule link, false-positive disposition, and coverage gap notes.
