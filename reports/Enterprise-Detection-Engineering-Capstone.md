# Enterprise Detection Engineering Capstone

## Executive Summary

This capstone summarizes a Windows Active Directory detection engineering portfolio built around Sysmon, Wazuh, controlled simulations, and MITRE ATT&CK. The portfolio documents 25 ATT&CK-aligned techniques across discovery, execution, credential access, persistence, privilege escalation, lateral movement, defense evasion, command and control, and impact. Individual techniques are described as validated only when current positive telemetry, alert evidence, ATT&CK enrichment, and required control testing are present.

## Lab Architecture

Telemetry originates on Windows endpoints, is collected by Sysmon and Windows Event Logs, forwarded by the Wazuh Agent, indexed by the Wazuh Manager, and reviewed through threat hunting and analyst investigation workflows.

Detailed architecture: [Detection Engineering Lab Architecture](../architecture/detection-engineering-lab-architecture.md)

~~~mermaid
flowchart LR
    A["Windows Endpoint"] --> B["Sysmon and Windows Logs"]
    B --> C["Wazuh Agent"]
    C --> D["Wazuh Manager"]
    D --> E["Threat Hunting"]
    E --> F["SOC Investigation"]
    F --> G["Metrics and Executive Reporting"]
~~~

## Detection Coverage by ATT&CK Tactic

| ATT&CK Tactic | Techniques Documented | Portfolio Status |
|---|---:|---|
| Discovery | 8 | Documented; validation evidence varies by case study |
| Execution | 3 | Documented; T1047 and T1059.001 include detailed validation evidence |
| Credential Access | 3 | Documented; verify evidence before claiming validated coverage |
| Persistence | 1 | Documented; verify evidence before claiming validated coverage |
| Privilege Escalation | 1 | Documented; verify evidence before claiming validated coverage |
| Lateral Movement | 1 | Documented; verify evidence before claiming validated coverage |
| Defense Evasion | 6 | Documented; verify evidence before claiming validated coverage |
| Command and Control | 1 | Documented; verify evidence before claiming validated coverage |
| Impact | 1 | Documented; verify evidence before claiming validated coverage |

## Detection Success Criteria

The scorecard status `Documented` indicates that a case-study artifact exists. It is not equivalent to telemetry-confirmed or alert-validated coverage.

| Criterion | Target |
|---|---|
| Endpoint telemetry generated | Yes |
| Wazuh event indexed | Yes |
| ATT&CK mapping documented | Yes |
| Analyst workflow documented | Yes |
| Evidence captured | Required per case study |
| Time to detect | Less than 60 seconds |

Scorecard: [Detection Validation Scorecard](./detection-validation-scorecard.csv)

Operational artifacts:

- [Wazuh Threat Hunting Queries](../wazuh/threat-hunting-queries.md)
- [Example Wazuh Local Rules](../wazuh/local_rules.xml)
- [Sysmon Event Reference](../sysmon/event-reference.md)
- [Atomic Red Team Runbook](../powershell/atomic-red-team-runbook.md)

## Detection Gaps to Track

- Promote the example Wazuh rules into production-quality rules after repeated validation.
- Add Sigma equivalents for portability.
- Capture screenshots for every report.
- Add false-positive notes after multiple validation cycles.
- Add endpoint coverage metrics once additional hosts are onboarded.
- Reclassify each technique using consistent states: Planned, Documented, Telemetry Confirmed, Alert Validated, Tuned, or Retired.
- Resolve duplicate local Wazuh rule IDs `100201`–`100210` and invalid group references affecting `100212` and `100214`.

## Recommendations

1. Deploy Sysmon through Group Policy or endpoint management.
2. Enable PowerShell Script Block Logging and process command-line auditing.
3. Convert validated logic into Wazuh rules and Sigma detections.
4. Review ATT&CK coverage monthly with security operations stakeholders.
5. Add SOAR enrichment for host, user, and threat intelligence context.
6. Maintain a detection backlog that prioritizes credential access, defense evasion, and lateral movement.

## Security Engineering Management Value

This portfolio demonstrates more than tool deployment. It shows how technical telemetry becomes measurable detection coverage, how ATT&CK creates a shared operating language, and how SOC investigation, risk tracking, metrics, and executive reporting can be tied into one security engineering program.
