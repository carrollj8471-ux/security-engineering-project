# Enterprise Security Baseline

## Objective

Establish a measurable minimum control set for systems represented in the security engineering portfolio. The baseline aligns conceptually with CIS Controls, Microsoft security baselines, NIST CSF, and ISO/IEC 27001; it does not claim certification.

## Baseline Controls

| Domain | Minimum requirement | Evidence |
|---|---|---|
| Asset management | Owner, purpose, environment, criticality, and supported OS recorded | inventory or architecture record |
| Identity | Unique accounts, least privilege, separate admin access, timely disablement | directory exports and access review |
| Authentication | MFA where supported; strong password and lockout settings | policy export and test |
| Endpoint | Supported OS, host firewall, antimalware, secure configuration | baseline scan and screenshots |
| Logging | Required sources collected centrally with synchronized time | Wazuh health and sample events |
| Detection | Priority behaviors mapped to ATT&CK and validated | case study, rule, positive/negative evidence |
| Vulnerability | Authenticated scanning, risk prioritization, SLA tracking | findings and remediation backlog |
| Patching | Critical security updates prioritized and exceptions documented | patch status and change evidence |
| Data protection | Sensitive data identified, access controlled, encrypted where appropriate | configuration and access evidence |
| Recovery | Backups protected and restoration tested | backup and recovery-test record |
| Change control | Security-relevant changes reviewed, tested, and reversible | repository history and approvals |

## Severity and Remediation

Baseline failures enter the risk register and remediation backlog. Critical and High failures follow the remediation SLA policy. Exceptions must be time-bound and include compensating controls.

## Validation

Controls are not considered implemented solely because a setting is documented. Validation requires current evidence, expected-result testing, and an accountable reviewer. Revalidate after major changes and at least annually.

## Lab-Specific Limitations

The lab uses single-instance infrastructure and private networking for learning. High availability, enterprise backup, certificate lifecycle, privacy governance, and production-scale retention are documented as design considerations rather than fully implemented controls.
