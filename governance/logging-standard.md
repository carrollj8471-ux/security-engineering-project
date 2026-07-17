# Security Logging Standard

## Purpose and Scope

This standard defines minimum security telemetry for Windows, Linux, identity, network, cloud, and security platforms in the lab program. Production adoption requires capacity planning, privacy review, and system-owner approval.

## Minimum Sources

| Source | Required telemetry |
|---|---|
| Windows | Security, System, Application, Sysmon Operational, PowerShell Operational |
| Active Directory | authentication, account lifecycle, group changes, policy changes, directory-service events |
| Linux | authentication, sudo, system service, package, audit, and security-tool logs |
| Wazuh | agent status, archives, alerts, manager/API errors, rule-validation output |
| Network | DNS, firewall allow/deny, VPN, proxy, and remote-administration events where available |
| Cloud/SaaS | identity, administrative, control-plane, authentication, and configuration changes |

## Event Requirements

Logs must include a synchronized timestamp with time zone, source host, user or service identity, event/action, result, and relevant source/destination context. Endpoint process telemetry should preserve image, command line, parent process, hashes, process identifiers, integrity level, and user context when available.

## Collection and Monitoring

- Critical sources forward to the central security platform.
- Collection health is monitored for missing agents, stale timestamps, parsing failures, and volume anomalies.
- Raw telemetry and alerts are treated separately; successful collection does not prove detection.
- Rule changes require backup, validation, controlled restart, and a fresh test event.
- Clock synchronization is required across endpoints, identity services, and collectors.

## Retention

| Data class | Minimum lab target |
|---|---:|
| Searchable security alerts | 90 days |
| Raw security telemetry | 30 days or available capacity |
| Incident evidence and exported alerts | Life of case plus one year |
| Administrative and rule-change records | One year |

Production retention must reflect legal, contractual, privacy, investigation, and cost requirements.

## Access and Integrity

Access is role-based and limited to authorized administrators and analysts. Logs must not be edited to alter evidentiary meaning. Exported evidence should use hashes or repository history where practical, and administrative access should itself be logged.

## Sensitive Data

Avoid collecting secrets, tokens, or unnecessary personal data. Review screenshots and exports for private IP addresses, usernames, domains, and identifiers before public publication.

## Exceptions and Review

Exceptions require documented scope, business justification, compensating controls, owner, approval, and expiration. Review this standard annually and after material architecture or regulatory change.
