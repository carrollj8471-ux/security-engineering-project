# Incident Response Workflow

## Purpose

This workflow standardizes how alerts from the detection engineering lab are reviewed and documented.

## SOC Triage Flow

1. Confirm the alert source, host, user, and timestamp.
2. Review process image, command line, parent process, and integrity level.
3. Check whether the activity came from approved administration, automation, or lab testing.
4. Search for related discovery, credential access, persistence, defense evasion, or lateral movement.
5. Assign severity and priority based on technique, user context, and event chain.
6. Document containment, eradication, and recovery recommendations.
7. Attach screenshots and raw event details to the case study.

## Escalation Guidance

Escalate immediately for credential dumping, security tool tampering, ransomware simulation outside the approved test path, suspicious remote service execution, or activity involving privileged accounts.

## Evidence Standard

Every investigation should preserve Wazuh query results, Sysmon event details, command line evidence, affected user, affected host, and a short conclusion.
