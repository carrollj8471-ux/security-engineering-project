# Failed Logon Investigation Playbook

## Purpose

Guide repeatable triage of Windows failed-logon activity, primarily Security Event ID `4625`, while distinguishing user error and stale credentials from password spraying, brute force, and compromised-account activity.

## Trigger and Severity

| Condition | Initial severity |
|---|---|
| Isolated failure from expected host | Informational/Low |
| Repeated failures for one user | Medium |
| One source targeting many users | High — possible password spray |
| Privileged account, external source, or success after failures | High/Critical |
| Failures paired with lockout Event ID `4740` | Medium/High depending on scope |

## Required Fields

- event time and time zone;
- target user and domain;
- source workstation and IP address;
- logon type and authentication package;
- status/substatus or failure reason;
- process name and caller context when present;
- nearby successful logons (`4624`), explicit credentials (`4648`), and lockouts (`4740`).

## Triage Procedure

1. Confirm the event is genuine Windows Security telemetry and identify the affected host.
2. Normalize the time window and count failures by source, user, and destination.
3. Determine whether the source is an expected endpoint, server, scanner, VPN, or management system.
4. Review the failure reason for bad password, unknown user, disabled account, expired credential, or policy restriction.
5. Search for successful authentication after the failures.
6. Check whether the user recently changed a password or has a service, task, drive mapping, or mobile client using stale credentials.
7. Determine whether privileged accounts or multiple accounts were targeted.
8. Assign disposition and document evidence.

## Wazuh Hunting Examples

```text
agent.name:"WIN11" AND data.win.system.eventID:"4625"
```

```text
data.win.system.eventID:"4625" AND data.win.eventdata.targetUserName:"USERNAME"
```

```text
(data.win.system.eventID:"4625" OR data.win.system.eventID:"4624") AND data.win.eventdata.targetUserName:"USERNAME"
```

Field names can differ by decoder version; confirm them in an expanded event before finalizing saved queries.

## Containment

Contain only when evidence supports malicious or materially risky activity:

- block or isolate the confirmed malicious source;
- disable or restrict the affected account;
- revoke sessions and reset credentials through an approved channel;
- require MFA re-registration if compromise is suspected;
- preserve endpoint, identity, VPN, firewall, and Wazuh evidence.

Avoid disabling business-critical or service accounts without an impact assessment and owner coordination.

## Eradication and Recovery

Remove malicious persistence or tools, correct stale credentials, rotate exposed secrets, patch exploited systems, restore access after verification, and monitor for recurrence. Confirm that legitimate services resume without repeated failures.

## Escalation Criteria

Escalate when failures target privileged accounts, originate externally, span multiple accounts or hosts, lead to a successful logon, coincide with suspicious process activity, or cannot be explained by an approved business process.

## Closure Evidence

- relevant event JSON and queries;
- timeline and affected identities/assets;
- source validation and failure reason;
- successful-logon and lockout review;
- containment and credential actions;
- final disposition, owner, and lessons learned.
