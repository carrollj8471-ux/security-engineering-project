# MITRE ATT&CK Detection Engineering Case Study

> **Portfolio**
>
> Security Engineering Portfolio
>
> Project: Active Directory Attack & Defense Lab
>
> Case Study #: XX
>
> MITRE ATT&CK Technique: TXXXX
>
> Technique Name:
>
> Status:
> - [ ] Planned
> - [ ] In Progress
> - [ ] Complete

---

# Executive Summary

## Purpose

Briefly explain what this technique represents and why defenders should care.

**Example**

Attackers commonly perform process discovery immediately after gaining access to determine running security software, identify privileged applications, and understand the operating environment. This case study validates that Sysmon and Wazuh successfully detect process enumeration activity within the Active Directory lab.

---

# Learning Objectives

By completing this exercise I will:

- Understand the attacker technique
- Execute the technique safely
- Observe Windows telemetry
- Observe Sysmon telemetry
- Validate Wazuh detections
- Perform threat hunting
- Document incident response procedures

---

# MITRE ATT&CK Information

Technique ID:

```
TXXXX
```

Technique Name

```
Example:
Process Discovery
```

MITRE Tactic

```
Discovery
```

Official ATT&CK Description

*(Summarize in your own words rather than copying directly.)*

MITRE Reference

(Add the ATT&CK technique URL.)

---

# Lab Environment

| Component | Configuration |
|------------|--------------|
| Hypervisor | VMware Workstation |
| Domain | corp.local |
| Domain Controller | DC01 |
| Workstation | WIN11 |
| SIEM | Wazuh |
| Endpoint Telemetry | Sysmon |
| Domain User | Alice Johnson |
| Attacker | Atomic Red Team |

---

# Attack Scenario

Describe the scenario.

Example:

A threat actor has obtained code execution on a domain workstation and begins collecting information about the operating system before attempting privilege escalation.

---

# Detection Objective

Explain what you want your SOC to detect.

Example

Detect execution of:

- tasklist.exe
- systeminfo.exe
- net user
- whoami
- ipconfig

---

# Attack Simulation

## Tool Used

Example

Atomic Red Team

---

Technique

```
TXXXX
```

Test Number

```
#
```

---

## Command Executed

```powershell
<Insert PowerShell command>
```

---

## Why This Command Matters

Explain what the command does from an attacker perspective.

---

# Expected Windows Activity

Fill in before running.

Windows Event Logs

- [ ]

PowerShell Logs

- [ ]

Security Logs

- [ ]

Registry Changes

- [ ]

File Creation

- [ ]

Network Connections

- [ ]

Services

- [ ]

Scheduled Tasks

- [ ]

---

# Expected Sysmon Events

| Event ID | Description |
|----------|-------------|
| | |

Fill in:

Example

```
Event ID 1
Process Creation
```

---

# Detection Validation

## Did Sysmon Capture It?

Yes / No

Evidence

Describe what you observed.

---

## Did Wazuh Capture It?

Yes / No

Evidence

Describe the alert.

---

## Wazuh Rule

Fill in

Rule ID

```
```

Rule Level

```
```

Rule Description

```
```

MITRE Mapping

```
```

---

# Threat Hunting

Search Performed

```
agent.name:"WIN11"
```

Additional Queries

```
process.name:
```

```
event.code:
```

```
rule.id:
```

Document the queries you used.

---

# Timeline

| Time | Event |
|------|-------|
| | |

Example

```
19:21
Atomic test executed

19:21

Sysmon Event ID 1

19:22

Wazuh alert generated

19:23

Threat hunt performed
```

---

# Detection Analysis

Explain

- Why detection worked
- What telemetry was generated
- What the SOC analyst would investigate

---

# False Positives

Examples

Legitimate administrators

Software deployment

PowerShell automation

Remote management

Explain how you would differentiate legitimate activity from malicious activity.

---

# Incident Response

Document your response process.

Example

1. Validate user
2. Review parent process
3. Check command line
4. Investigate lateral movement
5. Review authentication logs
6. Determine impact

---

# Security Engineering Improvements

After completing this exercise, what could improve detection?

Examples

- Increase Sysmon coverage
- Enable PowerShell logging
- Deploy Sigma rules
- Improve Wazuh correlation
- Tune alert severity
- Forward additional logs

---

# Lessons Learned

What did you learn?

Examples

- Sysmon generated expected telemetry.
- Wazuh successfully parsed process creation.
- Detection occurred within one minute.
- Additional PowerShell logging would improve visibility.

---

# Evidence

## Screenshot 1

Atomic Red Team execution

Filename

```
01-atomic-test.png
```

---

## Screenshot 2

Sysmon Event Viewer

```
02-sysmon-event.png
```

---

## Screenshot 3

Wazuh Alert

```
03-wazuh-alert.png
```

---

## Screenshot 4

Threat Hunting

```
04-threat-hunting.png
```

---

## Screenshot 5

Timeline / Dashboard

```
05-dashboard.png
```

---

# References

Microsoft Documentation

Sysmon Documentation

MITRE ATT&CK

Atomic Red Team

Wazuh Documentation

---

# Portfolio Reflection

What engineering skills did this exercise demonstrate?

Examples

✔ Windows Administration

✔ Active Directory

✔ Detection Engineering

✔ Threat Hunting

✔ MITRE ATT&CK

✔ Incident Response

✔ SIEM Engineering

✔ Security Operations

✔ Documentation

✔ Continuous Improvement

---