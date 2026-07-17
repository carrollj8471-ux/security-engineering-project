# Atomic Red Team Runbook

## Purpose

This runbook standardizes safe Atomic Red Team execution for the detection engineering case studies.

## Safety Rules

- Run tests only on lab systems.
- Start with WIN11, not DC01.
- Take a VMware snapshot before testing.
- Review each test with `-ShowDetailsBrief` before execution.
- Run one test at a time.
- Capture screenshots immediately after each test.
- Run cleanup when the test supports it.

## PowerShell Setup

Run as Administrator on WIN11:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module Invoke-AtomicRedTeam -Force
$AtomicsPath = "C:\AtomicRedTeam\atomics"
Test-Path $AtomicsPath
```

## Standard Test Workflow

```powershell
Invoke-AtomicTest T1082 -PathToAtomicsFolder $AtomicsPath -ShowDetailsBrief
```

```powershell
Invoke-AtomicTest T1082 -PathToAtomicsFolder $AtomicsPath -TestNumbers 1 -CheckPrereqs
```

```powershell
Invoke-AtomicTest T1082 -PathToAtomicsFolder $AtomicsPath -TestNumbers 1
```

```powershell
Invoke-AtomicTest T1082 -PathToAtomicsFolder $AtomicsPath -TestNumbers 1 -Cleanup
```

## Recommended Starting Sequence

| Order | Technique | Purpose |
|---:|---|---|
| 1 | T1082 | System information discovery |
| 2 | T1057 | Process discovery |
| 3 | T1087.001 | Local account discovery |
| 4 | T1007 | Service discovery |
| 5 | T1016 | Network configuration discovery |
| 6 | T1033 | User discovery |
| 7 | T1059.001 | PowerShell execution |

## Wazuh Validation

After each test, search Wazuh Threat Hunting:

```text
agent.name:"WIN11"
```

Narrow the time range to the last 15 minutes and search for the executed command, such as:

```text
systeminfo.exe
```

or:

```text
tasklist.exe
```

## Evidence Checklist

- Atomic Red Team command and output
- Sysmon Event Viewer entry
- Wazuh Threat Hunting result
- Rule ID or event document fields
- ATT&CK technique mapping
- Short analyst conclusion
