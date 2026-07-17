# Sysmon Event Reference

## Purpose

This reference maps the Sysmon events used in the detection case studies to their investigation value.

| Event ID | Event | Investigation Value |
|---:|---|---|
| 1 | Process Create | Core source for process name, command line, parent process, user, hashes, and execution chain |
| 3 | Network Connection | Helps identify tool transfer, command and control, and unusual outbound activity |
| 7 | Image Loaded | Useful for suspicious DLL loading and signed binary proxy execution investigations |
| 10 | Process Access | Useful for LSASS access and credential access investigations |
| 11 | File Create | Captures staging, drops, test artifacts, and suspicious file writes |
| 12 | Registry Object Created or Deleted | Tracks persistence and tampering paths |
| 13 | Registry Value Set | Tracks Run keys, UAC-related changes, and security configuration changes |
| 22 | DNS Query | Helps identify suspicious lookup activity and tool transfer destinations |

## Validation Commands

Run on WIN11 or DC01 in PowerShell:

```powershell
Get-Service Sysmon
```

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

## Wazuh Collection Requirement

Confirm the Windows agent configuration includes:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent after changes:

```powershell
Restart-Service WazuhSvc
```

## Case Study Evidence

- event ID
- image
- command line
- parent image
- user
- UTC timestamp
- process GUID
- host name
