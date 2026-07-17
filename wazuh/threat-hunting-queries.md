# Wazuh Threat Hunting Queries

## Purpose

Use these queries while validating the MITRE ATT&CK case studies. Adjust field names as needed based on the Wazuh version and index mapping in your lab.

## Agent Health

```text
agent.name:"WIN11"
```

```text
agent.name:"DC01"
```

## Sysmon Process Creation

```text
agent.name:"WIN11" AND rule.groups:"sysmon" AND event.code:1
```

```text
agent.name:"WIN11" AND data.win.system.eventID:1
```

## Discovery Commands

```text
agent.name:"WIN11" AND process.name:(systeminfo.exe OR tasklist.exe OR whoami.exe OR ipconfig.exe OR netstat.exe)
```

```text
agent.name:"WIN11" AND process.command_line:(*systeminfo* OR *tasklist* OR *Get-Process* OR *Get-Service*)
```

## PowerShell Activity

```text
agent.name:"WIN11" AND process.name:(powershell.exe OR pwsh.exe)
```

```text
agent.name:"WIN11" AND process.command_line:(*EncodedCommand* OR *ExecutionPolicy* OR *DownloadString* OR *Invoke-WebRequest*)
```

## Account and Group Changes

```text
agent.name:"DC01" AND data.win.system.eventID:(4720 OR 4722 OR 4726 OR 4728 OR 4732 OR 4756)
```

```text
agent.name:"DC01" AND rule.description:*group*
```

## Failed Logons

```text
agent.name:("DC01" OR "WIN11") AND data.win.system.eventID:4625
```

```text
agent.name:("DC01" OR "WIN11") AND rule.description:*failed* AND rule.description:*logon*
```

## Registry Persistence

```text
agent.name:"WIN11" AND event.code:13 AND registry.path:*CurrentVersion\\Run*
```

```text
agent.name:"WIN11" AND process.name:reg.exe AND process.command_line:*CurrentVersion\\Run*
```

## Tool Transfer

```text
agent.name:"WIN11" AND process.name:(bitsadmin.exe OR certutil.exe OR curl.exe OR powershell.exe)
```

```text
agent.name:"WIN11" AND process.command_line:(*http://* OR *https://* OR *DownloadFile* OR *Invoke-WebRequest*)
```

## Investigation Notes

For each result, capture:

- agent name
- timestamp
- user
- process name
- parent process
- command line
- rule ID and rule level
- ATT&CK technique
- screenshot path
