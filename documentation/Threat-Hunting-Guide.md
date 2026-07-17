# Threat Hunting Guide

## Core Hunts

Use these searches as starting points during validation:

~~~text
agent.name:"WIN11" AND rule.groups:"sysmon"
event.code:1 AND process.parent.name:powershell.exe
event.code:1 AND process.command_line:*EncodedCommand*
event.code:1 AND process.name:(systeminfo.exe OR tasklist.exe OR whoami.exe OR net.exe)
event.code:13 AND registry.path:*CurrentVersion\\Run*
~~~

## Hunting Questions

- Which user launched the command?
- What parent process created it?
- Did the activity occur after suspicious execution?
- Did the host also show credential access, defense evasion, or remote service usage?
- Is this behavior expected for the user's role?

## Output

Each hunt should produce a short conclusion, a screenshot, and a decision: expected activity, suspicious activity, confirmed malicious simulation, or detection gap.
