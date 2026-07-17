$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$detectionsRoot = Join-Path $repoRoot "detections"
$documentationRoot = Join-Path $repoRoot "documentation"
$reportsRoot = Join-Path $repoRoot "reports"
$supportRoots = @("wazuh", "sysmon", "powershell", "incident-response")

New-Item -ItemType Directory -Force -Path $detectionsRoot, $documentationRoot, $reportsRoot | Out-Null
foreach ($root in $supportRoots) {
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $root) | Out-Null
}

$environment = @"
| Component | Configuration |
|---|---|
| Hypervisor | VMware Workstation |
| Domain Controller | Windows Server 2022 |
| Workstation | Windows 11 Enterprise |
| Domain | corp.local |
| SIEM | Wazuh 4.x |
| Endpoint Telemetry | Sysmon |
| Endpoint Logs | Windows Event Logs and PowerShell Operational |
"@

$techniques = @(
    [ordered]@{ Id="T1082"; Name="System Information Discovery"; Folder="T1082-System-Information-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1082 -PathToAtomicsFolder C:\AtomicRedTeam\atomics -TestNumbers 1"; Commands=@("systeminfo.exe","hostname.exe","wmic computersystem get domain,name,model,manufacturer","Get-ComputerInfo"); Logic="Alert when a standard user or unexpected parent process launches system inventory utilities that reveal host, OS, hardware, or domain details."; Impact="System inventory helps adversaries select privilege escalation paths, compatible payloads, and follow-on discovery actions." },
    [ordered]@{ Id="T1057"; Name="Process Discovery"; Folder="T1057-Process-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1057 -PathToAtomicsFolder C:\AtomicRedTeam\atomics -TestNumbers 1"; Commands=@("tasklist.exe","Get-Process","wmic process list brief","powershell.exe -Command Get-Process"); Logic="Alert on process enumeration from shells, scripts, Office child processes, or other unusual parents."; Impact="Process discovery allows adversaries to identify EDR, backup software, privileged services, and targets for injection or dumping." },
    [ordered]@{ Id="T1087"; Name="Account Discovery"; Folder="T1087-Account-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1087 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("whoami /all","net user","net user /domain","Get-LocalUser"); Logic="Alert when account enumeration occurs from non-administrative workstations or after suspicious process execution."; Impact="Account discovery helps adversaries identify privileged users, service accounts, and targets for lateral movement." },
    [ordered]@{ Id="T1007"; Name="Service Discovery"; Folder="T1007-Service-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1007 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("sc.exe query","net start","Get-Service","wmic service list brief"); Logic="Alert on service inventory commands launched by shells, scripts, or remote execution tooling."; Impact="Service discovery helps adversaries identify security controls, persistence options, and high-value services." },
    [ordered]@{ Id="T1016"; Name="Network Discovery"; Folder="T1016-Network-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1016 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("ipconfig /all","route print","arp -a","netsh interface show interface"); Logic="Alert on network configuration enumeration from unusual users, processes, or newly compromised hosts."; Impact="Network discovery helps adversaries understand subnets, gateways, adapters, and paths for lateral movement." },
    [ordered]@{ Id="T1033"; Name="System Owner/User Discovery"; Folder="T1033-User-Discovery"; Tactic="Discovery"; Severity="Low"; Priority="P3"; Simulation="Invoke-AtomicTest T1033 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("whoami","echo %USERNAME%","query user",'$env:USERNAME'); Logic="Alert when user discovery appears in a sequence with execution, credential access, or lateral movement signals."; Impact="User context helps adversaries determine privilege level and decide whether to escalate or move laterally." },
    [ordered]@{ Id="T1049"; Name="System Network Connections Discovery"; Folder="T1049-Network-Connections"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1049 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("netstat -ano","Get-NetTCPConnection","net use","net session"); Logic="Alert on connection enumeration from suspicious parents or when followed by remote service activity."; Impact="Connection discovery reveals active sessions, listening services, and potential lateral movement targets." },
    [ordered]@{ Id="T1083"; Name="File and Directory Discovery"; Folder="T1083-File-Discovery"; Tactic="Discovery"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1083 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("dir C:\Users","tree /f","Get-ChildItem -Recurse","where /r C:\ *.kdbx"); Logic="Alert on broad recursive listing, sensitive extension searches, or discovery from unusual process ancestry."; Impact="File discovery helps adversaries locate sensitive data, credentials, source code, and staging locations." },
    [ordered]@{ Id="T1059.001"; Name="PowerShell"; Folder="T1059.001-PowerShell"; Tactic="Execution"; Severity="High"; Priority="P1"; Simulation="Run the approved Atomic Red Team T1059.001 test in an isolated lab."; Commands=@("powershell.exe with a lab-safe execution-policy test","powershell.exe with a benign encoded test string","pwsh.exe running an approved lab script","PowerShell web request to an internal test file"); Logic="Alert on encoded commands, execution policy bypass, download cradles, suspicious parent processes, or script block indicators."; Impact="PowerShell provides flexible execution, discovery, defense evasion, download, and post-exploitation capability." },
    [ordered]@{ Id="T1106"; Name="Native API"; Folder="T1106-Native-API"; Tactic="Execution"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1106 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("rundll32.exe","regsvr32.exe","custom loader invoking Win32 APIs","PowerShell Add-Type API calls"); Logic="Alert on suspicious Windows API execution patterns, especially when paired with injection, unsigned binaries, or LOLBin parents."; Impact="Native API use can bypass command-line focused detections and enable injection, evasion, and stealthy execution." },
    [ordered]@{ Id="T1218"; Name="Signed Binary Proxy Execution"; Folder="T1218-Signed-Binary-Proxy-Execution"; Tactic="Defense Evasion"; Severity="High"; Priority="P1"; Simulation="Run the approved Atomic Red Team T1218 test in an isolated lab."; Commands=@("signed Windows binary loading a benign lab DLL","signed Windows binary opening an internal lab script","HTML application handler with a benign test page","installer utility launching a harmless test executable"); Logic="Alert on signed Microsoft binaries executing scripts, remote content, unusual DLL exports, or user-writable paths."; Impact="Proxy execution can make malicious activity appear trusted and bypass application control assumptions." },
    [ordered]@{ Id="T1003.001"; Name="LSASS Memory"; Folder="T1003-LSASS-Credential-Dumping"; Tactic="Credential Access"; Severity="Critical"; Priority="P1"; Simulation="Run only a safe, approved credential-access simulation in an isolated lab."; Commands=@("approved LSASS access simulation using benign test tooling","controlled dump-like file creation in a test directory","credential-access emulator with no real secrets","EDR-safe handle access test against a lab process"); Logic="Alert on LSASS handle access, dump creation, credential dumping tools, or suspicious memory collection behavior."; Impact="Credential dumping can expose reusable credentials and enable rapid lateral movement or domain compromise." },
    [ordered]@{ Id="T1552"; Name="Unsecured Credentials"; Folder="T1552-Credentials-in-Files"; Tactic="Credential Access"; Severity="High"; Priority="P1"; Simulation="Run the approved Atomic Red Team T1552 test with seeded dummy credentials only."; Commands=@("search for seeded dummy credential files","PowerShell search against a lab-only test directory","directory listing for seeded secret-like filenames","read a lab web.config containing dummy values"); Logic="Alert on broad credential keyword searches, sensitive file access, or recursive discovery in user and application directories."; Impact="Credentials in files can provide direct access to applications, databases, service accounts, and remote systems." },
    [ordered]@{ Id="T1555"; Name="Credentials from Password Stores"; Folder="T1555-Credentials-from-Password-Stores"; Tactic="Credential Access"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1555 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("vaultcmd /list","cmdkey /list","browser credential store access","PowerShell credential manager enumeration"); Logic="Alert on credential store enumeration from non-admin workflows or processes outside normal endpoint management."; Impact="Password store access can expose saved credentials for web apps, remote systems, and privileged operations." },
    [ordered]@{ Id="T1547.001"; Name="Registry Run Keys / Startup Folder"; Folder="T1547-Registry-Run-Keys"; Tactic="Persistence"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1547.001 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run","New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","schtasks /create","startup folder file write"); Logic="Alert on Run key modification, suspicious startup folder writes, or persistence changes from user-writable payload paths."; Impact="Autostart persistence allows adversaries to regain execution after reboot or user logon." },
    [ordered]@{ Id="T1548.002"; Name="Bypass User Account Control"; Folder="T1548-UAC-Bypass"; Tactic="Privilege Escalation"; Severity="High"; Priority="P1"; Simulation="Run only approved UAC telemetry simulations in an isolated lab."; Commands=@("auto-elevated binary telemetry test","registry-change precondition simulation","benign elevation-control test executable","approved COM telemetry simulation"); Logic="Alert on auto-elevated binaries launched after suspicious registry changes or from unexpected interactive users."; Impact="UAC bypass can turn local footholds into elevated execution when combined with permissive local controls." },
    [ordered]@{ Id="T1021"; Name="Remote Services"; Folder="T1021-Remote-Services"; Tactic="Lateral Movement"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1021 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("mstsc.exe /v:<host>","Enter-PSSession -ComputerName <host>","wmic /node:<host> process call create","psexec-style service execution"); Logic="Alert on remote service usage from unusual accounts, non-admin workstations, or after discovery and credential access activity."; Impact="Remote services enable adversaries to expand access across the Windows environment." },
    [ordered]@{ Id="T1078"; Name="Valid Accounts"; Folder="T1078-Valid-Accounts"; Tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1078 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("interactive logon with privileged account","runas /user:<domain\user> cmd","net use \\host\c$ /user:<user>","remote PowerShell with domain credentials"); Logic="Alert on abnormal account usage by time, host, source workstation, privilege level, or impossible travel context."; Impact="Valid account abuse reduces exploit noise and can blend into normal administrative activity." },
    [ordered]@{ Id="T1562"; Name="Impair Defenses"; Folder="T1562-Impair-Defenses"; Tactic="Defense Evasion"; Severity="Critical"; Priority="P1"; Simulation="Run only approved defense-impairment telemetry simulations in an isolated lab."; Commands=@("security service stop attempt against a lab-only dummy service","Defender setting change simulation in audit-only mode","logging configuration change simulation","agent configuration tamper simulation using test files"); Logic="Alert on attempts to stop security services, disable logging, alter Defender settings, or modify agent configuration."; Impact="Defense impairment can blind monitoring and increase dwell time during active compromise." },
    [ordered]@{ Id="T1070"; Name="Indicator Removal"; Folder="T1070-Indicator-Removal"; Tactic="Defense Evasion"; Severity="High"; Priority="P1"; Simulation="Run only safe indicator-removal simulations against lab test logs and files."; Commands=@("clear a lab-created custom event log","remove lab-only staging artifacts","delete temporary test files","simulate cleanup after an approved test run"); Logic="Alert on log clearing, suspicious bulk deletion, timestomp indicators, or cleanup activity after alerts."; Impact="Indicator removal reduces forensic evidence and can delay investigation or containment." },
    [ordered]@{ Id="T1105"; Name="Ingress Tool Transfer"; Folder="T1105-Ingress-Tool-Transfer"; Tactic="Command and Control"; Severity="High"; Priority="P1"; Simulation="Run the approved Atomic Red Team T1105 test against an internal benign file."; Commands=@("built-in transfer utility downloading a harmless internal test file","BITS transfer of a benign text file","PowerShell download of an internal lab file","curl download of a benign lab artifact"); Logic="Alert on built-in transfer utilities downloading executables, scripts, or archives into user-writable paths."; Impact="Tool transfer enables staging of payloads, credential tools, scanners, and persistence utilities." },
    [ordered]@{ Id="T1497"; Name="Virtualization/Sandbox Evasion"; Folder="T1497-Virtualization-Checks"; Tactic="Defense Evasion"; Severity="Medium"; Priority="P2"; Simulation="Invoke-AtomicTest T1497 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("systeminfo | findstr /i vmware","wmic computersystem get model,manufacturer","Get-WmiObject Win32_BIOS","registry queries for VM artifacts"); Logic="Alert on virtualization checks when they appear in suspicious execution chains or from newly observed binaries."; Impact="Environment awareness helps adversaries avoid analysis sandboxes and tune payload behavior." },
    [ordered]@{ Id="T1486"; Name="Data Encrypted for Impact"; Folder="T1486-Data-Encrypted-for-Impact"; Tactic="Impact"; Severity="Critical"; Priority="P1"; Simulation="Use safe Atomic Red Team simulation only; do not encrypt production or personal data."; Commands=@("safe file rename simulation","test directory canary modification","high-volume write simulation","controlled encryption emulator in isolated folder"); Logic="Alert on high-volume file modification, suspicious extension changes, canary file touches, and unexpected encryption tooling."; Impact="Ransomware-style encryption can disrupt business operations and require incident response leadership escalation." },
    [ordered]@{ Id="T1112"; Name="Modify Registry"; Folder="T1112-Modify-Registry"; Tactic="Defense Evasion"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1112 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("reg add <key> /v <value>","reg delete <key> /f","Set-ItemProperty HKCU:\Software\...","New-ItemProperty HKLM:\Software\..."); Logic="Alert on registry changes affecting security settings, persistence locations, UAC behavior, or logon configuration."; Impact="Registry modification supports persistence, evasion, configuration tampering, and privilege escalation chains." },
    [ordered]@{ Id="T1047"; Name="Windows Management Instrumentation"; Folder="T1047-WMI"; Tactic="Execution"; Severity="High"; Priority="P1"; Simulation="Invoke-AtomicTest T1047 -PathToAtomicsFolder C:\AtomicRedTeam\atomics"; Commands=@("wmic process call create calc.exe","wmic /node:<host> process call create <command>","Get-WmiObject Win32_Process","Invoke-WmiMethod -Class Win32_Process"); Logic="Alert on local or remote WMI process creation, unusual WMI parentage, or WMI launched by Office, browsers, or scripts."; Impact="WMI enables stealthy local execution, remote execution, and administrative-looking lateral movement." }
)

function Join-List {
    param([string[]]$Items)
    return ($Items | ForEach-Object { "- $_" }) -join "`n"
}

foreach ($technique in $techniques) {
    $caseRoot = Join-Path $detectionsRoot $technique.Folder
    $caseFolders = @("screenshots", "logs", "powershell", "evidence")
    foreach ($folder in $caseFolders) {
        New-Item -ItemType Directory -Force -Path (Join-Path $caseRoot $folder) | Out-Null
    }

    $commands = Join-List $technique.Commands
    $readme = @"
# Detection Engineering Case Study: $($technique.Id) - $($technique.Name)

Use this README as the working template for validating, documenting, and presenting this detection. Replace every `Fill in` value with lab evidence from your own run.

## MITRE ATT&CK

| Item | Value |
|---|---|
| Technique | $($technique.Id) |
| Name | $($technique.Name) |
| Tactic | $($technique.Tactic) |
| Severity | $($technique.Severity) |
| Priority | $($technique.Priority) |
| ATT&CK Link | https://attack.mitre.org/techniques/$($technique.Id.Replace(".", "/"))/ |
| Date Performed | Fill in: YYYY-MM-DD |
| Analyst | Fill in: your name |
| Lab Host | Fill in: endpoint name, such as WIN11 |
| Detection Status | Fill in: Planned, Validated, Needs Tuning, or Gap |

## Executive Summary

Fill in a short leadership-readable summary after testing.

Example:

This exercise validated detection coverage for MITRE ATT&CK Technique $($technique.Id) ($($technique.Name)) within a Windows Active Directory environment. Endpoint telemetry generated by Sysmon was collected by Wazuh, indexed, and analyzed through threat hunting. The exercise demonstrated the ability to detect activity associated with $($technique.Tactic.ToLower()) behavior and document the analyst response workflow.

## Objective

Fill in what you wanted to validate.

Suggested objective:

Validate that Sysmon and Wazuh can detect $($technique.Name.ToLower()) behavior, capture the required telemetry, and support a repeatable SOC investigation.

## Business Value

Fill in why this detection matters to the business or SOC.

Suggested value:

$($technique.Impact)

Detecting this behavior helps the team:

- identify suspicious activity earlier
- understand attacker progression
- validate endpoint telemetry coverage
- improve incident response decisions
- reduce attacker dwell time

## Lab Environment

| Component | Configuration |
|---|---|
| Hypervisor | Fill in: VMware Workstation, VirtualBox, Hyper-V, or other |
| Domain | Fill in: corp.local or your lab domain |
| Domain Controller | Fill in: DC01 / OS version |
| Workstation | Fill in: WIN11 / OS version |
| Wazuh | Fill in: version and role |
| Sysmon | Fill in: version and config source |
| Windows Logs | Fill in: Security, Sysmon Operational, PowerShell Operational |
| Test Tooling | Fill in: Atomic Red Team or manual simulation |

## Network Diagram

Insert or link the architecture image for this test.

Fill in:

- Diagram path: `../../architecture/Lab-Network-Diagram.png`
- Endpoint tested:
- Wazuh manager:
- Domain controller:

Screenshot required:

~~~text
screenshots/00-network-diagram.png
~~~

## Detection Objective

Fill in the behavior that should be detected.

Suggested detection focus:

$($technique.Logic)

Expected commands or behaviors:

$commands

## Attack Simulation

### Tool Used

Fill in the tool used for testing.

Suggested:

- Atomic Red Team
- Manual PowerShell or command-line simulation
- Wazuh threat hunting
- Sysmon Event Viewer

### Command Executed

Paste the exact command you ran.

~~~powershell
$($technique.Simulation)
~~~

### Command Output

Fill in the command output or summarize the successful execution result.

Screenshot required:

~~~text
screenshots/01-atomic-test.png
~~~

## Commands Observed

$commands

## Expected Telemetry

| Source | Event or Signal | Purpose |
|---|---|---|
| Sysmon | Event ID 1 - Process Creation | Captures image, command line, parent process, user, and hashes |
| Sysmon | Event ID 11 - File Create | Captures staged tools, dumps, or test artifacts when applicable |
| Sysmon | Event ID 13 - Registry Value Set | Captures registry-based persistence or configuration changes when applicable |
| Sysmon | Event ID 22 - DNS Query | Captures DNS behavior when network resolution is involved |
| Sysmon | Event ID 3 - Network Connection | Captures network connections when enabled in the Sysmon config |
| Windows Security | 4688 Process Creation | Secondary process execution evidence when enabled |
| PowerShell Operational | 4104 Script Block Logging | Captures script content when PowerShell is involved |

## Expected Processes

Fill in the actual process names observed during testing.

| Process | Expected? | Notes |
|---|---|---|
| Fill in | Yes/No | Fill in |
| Fill in | Yes/No | Fill in |
| Fill in | Yes/No | Fill in |

## Wazuh Detection

### Search Used

Record the exact Wazuh query used.

~~~text
agent.name:"WIN11"
rule.groups:"sysmon"
process.name:"$($technique.Commands[0].Split(" ")[0])"
~~~

### Wazuh Alert

Fill in the alert metadata.

| Field | Value |
|---|---|
| Rule ID | Fill in |
| Rule Level | Fill in |
| Decoder | Fill in |
| Agent | Fill in |
| MITRE Technique | Fill in |
| Timestamp | Fill in |
| Index | Fill in |

Screenshot required:

~~~text
screenshots/02-wazuh-alert.png
~~~

## Threat Hunting

Record every query used during validation.

~~~text
agent.name:"WIN11"
event.code:1
process.name:"Fill in"
process.command_line:"Fill in"
rule.mitre.id:"$($technique.Id)"
~~~

Fill in hunting conclusion:

- What activity was found:
- Host affected:
- User affected:
- Parent process:
- Follow-on activity:
- Analyst assessment:

Screenshot required:

~~~text
screenshots/03-threat-hunting.png
~~~

## Sysmon Event

Fill in the event fields from Event Viewer or Wazuh.

| Item | Value |
|---|---|
| Event ID | Fill in |
| UtcTime | Fill in |
| Host | Fill in |
| User | Fill in |
| Image | Fill in |
| Parent Image | Fill in |
| Command Line | Fill in |
| Parent Command Line | Fill in |
| Hashes | Fill in |
| Integrity Level | Fill in |

Screenshot required:

~~~text
screenshots/04-sysmon-event.png
~~~

## Windows Logs

Fill in any supporting Windows logs.

| Log Source | Event ID | Finding |
|---|---:|---|
| Security | Fill in | Fill in |
| PowerShell Operational | Fill in | Fill in |
| System | Fill in | Fill in |

## MITRE Mapping

| Tactic | Technique | Sub-technique | Justification |
|---|---|---|---|
| $($technique.Tactic) | $($technique.Id) - $($technique.Name) | Fill in if applicable | Fill in why the observed behavior maps to this technique |

Screenshot required:

~~~text
screenshots/05-mitre-mapping.png
~~~

## Detection Logic

Fill in why the alert should fire.

Starting logic:

$($technique.Logic)

Correlate command line, parent process, user context, host role, and nearby events. Prioritize activity that follows initial access, script execution, credential access, or remote service usage.

## SOC Playbook

| Item | Value |
|---|---|
| Severity | $($technique.Severity) |
| Priority | $($technique.Priority) |
| MITRE Tactic | $($technique.Tactic) |
| MITRE Technique | $($technique.Id) - $($technique.Name) |
| Alert Source | Fill in: Sysmon, Wazuh rule, Windows log, or custom rule |
| Collection | Fill in: Wazuh Agent, Windows Event Forwarding, or other |
| Detection Logic | Fill in |
| False Positives | Fill in |
| Threat | Fill in |
| Containment | Fill in |

## False Positives

Fill in legitimate activity that may look similar.

Examples:

- system administrators
- endpoint management tooling
- vulnerability scanners
- software inventory jobs
- backup or monitoring agents

## Incident Response

If this occurred in production:

1. Identify the user account and host.
2. Verify the parent process and full command line.
3. Determine whether the activity matches approved administrative behavior.
4. Review related authentication, PowerShell, and Sysmon events.
5. Search for additional discovery, credential access, persistence, or lateral movement.
6. Check whether other hosts show the same behavior.
7. Preserve Wazuh alerts, Sysmon events, screenshots, and command output.
8. Escalate or contain the host if activity is unauthorized.

## Detection Metrics

| Metric | Result |
|---|---|
| Detection Successful | Fill in: Yes/No |
| Sysmon Collected | Fill in: Yes/No |
| Wazuh Alert Generated | Fill in: Yes/No |
| ATT&CK Tagged | Fill in: Yes/No |
| Time to Detect | Fill in |
| Time to Investigate | Fill in |
| Analyst Investigation | Fill in: Successful, Partial, or Needs Tuning |
| False Positive Status | Fill in |

## Lessons Learned

Fill in what you observed.

Prompts:

- What telemetry appeared immediately?
- What telemetry was missing?
- Did Wazuh parse the fields correctly?
- Did the query need tuning?
- What would improve detection fidelity?

## Engineering Improvements

Fill in recommended improvements.

Examples:

- Deploy Sysmon via Group Policy.
- Enable PowerShell Script Block Logging.
- Increase Wazuh rule severity for confirmed malicious chains.
- Create a Sigma detection.
- Create a Microsoft Sentinel analytic rule.
- Add SOAR enrichment for host and user context.
- Add false-positive suppression for approved admin tooling.

## Evidence

Attach screenshots and raw artifacts.

| Evidence | Path | Complete? |
|---|---|---|
| Atomic test execution | `screenshots/01-atomic-test.png` | Fill in |
| Wazuh alert | `screenshots/02-wazuh-alert.png` | Fill in |
| Threat hunting results | `screenshots/03-threat-hunting.png` | Fill in |
| Sysmon event | `screenshots/04-sysmon-event.png` | Fill in |
| MITRE mapping | `screenshots/05-mitre-mapping.png` | Fill in |
| Raw logs | `logs/` | Fill in |
| PowerShell transcript or commands | `powershell/` | Fill in |
| Supporting evidence | `evidence/` | Fill in |

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/$($technique.Id.Replace(".", "/"))/
- Microsoft Sysmon documentation
- Wazuh documentation
- Atomic Red Team atomics

## Portfolio Summary

Fill in the final portfolio-ready conclusion.

Suggested summary:

This exercise validated detection coverage for $($technique.Id) - $($technique.Name) using Sysmon and Wazuh in a Windows Active Directory lab. The test documented endpoint telemetry, Wazuh visibility, ATT&CK mapping, analyst triage steps, and engineering recommendations.

## What You Need to Fill In

| Section | What to Add |
|---|---|
| Date Performed | Test date |
| Analyst | Your name |
| Objective | Why you ran the test |
| Lab Environment | Actual hostnames, versions, and logging configuration |
| Network Diagram | Screenshot or link to the relevant architecture diagram |
| Exact Command | The command you executed |
| Command Output | Copy/paste output or screenshot |
| Expected Processes | Processes observed during the test |
| Sysmon Event ID | Actual event IDs observed |
| Parent Process | Parent image and command line |
| Process Name | Process image from Sysmon or Wazuh |
| Command Line | Full command line from telemetry |
| User | Account that executed the activity |
| Wazuh Rule ID | Alert rule metadata |
| Wazuh Rule Level | Alert severity |
| Wazuh Decoder | Decoder used, if shown |
| Threat Hunting Query | Exact Wazuh search used |
| MITRE Mapping | Tactic, technique, and evidence-based justification |
| False Positives | Legitimate sources of similar activity |
| Detection Metrics | Success, timing, and analyst result |
| Screenshots | Atomic test, Wazuh alert, threat hunting, Sysmon event, MITRE mapping |
| Lessons Learned | What worked, what failed, and what needs tuning |
| Engineering Improvements | Rule tuning, logging, Sigma, Sentinel, SOAR, or GPO improvements |
"@

    Set-Content -LiteralPath (Join-Path $caseRoot "README.md") -Value $readme -Encoding utf8
    foreach ($folder in $caseFolders) {
        $gitkeep = Join-Path (Join-Path $caseRoot $folder) ".gitkeep"
        Set-Content -LiteralPath $gitkeep -Value "" -Encoding utf8
    }
}

$matrixRows = $techniques | ForEach-Object {
    "| $($_.Tactic) | $($_.Id) | $($_.Name) | [$($_.Folder)](./$($_.Folder)/) | $($_.Severity) | $($_.Priority) |"
}

$matrix = @"
# MITRE ATT&CK Detection Matrix

This matrix tracks the detection engineering case studies included in this portfolio. Each folder contains a repeatable validation report with simulation steps, telemetry expectations, Wazuh hunting guidance, incident response actions, metrics, and screenshot placeholders.

| Tactic | Technique | Name | Case Study | Severity | Priority |
|---|---|---|---|---|---|
$($matrixRows -join "`n")

## Coverage Summary

| ATT&CK Area | Techniques Included |
|---|---:|
| Discovery | 8 |
| Execution | 3 |
| Credential Access | 3 |
| Persistence | 1 |
| Privilege Escalation | 1 |
| Lateral Movement | 1 |
| Defense Evasion | 6 |
| Command and Control | 1 |
| Impact | 1 |

## Operating Model

The portfolio is designed to be updated as screenshots, rule files, and false-positive notes are added. A mature version of the matrix should include owner, last validation date, detection status, rule link, false-positive disposition, and coverage gap notes.
"@
Set-Content -LiteralPath (Join-Path $detectionsRoot "MITRE-Matrix.md") -Value $matrix -Encoding utf8

$methodology = @"
# Detection Engineering Methodology

## Purpose

This methodology describes the repeatable workflow used across the ATT&CK detection case studies in this portfolio.

## Workflow

1. Select a MITRE ATT&CK technique relevant to Windows enterprise risk.
2. Execute a safe Atomic Red Team test or equivalent lab simulation.
3. Confirm Sysmon and Windows logs were generated on the endpoint.
4. Verify Wazuh ingestion, indexing, and searchability.
5. Document command lines, parent-child process relationships, users, hosts, and timestamps.
6. Map observed telemetry to ATT&CK tactic and technique.
7. Write analyst investigation steps and false-positive considerations.
8. Capture screenshots for evidence.
9. Convert validated logic into durable rules, dashboards, or runbooks.
10. Report coverage, gaps, and improvement actions through the management portfolio.

## Validation Standard

A detection is considered validated when endpoint telemetry is present, Wazuh search can retrieve the event, the behavior maps to ATT&CK, and the analyst can explain what happened from available evidence.

## Documentation Standard

Each case study includes executive summary, objective, ATT&CK mapping, lab environment, simulation command, expected telemetry, Wazuh queries, detection logic, incident response, metrics, recommendations, lessons learned, and evidence placeholders.
"@
Set-Content -LiteralPath (Join-Path $documentationRoot "Detection-Engineering-Methodology.md") -Value $methodology -Encoding utf8

$ir = @"
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
"@
Set-Content -LiteralPath (Join-Path $documentationRoot "Incident-Response-Workflow.md") -Value $ir -Encoding utf8

$hunting = @"
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
"@
Set-Content -LiteralPath (Join-Path $documentationRoot "Threat-Hunting-Guide.md") -Value $hunting -Encoding utf8

$labGuide = @"
# Lab Build Guide

## Purpose

This guide describes the target environment assumed by the detection engineering case studies.

## Components

| Component | Purpose |
|---|---|
| Windows Server 2022 Domain Controller | Active Directory, DNS, and domain policy |
| Windows 11 Workstation | Endpoint test system |
| Sysmon | Endpoint process, file, registry, and network telemetry |
| Wazuh Agent | Log forwarding from Windows endpoints |
| Wazuh Manager | SIEM ingestion, indexing, alerting, and threat hunting |
| Atomic Red Team | Safe ATT&CK-aligned test execution |

## Build Notes

Deploy Sysmon before running tests, confirm the Wazuh agent is connected, and validate that Microsoft-Windows-Sysmon/Operational events appear in Wazuh before collecting evidence.
"@
Set-Content -LiteralPath (Join-Path $documentationRoot "Lab-Build-Guide.md") -Value $labGuide -Encoding utf8

$lessons = @"
# Lessons Learned

## Technical Lessons

- Process creation telemetry is the foundation for most Windows detection validation.
- Parent-child process context is often more useful than process name alone.
- PowerShell logging materially improves investigation quality.
- Registry and file events help distinguish simple discovery from persistence or defense evasion.

## Program Lessons

- A consistent case-study format makes coverage easier to review.
- ATT&CK mapping helps translate technical alerts into leadership-readable risk.
- Detection metrics should include both successful validation and known gaps.
- Screenshots and raw evidence make portfolio claims more credible.

## Future Improvements

- Add Sigma rules for each detection.
- Add Wazuh custom rules and severity tuning.
- Track false positives by technique.
- Add a monthly detection coverage scorecard.
- Expand the lab with Microsoft Sentinel and SOAR automation.
"@
Set-Content -LiteralPath (Join-Path $documentationRoot "Lessons-Learned.md") -Value $lessons -Encoding utf8

$capstone = @"
# Enterprise Detection Engineering Capstone

## Executive Summary

This capstone summarizes a Windows Active Directory detection engineering portfolio built around Sysmon, Wazuh, Atomic Red Team, and MITRE ATT&CK. The portfolio validates 25 ATT&CK-aligned techniques across discovery, execution, credential access, persistence, privilege escalation, lateral movement, defense evasion, command and control, and impact.

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

| ATT&CK Tactic | Techniques Tested | Detection Status |
|---|---:|---|
| Discovery | 8 | Documented |
| Execution | 3 | Documented |
| Credential Access | 3 | Documented |
| Persistence | 1 | Documented |
| Privilege Escalation | 1 | Documented |
| Lateral Movement | 1 | Documented |
| Defense Evasion | 6 | Documented |
| Command and Control | 1 | Documented |
| Impact | 1 | Documented |

## Detection Success Criteria

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

## Recommendations

1. Deploy Sysmon through Group Policy or endpoint management.
2. Enable PowerShell Script Block Logging and process command-line auditing.
3. Convert validated logic into Wazuh rules and Sigma detections.
4. Review ATT&CK coverage monthly with security operations stakeholders.
5. Add SOAR enrichment for host, user, and threat intelligence context.
6. Maintain a detection backlog that prioritizes credential access, defense evasion, and lateral movement.

## Security Engineering Management Value

This portfolio demonstrates more than tool deployment. It shows how technical telemetry becomes measurable detection coverage, how ATT&CK creates a shared operating language, and how SOC investigation, risk tracking, metrics, and executive reporting can be tied into one security engineering program.
"@
Set-Content -LiteralPath (Join-Path $reportsRoot "Enterprise-Detection-Engineering-Capstone.md") -Value $capstone -Encoding utf8

$wazuh = @"
# Wazuh Notes

Store Wazuh custom rules, dashboard screenshots, search queries, and alert tuning notes here. Each detection case study should eventually link to the related rule or query artifact in this folder.
"@
Set-Content -LiteralPath (Join-Path $repoRoot "wazuh\README.md") -Value $wazuh -Encoding utf8

$sysmon = @"
# Sysmon Notes

Store Sysmon configuration references, event screenshots, and telemetry validation notes here. The case studies assume Sysmon process creation, file create, registry value set, and network telemetry are available where applicable.
"@
Set-Content -LiteralPath (Join-Path $repoRoot "sysmon\README.md") -Value $sysmon -Encoding utf8

$powershell = @"
# PowerShell Notes

Store safe lab commands, Atomic Red Team execution notes, and PowerShell logging validation here. Do not store secrets, tokens, production data, or destructive commands.
"@
Set-Content -LiteralPath (Join-Path $repoRoot "powershell\README.md") -Value $powershell -Encoding utf8

$incidentResponse = @"
# Incident Response Notes

Store alert triage notes, investigation timelines, containment recommendations, and case-study evidence summaries here.
"@
Set-Content -LiteralPath (Join-Path $repoRoot "incident-response\README.md") -Value $incidentResponse -Encoding utf8

Write-Host "Generated $($techniques.Count) detection case studies and supporting portfolio artifacts."
