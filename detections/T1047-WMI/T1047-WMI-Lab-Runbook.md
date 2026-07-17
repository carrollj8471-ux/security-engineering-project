# T1047 Windows Management Instrumentation Detection Lab

> **Implementation note:** The initial `100130`/`100131` design did not generate the expected live alert. The final validated implementation extends built-in WMI rule `92069` with custom rule `100132`; see `README.md` for the observed evidence and troubleshooting sequence.

## Portfolio objective

Validate that Sysmon and Wazuh can identify a process created through Windows Management Instrumentation (WMI), preserve the `WmiPrvSE.exe` process lineage, and generate an alert mapped to MITRE ATT&CK T1047.

This lab follows the completed PowerShell and Scheduled Task case studies by adding a native Windows management execution path and parent-child process analysis.

## MITRE ATT&CK mapping

| Field | Value |
|---|---|
| Technique | `T1047 – Windows Management Instrumentation` |
| Tactic | Execution |
| Platform | Windows |
| Observed behavior | The local `Win32_Process.Create` WMI method starts a benign command process. |
| Primary evidence | Sysmon Event ID 1 showing `WmiPrvSE.exe` as the parent of the created process |
| Supporting evidence | WMI method result, command line, marker file, Wazuh alert, and ATT&CK fields |
| MITRE reference | https://attack.mitre.org/techniques/T1047/ |
| Microsoft method reference | https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process |

WMI is a legitimate Windows management infrastructure. WMI execution is not malicious by itself; the parent-child relationship, created image, command line, user, integrity level, and surrounding activity provide the investigative context.

## Lab environment

| Component | Expected value |
|---|---|
| Endpoint | WIN11 |
| Domain | corp.local |
| Test user | CORP\Administrator |
| Sysmon | Running and collecting Event ID 1 |
| Wazuh agent | Running |
| Wazuh manager | 192.168.232.20 |
| Wazuh version | 4.14.6 |
| Primary source | Microsoft-Windows-Sysmon/Operational |
| Primary event | Sysmon Event ID 1 – Process Create |

## Safety boundaries

- Use only the local WIN11 endpoint.
- Do not supply `-ComputerName`, remote credentials, or a remote CIM session.
- Do not create permanent WMI event subscriptions.
- Do not download or execute external content.
- The positive test writes one text marker to `C:\ProgramData`.
- The negative control starts only `hostname.exe`.
- Remove the marker file after validation.

## Detection hypothesis

If `Win32_Process.Create` launches a process through WMI, Sysmon should record the created process with `WmiPrvSE.exe` as its parent. Wazuh should collect that Process Create event. A baseline rule should identify WMI-spawned processes, while a higher-severity rule should identify WMI spawning a command or scripting interpreter.

## Phase 1: Verify readiness

Run in Administrator PowerShell on WIN11:

```powershell
Get-Date -Format o

Get-Service Sysmon, Sysmon64, WazuhSvc, Winmgmt -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object TimeCreated, Id, ProviderName
```

Expected:

- `Winmgmt` is running.
- Either `Sysmon` or `Sysmon64` is running.
- `WazuhSvc` is running.
- Recent Sysmon events are available.

Record the timestamp and save the readiness screenshot.

## Phase 2: Perform the safe WMI simulation

Run in Administrator PowerShell:

```powershell
$Start = Get-Date
$Marker = "C:\ProgramData\T1047-WMI-marker.txt"
$Command = 'cmd.exe /c echo Benign T1047 WMI validation > C:\ProgramData\T1047-WMI-marker.txt'

$Result = Invoke-CimMethod `
    -Namespace root\cimv2 `
    -ClassName Win32_Process `
    -MethodName Create `
    -Arguments @{ CommandLine = $Command }

$Result | Format-List ReturnValue, ProcessId
Start-Sleep -Seconds 3

Get-Item $Marker |
    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc

Get-Content $Marker
Get-FileHash -Algorithm SHA256 $Marker | Format-List
Get-Date -Format o
```

Expected:

- `ReturnValue` is `0`.
- `ProcessId` contains the created process ID.
- The marker file exists and contains `Benign T1047 WMI validation`.
- A SHA-256 hash is returned.

Save the complete PowerShell output. The returned process ID will help correlate the WMI method call with Sysmon.

## Phase 3: Confirm local Sysmon telemetry

Search for the distinctive command:

```powershell
$WmiEvent = Get-WinEvent -FilterHashtable @{
    LogName  = "Microsoft-Windows-Sysmon/Operational"
    Id       = 1
    StartTime = $Start
} | Where-Object {
    $_.Message -match "T1047-WMI-marker"
} | Select-Object -First 1

$WmiEvent | Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

The event should establish:

| Field | Required observation |
|---|---|
| Event ID | `1` |
| Image | `cmd.exe` |
| Command line | Contains `T1047-WMI-marker.txt` |
| Parent image | Ends with `WmiPrvSE.exe` |
| Process ID | Correlates with the WMI result when available |
| User | Record the observed account |
| Integrity level | Record the observed level |
| Hashes | Record the executable hashes |
| UTC time | Record the Sysmon timestamp |

Do not continue until the local event shows both the marker command and `WmiPrvSE.exe` parentage.

## Phase 4: Hunt in Wazuh before adding rules

Set the Wazuh time range to include the test, then run the queries progressively.

### Query 1: Confirm endpoint telemetry

```text
agent.name:"WIN11"
```

### Query 2: Review Sysmon Process Create activity

```text
agent.name:"WIN11" AND data.win.system.eventID:"1"
```

### Query 3: Locate WMI parentage

```text
agent.name:"WIN11" AND data.win.eventdata.parentImage:*WmiPrvSE.exe
```

### Query 4: Locate the distinctive marker command

```text
agent.name:"WIN11" AND data.win.eventdata.commandLine:*T1047-WMI-marker*
```

### Query 5: Correlate parent and command

```text
agent.name:"WIN11" AND data.win.eventdata.parentImage:*WmiPrvSE.exe AND data.win.eventdata.commandLine:*T1047-WMI-marker*
```

Record the event count and decisive fields for each query. Finding the raw event proves collection, not a dedicated T1047 detection.

## Required event fields

Open the exact Wazuh event and record:

| Field | Observed value |
|---|---|
| Agent | `[ENTER VALUE]` |
| Event ID | `[ENTER VALUE]` |
| Timestamp and time zone | `[ENTER VALUE]` |
| Image | `[ENTER VALUE]` |
| Original filename | `[ENTER VALUE]` |
| Command line | `[ENTER VALUE]` |
| Parent image | `[ENTER VALUE]` |
| Parent command line | `[ENTER VALUE]` |
| Process ID | `[ENTER VALUE]` |
| Parent process ID | `[ENTER VALUE]` |
| Process GUID | `[ENTER VALUE]` |
| Parent process GUID | `[ENTER VALUE]` |
| User | `[ENTER VALUE]` |
| Integrity level | `[ENTER VALUE]` |
| Hashes | `[ENTER VALUE]` |
| Existing Wazuh rule | `[ENTER VALUE]` |

## Phase 5: Add the ATT&CK-mapped Wazuh rule

Confirm rule ID `100132` is unused and inspect the built-in WMI branch:

```bash
sudo grep -R -n --include='*.xml' 'id="100132"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules

sudo grep -R -n -B 6 -A 18 '<rule id="92069"' \
  /var/ossec/ruleset/rules
```

Rule `92069` should identify `WmiPrvSE.exe` parentage at level 0. If `100132` exists, select an unused local ID and update the validation queries.

Back up the current rule file:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak-$(date +%Y%m%d-%H%M%S)
```

Open the file:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add this group:

```xml
<group name="windows,sysmon,wmi,mitre,">

  <rule id="100132" level="8">
    <if_sid>92069</if_sid>
    <field name="win.eventdata.originalFileName"
           type="pcre2">(?i)^Cmd\.Exe$</field>
    <description>WMI spawned a command or script interpreter</description>
    <mitre>
      <id>T1047</id>
    </mitre>
  </rule>

</group>
```

Validate the configuration:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Restart only after validation succeeds:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

Do not attach the rule directly to `61603`, `61600`, or `92052`. In the validated Wazuh 4.14.6 ruleset, WMI-created processes followed the `92069` branch.

## Phase 6: Positive detection validation

Rules do not process old events retroactively. After the manager restarts, execute a fresh positive test:

```powershell
$ValidationMarker = "C:\ProgramData\T1047-WMI-validation-marker.txt"
$ValidationCommand = 'cmd.exe /c echo Benign T1047 rule validation > C:\ProgramData\T1047-WMI-validation-marker.txt'

$ValidationResult = Invoke-CimMethod `
    -Namespace root\cimv2 `
    -ClassName Win32_Process `
    -MethodName Create `
    -Arguments @{ CommandLine = $ValidationCommand }

$ValidationResult | Format-List ReturnValue, ProcessId
Start-Sleep -Seconds 3
Get-Content $ValidationMarker
```

Search Wazuh:

```text
agent.name:"WIN11" AND rule.id:"100132"
```

Then verify the mapping:

```text
agent.name:"WIN11" AND rule.mitre.id:"T1047"
```

The final alert should contain:

- Rule ID `100132`
- Rule level `8`
- MITRE ID `T1047`
- Technique `Windows Management Instrumentation`
- Tactic `Execution`
- `cmd.exe` image
- `WmiPrvSE.exe` parent image
- The distinctive validation command

Export or copy the complete alert JSON.

## Phase 7: Benign negative control

The negative control uses the same WMI process-creation method to start `hostname.exe`. It should be preserved in the Wazuh archive through the same WMI path but must not trigger rule `100132`.

```powershell
$ControlResult = Invoke-CimMethod `
    -Namespace root\cimv2 `
    -ClassName Win32_Process `
    -MethodName Create `
    -Arguments @{ CommandLine = "C:\Windows\System32\hostname.exe" }

$ControlResult | Format-List ReturnValue, ProcessId
```

Confirm archive collection:

```text
agent.name:"WIN11" AND data.win.system.eventID:"1" AND data.win.eventdata.parentImage:*WmiPrvSE.exe AND data.win.eventdata.image:*hostname.exe
```

Expected elevated result:

```text
agent.name:"WIN11" AND rule.id:"100132" AND data.win.eventdata.image:*hostname.exe
```

The archive or archive-backed query should return the control event. The rule `100132` query should return no results.

## Phase 8: Cleanup

Remove the two marker files:

```powershell
Remove-Item "C:\ProgramData\T1047-WMI-marker.txt" `
  -ErrorAction SilentlyContinue

Remove-Item "C:\ProgramData\T1047-WMI-validation-marker.txt" `
  -ErrorAction SilentlyContinue

Test-Path "C:\ProgramData\T1047-WMI-marker.txt"
Test-Path "C:\ProgramData\T1047-WMI-validation-marker.txt"
```

Both `Test-Path` commands should return `False`.

No permanent WMI consumer, filter, binding, scheduled task, service, user, or firewall rule is created by this lab.

## Screenshot plan

Use this sequence:

1. `01-readiness-services-sysmon.png`
2. `02-wmi-positive-simulation.png`
3. `03-marker-file-and-hash.png`
4. `04-local-sysmon-wmi-process-event.png`
5. `05-wazuh-wmiprvse-parent-hunt.png`
6. `06-wazuh-marker-command-hunt.png`
7. `07-custom-wmi-rule-configuration.png`
8. `08-positive-wmi-alert.png`
9. `09-wmi-mitre-mapping.png`
10. `10-negative-control-baseline.png`
11. `11-negative-control-no-elevated-alert.png`
12. `12-cleanup-validation.png`

Suggested caption format:

*Figure N. Wazuh alert generated from Sysmon Process Create telemetry, highlighting `cmd.exe`, its `WmiPrvSE.exe` parent, the distinctive validation command, and the T1047 mapping used to validate WMI execution detection.*

## Timeline worksheet

| Time | Source | Event | Evidence | Interpretation |
|---|---|---|---|---|
| `[TIME]` | WIN11 | Readiness verified | Services and Sysmon events | Endpoint prepared for testing |
| `[TIME]` | PowerShell/WMI | `Win32_Process.Create` invoked | Return value and process ID | Benign WMI process creation requested |
| `[TIME]` | WIN11 | Marker file created | File, contents, and hash | WMI-spawned command executed |
| `[TIME]` | Sysmon | Event ID 1 recorded | Image, parent image, command, user | Endpoint telemetry confirmed WMI lineage |
| `[TIME]` | Wazuh | Raw event found | Progressive hunt query | Collection confirmed |
| `[TIME]` | Wazuh | Rule `100132` fired | Alert and ATT&CK fields | Positive detection succeeded |
| `[TIME]` | Wazuh | `hostname.exe` control evaluated | Archive plus rule `100132` query | Image condition tested |
| `[TIME]` | WIN11 | Markers removed | `Test-Path` results | Cleanup confirmed |

## Expected findings

### Outcome

Sysmon and Wazuh captured the process created through WMI. The final custom rule identified the `WmiPrvSE.exe` lineage, elevated the alert when WMI spawned `cmd.exe`, and mapped the behavior to T1047.

### Detection meaning

The decisive signal is not merely that WMI was queried. It is that the WMI provider host created a process, preserving a parent-child relationship that can be combined with the image, command line, user, integrity level, and subsequent activity.

### Expected limitation

Legitimate software-management, monitoring, administrative, and security tools can create processes through WMI. The alert requires environment-specific tuning and should not be treated as proof of malicious activity.

## Detection engineering analysis

### Detection strengths

- Uses parent-child process lineage rather than a deprecated utility name.
- Works when WMI is invoked through PowerShell/CIM instead of `wmic.exe`.
- Retains complete command-line, user, integrity, hash, and process-identifier context.
- Separates baseline WMI process creation from interpreter-based actions.

### Likely false positives

- endpoint-management platforms;
- inventory and monitoring agents;
- software deployment systems;
- administrative scripts;
- security tools and support utilities.

### Recommended improvements

- baseline known WMI-spawned images and service accounts;
- increase severity for encoded commands, user-writable paths, remote content, or unexpected privileged users;
- correlate with WMI Activity Operational events when available;
- correlate with network authentication when testing authorized remote WMI later;
- add time-bound allowlists for approved management tools rather than suppressing all WMI lineage.

## Completion checklist

- [ ] WMI, Sysmon, and Wazuh services verified
- [ ] Initial timestamp recorded
- [ ] Positive WMI method returned `0`
- [ ] Marker file and SHA-256 captured
- [ ] Local Sysmon Event ID 1 found
- [ ] `WmiPrvSE.exe` parent verified
- [ ] Raw Wazuh event found
- [ ] Required fields recorded
- [ ] Rule ID `100132` confirmed unused
- [ ] Rule configuration validated
- [ ] Fresh positive event generated after restart
- [ ] Rule `100132` fired
- [ ] T1047 mapping confirmed
- [ ] Negative control archived without rule `100132`
- [ ] Alert JSON exported
- [ ] Marker files removed
- [ ] Screenshots saved with matching filenames
