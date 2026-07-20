# T1007 System Service Discovery Detection Lab

> **Implementation note:** The validated design extends the two Wazuh rules that initially process the Atomic test: rule `100205` for `tasklist.exe /svc` and rule `92032` for `sc.exe query`. The observed troubleshooting sequence is documented in `README.md`.

## Portfolio objective

Safely enumerate Windows services, confirm Sysmon and Wazuh visibility, identify existing rule coverage, add accurate T1007 classification, validate positive and negative cases, export raw alerts, and clean up the lab.

## MITRE ATT&CK mapping

| Attribute | Value |
|---|---|
| Technique | `T1007 – System Service Discovery` |
| Tactic | Discovery |
| Positive commands | `tasklist.exe /svc`, `sc.exe query` |
| Primary telemetry | Sysmon Event ID `1` |

## Lab environment

| Component | Value |
|---|---|
| Endpoint | `WIN11` |
| Wazuh agent | `WIN11`, agent `002` |
| User | `CORP\Administrator` |
| Simulation framework | Atomic Red Team |
| Atomics path | `C:\AtomicRedTeam\atomics` |
| Wazuh manager | `wazuh-manager` |

## Safety boundaries

- Run only on WIN11 in the isolated lab.
- Take a VM snapshot before testing.
- Review the Atomic test before execution.
- Execute one test at a time.
- Do not start, stop, create, modify, or delete services.
- Run Atomic cleanup and verify no test processes remain.

## Detection hypothesis

Sysmon should record service enumeration as process creation. Wazuh should collect the image and command line. Argument-aware children of the existing rule paths should map `/svc` and `query` behavior to T1007 while excluding ordinary execution of the same binaries.

## Phase 1: Verify readiness

In Administrator PowerShell on WIN11:

```powershell
Get-Date -Format o

Get-Service Sysmon, Sysmon64, WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object TimeCreated, Id, ProviderName

$ScPath = "$env:WINDIR\System32\sc.exe"

Get-Item $ScPath |
    Select-Object FullName, Length, LastWriteTimeUtc

Get-FileHash -Path $ScPath -Algorithm SHA256
Get-Date -Format o
```

Confirm Sysmon and Wazuh are running, Sysmon is generating events, and `sc.exe` exists and hashes successfully.

## Phase 2: Review the Atomic test and prerequisites

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module Invoke-AtomicRedTeam -Force
$AtomicsPath = "C:\AtomicRedTeam\atomics"

Test-Path $AtomicsPath

Invoke-AtomicTest T1007 `
    -PathToAtomicsFolder $AtomicsPath `
    -ShowDetailsBrief

Invoke-AtomicTest T1007 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1 `
    -CheckPrereqs
```

Do not execute until the test details confirm that it only enumerates services.

## Phase 3: Execute T1007

```powershell
$Start = Get-Date

Invoke-AtomicTest T1007 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1

$End = Get-Date

[PSCustomObject]@{
    StartTime = $Start.ToString("o")
    EndTime   = $End.ToString("o")
}
```

Record each command executed by the Atomic test. The validated test produced `tasklist.exe /svc`, `sc query`, and `sc query state= all`.

## Phase 4: Confirm local Sysmon telemetry

```powershell
$ServiceEvents = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $Start
    EndTime   = $End.AddMinutes(1)
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match "(?i)\\(sc|tasklist|net)\.exe" -or
    $_.Message -match "(?i)(sc(\.exe)?\s+query|tasklist(\.exe)?\s+/svc|net(\.exe)?\s+start)"
} |
Select-Object -First 5

$ServiceEvents |
    Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

Record image, command line, parent, user, integrity level, process identifiers, hashes, and timestamp.

## Phase 5: Hunt in Wazuh before adding rules

Set the time range to cover the execution and search progressively:

```text
agent.name:"WIN11" AND data.win.system.eventID:"1"
```

```text
agent.name:"WIN11" AND data.win.system.eventID:"1" AND (data.win.eventdata.image:*sc.exe OR data.win.eventdata.image:*tasklist.exe OR data.win.eventdata.image:*net.exe)
```

```text
agent.name:"WIN11" AND (data.win.eventdata.commandLine:*query* OR data.win.eventdata.commandLine:*/svc*)
```

Open matching events and record all `data.win.eventdata.*`, `rule.*`, and `rule.mitre.*` fields.

On the manager, compare archives and alerts:

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventID == "1") |
  select((.data.win.eventdata.image // "") |
    test("\\\\(sc|tasklist|net)\\.exe$"; "i")) |
  {timestamp, rule, image: .data.win.eventdata.image,
   commandLine: .data.win.eventdata.commandLine,
   parentImage: .data.win.eventdata.parentImage,
   recordID: .data.win.system.eventRecordID}
' /var/ossec/logs/archives/archives.json |
tail -8
```

An archive record proves collection. An alert record proves rule promotion.

## Phase 6: Inspect the active rule paths

The validated environment produced:

- `tasklist.exe /svc` under rule `100205`;
- `sc.exe query` under rule `92032`.

Locate the rules and confirm the proposed IDs are unused:

```bash
sudo grep -R -n --include='*.xml' \
  -E 'id="(100170|100171|100205|92032)"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules
```

Do not create a duplicate standalone baseline when an existing winning rule can be extended.

## Phase 7: Install the final custom rules

Back up and edit the active custom file:

```bash
sudo cp /var/ossec/etc/rules/mitre_detection_rules.xml \
  /var/ossec/etc/rules/mitre_detection_rules.xml.bak-t1007-$(date +%Y%m%d-%H%M%S)

sudo nano /var/ossec/etc/rules/mitre_detection_rules.xml
```

Place these rules inside the existing group after rule `100205`:

```xml
<rule id="100170" level="7">
  <if_sid>100205</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\tasklist\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\s/svc(?:\s|$)</field>
  <description>Windows services enumerated with tasklist</description>
  <mitre>
    <id>T1007</id>
  </mitre>
  <group>discovery,service_discovery,</group>
</rule>

<rule id="100171" level="7">
  <if_sid>92032</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\sc\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\bquery\b</field>
  <description>Windows services enumerated with sc.exe</description>
  <mitre>
    <id>T1007</id>
  </mitre>
  <group>discovery,service_discovery,</group>
</rule>
```

Validate and activate:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager

sudo grep -R -n --include='*.xml' -E 'id="(100170|100171)"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules
```

Each ID must appear once. Do not restart if validation reports a new error involving either rule.

## Phase 8: Positive validation

Generate fresh events:

```powershell
$ValidationStart = Get-Date

Invoke-AtomicTest T1007 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1

$ValidationEnd = Get-Date
```

Search Wazuh:

```text
agent.name:"WIN11" AND rule.mitre.id:"T1007"
```

```text
agent.name:"WIN11" AND (rule.id:"100170" OR rule.id:"100171")
```

Confirm:

- one `100170` result for `tasklist.exe /svc`;
- two `100171` results for the `sc.exe query` variants;
- level `7`;
- T1007 and Discovery metadata;
- correct parent, user, record ID, and command line.

## Phase 9: Negative control

Execute the same utilities without discovery-specific arguments:

```powershell
$ControlStart = Get-Date

tasklist.exe
sc.exe

$ControlEnd = Get-Date
```

Search for incorrect matches:

```text
agent.name:"WIN11" AND rule.id:"100170" AND NOT data.win.eventdata.commandLine:*/svc*
```

```text
agent.name:"WIN11" AND rule.id:"100171" AND NOT data.win.eventdata.commandLine:*query*
```

Both queries should return no control-time result. Correlate by timestamp so earlier positive events are not mistaken for failures.

## Phase 10: Export alerts and clean up

Export one raw alert per rule:

```bash
sudo grep -F '"id":"100170"' /var/ossec/logs/alerts/alerts.json |
  tail -1 |
  jq . > /home/wazuh/16-positive-t1007-tasklist-rule-100170.json

sudo grep -F '"id":"100171"' /var/ossec/logs/alerts/alerts.json |
  tail -1 |
  jq . > /home/wazuh/17-positive-t1007-sc-rule-100171.json
```

Run cleanup on WIN11:

```powershell
Invoke-AtomicTest T1007 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1 `
    -Cleanup

Get-Process sc, tasklist -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime

Get-Date -Format o
```

The test should leave no persistent artifacts and no discovery processes running.

## Completion checklist

- [ ] Readiness confirmed
- [ ] Atomic details reviewed
- [ ] Prerequisites checked
- [ ] T1007 test executed once
- [ ] Local Sysmon Event ID `1` captured
- [ ] Wazuh collection confirmed
- [ ] Initial rule paths documented
- [ ] IDs `100170` and `100171` verified as unique
- [ ] Rules validated and manager active
- [ ] Fresh positive alerts generated
- [ ] T1007 mapping confirmed
- [ ] Both negative controls passed
- [ ] Raw alert JSON files exported
- [ ] Atomic cleanup completed
- [ ] No test processes remained
