# T1016 System Network Configuration Discovery Detection Lab

> **Implementation note:** The validated environment preserves existing rule `100203` for ipconfig and ARP activity. It extends active rules `100208`, `92032`, and `92036` for netsh, nbtstat, and net config. Rule `100180` must appear after custom parent `100208` in the loaded XML file.

## Portfolio objective

Safely enumerate Windows network configuration, validate Sysmon and Wazuh visibility, identify existing rule coverage, fill the T1016 classification gaps, test positive and negative cases, export raw alerts, and document cleanup.

## MITRE ATT&CK mapping

| Attribute | Value |
|---|---|
| Technique | `T1016 – System Network Configuration Discovery` |
| Tactic | Discovery |
| Positive commands | `ipconfig /all`, `netsh interface show interface`, `arp -a`, `nbtstat -n`, `net config` |
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
- Do not change interface, route, DNS, DHCP, VPN, or firewall configuration.
- Use only read-only discovery commands.
- Run cleanup and confirm no unexpected process or artifact remains.

## Detection hypothesis

Sysmon should record the native discovery commands as process creation. Wazuh should retain their image, command line, parent, and user. Argument-aware children of the active rule paths should map uncovered behavior to T1016 while excluding help-only executions.

## Phase 1: Verify readiness

In Administrator PowerShell on WIN11:

```powershell
Get-Date -Format o

Get-Service Sysmon, Sysmon64, WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object TimeCreated, Id, ProviderName

$Utilities = "ipconfig.exe", "netsh.exe", "arp.exe", "nbtstat.exe", "net.exe"

$Utilities | ForEach-Object {
    Get-Item "$env:WINDIR\System32\$_" -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTimeUtc
}

Get-Date -Format o
```

Confirm Sysmon and Wazuh are running and the signed Windows utilities are present.

## Phase 2: Review the Atomic test and prerequisites

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module Invoke-AtomicRedTeam -Force
$AtomicsPath = "C:\AtomicRedTeam\atomics"

Test-Path $AtomicsPath

Invoke-AtomicTest T1016 `
    -PathToAtomicsFolder $AtomicsPath `
    -ShowDetailsBrief

Invoke-AtomicTest T1016 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1 `
    -CheckPrereqs
```

Review the exact commands and confirm they only display local configuration.

## Phase 3: Execute T1016

```powershell
$Start = Get-Date

Invoke-AtomicTest T1016 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1

$End = Get-Date

[PSCustomObject]@{
    StartTime = $Start.ToString("o")
    EndTime   = $End.ToString("o")
}
```

The validated test produced `ipconfig /all`, `netsh interface show interface`, `arp -a`, `nbtstat -n`, and `net config`.

## Phase 4: Confirm local Sysmon telemetry

```powershell
$Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $Start
    EndTime   = $End.AddMinutes(1)
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match "(?i)\\(ipconfig|netsh|arp|nbtstat|net)\.exe" -or
    $_.Message -match "(?i)(interface\s+show|nbtstat\s+-n|net\s+config)"
} |
Select-Object -First 15

$Events | Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

Record the image, full command, parent, user, integrity level, process IDs, hashes, and timestamp.

## Phase 5: Hunt in Wazuh before adding rules

Set the time range to cover the test and search:

```text
agent.name:"WIN11" AND data.win.system.eventID:"1"
```

```text
agent.name:"WIN11" AND (data.win.eventdata.image:*ipconfig.exe OR data.win.eventdata.image:*netsh.exe OR data.win.eventdata.image:*arp.exe OR data.win.eventdata.image:*nbtstat.exe OR data.win.eventdata.image:*net.exe)
```

```text
agent.name:"WIN11" AND (data.win.eventdata.commandLine:*interface show* OR data.win.eventdata.commandLine:*-n* OR data.win.eventdata.commandLine:*config*)
```

On the manager, compare archives and alerts:

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventID == "1") |
  select((.data.win.eventdata.image // "") |
    test("\\\\(ipconfig|netsh|arp|nbtstat|net)\\.exe$"; "i")) |
  {timestamp, rule, recordID: .data.win.system.eventRecordID,
   image: .data.win.eventdata.image,
   commandLine: .data.win.eventdata.commandLine,
   parentImage: .data.win.eventdata.parentImage}
' /var/ossec/logs/archives/archives.json |
tail -15
```

Archive presence proves collection; an entry in `alerts.json` proves rule promotion.

## Phase 6: Inspect active rule paths

The validated environment used:

- rule `100203` for `ipconfig /all` and `arp -a`;
- rule `100208` for the parent `cmd.exe` netsh command;
- rule `92032` for `nbtstat -n`;
- rule `92036` for `net config`.

Locate them and confirm the new IDs are unique:

```bash
sudo grep -R -n --include='*.xml' \
  -E 'id="(100180|100181|100182|100203|100208|92032|92036)"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules
```

Do not duplicate coverage already provided by `100203`.

## Phase 7: Install the final rules

Back up the active custom file:

```bash
sudo cp /var/ossec/etc/rules/mitre_detection_rules.xml \
  /var/ossec/etc/rules/mitre_detection_rules.xml.bak-t1016-$(date +%Y%m%d-%H%M%S)

sudo nano /var/ossec/etc/rules/mitre_detection_rules.xml
```

Place rule `100180` immediately after custom parent `100208`. Add `100181` and `100182` inside the loaded group:

```xml
<rule id="100180" level="8">
  <if_sid>100208</if_sid>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\bnetsh(?:\.exe)?\s+interface\s+show\b</field>
  <description>Windows network interfaces enumerated with netsh</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>

<rule id="100181" level="8">
  <if_sid>92032</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\nbtstat\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\s-n(?:\s|$)</field>
  <description>Local NetBIOS configuration enumerated with nbtstat</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>

<rule id="100182" level="8">
  <if_sid>92036</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\net\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\bconfig\b</field>
  <description>Windows network configuration enumerated with net.exe</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>
```

Validate and activate:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager

sudo grep -n -E 'id="(100180|100181|100182|100208)"' \
  /var/ossec/etc/rules/mitre_detection_rules.xml
```

Each new ID must occur once, and `100180` must be below `100208`.

## Phase 8: Positive validation and netsh troubleshooting

Generate fresh events after the restart:

```powershell
$ValidationStart = Get-Date

cmd.exe /c "netsh interface show interface"
cmd.exe /c "nbtstat -n"
cmd.exe /c "net config"

$ValidationEnd = Get-Date
```

Search:

```text
agent.name:"WIN11" AND (rule.id:"100180" OR rule.id:"100181" OR rule.id:"100182")
```

Expected:

- `100180` for the parent `cmd.exe /c "netsh interface show interface"` command;
- `100181` for `nbtstat.exe -n`;
- `100182` for `net.exe config`;
- level `8` and T1016/Discovery metadata.

If `100181` and `100182` fire but `100180` does not:

1. Confirm the child `netsh.exe` event exists in `archives.json`.
2. Inspect which rule wins for the parent `cmd.exe` event.
3. Confirm `100180` inherits from that parent (`100208` in this environment).
4. Confirm `100180` appears after `100208` in the XML file.
5. Validate, restart, and generate another fresh event.

Do not repeatedly change regexes before confirming hierarchy and rule order.

## Phase 9: Negative control

Run help-only variants:

```powershell
$ControlStart = Get-Date

cmd.exe /c "netsh /?"
cmd.exe /c "nbtstat /?"
cmd.exe /c "net /?"

$ControlEnd = Get-Date
```

Search for incorrect results correlated to the control window:

```text
agent.name:"WIN11" AND rule.id:"100180" AND NOT data.win.eventdata.commandLine:*interface show*
```

```text
agent.name:"WIN11" AND rule.id:"100181" AND NOT data.win.eventdata.commandLine:*-n*
```

```text
agent.name:"WIN11" AND rule.id:"100182" AND NOT data.win.eventdata.commandLine:*config*
```

All three should return no control-time result.

## Phase 10: Export alerts and clean up

Export one raw alert per new rule:

```bash
sudo grep -F '"id":"100180"' /var/ossec/logs/alerts/alerts.json |
  tail -1 | jq . > /home/wazuh/23-positive-t1016-netsh-rule-100180.json

sudo grep -F '"id":"100181"' /var/ossec/logs/alerts/alerts.json |
  tail -1 | jq . > /home/wazuh/24-positive-t1016-nbtstat-rule-100181.json

sudo grep -F '"id":"100182"' /var/ossec/logs/alerts/alerts.json |
  tail -1 | jq . > /home/wazuh/25-positive-t1016-net-config-rule-100182.json
```

Run Atomic cleanup and verify no relevant processes remain:

```powershell
Invoke-AtomicTest T1016 `
    -PathToAtomicsFolder $AtomicsPath `
    -TestNumbers 1 `
    -Cleanup

Get-Process ipconfig, netsh, arp, nbtstat, net -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime

Get-Date -Format o
```

These commands are read-only and should not create persistent configuration changes. Preserve a cleanup screenshot when reproducing the lab.

## Completion checklist

- [ ] Readiness confirmed
- [ ] Atomic details reviewed
- [ ] Prerequisites checked
- [ ] T1016 test executed once
- [ ] Local Sysmon Event ID `1` captured
- [ ] Wazuh collection confirmed
- [ ] Existing rule `100203` coverage documented
- [ ] Active parent rules identified
- [ ] IDs `100180–100182` verified unique
- [ ] Rule `100180` placed after `100208`
- [ ] Rules validated and manager active
- [ ] Three fresh positive alerts generated
- [ ] T1016 mapping confirmed
- [ ] Three negative controls passed
- [ ] Raw alert JSON files exported
- [ ] Atomic cleanup executed
- [ ] Cleanup evidence captured
