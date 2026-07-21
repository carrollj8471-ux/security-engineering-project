# T1082 System Information Discovery Detection Lab

## Objective

Validate Sysmon and Wazuh visibility for Windows system-information discovery, confirm ATT&CK T1082 enrichment, and demonstrate that a nearby discovery utility is routed to its own analytic.

## Safety boundaries

- Run only built-in read-only commands.
- Do not change system configuration, services, users, or network settings.
- Use `systeminfo.exe` for the positive test and `whoami.exe` for the control.

## Environment

| Component | Value |
|---|---|
| Endpoint | `WIN11.corp.local` |
| Agent | `WIN11`, ID `002` |
| Manager | `wazuh-manager`, Wazuh `4.14.6` |
| Primary event | Sysmon Event ID `1` |
| Positive rule | `100201`, level `8` |
| Control rule | `100206`, level `8`, T1087 |

## Readiness and positive test

Run in PowerShell on WIN11:

```powershell
$Start = Get-Date

Get-Service WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
    Select-Object TimeCreated, Id, RecordId

systeminfo.exe

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $Start
} |
Where-Object Message -Match 'systeminfo\.exe' |
Select-Object TimeCreated, Id, RecordId, Message |
Format-List
```

Expected local result: Sysmon Event `1` with `systeminfo.exe`, command line, user, hashes, integrity, and parent process.

## Manager validation

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventID == "1") |
  select(.data.win.system.eventRecordID == "23967") |
  {timestamp, rule, recordID: .data.win.system.eventRecordID,
   image: .data.win.eventdata.image,
   commandLine: .data.win.eventdata.commandLine,
   parent: .data.win.eventdata.parentImage,
   user: .data.win.eventdata.user}
' /var/ossec/logs/alerts/alerts.json
```

Threat Hunting query:

```text
agent.name:"WIN11" AND rule.id:"100201" AND data.win.system.eventRecordID:"23967"
```

Expected: one rule `100201`, level `8` alert mapped to T1082.

## Negative control

Run on WIN11:

```powershell
$ControlStart = Get-Date
whoami.exe
$ControlStart
```

Confirm the control event arrived:

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "23978") |
  {timestamp, rule, recordID: .data.win.system.eventRecordID,
   image: .data.win.eventdata.image,
   parent: .data.win.eventdata.parentImage,
   user: .data.win.eventdata.user}
' /var/ossec/logs/alerts/alerts.json
```

Expected: the control is detected by rule `100206` as T1087 Account Discovery, not by T1082 rule `100201`.

Verify the T1082 exclusion:

```text
agent.name:"WIN11" AND rule.id:"100201" AND data.win.eventdata.image:*whoami.exe
```

Expected: no results.

## Export evidence

```bash
sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "23967")
' /var/ossec/logs/alerts/alerts.json \
  > /home/wazuh/t1082-positive-alert-23967.json

sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "23978")
' /var/ossec/logs/alerts/alerts.json \
  > /home/wazuh/t1082-negative-whoami-23978.json
```

## Rule validation and hygiene

```bash
sudo grep -R -n --include='*.xml' 'id="100201"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules

sudo /var/ossec/bin/wazuh-analysisd -t
```

The lab currently contains duplicate ID `100201` in `mitre_detection_rules.xml` and `mitre_sysmon_rules.xml`. The loaded first occurrence produced the validated alert, but the duplicate should be removed or renumbered before production use.

## Completion checklist

- [x] Wazuh and Sysmon readiness confirmed
- [x] Safe `systeminfo.exe` simulation executed
- [x] Local Sysmon Event `1`, record `23967`, captured
- [x] Wazuh alert `100201` generated
- [x] T1082 mapping and level `8` verified
- [x] Raw positive JSON exported
- [x] `whoami.exe` control executed
- [x] Control record `23978` collected
- [x] Control routed to T1087 rule `100206`
- [x] No T1082 alert generated for the control
- [x] Raw control JSON exported
- [x] Duplicate rule-ID finding documented
