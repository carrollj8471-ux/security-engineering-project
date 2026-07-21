# T1078 Valid Accounts Detection Lab

## Objective

Validate collection and alerting for Windows explicit-credential use, map the behavioral signal to MITRE ATT&CK T1078, and distinguish RunAs/Secondary Logon activity from routine session authentication.

## Safety boundaries

- Use only existing authorized lab accounts.
- Do not create users, change passwords, enable remote services, or intentionally cause lockouts.
- Enter a valid password once per positive attempt.
- Use a transient `whoami` child process and create no durable artifacts.

## Environment

| Component | Value |
|---|---|
| Endpoint | `WIN11.corp.local` |
| Agent | `WIN11`, ID `002`, `192.168.232.134` |
| Manager | `wazuh-manager`, Wazuh `4.14.6` |
| Security audit policy | Logon success and failure enabled |
| Primary event | Security Event ID `4648` |
| Built-in parent | Rule `60103` — Windows audit success event |
| Custom rule | `100192`, level `8` |

## Readiness

Run on WIN11:

```powershell
Get-Date -Format o
$env:COMPUTERNAME
whoami

Get-Service WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

auditpol /get /subcategory:"Logon"

Get-WinEvent -ListLog Security |
    Select-Object LogName, IsEnabled, RecordCount
```

Expected: Wazuh agent running, Security log enabled, and Logon auditing configured for success and failure.

## Baseline collection check

Review recent authentication events locally:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624,4625,4648
} -MaxEvents 10 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, RecordId, Message |
Format-List
```

Confirm Event `4648` reaches manager archives:

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventID == "4648") |
  {timestamp, recordID: .data.win.system.eventRecordID,
   subject: .data.win.eventdata.subjectUserName,
   target: .data.win.eventdata.targetUserName,
   process: .data.win.eventdata.processName,
   ip: .data.win.eventdata.ipAddress}
' /var/ossec/logs/archives/archives.json | tail -10
```

If Threat Hunting is empty while archives contain the event, collection works and alert coverage is missing.

## Install the rule

Verify the ID is unused, back up the active file, and add the rule from `detection-rules.xml` before its final `</group>`:

```bash
sudo grep -R -n --include='*.xml' 'id="100192"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules

sudo cp /var/ossec/etc/rules/mitre_detection_rules.xml \
  /var/ossec/etc/rules/mitre_detection_rules.xml.bak-t1078-$(date +%Y%m%d-%H%M%S)

sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Do not restart if validation reports an error.

## Positive test

From an elevated PowerShell session on WIN11:

```powershell
$PositiveStart = Get-Date
runas /user:CORP\alice.johnson "cmd.exe /c whoami"
```

Enter the valid password once. Search Wazuh:

```text
agent.name:"WIN11" AND rule.id:"100192"
```

Expected: one level `8` alert containing Event `4648`, the source and target accounts, `svchost.exe` or `runas.exe`, and T1078 enrichment.

## Negative control

Use a fresh, naturally occurring Event `4648` attributed to `lsass.exe`, such as session unlock/authentication. Confirm the record in archives and use its record ID for the alert check:

```bash
CONTROL_RECORD="306538"

sudo jq -c --arg record "$CONTROL_RECORD" '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == $record)
' /var/ossec/logs/archives/archives.json

sudo jq -r --arg record "$CONTROL_RECORD" '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == $record) |
  .rule.id
' /var/ossec/logs/alerts/alerts.json | wc -l
```

Expected: the archive record shows Event `4648` and `lsass.exe`; the alert count is `0`.

## Export evidence

```bash
sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.rule.id == "100192")
' /var/ossec/logs/alerts/alerts.json | tail -1 \
  > /home/wazuh/t1078-positive-alert.json

sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "306538")
' /var/ossec/logs/archives/archives.json \
  > /home/wazuh/t1078-negative-lsass-archive.json
```

## Completion checklist

- [x] Security auditing and agent readiness confirmed
- [x] Local Event `4648` observed
- [x] Archive collection confirmed
- [x] Initial alert gap documented
- [x] Active parent rule `60103` identified
- [x] Rule `100192` validated and activated
- [x] Fresh positive alert generated
- [x] T1078 mapping confirmed
- [x] Fresh LSASS negative control archived
- [x] No alert found for control record `306538`
- [x] Positive and negative raw JSON exported
- [x] No durable endpoint artifact created
