# T1552 Credentials in Files Detection Lab

## Objective

Validate detection of a credential-oriented file search using a clearly fake marker, confirm Sysmon and Wazuh visibility, test a non-credential search with identical process lineage, and remove every test artifact.

## Safety boundaries

- Use only the isolated WIN11 lab endpoint.
- Never use a real username, password, token, API key, or production file.
- Label the marker `NOT_A_REAL_PASSWORD_T1552`.
- Restrict searches to `C:\ProgramData\T1552-Portfolio-Lab`.
- Remove the directory after positive validation and again after the control.

## Environment

| Component | Value |
|---|---|
| Endpoint | `WIN11.corp.local` |
| User | `CORP\Administrator` |
| Manager | `wazuh-manager`, Wazuh `4.14.6` |
| Primary telemetry | Sysmon Event ID `1` |
| Positive process | `findstr.exe` |
| Positive record | `24074` |
| Control record | `24084` |
| Detection | Rule `100220`, level `11` |

## Phase 1: Readiness and baseline

```powershell
$LabDirectory = 'C:\ProgramData\T1552-Portfolio-Lab'
$LabFile      = Join-Path $LabDirectory 'benign-config.txt'

Get-Date -Format o
Get-Service WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
    Select-Object TimeCreated, Id, RecordId

[PSCustomObject]@{
    DirectoryExists = Test-Path $LabDirectory
    FileExists      = Test-Path $LabFile
}
```

Expected: Wazuh running, current Sysmon events, and both paths absent.

## Phase 2: Create a fake marker and execute the positive search

```powershell
New-Item -ItemType Directory -Path $LabDirectory -Force | Out-Null

@'
application=security-portfolio-demo
password=NOT_A_REAL_PASSWORD_T1552
owner=security-lab
'@ | Set-Content -Path $LabFile -Encoding ASCII

Get-FileHash $LabFile -Algorithm SHA256

$Start = Get-Date

findstr.exe /s /i /n \
    "password secret token" \
    "$LabDirectory\*.txt"

Start-Sleep 3

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $Start
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match 'findstr\.exe' -and
    $_.Message -match 'password'
} |
Select-Object TimeCreated, Id, RecordId, Message |
Format-List
```

Expected: only the fake line is displayed and Sysmon Event `1` records the command.

## Phase 3: Validate Wazuh

```text
agent.name:"WIN11" AND rule.id:"100220" AND data.win.system.eventRecordID:"24074"
```

Manager verification:

```bash
sudo jq -rc '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "24074") |
  {timestamp, rule, eventID: .data.win.system.eventID,
   recordID: .data.win.system.eventRecordID,
   image: .data.win.eventdata.image,
   commandLine: .data.win.eventdata.commandLine,
   parent: .data.win.eventdata.parentImage,
   user: .data.win.eventdata.user}
' /var/ossec/logs/alerts/alerts.json
```

Expected: rule `100220`, level `11`, mapped to T1552.

## Phase 4: Non-credential negative control

Remove the positive file, recreate the same path without credential terms, execute the same utility, and clean up:

```powershell
Remove-Item $LabDirectory -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $LabDirectory -Force | Out-Null

@'
application=security-portfolio-demo
status=healthy
owner=security-lab
'@ | Set-Content -Path $LabFile -Encoding ASCII

$ControlStart = Get-Date

findstr.exe /s /i /n \
    "status healthy" \
    "$LabDirectory\*.txt"

Start-Sleep 3

$ControlEvent = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $ControlStart
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match 'findstr\.exe' -and
    $_.Message -match 'status healthy'
} |
Select-Object -First 1

Remove-Item $LabDirectory -Recurse -Force -ErrorAction SilentlyContinue

[PSCustomObject]@{
    ControlCaptured = [bool]$ControlEvent
    ControlRecordId = $ControlEvent.RecordId
    LabRemoved      = -not (Test-Path $LabDirectory)
}
```

Expected: record `24084`, `ControlCaptured = True`, and `LabRemoved = True`.

Confirm the control exists in archives but not alerts:

```bash
sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "24084")
' /var/ossec/logs/archives/archives.json

sudo jq -r '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "24084") |
  .rule.id
' /var/ossec/logs/alerts/alerts.json | wc -l
```

Expected alert count: `0`.

## Phase 5: Export evidence

```bash
sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "24074")
' /var/ossec/logs/alerts/alerts.json \
  > /home/wazuh/t1552-positive-alert-24074.json

sudo jq -c '
  select(.agent.name == "WIN11") |
  select(.data.win.system.eventRecordID == "24084")
' /var/ossec/logs/archives/archives.json \
  > /home/wazuh/t1552-negative-control-24084.json
```

## Completion checklist

- [x] Clean baseline confirmed
- [x] Only a clearly fake marker created
- [x] Search restricted to the lab directory
- [x] Sysmon Event `1`, record `24074`, captured
- [x] Rule `100220`, level `11`, generated
- [x] T1552 mapping confirmed
- [x] Raw positive JSON exported
- [x] Same utility and parent used for control
- [x] Control record `24084` confirmed in archives
- [x] Zero alert matches for control record
- [x] Raw control JSON exported
- [x] Lab directory and fake file removed
