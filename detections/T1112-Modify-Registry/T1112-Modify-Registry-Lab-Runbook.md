# T1112 Modify Registry Detection Lab

## Objective

Safely validate a monitored Windows registry modification, confirm Sysmon and Wazuh visibility, enrich a Run-key alert with MITRE ATT&CK T1112, test a read-only control, and remove every test artifact.

## Safety boundaries

- Use only the isolated WIN11 lab endpoint.
- Start with an unmonitored portfolio-only HKCU key.
- Do not replace or weaken the Sysmon configuration.
- Use the existing HKCU Run key only after confirming it is monitored.
- Point the temporary value to `cmd.exe /c exit` and do not sign out or restart while it exists.
- Remove the value immediately after local Event `13` capture.

## Environment

| Component | Value |
|---|---|
| Endpoint | `WIN11.corp.local` |
| User | `CORP\Administrator` |
| Manager | `wazuh-manager`, Wazuh `4.14.6` |
| Primary telemetry | Sysmon Event ID `13` |
| Positive record | `24052` |
| Parent rule | `100141`, level `8`, T1547.001 |
| Final rule | `100212`, level `10`, T1112 and T1547.001 |

## Phase 1: Readiness and clean baseline

```powershell
$LabKey = 'HKCU:\Software\SecurityPortfolio\T1112'

Get-Date -Format o

Get-Service WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
    Select-Object TimeCreated, Id, RecordId

Test-Path $LabKey
```

Expected: Wazuh running, recent Sysmon events, and `False` for the test key.

## Phase 2: Establish the telemetry boundary

Create a benign value in the portfolio-only key and query Events `12–14`. On this lab, the write succeeds but produces no matching RegistryEvent because the active Sysmon configuration uses selective includes.

```powershell
$Start = Get-Date
New-Item -Path $LabKey -Force | Out-Null
New-ItemProperty -Path $LabKey -Name PortfolioMarker \
    -PropertyType String -Value 'Benign-T1112-Validation' -Force

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 12,13,14
    StartTime = $Start
} -ErrorAction SilentlyContinue |
Where-Object Message -Match 'SecurityPortfolio|PortfolioMarker' |
Format-List
```

Preserve the empty result as a coverage finding rather than treating it as a failed write.

## Phase 3: Confirm RegistryEvent monitoring

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 12,13,14
} -MaxEvents 20 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, RecordId, Message |
Format-List

Get-CimInstance Win32_Service |
Where-Object Name -Match '^Sysmon' |
Select-Object Name, State, StartMode, PathName
```

Existing Event `13` records prove RegistryEvent is enabled but filtered. Do not replace the configuration.

## Phase 4: Monitored positive test

Use the existing HKCU Run key and remove the value immediately after capture:

```powershell
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Start  = Get-Date

New-ItemProperty $RunKey \
    -Name 'T1112PortfolioValidation' \
    -PropertyType String \
    -Value 'C:\Windows\System32\cmd.exe /c exit' \
    -Force | Out-Null

Start-Sleep 3

$Event = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 13
    StartTime = $Start
} |
Where-Object Message -Match 'T1112PortfolioValidation' |
Select-Object -First 1

Remove-ItemProperty $RunKey \
    -Name 'T1112PortfolioValidation' \
    -ErrorAction SilentlyContinue

[PSCustomObject]@{
    EventRecordId = $Event.RecordId
    ValueRemoved  = -not [bool](
        Get-ItemProperty $RunKey \
            -Name 'T1112PortfolioValidation' \
            -ErrorAction SilentlyContinue
    )
}
```

Expected final result: Event record ID present and `ValueRemoved = True`.

## Phase 5: Identify and repair the Wazuh hierarchy

The first event is handled by rule `100141`. The original `100212` used nonexistent group `sysmon_event13` and was ignored. A cross-file child also failed to promote the event. Move `100212` immediately after `100141` inside the same `local_rules.xml` group, using the rule in `detection-rules.xml`.

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak-t1112-$(date +%Y%m%d-%H%M%S)

sudo grep -R -n --include='*.xml' -E 'id="(100141|100212)"' \
  /var/ossec/etc/rules

sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Generate fresh activity after every rule change.

## Phase 6: Positive validation

```text
agent.name:"WIN11" AND rule.id:"100212"
```

Expected: one level `10` alert with T1112 and T1547.001. Validated record: `24052` at `2026-07-20T22:34:26.089-0400`.

## Phase 7: Read-only negative control

```powershell
$ControlStart = Get-Date
reg.exe query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'

[PSCustomObject]@{
    TestValueAbsent = -not [bool](
        Get-ItemProperty \
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' \
            -Name 'T1112PortfolioValidation' \
            -ErrorAction SilentlyContinue
    )
}
```

Because this command only reads the registry, no Sysmon registry-modification Event `13` is expected. Confirm no T1112 modification alert:

```text
agent.name:"WIN11" AND rule.id:"100212" AND data.win.eventdata.image:*reg.exe
```

Expected: no results.

## Phase 8: Cleanup

```powershell
Remove-ItemProperty \
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' \
    -Name 'T1112PortfolioValidation' \
    -ErrorAction SilentlyContinue

Remove-Item 'HKCU:\Software\SecurityPortfolio\T1112' \
    -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item 'C:\ProgramData\T1112-sysmon-current-config.txt' \
    -Force -ErrorAction SilentlyContinue
```

## Completion checklist

- [x] Clean baseline confirmed
- [x] Portfolio-only registry write executed
- [x] Initial Sysmon coverage gap documented
- [x] Selective RegistryEvent monitoring confirmed
- [x] Monitored Run-key write generated Event `13`
- [x] Initial winning rule `100141` identified
- [x] Invalid `sysmon_event13` dependency removed
- [x] Child rule placed beside active parent
- [x] Fresh record `24052` generated
- [x] Rule `100212`, level `10`, validated
- [x] T1112 and T1547.001 mappings confirmed
- [x] Raw positive JSON exported
- [x] Read-only query produced no modification alert
- [x] Temporary value and files removed
