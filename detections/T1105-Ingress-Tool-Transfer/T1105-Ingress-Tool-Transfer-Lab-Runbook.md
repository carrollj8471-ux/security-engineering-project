# T1105 Ingress Tool Transfer Detection Lab

## Portfolio objective

Validate a benign HTTP file transfer from a lab server to WIN11, identify the telemetry available in Sysmon and PowerShell logging, confirm Wazuh collection, implement an ATT&CK-mapped detection, test its precision, and remove all artifacts.

## MITRE ATT&CK mapping

| Attribute | Value |
|---|---|
| Technique | `T1105 – Ingress Tool Transfer` |
| Tactic | Command and Control |
| Positive behavior | PowerShell retrieves a file and writes it with `-OutFile` |
| Negative control | PowerShell retrieves content without writing a file |

## Lab environment

| Role | Value |
|---|---|
| Windows endpoint | `WIN11` |
| Wazuh manager/server | `192.168.232.20` |
| Temporary HTTP port | `8000` |
| Source directory | `/home/wazuh/t1105-lab` |
| Source file | `benign-transfer.txt` |
| Destination | `C:\ProgramData\T1105-benign-transfer.txt` |
| Primary event | PowerShell Event ID `4104` |
| Supporting event | Sysmon Event ID `3` |

## Safety boundaries

- Use only the isolated lab network.
- Host only the benign text supplied below.
- Do not expose the HTTP service externally.
- Do not transfer or execute binaries, tools, scripts, credentials, or malware.
- Stop the server and remove all artifacts after testing.

## Detection hypothesis

PowerShell Script Block Event ID `4104` should retain `Invoke-WebRequest`. A script block containing both a transfer utility and `-OutFile` should trigger a level 8 T1105 alert. The same request without a file-output operation should remain outside the elevated condition.

## Phase 1: Prepare the benign transfer server

On the Wazuh manager:

```bash
mkdir -p /home/wazuh/t1105-lab
printf '%s\n' 'Benign T1105 ingress tool transfer validation' > /home/wazuh/t1105-lab/benign-transfer.txt
chmod 644 /home/wazuh/t1105-lab/benign-transfer.txt
ls -l /home/wazuh/t1105-lab/benign-transfer.txt
sha256sum /home/wazuh/t1105-lab/benign-transfer.txt
sudo ss -ltnp | grep ':8000'
```

Start the temporary server:

```bash
python3 -m http.server 8000 \
  --bind 192.168.232.20 \
  --directory /home/wazuh/t1105-lab
```

In a second terminal, verify the file is available:

```bash
curl -I http://192.168.232.20:8000/benign-transfer.txt
```

Do not continue until the response is HTTP `200`.

## Phase 2: Verify endpoint and network readiness

In Administrator PowerShell on WIN11:

```powershell
Get-Date -Format o

Get-Service Sysmon, Sysmon64, WazuhSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = 3, 11
} -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName

$Server = "192.168.232.20"
$Port = 8000
$Destination = "C:\ProgramData\T1105-benign-transfer.txt"

Test-NetConnection -ComputerName $Server -Port $Port
Test-Path $Destination
Get-Date -Format o
```

Confirm that the services are running, TCP succeeds, and the destination is absent.

## Phase 3: Perform the benign transfer

```powershell
$Start = Get-Date
$Uri = "http://192.168.232.20:8000/benign-transfer.txt"
$Destination = "C:\ProgramData\T1105-benign-transfer.txt"

Remove-Item $Destination -ErrorAction SilentlyContinue

Invoke-WebRequest `
    -Uri $Uri `
    -OutFile $Destination `
    -UseBasicParsing

Get-Item $Destination |
    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc

Get-Content $Destination
Get-FileHash -Path $Destination -Algorithm SHA256
Get-Date -Format o
```

Confirm the content, compare hashes, and verify the server logged a successful GET request.

If the request returns HTTP 404, verify the server process, directory, filename, and permissions. Recreate the directory and file, restart the server with the explicit `--directory` argument, and confirm HTTP 200 before retrying.

## Phase 4: Confirm local telemetry

Network telemetry:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 3
    StartTime = $Start
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match "DestinationIp:\s+192\.168\.232\.20" -and
    $_.Message -match "DestinationPort:\s+8000"
} |
Select-Object -First 1 |
Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

File-creation telemetry:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 11
    StartTime = $Start
} -ErrorAction SilentlyContinue |
Where-Object Message -Match "T1105-benign-transfer\.txt" |
Select-Object -First 1 |
Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

Script Block telemetry:

```powershell
$WindowStart = (Get-Date).AddMinutes(-30)

Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-PowerShell/Operational"
    Id        = 4104
    StartTime = $WindowStart
} -ErrorAction SilentlyContinue |
Where-Object Message -Match "Invoke-WebRequest" |
Select-Object -First 3 |
Format-List TimeCreated, Id, RecordId, ProviderName, Message
```

Preserve blank results as explicit telemetry gaps. Script blocks may contain variable names instead of resolved paths or URLs.

## Phase 5: Confirm Wazuh collection before alerting

On the manager:

```bash
sudo grep -F '"eventID":"3"' /var/ossec/logs/archives/archives.json |
  grep -F '"destinationIp":"192.168.232.20"' |
  grep -F '"destinationPort":"8000"' |
  tail -1
```

```bash
sudo grep -F '"eventID":"4104"' /var/ossec/logs/archives/archives.json |
  grep -F 'Invoke-WebRequest' |
  tail -1
```

An archive record proves collection. A record in `alerts.json` proves rule promotion. Do not treat an empty dashboard result as a collection failure without checking the archive.

## Phase 6: Install the final rules

Confirm IDs are unused and back up `local_rules.xml`:

```bash
sudo grep -R -n --include='*.xml' -E 'id="(100160|100161)"' \
  /var/ossec/etc/rules /var/ossec/ruleset/rules

sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak-t1105-$(date +%Y%m%d-%H%M%S)
```

Add:

```xml
<group name="windows,powershell,file_transfer,network,mitre,">
  <rule id="100160" level="5">
    <if_sid>91802</if_sid>
    <field name="win.eventdata.scriptBlockText"
           type="pcre2">(?i)(Invoke-WebRequest|Start-BitsTransfer|DownloadFile|curl(?:\.exe)?|wget(?:\.exe)?)</field>
    <description>Command-line file-transfer utility observed</description>
  </rule>

  <rule id="100161" level="8">
    <if_sid>100160</if_sid>
    <field name="win.eventdata.scriptBlockText"
           type="pcre2">(?i)(-OutFile|DownloadFile|T1105-benign-transfer)</field>
    <description>PowerShell used to transfer a file onto the endpoint</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
```

Validate and activate:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Do not proceed if validation reports a new error involving either rule.

## Phase 7: Positive validation

Generate fresh activity after the restart:

```powershell
$Uri = "http://192.168.232.20:8000/benign-transfer.txt"
$Destination = "C:\ProgramData\T1105-validation-03.txt"

Remove-Item $Destination -ErrorAction SilentlyContinue

Invoke-WebRequest `
    -Uri $Uri `
    -OutFile $Destination `
    -UseBasicParsing

Get-Content $Destination
Get-Date -Format o
```

Search Wazuh:

```text
agent.name:"WIN11" AND rule.id:"100161"
```

Verify rule `100161`, level `8`, Event ID `4104`, ATT&CK `T1105`, and Command and Control.

If the archived script block contains both conditions but no alert appears, inspect `/var/ossec/ruleset/rules/0915-win-powershell_rules.xml`. PowerShell Script Block events follow built-in parent `91802`; rule `100160` must inherit from it.

## Phase 8: Negative control

Retrieve content without writing it:

```powershell
$ControlStart = Get-Date
$Uri = "http://192.168.232.20:8000/benign-transfer.txt"

$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
$Response.StatusCode
$Response.Content
Get-Date -Format o
```

Search the baseline:

```text
agent.name:"WIN11" AND rule.id:"100160"
```

Check for an incorrect elevated result:

```text
agent.name:"WIN11" AND rule.id:"100161" AND NOT data.win.eventdata.scriptBlockText:*-OutFile*
```

Correlate results to the control timestamp so an earlier positive event is not mistaken for a failure.

## Phase 9: Export the positive alert

```bash
sudo grep -F '"id":"100161"' /var/ossec/logs/alerts/alerts.json |
  tail -1 |
  jq . > /home/wazuh/22-positive-t1105-alert-rule-100161.json

jq '{timestamp, agent, rule, eventID: .data.win.system.eventID,
     scriptBlockText: .data.win.eventdata.scriptBlockText}' \
  /home/wazuh/22-positive-t1105-alert-rule-100161.json
```

Copy the JSON itself into the local evidence directory and verify it is nonempty.

## Phase 10: Cleanup

On WIN11:

```powershell
$Artifacts = @(
    "C:\ProgramData\T1105-benign-transfer.txt",
    "C:\ProgramData\T1105-validation-02.txt",
    "C:\ProgramData\T1105-validation-03.txt"
)

$Artifacts | ForEach-Object {
    Remove-Item -LiteralPath $_ -ErrorAction SilentlyContinue
}

$Artifacts | ForEach-Object {
    [PSCustomObject]@{
        Path = $_
        Exists = Test-Path -LiteralPath $_
    }
}
```

Stop the HTTP server with `Ctrl+C`, then run on the manager:

```bash
sudo ss -ltnp | grep ':8000'
rm -f /home/wazuh/t1105-lab/benign-transfer.txt
rmdir /home/wazuh/t1105-lab
test -e /home/wazuh/t1105-lab
```

The listener should be absent, all endpoint artifact checks should return `False`, and the manager directory should not exist.

## Completion checklist

- [ ] Benign source and SHA-256 recorded
- [ ] Endpoint and TCP readiness confirmed
- [ ] Successful HTTP transfer captured
- [ ] Endpoint content and hash validated
- [ ] Event ID `3` confirmed or gap documented
- [ ] Event ID `4104` confirmed
- [ ] Event ID `11` confirmed or gap documented
- [ ] Wazuh archive collection confirmed
- [ ] Rules `100160` and `100161` validated
- [ ] Fresh rule `100161` alert generated
- [ ] T1105 mapping verified
- [ ] Negative control completed
- [ ] Raw positive-alert JSON copied locally
- [ ] Endpoint artifacts removed
- [ ] Temporary server and source removed
