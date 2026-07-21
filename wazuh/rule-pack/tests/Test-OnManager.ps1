[CmdletBinding()]
param(
    [string]$ManagerHost = '192.168.232.20',
    [string]$ManagerUser = 'wazuh',
    [string]$RemoteRulePath = '/var/ossec/etc/rules/1100-security-engineering-lab.xml'
)

$ErrorActionPreference = 'Stop'
$packRoot = Split-Path -Parent $PSScriptRoot
$ruleFile = Join-Path $packRoot 'rules/1100-security-engineering-lab.xml'

Write-Output 'Running portable rule-pack tests first...'
& (Join-Path $PSScriptRoot 'Test-WazuhRulePack.ps1') -PackRoot $packRoot

Write-Output 'Copying the candidate rule to a non-active temporary path...'
scp $ruleFile "${ManagerUser}@${ManagerHost}:/tmp/1100-security-engineering-lab.xml"
if ($LASTEXITCODE -ne 0) { throw 'SCP failed.' }

Write-Output 'The following commands require sudo on the manager.'
ssh -t "${ManagerUser}@${ManagerHost}" "sudo cp /tmp/1100-security-engineering-lab.xml '$RemoteRulePath' && sudo chown root:wazuh '$RemoteRulePath' && sudo chmod 640 '$RemoteRulePath' && sudo /var/ossec/bin/wazuh-analysisd -t"
if ($LASTEXITCODE -ne 0) { throw 'Manager-side rule installation or syntax validation failed.' }

Write-Output 'PASS: manager accepted the rule file. Restart Wazuh only through the documented deployment procedure, then generate fresh positive and negative events.'
