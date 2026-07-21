[CmdletBinding()]
param(
    [string]$PackRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure([string]$Message) {
    $script:failures.Add($Message)
}

$versionPath = Join-Path $PackRoot 'VERSION'
$manifestPath = Join-Path $PackRoot 'manifest.json'
$rulePath = Join-Path $PackRoot 'rules/1100-security-engineering-lab.xml'
$fixturePath = Join-Path $PackRoot 'tests/fixtures/rule-cases.json'

foreach ($path in @($versionPath, $manifestPath, $rulePath, $fixturePath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        Add-Failure "Required file missing: $path"
    }
}
if ($failures.Count) { throw ($failures -join [Environment]::NewLine) }

$version = (Get-Content -LiteralPath $versionPath -Raw).Trim()
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$fixtures = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
$ruleText = Get-Content -LiteralPath $rulePath -Raw

if ($version -notmatch '^\d+\.\d+\.\d+$') {
    Add-Failure "VERSION is not semantic version format: $version"
}
if ($manifest.version -ne $version) {
    Add-Failure "Manifest version $($manifest.version) does not match VERSION $version"
}
if ($ruleText -notmatch "rule-pack-version:\s*$([regex]::Escape($version))") {
    Add-Failure 'Rule-file version comment does not match VERSION'
}
if ($manifest.behavioral_fixture_count -ne @($fixtures.cases).Count) {
    Add-Failure 'Manifest fixture count does not match fixture file'
}

try {
    [xml]$xml = $ruleText
} catch {
    Add-Failure "Rule XML is not well formed: $($_.Exception.Message)"
}

if ($xml) {
    $rules = @($xml.SelectNodes('//rule'))
    $ids = @($rules | ForEach-Object { [int]$_.id })
    $duplicateIds = @($ids | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    if ($duplicateIds.Count) { Add-Failure "Duplicate rule IDs: $($duplicateIds -join ', ')" }

    $manifestIds = @($manifest.rules | ForEach-Object { [int]$_.id } | Sort-Object)
    $xmlIds = @($ids | Sort-Object)
    if (($manifestIds -join ',') -ne ($xmlIds -join ',')) {
        Add-Failure 'Manifest rule IDs do not exactly match XML rule IDs'
    }

    $externalParents = @($manifest.external_parent_rules | ForEach-Object { [int]$_ })
    foreach ($rule in $rules) {
        $id = [int]$rule.id
        if ($id -lt 110100 -or $id -gt 110199) {
            Add-Failure "Rule $id is outside the pack range 110100-110199"
        }
        if ([int]$rule.level -lt 1 -or [int]$rule.level -gt 16) {
            Add-Failure "Rule $id has invalid level $($rule.level)"
        }
        if (-not $rule.description) { Add-Failure "Rule $id lacks a description" }
        if (-not $rule.mitre.id) { Add-Failure "Rule $id lacks a MITRE technique" }

        if ($rule.if_sid) {
            foreach ($parent in "$($rule.if_sid)" -split ',') {
                $parentId = [int]$parent.Trim()
                if ($parentId -notin $ids -and $parentId -notin $externalParents) {
                    Add-Failure "Rule $id references undeclared parent $parentId"
                }
            }
        }
    }

    $coveredPositive = [System.Collections.Generic.HashSet[int]]::new()
    $coveredNegative = [System.Collections.Generic.HashSet[int]]::new()
    $passedCases = 0

    foreach ($case in @($fixtures.cases)) {
        $matched = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($parent in @($case.parent_sids)) { [void]$matched.Add([int]$parent) }
        $caseGroups = @($case.groups | ForEach-Object { "$($_)" })

        foreach ($rule in $rules) {
            $id = [int]$rule.id
            $dependencyMatch = $true

            if ($rule.if_sid) {
                $requiredParents = @("$($rule.if_sid)" -split ',' | ForEach-Object { [int]$_.Trim() })
                $dependencyMatch = @($requiredParents | Where-Object { $matched.Contains($_) }).Count -gt 0
            } elseif ($rule.if_group) {
                $requiredGroups = @("$($rule.if_group)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $dependencyMatch = @($requiredGroups | Where-Object { $_ -in $caseGroups }).Count -gt 0
            }

            if (-not $dependencyMatch) { continue }

            $fieldMatch = $true
            foreach ($field in @($rule.SelectNodes('field'))) {
                $fieldName = "$($field.name)"
                $property = $case.fields.PSObject.Properties[$fieldName]
                if (-not $property) {
                    $fieldMatch = $false
                    break
                }
                try {
                    if (-not [regex]::IsMatch("$($property.Value)", "$($field.InnerText)")) {
                        $fieldMatch = $false
                        break
                    }
                } catch {
                    Add-Failure "Rule $id has an invalid test-compatible regex: $($_.Exception.Message)"
                    $fieldMatch = $false
                    break
                }
            }

            if ($fieldMatch) { [void]$matched.Add($id) }
        }

        $caseFailed = $false
        foreach ($expected in @($case.expect_match)) {
            $expectedId = [int]$expected
            [void]$coveredPositive.Add($expectedId)
            if (-not $matched.Contains($expectedId)) {
                Add-Failure "[$($case.name)] expected rule $expectedId to match"
                $caseFailed = $true
            }
        }
        foreach ($unexpected in @($case.expect_not_match)) {
            $unexpectedId = [int]$unexpected
            [void]$coveredNegative.Add($unexpectedId)
            if ($matched.Contains($unexpectedId)) {
                Add-Failure "[$($case.name)] expected rule $unexpectedId not to match"
                $caseFailed = $true
            }
        }
        if (-not $caseFailed) { $passedCases++ }
    }

    foreach ($id in $ids) {
        if (-not $coveredPositive.Contains($id)) { Add-Failure "Rule $id lacks a positive fixture" }
        if (-not $coveredNegative.Contains($id)) { Add-Failure "Rule $id lacks a negative fixture" }
    }
}

if ($failures.Count) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "Rule-pack tests failed: $($failures.Count) failure(s)."
}

Write-Output "PASS: version=$version; rules=$($rules.Count); fixtures=$passedCases/$(@($fixtures.cases).Count); IDs unique; dependencies declared; positive and negative coverage complete."
