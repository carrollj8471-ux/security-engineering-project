param(
    [string]$Root = 'C:\Users\User\Documents\security-engineering-project\detections'
)

$required = @(
    'Result', 'Objective and hypothesis', 'Lab environment', 'Safe simulation',
    'Endpoint telemetry', 'Wazuh hunt and collection validation',
    'Troubleshooting and detection engineering', 'Positive validation',
    'Negative control', 'False positives and triage', 'Engineering considerations',
    'Cleanup', 'Timeline', 'Findings', 'Evidence inventory', 'Reproduction'
)

$failures = @()
$completed = Get-ChildItem -LiteralPath $Root -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'README.md') }

foreach ($folder in $completed) {
    $path = Join-Path $folder.FullName 'README.md'
    $text = Get-Content -LiteralPath $path -Raw
    $missing = @($required | Where-Object {
        $text -notmatch "(?m)^## $([regex]::Escape($_))\s*$"
    })
    $placeholders = Select-String -LiteralPath $path -Pattern 'TODO|TBD|PLACEHOLDER' -CaseSensitive:$false
    $duplicateHeadings = @(
        Select-String -LiteralPath $path -Pattern '^## ' |
            ForEach-Object { $_.Line.Trim() } |
            Group-Object |
            Where-Object Count -gt 1 |
            ForEach-Object Name
    )
    $broken = @()
    foreach ($match in [regex]::Matches($text, '!?(?:\[[^\]]*\])\((?!https?://|#)([^)]+)\)')) {
        $target = $match.Groups[1].Value.Trim('<', '>')
        $target = [System.Uri]::UnescapeDataString($target)
        $target = $target.Split('#')[0]
        if ($target -and -not (Test-Path -LiteralPath (Join-Path $folder.FullName $target))) {
            $broken += $target
        }
    }
    if ($missing.Count -or $placeholders.Count -or $broken.Count -or $duplicateHeadings.Count) {
        $failures += [pscustomobject]@{
            CaseStudy = $folder.Name
            MissingSections = $missing -join '; '
            Placeholders = $placeholders.Count
            BrokenLinks = ($broken | Sort-Object -Unique) -join '; '
            DuplicateHeadings = $duplicateHeadings -join '; '
        }
    }
}

if ($failures.Count) {
    $failures | Format-Table -AutoSize | Out-String | Write-Output
    throw "$($failures.Count) completed case-study README(s) failed validation."
}

Write-Output "PASS: $($completed.Count) completed case-study READMEs satisfy the common section contract; no placeholders or broken local links were found."
