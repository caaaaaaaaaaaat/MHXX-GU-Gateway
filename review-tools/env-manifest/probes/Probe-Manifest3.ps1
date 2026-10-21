#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$collector = Join-Path (Split-Path $here -Parent) 'Collect-EnvironmentManifest.ps1'
$toolTree = Split-Path $collector -Parent
$wsRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here)))
$runRoot = Join-Path $here ('run3-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($runRoot)
$obs = New-Object 'Collections.Generic.List[object]'
function Obs([string]$id,[string]$status,[string]$detail) {
    $script:obs.Add([ordered]@{id=$id;status=$status;detail=$detail})
    Write-Output ('[' + $status + '] ' + $id + ' :: ' + $detail)
}
function RunC([hashtable]$a) {
    try { $printed = & $collector @a; return [ordered]@{ok=$true; printed=[string]$printed} }
    catch { return [ordered]@{ok=$false; error=$_.Exception.Message} }
}
Write-Output ('RUN3_DIR=' + $runRoot)
Write-Output ('TOOL_TREE=' + $toolTree)
Write-Output ('WS_ROOT=' + $wsRoot)

# Q01 default relative output while cwd is the workspace root (outside tool tree)
$defAbs = Join-Path $toolTree 'output\environment-manifest.json'
$defLeak = Join-Path $wsRoot 'output\environment-manifest.json'
if (Test-Path -LiteralPath $defAbs) { Remove-Item -LiteralPath $defAbs -Force }
Set-Location -LiteralPath $wsRoot
$r = RunC @{}
$printedWeb = if ($r.ok) { $r.printed.Trim() } else { '' }
$okAbs = Test-Path -LiteralPath $defAbs
$okLeak = Test-Path -LiteralPath $defLeak
if ($r.ok -and $printedWeb -eq 'output\environment-manifest.json' -and $okAbs -and -not $okLeak) { Obs 'Q01-default-relative-from-foreign-cwd' 'PASS' ('printed=' + $printedWeb + ' abs=' + $defAbs + ' leak=' + $okLeak) } else { Obs 'Q01-default-relative-from-foreign-cwd' 'FAIL' ('ok=' + $r.ok + ' printed=' + $printedWeb + ' abs=' + $okAbs + ' leak=' + $okLeak + ' err=' + $r.error) }

# Q02 explicit relative output while cwd is outside the tool tree
$relName = 'rel-canary.json'
$relAbs = Join-Path $toolTree $relName
$relLeak = Join-Path $wsRoot $relName
if (Test-Path -LiteralPath $relAbs) { Remove-Item -LiteralPath $relAbs -Force }
$r = RunC @{OutputPath=$relName}
$printedWeb = if ($r.ok) { $r.printed.Trim() } else { '' }
$okAbs = Test-Path -LiteralPath $relAbs
$okLeak = Test-Path -LiteralPath $relLeak
if ($r.ok -and $printedWeb -eq $relName -and $okAbs -and -not $okLeak) { Obs 'Q02-explicit-relative-from-foreign-cwd' 'PASS' ('printed=' + $printedWeb + ' abs=' + $okAbs + ' leak=' + $okLeak) } else { Obs 'Q02-explicit-relative-from-foreign-cwd' 'FAIL' ('ok=' + $r.ok + ' printed=' + $printedWeb + ' abs=' + $okAbs + ' leak=' + $okLeak + ' err=' + $r.error) }

# Q03 relative subdirectory output
$subRel = 'sub3\rel.json'
$subAbs = Join-Path $toolTree $subRel
$subLeak = Join-Path $wsRoot $subRel
if (Test-Path -LiteralPath $subAbs) { Remove-Item -LiteralPath $subAbs -Force }
$r = RunC @{OutputPath=$subRel}
$printedWeb = if ($r.ok) { $r.printed.Trim() } else { '' }
if ($r.ok -and (Test-Path -LiteralPath $subAbs) -and -not (Test-Path -LiteralPath $subLeak)) { Obs 'Q03-relative-subdir' 'PASS' ('printed=' + $printedWeb + ' abs=' + $subAbs) } else { Obs 'Q03-relative-subdir' 'FAIL' ('ok=' + $r.ok + ' printed=' + $printedWeb + ' err=' + $r.error) }

# Q04 absolute output inside tool tree still works; printed becomes relative
$absIn = Join-Path $toolTree 'abs-in.json'
if (Test-Path -LiteralPath $absIn) { Remove-Item -LiteralPath $absIn -Force }
$r = RunC @{OutputPath=$absIn}
$printedWeb = if ($r.ok) { $r.printed.Trim() } else { '' }
$rooted = [IO.Path]::IsPathRooted($printedWeb)
if ($r.ok -and ($printedWeb -eq 'abs-in.json') -and (-not $rooted) -and (Test-Path -LiteralPath $absIn)) { Obs 'Q04-absolute-inside-prints-relative' 'PASS' ('printed=' + $printedWeb + ' rooted=' + $rooted) } else { Obs 'Q04-absolute-inside-prints-relative' 'FAIL' ('ok=' + $r.ok + ' printed=' + $printedWeb + ' rooted=' + $rooted + ' err=' + $r.error) }

# Q05 absolute output outside the tool tree rejected, no leak
$absOutLeak = Join-Path $wsRoot 'outside-canary.json'
if (Test-Path -LiteralPath $absOutLeak) { Remove-Item -LiteralPath $absOutLeak -Force }
$r = RunC @{OutputPath=$absOutLeak}
if ((-not $r.ok) -and $r.error.Contains('OUTPUT_OUTSIDE_TOOL_TREE') -and (-not (Test-Path -LiteralPath $absOutLeak))) { Obs 'Q05-absolute-outside-rejected' 'PASS' ('err=' + $r.error) } else { Obs 'Q05-absolute-outside-rejected' 'FAIL' ('ok=' + $r.ok + ' err=' + $r.error + ' leak=' + (Test-Path -LiteralPath $absOutLeak)) }

# Q06 -Force still clobbers an arbitrary pre-existing non-manifest json under the tree (recheck on new build)
$canary = Join-Path $runRoot 'canary.json'
[IO.File]::WriteAllText($canary,'{"canary":true}')
$r = RunC @{OutputPath=$canary;Force=$true}
$after = Get-Content -LiteralPath $canary -Raw
if ($r.ok -and $after.Contains('crossplay.env-manifest/1')) { Obs 'Q06-force-clobbers-arbitrary-json' 'FINDING' ('reconfirmed on new build; post_len=' + $after.Length) } else { Obs 'Q06-force-clobbers-arbitrary-json' 'PASS' ('no clobber err=' + $r.error) }

# Q07 default no -Force refuses to overwrite the default output
$r = RunC @{}
if ((-not $r.ok) -and $r.error.Contains('OUTPUT_EXISTS_USE_FORCE')) { Obs 'Q07-default-no-clobber' 'PASS' ('err=' + $r.error) } else { Obs 'Q07-default-no-clobber' 'FAIL' ('ok=' + $r.ok + ' err=' + $r.error) }

# Q08 confirm nothing leaked to the workspace root during any of the above
$leaks = @()
foreach ($p in @((Join-Path $wsRoot 'output'), $relLeak, $absOutLeak, (Join-Path $wsRoot 'sub3'))) { if (Test-Path -LiteralPath $p) { $leaks += $p } }
if ($leaks.Count -eq 0) { Obs 'Q08-no-workspace-root-leak' 'PASS' 'no leaks at workspace root' } else { Obs 'Q08-no-workspace-root-leak' 'FAIL' ('leaks=' + ($leaks -join '; ')) }

$summaryPath = Join-Path $runRoot 'probe3-results.json'
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($summaryPath,([ordered]@{produced_utc=[DateTime]::UtcNow.ToString('o'); collector=$collector; run_root=$runRoot; observations=@($obs.ToArray())} | ConvertTo-Json -Depth 8) + [Environment]::NewLine,$utf8)
Write-Output ('PROBE3_RESULTS=' + $summaryPath)
