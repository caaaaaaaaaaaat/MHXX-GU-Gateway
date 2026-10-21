# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PreparedRuntime)
$ErrorActionPreference='Stop'
$module=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$workspace=[IO.Path]::GetFullPath((Join-Path $module '../..'))
$prepare=Join-Path $module 'prepare-instances.ps1'
$source=Join-Path $env:LOCALAPPDATA 'yuzu/yuzu-windows-msvc'
$manifest=Join-Path $PreparedRuntime 'preparation.json'
$before=(Get-FileHash -LiteralPath $manifest).Hash
$checks=0
foreach($case in @(
    @{target=(Join-Path $workspace 'forbidden-private-runtime');reason='outside workspace'},
    @{target=$source;reason='must be disjoint'},
    @{target=$PreparedRuntime;reason='must not exist'}
)){
    $rejected=$false
    try{& $prepare -Destination $case.target}catch{$rejected=$_.Exception.Message.Contains($case.reason)}
    if(-not $rejected){throw 'Preparation did not reject an unsafe destination before copying'}
    $checks++;Write-Host "PASS $checks rejected $($case.reason)"
}
if((Get-FileHash -LiteralPath $manifest).Hash -ne $before){throw 'Existing preparation evidence was modified'}
$checks++;Write-Host "PASS $checks existing preparation was not overwritten"
$report=Get-Content -LiteralPath $manifest -Encoding UTF8 -Raw | ConvertFrom-Json
if(-not $report.program_copies_verified -or $report.copied_private_data -or $report.game_verified -or $report.game_ready){throw 'Preparation scope or success claim is incorrect'}
foreach($entry in $report.program_files){
    $instance=Join-Path $PreparedRuntime ('yuzu-'+$entry.slot)
    if((Get-FileHash -LiteralPath (Join-Path $instance $entry.relative_path)).Hash.ToLowerInvariant() -ne $entry.sha256){throw 'Prepared program hash mismatch'}
}
$checks++;Write-Host "PASS $checks all copied program files match recorded hashes without private data"
Write-Host "RESULT preparation_checks=$checks failed=0"
