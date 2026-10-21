# SPDX-License-Identifier: GPL-3.0-or-later
# Dedicated EA room + empty capture only. No emulator frontend or game.
$ErrorActionPreference='Stop'
$module=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$shell=Join-Path $PSHOME 'powershell.exe'
$runner=Join-Path $module 'capture-run.ps1'
$out=Join-Path $module ('.build-direct/runner-tests/'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out -Force | Out-Null
$checks=0
function Check([bool]$Passed,[string]$Name){
    if(-not $Passed){throw "FAIL $Name"}
    $script:checks++;Write-Host "PASS $script:checks $Name"
}
function Invoke-Runner([string[]]$Extra,[int]$ExpectedExit){
    $label=[Guid]::NewGuid().ToString('N')
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$runner+'"'))+$Extra
    $process=Start-Process -FilePath $shell -ArgumentList $arguments -WorkingDirectory $module -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/$label.stdout.log" -RedirectStandardError "$out/$label.stderr.log"
    $null=$process.Handle
    try {
        if(-not $process.WaitForExit(20000)){throw 'Runner exceeded test watchdog'}
        Check ($process.ExitCode -eq $ExpectedExit) "runner exit=$ExpectedExit"
    }finally{if(-not $process.HasExited){$process.Kill();$process.WaitForExit()}}
}
# Paths containing spaces exercise actual Windows process argument quoting.
$evidence=Join-Path $out 'empty run with spaces'
Invoke-Runner @('-SyntheticOnly','-Seconds','2','-ListenPort','24948','-RoomPort','24949','-EvidenceDir',('"'+$evidence+'"')) 0
$report=Get-Content -LiteralPath "$evidence/report.json" -Raw | ConvertFrom-Json
Check ($report.passed -and $report.released -and -not $report.game_verified) 'empty run closes owned endpoints without claiming game success'
$audit=Get-Content -LiteralPath "$evidence/trace-audit.json" -Raw | ConvertFrom-Json
Check ($audit.events.'run.begin' -eq 1 -and $audit.events.'run.end' -eq 1 -and $audit.raw_records -eq 0) 'default trace has lifecycle markers and no raw payload records'
$before=(Get-FileHash -LiteralPath "$evidence/report.json").Hash
Invoke-Runner @('-SyntheticOnly','-EvidenceDir',('"'+$evidence+'"')) 1
Check ((Get-FileHash -LiteralPath "$evidence/report.json").Hash -eq $before) 'existing evidence is never overwritten'
Invoke-Runner @('-Seconds','1') 1
Invoke-Runner @('-SyntheticOnly','-ManifestId','bad/id') 1
Invoke-Runner @('-SyntheticOnly','-ListenPort','24948','-RoomPort','24948') 1
$reserved=New-Object Net.Sockets.UdpClient
try {
    $reserved.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Loopback,24948)))
    Invoke-Runner @('-SyntheticOnly','-Seconds','1','-ListenPort','24948','-RoomPort','24949') 1
}finally{$reserved.Close()}
. (Join-Path $module 'udp-table.ps1')
Check (@([CaptureUdp]::At(24948)).Count -eq 0 -and @([CaptureUdp]::At(24949)).Count -eq 0) 'negative paths leave no room or capture endpoints'
Write-Host "RESULT runner_checks=$checks failed=0 evidence=$out"
