# SPDX-License-Identifier: GPL-3.0-or-later
# Owns dedicated room/capture processes only; never launches or kills a GUI.
[CmdletBinding()]
param(
    [string]$EvidenceDir,
    [string]$InstanceA,
    [string]$InstanceB,
    [string]$ManifestId='unassigned',
    [ValidateRange(1,3600)][int]$Seconds=60,
    [ValidateRange(1024,65535)][int]$ListenPort=24940,
    [ValidateRange(1024,65535)][int]$RoomPort=24930,
    [switch]$TraceRaw,
    [switch]$SyntheticOnly
)
$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
$runId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
function Within([string]$Child,[string]$Parent) {
    $childPath=[IO.Path]::GetFullPath($Child).TrimEnd('\')
    $parentPath=[IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childPath.Equals($parentPath,[StringComparison]::OrdinalIgnoreCase) -or $childPath.StartsWith($parentPath+'\',[StringComparison]::OrdinalIgnoreCase)
}
if($ListenPort -eq $RoomPort){throw 'Listener and upstream room ports must differ'}
if($ManifestId -notmatch '^[A-Za-z0-9_.-]{1,128}$'){throw 'Manifest ID must contain only letters, digits, dot, dash or underscore'}
if(-not $SyntheticOnly -and ($ManifestId -eq 'unassigned' -or -not $InstanceA -or -not $InstanceB)) {
    throw 'Real baseline requires manifest ID and both isolated instance directories'
}
if(-not $EvidenceDir) {
    if(-not $SyntheticOnly){throw 'Real evidence requires an explicit private directory'}
    $EvidenceDir=Join-Path $PSScriptRoot ".build-direct/smoke/$runId"
}
$out=[IO.Path]::GetFullPath($EvidenceDir)
$localPrivate=Join-Path $workspace '.private-runtime'
if(-not $SyntheticOnly -and (Within $out $workspace) -and (-not (Within $out $localPrivate) -or $out.TrimEnd('\') -eq $localPrivate)){throw 'Real evidence inside workspace must be under .private-runtime'}
# Reject junctions/symlinks in the output ancestry before creating anything.
$ancestor=$out
while($ancestor){
    if(Test-Path -LiteralPath $ancestor){
        if((Get-Item -Force -LiteralPath $ancestor).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Evidence ancestry contains a reparse point'}
    }
    $ancestor=[IO.Path]::GetDirectoryName($ancestor)
}
if(Test-Path -LiteralPath $out){
    if(@(Get-ChildItem -Force -LiteralPath $out).Count){throw 'Evidence directory must be new or empty; existing records are never overwritten'}
}
$roomExe=Join-Path $env:LOCALAPPDATA 'yuzu/yuzu-windows-msvc-early-access/yuzu-room.exe'
$captureExe=Join-Path $PSScriptRoot '.build-direct/yuzu-capture.exe'
$roomHash=(Get-FileHash -LiteralPath $roomExe).Hash.ToLowerInvariant()
$captureHash=(Get-FileHash -LiteralPath $captureExe).Hash.ToLowerInvariant()
if($roomHash -ne '741ac5e936d8ec03b71442ef2ccb1f336907afe20477b6bac5da68177e0a32cc'){throw 'Unexpected EA room executable'}
if(-not $SyntheticOnly){
    # The CLI returns only check names/booleans, never config values or keys.
    $preflightText=& node (Join-Path $PSScriptRoot '../tools/yuzu-preflight.mjs') $InstanceA $InstanceB
    $preflightExit=$LASTEXITCODE
    if($preflightExit -ne 0){throw 'Yuzu isolation preflight failed; run yuzu-preflight.mjs for check names'}
    $preflight=$preflightText -join "`n" | ConvertFrom-Json
    if(-not $preflight.passed){throw 'Isolation report was not successful'}
    # The checked config uses 24940; do not silently use another listener.
    if($ListenPort -ne 24940){throw 'Real preflight currently pins listener port 24940'}
}
. (Join-Path $PSScriptRoot 'udp-table.ps1')
foreach($port in @($ListenPort,$RoomPort)){if(@([CaptureUdp]::At($port)).Count){throw "Port already occupied: $port"}}
New-Item -ItemType Directory -Path $out -Force | Out-Null
if(-not $SyntheticOnly){$preflightText | Set-Content -LiteralPath "$out/preflight.json" -Encoding UTF8}
[IO.File]::WriteAllText("$out/stage.txt",'ready',(New-Object Text.UTF8Encoding($false)))
$roomProcess=$null; $captureProcess=$null; $failure=$null; $released=$false; $captureExit=-1; $audit=$null
$roomArgs=@('--room-name','g2b-local','--room-description','private-loopback','--bind-address','127.0.0.1','--port',"$RoomPort",'--max_members','4','--preferred-game','MHGU','--log-file','server.log')
$captureArgs=@('--listen-port',"$ListenPort",'--room-port',"$RoomPort",'--seconds',"$Seconds",'--manifest',$ManifestId,'--build','main-7edc31be2','--trace-out',('"'+"$out/trace.jsonl"+'"'),'--stage-file',('"'+"$out/stage.txt"+'"'))
if($TraceRaw){$captureArgs+='--trace-raw'}
try {
    $roomProcess=Start-Process -FilePath $roomExe -ArgumentList $roomArgs -WorkingDirectory $out -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/room.stdout.log" -RedirectStandardError "$out/room.stderr.log"
    $null=$roomProcess.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do {
        if($roomProcess.HasExited){throw 'Room exited before binding'}
        $bound=@([CaptureUdp]::At($RoomPort))
        if($bound.Count){break}
        Start-Sleep -Milliseconds 50
    }while([DateTime]::UtcNow -lt $deadline)
    if($bound.Count -ne 1 -or $bound[0] -ne "$($roomProcess.Id)|127.0.0.1|$RoomPort"){throw 'Room binding/PID mismatch'}
    $captureProcess=Start-Process -FilePath $captureExe -ArgumentList $captureArgs -WorkingDirectory $out -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/capture.stdout.log" -RedirectStandardError "$out/capture.stderr.log"
    $null=$captureProcess.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do {
        if($captureProcess.HasExited){throw 'Capture exited before binding'}
        $bound=@([CaptureUdp]::At($ListenPort))
        if($bound.Count){break}
        Start-Sleep -Milliseconds 50
    }while([DateTime]::UtcNow -lt $deadline)
    if($bound.Count -ne 1 -or $bound[0] -ne "$($captureProcess.Id)|127.0.0.1|$ListenPort"){throw 'Capture binding/PID mismatch'}
    Write-Host "CAPTURE_RUNNING loopback_port=$ListenPort stage_file=$out/stage.txt seconds=$Seconds"
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds+10)
    while(-not $captureProcess.WaitForExit(250)){
        if($roomProcess.HasExited){throw 'Upstream room exited during capture'}
        if([DateTime]::UtcNow -ge $deadline){throw 'Capture exceeded watchdog'}
    }
    $captureExit=$captureProcess.ExitCode
    if($captureExit -ne 0){throw "Capture failed: $captureExit"}
    $auditLines=& node (Join-Path $PSScriptRoot '../tools/trace-audit.mjs') "$out/trace.jsonl"
    if($LASTEXITCODE -ne 0){throw 'Trace audit failed'}
    [IO.File]::WriteAllText("$out/trace-audit.json",(($auditLines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
    $audit=Get-Content -LiteralPath "$out/trace-audit.json" -Raw | ConvertFrom-Json
    if($audit.events.'run.end' -ne 1){throw 'Trace did not contain exactly one normal run.end'}
}catch{$failure=$_.Exception.Message}
finally {
    foreach($owned in @($captureProcess,$roomProcess)){
        if($owned -and -not $owned.HasExited){$owned.Kill();$owned.WaitForExit()}
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(3)
    do {
        $released=(@([CaptureUdp]::At($ListenPort)).Count -eq 0 -and @([CaptureUdp]::At($RoomPort)).Count -eq 0)
        if($released){break}; Start-Sleep -Milliseconds 50
    }while([DateTime]::UtcNow -lt $deadline)
    if(-not $released -and -not $failure){$failure='Owned endpoints remained after teardown'}
    $report=[ordered]@{schema='crossplay.capture-run/1';run_id=$runId;manifest_id=$ManifestId;synthetic_only=[bool]$SyntheticOnly;
        passed=($null -eq $failure);game_verified=$false;error=$failure;released=$released;capture_exit=$captureExit;
        room_sha256=$roomHash;capture_sha256=$captureHash;room_arguments=$roomArgs;capture_arguments=$captureArgs;
        trace_sha256=$(if(Test-Path -LiteralPath "$out/trace.jsonl"){(Get-FileHash -LiteralPath "$out/trace.jsonl").Hash.ToLowerInvariant()}else{$null});
        trace_events=$(if($audit){$audit.events}else{$null})}
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$out/report.json" -Encoding UTF8
    Write-Host "CAPTURE_REPORT $out/report.json"
}
if($failure){throw $failure}
Write-Host 'CAPTURE_RUN PASS (game success requires separate evidence)'
