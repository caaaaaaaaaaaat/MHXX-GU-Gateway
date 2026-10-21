# SPDX-License-Identifier: GPL-3.0-or-later
# Synthetic clients only. Starts one known EA dedicated room on loopback;
# never starts an emulator frontend, loads a game or contacts an external room.
[CmdletBinding()]
param(
    [string]$RoomExe = (Join-Path $env:LOCALAPPDATA 'yuzu/yuzu-windows-msvc-early-access/yuzu-room.exe'),
    [ValidateRange(1024,65535)][int]$RoomPort = 24949
)
$ErrorActionPreference='Stop'
$expectedHash='741ac5e936d8ec03b71442ef2ccb1f336907afe20477b6bac5da68177e0a32cc'
$roomHash=(Get-FileHash -LiteralPath $RoomExe -Algorithm SHA256).Hash.ToLowerInvariant()
if($roomHash -ne $expectedHash) {throw 'Only the previously authorized strict-loopback EA room hash is accepted'}
$runId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$relativeOut=".build-direct/real/$runId"
$out=Join-Path $PSScriptRoot $relativeOut
New-Item -ItemType Directory -Path "$out/evidence" -Force | Out-Null
$testExe=Join-Path $PSScriptRoot '.build-direct/yuzu-capture-tests.exe'
if(-not (Test-Path -LiteralPath $testExe)) {throw 'Build tests first'}
. (Join-Path $PSScriptRoot 'udp-table.ps1')
if(@([CaptureUdp]::At($RoomPort)).Count) {throw 'Room port already occupied'}
$arguments=@('--room-name','capture-interop','--room-description','synthetic-only',
    '--bind-address','127.0.0.1','--port',"$RoomPort",'--max_members','4','--password','pw',
    '--preferred-game','Capture','--log-file','server.log')
$roomProcess=$null
$testProcess=$null
$bound=@()
$testExit=-1
$failure=$null
$released=$false
$auditExit=$null
$auditReport=$null
try {
    $roomProcess=Start-Process -FilePath $RoomExe -ArgumentList $arguments -WorkingDirectory $out -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/room.stdout.log" -RedirectStandardError "$out/room.stderr.log"
    $null=$roomProcess.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do {
        if($roomProcess.HasExited) {throw 'EA room exited before binding'}
        $bound=@([CaptureUdp]::At($RoomPort))
        if($bound.Count) {break}
        Start-Sleep -Milliseconds 50
    } while([DateTime]::UtcNow -lt $deadline)
    if($bound.Count -ne 1 -or $bound[0] -ne "$($roomProcess.Id)|127.0.0.1|$RoomPort") {
        throw "Room did not bind exclusively to loopback: $($bound -join ',')"
    }
    $testProcess=Start-Process -FilePath $testExe -ArgumentList @("$relativeOut/evidence","$RoomPort") -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/test.stdout.log" -RedirectStandardError "$out/test.stderr.log"
    $null=$testProcess.Handle
    if(-not $testProcess.WaitForExit(45000)) {throw 'real-room synthetic tests exceeded watchdog'}
    $testExit=$testProcess.ExitCode
    if($testExit -ne 0) {throw "synthetic tests failed: $testExit"}
    $auditLines=& node (Join-Path $PSScriptRoot '../tools/trace-audit.mjs') "$out/evidence/relay.jsonl"
    $auditExit=$LASTEXITCODE
    $auditReport=($auditLines -join "`n") | ConvertFrom-Json
    [IO.File]::WriteAllText("$out/trace-audit.json",(($auditLines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
    # Same native negative fixture as build.ps1: one malformed LDN body is
    # recorded and blocked. Require its exact error, never weaken real auditing.
    if($auditExit -ne 1 -or $auditReport.passed -ne $false -or $auditReport.errors -ne 1 -or
       $auditReport.error_reasons.'invalid LdnPacket type, body size or broadcast' -ne 1) {
        throw 'independent trace audit did not identify exactly the injected malformed LDN body'
    }
} catch {$failure=$_.Exception.Message}
finally {
    if($testProcess -and -not $testProcess.HasExited) {$testProcess.Kill();$testProcess.WaitForExit()}
    if($roomProcess -and -not $roomProcess.HasExited) {$roomProcess.Kill();$roomProcess.WaitForExit()}
    $deadline=[DateTime]::UtcNow.AddSeconds(3)
    do {
        $released=@([CaptureUdp]::At($RoomPort)).Count -eq 0
        if($released) {break}
        Start-Sleep -Milliseconds 50
    } while([DateTime]::UtcNow -lt $deadline)
    if(-not $released -and -not $failure) {$failure='room endpoint remained after teardown'}
    $report=[ordered]@{schema='crossplay.capture-real/1';run_id=$runId;room_exe=$RoomExe;room_sha256=$roomHash;
        room_arguments=$arguments;bound=$bound;test_exit=$testExit;released=$released;error=$failure;
        passed=($null -eq $failure);scope='dedicated room and synthetic clients; no emulator/game';
        game_verified=$false;negative_fixture=$true;audit_exit=$auditExit;
        audit_errors=$(if($null -ne $auditReport){$auditReport.errors}else{$null});expected_audit_errors=1;
        trace_sha256=$(if(Test-Path "$out/evidence/relay.jsonl"){(Get-FileHash "$out/evidence/relay.jsonl").Hash.ToLowerInvariant()}else{$null})}
    $report | ConvertTo-Json -Depth 6 | Set-Content "$out/report.json" -Encoding UTF8
    Write-Host "REAL_CAPTURE_REPORT $out/report.json"
}
if($failure) {throw $failure}
Write-Host 'REAL_CAPTURE_INTEROP PASS'
