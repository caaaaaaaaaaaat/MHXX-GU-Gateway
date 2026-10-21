# SPDX-License-Identifier: GPL-2.0-or-later
# real-room-interop: observe self-test (in-tree original-source room server).
#
# Proves the "observe" member-table oracle works against the unmodified
# 01052024-yuzu-mirror-master room source before it is pointed at a real binary:
#   1. one observer joins, sees itself, and the room reports the right member count;
#   2. a second observer joins and the FIRST observer receives a room_information
#      broadcast containing BOTH members (the oracle sees membership changes).
#
# Nothing here is a G-c result: the gateway/Citra link is untouched by this script.
[CmdletBinding()]
param(
  [int]$Port = 39690,
  [int]$Seconds = 6,
  [string]$OutRoot = "evidence/observe-selftest",
  [string]$Exe = "build-mingw/real_room_interop.exe",
  [string]$ServerExe = "build-mingw/real_room_self_server.exe"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$script:HasNetUdp = [bool](Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)

$checks = New-Object System.Collections.ArrayList
function Add-Check([string]$name, [bool]$ok, [string]$detail) {
  [void]$checks.Add([ordered]@{ name = $name; ok = $ok; detail = $detail })
  $flag = if ($ok) { "ok  " } else { "FAIL" }
  Write-Host ("CHECK {0} {1} :: {2}" -f $flag, $name, $detail)
}

function Get-Endpoints([int]$ownerPid) {
  $result = @()
  if ($script:HasNetUdp) {
    try {
      $result = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $ownerPid })
    } catch { $result = @() }
  }
  if ($result.Count -eq 0) {
    foreach ($line in @(netstat -ano -p udp)) {
      $m = [regex]::Match($line, "^\s*UDP\s+(\S+):(\d+)\s+\S*\s*(\d+)\s*$")
      if ($m.Success -and ([int]$m.Groups[3].Value -eq $ownerPid)) {
        $result += [pscustomobject]@{ LocalAddress = $m.Groups[1].Value; LocalPort = [int]$m.Groups[2].Value; OwningProcess = $ownerPid }
      }
    }
  }
  return $result
}

function Wait-BoundEndpoint([int]$ownerPid, [int]$port, [int]$timeoutMs) {
  $deadline = (Get-Date).AddMilliseconds($timeoutMs)
  while ((Get-Date) -lt $deadline) {
    foreach ($e in (Get-Endpoints $ownerPid)) {
      if ($e.LocalPort -eq $port) { return $true }
    }
    Start-Sleep -Milliseconds 100
  }
  return $false
}

if (-not (Test-Path $OutRoot)) { New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null }
$OutRoot = (Resolve-Path $OutRoot).Path
$exePath = (Resolve-Path $Exe).Path
$serverPath = (Resolve-Path $ServerExe).Path

function Start-Captured([string]$file, [string]$argLine, [string]$workDir) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $file
  $psi.Arguments = $argLine
  $psi.WorkingDirectory = $workDir
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.RedirectStandardInput = $true
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()
  return [pscustomobject]@{
    proc = $proc
    out = $proc.StandardOutput.ReadToEndAsync()
    err = $proc.StandardError.ReadToEndAsync()
  }
}

function Finish-Captured($state, [string]$outFile, [string]$errFile, [int]$timeoutMs = 30000) {
  $proc = $state.proc
  if (-not $proc.WaitForExit($timeoutMs)) { $proc.Kill(); [void]$proc.WaitForExit(5000) }
  $outText = ""
  $errText = ""
  try { $outText = $state.out.Result } catch { $outText = "" }
  try { $errText = $state.err.Result } catch { $errText = "" }
  [IO.File]::WriteAllText($outFile, $outText)
  [IO.File]::WriteAllText($errFile, $errText)
  return $proc
}

$roomName = "rri-observe-self"
$password = "pw1"
$started = Get-Date

# ---- self server -----------------------------------------------------------
$serverArgs = "--name $roomName --description observe-self-test --preferred-game RealRoomInterop " +
              "--port $Port --password $password --slots 4"
Write-Host "SELF SERVER: $serverPath $serverArgs"
$server = Start-Captured $serverPath $serverArgs $Root
$bound = Wait-BoundEndpoint $server.proc.Id $Port 8000
Add-Check "self_server_ready_by_endpoint" $bound ("pid={0} port={1}" -f $server.proc.Id, $Port)
if (-not $bound) {
  $null = Finish-Captured $server "$OutRoot/self-server.out.txt" "$OutRoot/self-server.err.txt"
  Write-Host "OBSERVE_SELFTEST_RESULT checks=1 failed=1 exit=9"
  exit 9
}

# Everything below is wrapped in try/finally: no assertion failure may leak the server
# process (which would keep the port bound and break the next run).
$serverProc = $null
try {
# ---- observers -------------------------------------------------------------
$aNick = "rri-obs-a"
$bNick = "rri-obs-b"
$aJson = Join-Path $OutRoot "observer-a.json"
$bJson = Join-Path $OutRoot "observer-b.json"
$aArgs = "observe --room 127.0.0.1 --room-port $Port --password $password --nickname $aNick " +
         "--seconds $Seconds --out $aJson"
$bArgs = "observe --room 127.0.0.1 --room-port $Port --password $password --nickname $bNick " +
         "--seconds $($Seconds - 2) --out $bJson"
Write-Host "OBSERVER A: $exePath $aArgs"
$a = Start-Captured $exePath $aArgs $Root
Start-Sleep -Milliseconds 1500
Write-Host "OBSERVER B: $exePath $bArgs"
$b = Start-Captured $exePath $bArgs $Root
$aProc = Finish-Captured $a "$OutRoot/observer-a.out.txt" "$OutRoot/observer-a.err.txt" (($Seconds + 25) * 1000)
$bProc = Finish-Captured $b "$OutRoot/observer-b.out.txt" "$OutRoot/observer-b.err.txt" (($Seconds + 25) * 1000)
Add-Check "observer_a_exit0" ($aProc.ExitCode -eq 0) ("exit={0}" -f $aProc.ExitCode)
Add-Check "observer_b_exit0" ($bProc.ExitCode -eq 0) ("exit={0}" -f $bProc.ExitCode)

# ---- evidence assertions ---------------------------------------------------
function Read-Json([string]$path) {
  if (-not (Test-Path $path)) { return $null }
  # The evidence file is UTF-8; Get-Content would decode it with the ANSI code page and
  # turn a non-ASCII workspace path into an invalid escape sequence.
  $text = [IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
  return ($text | ConvertFrom-Json)
}
$aj = Read-Json $aJson
$bj = Read-Json $bJson
Add-Check "observer_a_json_written" ($null -ne $aj) $aJson
Add-Check "observer_b_json_written" ($null -ne $bj) $bJson

function Get-EventsOf($json, [string]$kind) {
  if ($null -eq $json) { return @() }
  return @($json.events | Where-Object { $_.kind -eq $kind })
}

if ($null -ne $aj -and $null -ne $bj) {
  Add-Check "a_joined" ([bool]$aj.summary.joined) ("joined={0}" -f $aj.summary.joined)
  Add-Check "a_saw_self" ([bool]$aj.summary.saw_self) ("saw_self={0}" -f $aj.summary.saw_self)
  Add-Check "a_decode_failures_zero" ($aj.summary.decode_failures -eq 0) ("decode_failures={0}" -f $aj.summary.decode_failures)
  Add-Check "b_joined" ([bool]$bj.summary.joined) ("joined={0}" -f $bj.summary.joined)
  Add-Check "b_saw_self" ([bool]$bj.summary.saw_self) ("saw_self={0}" -f $bj.summary.saw_self)
  Add-Check "b_decode_failures_zero" ($bj.summary.decode_failures -eq 0) ("decode_failures={0}" -f $bj.summary.decode_failures)

  $aInfos = @(Get-EventsOf $aj "room_information")
  Add-Check "a_room_information_seen" ($aInfos.Count -ge 2) ("count={0}" -f $aInfos.Count)
  $sizes = @($aInfos | ForEach-Object { $_.member_count })
  Add-Check "a_first_room_information_member_count_1" ($sizes.Count -ge 1 -and $sizes[0] -eq 1) ("counts={0}" -f ($sizes -join ","))
  $maxA = 0
  foreach ($i in $aInfos) { if ($i.member_count -gt $maxA) { $maxA = $i.member_count } }
  Add-Check "a_sees_two_members_after_second_join" ($maxA -eq 2) ("max_member_count={0}" -f $maxA)

  $two = $aInfos | Where-Object { $_.member_count -eq 2 } | Select-Object -First 1
  if ($null -ne $two) {
    $names = @($two.members | ForEach-Object { $_.nickname })
    $hasBoth = ($names -contains $aNick) -and ($names -contains $bNick)
    Add-Check "a_two_member_broadcast_contains_both_nicknames" $hasBoth ("members={0}" -f ($names -join ","))
    $selfEntry = $two.members | Where-Object { $_.nickname -eq $aNick } | Select-Object -First 1
    $joinA = @(Get-EventsOf $aj "join_success") | Select-Object -First 1
    $sameIp = ($null -ne $selfEntry) -and ($null -ne $joinA) -and ($selfEntry.fake_ip -eq $joinA.fake_ip)
    Add-Check "a_assigned_fake_ip_matches_member_table" $sameIp ("join_success={0} member_table={1}" -f $joinA.fake_ip, $selfEntry.fake_ip)
    Add-Check "a_room_name_matches" ($two.room_name -eq $roomName) ("room_name={0}" -f $two.room_name)
  } else {
    Add-Check "a_two_member_broadcast_contains_both_nicknames" $false "no room_information with member_count=2"
    Add-Check "a_assigned_fake_ip_matches_member_table" $false "no room_information with member_count=2"
    Add-Check "a_room_name_matches" $false "no room_information with member_count=2"
  }
  Add-Check "b_max_member_count_two" ($bj.summary.max_member_count -eq 2) ("max_member_count={0}" -f $bj.summary.max_member_count)
  $aSeen = @($aj.summary.members_seen)
  Add-Check "a_members_seen_both" (($aSeen -contains $aNick) -and ($aSeen -contains $bNick)) ("members_seen={0}" -f ($aSeen -join ","))
}

} finally {
# ---- stop the server, check the log and the port release -------------------
try {
  $server.proc.StandardInput.WriteLine("q")
  $server.proc.StandardInput.Flush()
} catch { }
$serverProc = Finish-Captured $server "$OutRoot/self-server.out.txt" "$OutRoot/self-server.err.txt"
$serverOut = [IO.File]::ReadAllText("$OutRoot/self-server.out.txt")
$serverErr = [IO.File]::ReadAllText("$OutRoot/self-server.err.txt")
Add-Check "self_server_graceful_stop" ($serverProc.ExitCode -eq 0) ("exit={0}" -f $serverProc.ExitCode)
$logText = $serverErr + $serverOut
$joinRe = [regex]::new("rri-obs-a has joined[\s\S]*rri-obs-b has joined")
Add-Check "self_server_log_reports_two_joins" $joinRe.IsMatch($logText) "stderr/stdout contains both has-joined lines"
$released = -not (Wait-BoundEndpoint $serverProc.Id $Port 1500)
Add-Check "self_server_port_released" $released ("no UDP endpoint for pid={0} port={1}" -f $serverProc.Id, $Port)
}

$failed = @($checks | Where-Object { -not $_.ok }).Count
$elapsed = (Get-Date) - $started
$summary = [ordered]@{
  tool = "real-room-interop"
  mode = "observe-selftest"
  server = "in-tree original source (01052024-yuzu-mirror-master)"
  room = @{ address = "127.0.0.1"; port = $Port; slots = 4; password_set = $true }
  observers = @{ a = $aNick; b = $bNick; b_join_delay_ms = 1500; a_seconds = $Seconds; b_seconds = $Seconds - 2 }
  server_command = "$serverPath $serverArgs"
  server_bound_loopback_only = $true
  checks_total = $checks.Count
  checks_failed = $failed
  checks = $checks
  elapsed_ms = [int]$elapsed.TotalMilliseconds
  note = "harness self-proof only; it says nothing about real release binaries or G-c"
}
[IO.File]::WriteAllText((Join-Path $OutRoot "selftest.json"), ($summary | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("OBSERVE_SELFTEST_RESULT checks={0} failed={1} elapsed_ms={2}" -f $checks.Count, $failed, $summary.elapsed_ms)
if ($failed -gt 0) { exit 1 }
exit 0
