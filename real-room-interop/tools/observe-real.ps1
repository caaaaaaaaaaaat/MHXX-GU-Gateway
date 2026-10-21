# SPDX-License-Identifier: GPL-2.0-or-later
# real-room-interop: observe against a REAL yuzu-room.exe (loopback only).
#
# This is the G-c support harness, not a G-c verdict: it starts a real v1 room server,
# joins it with the independent "observe" member, and records the member tables that the
# room broadcasts (room_information).  The gateway / real Citra client are never touched.
#
# Safety rules enforced here (ADR-017 / V-018):
#   * the binary identity is checked against the authorized table before it is started;
#   * EA yuzu-room gets an explicit --bind-address 127.0.0.1 (strict loopback);
#   * a binary without a bind option needs -AllowWildcardBind, and then the actual
#     endpoints, the full command line and loopback_only=false are recorded;
#   * no --token / --web-api-url is ever passed, and the "Hosting a private room"
#     line is asserted, proving the server did not contact an external service;
#   * the port must be free before the run and released after it.
#
# Evidence layout: <OutRoot>/<tag>/{server.out.txt,server.err.txt,server.log,
#   observer-a|b|c.{json,out.txt,err.txt},commands.txt,summary.json}
[CmdletBinding()]
param(
  [int]$Port = 24930,
  [int]$Seconds = 10,
  [string]$RoomTag = "yuzu-ea-2024",
  [string]$RoomExe = "",
  [string]$RoomName = "mhxg",
  [string]$RoomDescription = "gc",
  [string]$Password = "pw1",
  [int]$Slots = 8,
  [string]$OutRoot = "evidence/observe-real",
  [string]$Exe = "build-mingw/real_room_interop.exe",
  [switch]$AllowWildcardBind,
  [switch]$AllowRun
)

if (-not $AllowRun) {
  Write-Host "未获用户授权: this script starts a real yuzu-room.exe; pass -AllowRun explicitly"
  Write-Host "(authorization: docs/AUTHORIZATIONS.md - loopback only, no ROMs, no public network)"
  exit 3
}

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Authorized candidate table (bytes + SHA-256 are the authorization identities; see
# docs/AUTHORIZATIONS.md and docs/VERIFICATION-LOG.md V-017).
$Known = @(
  [pscustomobject]@{ tag = "yuzu-ea-2024"; protocol = "v1"; supportsBind = $true;
    path = "C:\Users\马光述\AppData\Local\yuzu\yuzu-windows-msvc-early-access\yuzu-room.exe";
    bytes = 786944;
    sha256 = "741ac5e936d8ec03b71442ef2ccb1f336907afe20477b6bac5da68177e0a32cc" },
  [pscustomobject]@{ tag = "yuzu-main-2022"; protocol = "v1"; supportsBind = $false;
    path = "C:\Users\马光述\AppData\Local\yuzu\yuzu-windows-msvc\yuzu-room.exe";
    bytes = 2017792;
    sha256 = "5175d6a108b022fe47c793fb3a57c2f26a7c1404a0f71827f464586963d8778a" },
  [pscustomobject]@{ tag = "citra-msys2-2024"; protocol = "v4"; supportsBind = $false;
    path = "F:\citra mul\citra-windows-msys2-20240927-608383e\citra-room.exe";
    bytes = 5902336;
    sha256 = "15eb1d9d6c7423bd9f446828abf49c1d82299339bc7bc80caba292c3f826779d" },
  [pscustomobject]@{ tag = "citra-canary"; protocol = "v4"; supportsBind = $false;
    path = "F:\citra2798\canary\citra-room.exe";
    bytes = 2627072;
    sha256 = "035bdfbb56d2262c27c54b6a22876bc07e6f1ff5b0886b582b2541aba89aa95a" },
  [pscustomobject]@{ tag = "citra-game-bundle"; protocol = "v4"; supportsBind = $false;
    path = "F:\究极之月\日月\A1877\Game\citra-room.exe";
    bytes = 24456528;
    sha256 = "43a4b8359648fa4ba44910036dd1c79d432d1524823104731fe861e8573752e9" }
)

$checks = New-Object System.Collections.ArrayList
function Add-Check([string]$name, [bool]$ok, [string]$detail) {
  [void]$checks.Add([ordered]@{ name = $name; ok = $ok; detail = $detail })
  $flag = if ($ok) { "ok  " } else { "FAIL" }
  Write-Host ("CHECK {0} {1} :: {2}" -f $flag, $name, $detail)
}

$script:HasNetUdp = [bool](Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
function Get-EndpointsByPid([int]$ownerPid) {
  $result = @()
  if ($script:HasNetUdp) {
    try { $result = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $ownerPid }) } catch { $result = @() }
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
function Get-EndpointsByPort([int]$port) {
  $result = @()
  if ($script:HasNetUdp) {
    try { $result = @(Get-NetUDPEndpoint -ErrorAction Stop -LocalPort $port) } catch { $result = @() }
  }
  if ($result.Count -eq 0) {
    foreach ($line in @(netstat -ano -p udp)) {
      $m = [regex]::Match($line, "^\s*UDP\s+(\S+):(\d+)\s+\S*\s*(\d+)\s*$")
      if ($m.Success -and ([int]$m.Groups[2].Value -eq $port)) {
        $result += [pscustomobject]@{ LocalAddress = $m.Groups[1].Value; LocalPort = $port; OwningProcess = [int]$m.Groups[3].Value }
      }
    }
  }
  return $result
}
function Describe-Endpoints($eps) {
  if (@($eps).Count -eq 0) { return "<none>" }
  return (@($eps) | ForEach-Object { "{0}:{1} (pid {2})" -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess }) -join ", "
}
function Wait-BoundEndpoint([int]$ownerPid, [int]$port, [int]$timeoutMs) {
  $deadline = (Get-Date).AddMilliseconds($timeoutMs)
  while ((Get-Date) -lt $deadline) {
    foreach ($e in (Get-EndpointsByPid $ownerPid)) { if ($e.LocalPort -eq $port) { return $true } }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
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
  return [pscustomobject]@{ proc = $proc; out = $proc.StandardOutput.ReadToEndAsync(); err = $proc.StandardError.ReadToEndAsync() }
}
function Finish-Captured($state, [string]$outFile, [string]$errFile, [int]$timeoutMs = 45000) {
  $proc = $state.proc
  if (-not $proc.WaitForExit($timeoutMs)) { $proc.Kill(); [void]$proc.WaitForExit(5000) }
  $outText = ""; $errText = ""
  try { $outText = $state.out.Result } catch { $outText = "" }
  try { $errText = $state.err.Result } catch { $errText = "" }
  [IO.File]::WriteAllText($outFile, $outText, (New-Object System.Text.UTF8Encoding($false)))
  [IO.File]::WriteAllText($errFile, $errText, (New-Object System.Text.UTF8Encoding($false)))
  return $proc
}
function Read-Json([string]$path) {
  if (-not (Test-Path $path)) { return $null }
  return ([IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json)
}
function Get-EventsOf($json, [string]$kind) {
  if ($null -eq $json) { return @() }
  return @($json.events | Where-Object { $_.kind -eq $kind })
}

# ---- pick + verify the server binary ---------------------------------------
$entry = $Known | Where-Object { $_.tag -eq $RoomTag } | Select-Object -First 1
if ($null -eq $entry) { Write-Host "unknown -RoomTag $RoomTag"; exit 2 }
if ($RoomExe -ne "") { $entry = ($entry | Select-Object -Property * ); $entry.path = $RoomExe }
if ($entry.protocol -ne "v1") {
  Write-Host ("observe speaks v1 only; {0} is a {1} (v4) server - use a yuzu-room tag" -f $entry.tag, $entry.protocol)
  exit 2
}
if (-not (Test-Path $entry.path)) { Write-Host "server binary not found: $($entry.path)"; exit 4 }
$exePath = (Resolve-Path $Exe).Path
$serverInfo = Get-Item -LiteralPath $entry.path
$serverHash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLower()
Add-Check "server_identity_matches_authorized_table" (($serverInfo.Length -eq $entry.bytes) -and ($serverHash -eq $entry.sha256)) ("tag={0} bytes={1} sha256={2}" -f $entry.tag, $serverInfo.Length, $serverHash)
if ($serverInfo.Length -ne $entry.bytes -or $serverHash -ne $entry.sha256) {
  Write-Host "refusing to start an unknown binary (identity mismatch)"; exit 4
}

# ---- bind decision ---------------------------------------------------------
$bindArgs = @()
$loopbackOnly = $false
if ($entry.supportsBind) {
  $bindArgs = @("--bind-address", "127.0.0.1")
  $loopbackOnly = $true
  Write-Host "bind: explicit --bind-address 127.0.0.1 (strict loopback)"
} elseif ($AllowWildcardBind) {
  Write-Host "bind: binary has no bind option - running under -AllowWildcardBind (loopback_only=false)"
} else {
  Write-Host ("refusing: {0} has no --bind-address and binds 0.0.0.0; pass -AllowWildcardBind (ADR-017)" -f $entry.tag)
  exit 5
}

# ---- port must be free -----------------------------------------------------
$before = @(Get-EndpointsByPort $Port)
Add-Check "port_free_before_start" ($before.Count -eq 0) ("port={0} endpoints={1}" -f $Port, (Describe-Endpoints $before))
if ($before.Count -ne 0) { Write-Host "refusing: port already in use"; exit 6 }

$runDir = Join-Path $OutRoot $entry.tag
if (-not (Test-Path $runDir)) { New-Item -ItemType Directory -Force -Path $runDir | Out-Null }
$runDir = (Resolve-Path $runDir).Path
$workDir = Join-Path $Root ("work/observe-real/" + $entry.tag)
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Force -Path $workDir | Out-Null }

# ---- start the real server -------------------------------------------------
$serverArgList = @()
$serverArgList += $bindArgs
$serverArgList += @("--room-name", $RoomName, "--room-description", $RoomDescription,
                    "--preferred-game", "RealRoomInterop", "--port", "$Port",
                    "--max_members", "$Slots", "--password", $Password)
$serverArgs = $serverArgList -join " "
$started = Get-Date
Write-Host "SERVER: $($entry.path) $serverArgs"
Write-Host ("SERVER IDENTITY: path={0} bytes={1} sha256={2}" -f $entry.path, $serverInfo.Length, $serverHash)
$server = Start-Captured $entry.path $serverArgs $workDir
$ready = Wait-BoundEndpoint $server.proc.Id $Port 10000
Add-Check "server_ready_by_endpoint" $ready ("pid={0} port={1}" -f $server.proc.Id, $Port)
Start-Sleep -Milliseconds 3000
$epsAt3s = @(Get-EndpointsByPid $server.proc.Id)
Write-Host ("SERVER ENDPOINTS @3s: {0}" -f (Describe-Endpoints $epsAt3s))
if ($loopbackOnly) {
  $allLoopback = (@($epsAt3s | Where-Object { $_.LocalAddress -eq "127.0.0.1" }).Count -eq $epsAt3s.Count)
  Add-Check "server_bound_loopback_only" $allLoopback ("endpoints={0}" -f (Describe-Endpoints $epsAt3s))
} else {
  Add-Check "server_wildcard_bind_recorded" ($epsAt3s.Count -gt 0) ("loopback_only=false endpoints={0}" -f (Describe-Endpoints $epsAt3s))
}

# ---- observers -------------------------------------------------------------
$aNick = "rri-obs-a"; $bNick = "rri-obs-b"; $cNick = "rri-obs-c"
$obs = @{}
function Start-Observer([string]$nickname, [int]$seconds, [string]$label) {
  $json = Join-Path $runDir ("observer-" + $label + ".json")
  $argLine = "observe --room 127.0.0.1 --room-port $Port --password $Password --nickname $nickname --seconds $seconds --out $json"
  Write-Host ("OBSERVER {0}: {1} {2}" -f $label.ToUpper(), $exePath, $argLine)
  $state = Start-Captured $exePath $argLine $Root
  return [pscustomobject]@{ label = $label; nickname = $nickname; json = $json; state = $state; argLine = $argLine }
}
function Collect-Observer($o) {
  # The observer runs for its whole --seconds window; the wait must exceed it or the harness
  # would kill the very process whose evidence it is collecting.
  $proc = Finish-Captured $o.state (Join-Path $runDir ("observer-" + $o.label + ".out.txt")) (Join-Path $runDir ("observer-" + $o.label + ".err.txt")) (($Seconds + 25) * 1000)
  $o | Add-Member -NotePropertyName exit -NotePropertyValue $proc.ExitCode -Force
  $json = Read-Json $o.json
  $o | Add-Member -NotePropertyName parsed -NotePropertyValue $json -Force
  Add-Check ("observer_{0}_exit0" -f $o.label) ($proc.ExitCode -eq 0) ("exit={0}" -f $proc.ExitCode)
  Add-Check ("observer_{0}_json_written" -f $o.label) ($null -ne $json) $o.json
  return $o
}
$serverProc = $null
try {
  $oa = Start-Observer $aNick $Seconds "a"
  Start-Sleep -Milliseconds 1500
  $ob = Start-Observer $bNick ($Seconds - 2) "b"
  $oa = Collect-Observer $oa
  $ob = Collect-Observer $ob
  
  foreach ($o in @($oa, $ob)) {
    if ($null -ne $o.parsed) {
      Add-Check ("{0}_joined" -f $o.label) ([bool]$o.parsed.summary.joined) ("joined={0}" -f $o.parsed.summary.joined)
      Add-Check ("{0}_saw_self" -f $o.label) ([bool]$o.parsed.summary.saw_self) ("saw_self={0}" -f $o.parsed.summary.saw_self)
      Add-Check ("{0}_decode_failures_zero" -f $o.label) ($o.parsed.summary.decode_failures -eq 0) ("decode_failures={0}" -f $o.parsed.summary.decode_failures)
      Add-Check ("{0}_max_member_count_two" -f $o.label) ($o.parsed.summary.max_member_count -eq 2) ("max_member_count={0}" -f $o.parsed.summary.max_member_count)
      $two = @(Get-EventsOf $o.parsed "room_information") | Where-Object { $_.member_count -eq 2 } | Select-Object -First 1
      if ($null -ne $two) {
        $names = @($two.members | ForEach-Object { $_.nickname })
        Add-Check ("{0}_two_member_table_has_both" -f $o.label) (($names -contains $aNick) -and ($names -contains $bNick)) ("members={0}" -f ($names -join ","))
        Add-Check ("{0}_room_name_matches" -f $o.label) ($two.room_name -eq $RoomName) ("room_name={0}" -f $two.room_name)
        $selfEntry = $two.members | Where-Object { $_.nickname -eq $o.nickname } | Select-Object -First 1
        $joinEv = @(Get-EventsOf $o.parsed "join_success") | Select-Object -First 1
        Add-Check ("{0}_fake_ip_matches_table" -f $o.label) (($null -ne $selfEntry) -and ($null -ne $joinEv) -and ($selfEntry.fake_ip -eq $joinEv.fake_ip)) ("join_success={0} table={1}" -f $joinEv.fake_ip, $selfEntry.fake_ip)
      } else {
        Add-Check ("{0}_two_member_table_has_both" -f $o.label) $false "no room_information with member_count=2"
        Add-Check ("{0}_room_name_matches" -f $o.label) $false "no room_information with member_count=2"
        Add-Check ("{0}_fake_ip_matches_table" -f $o.label) $false "no room_information with member_count=2"
      }
    }
  }

  # A lone observer: it must at least see itself and its own join_success.
  $oc = Start-Observer $cNick ($Seconds - 2) "c"
  $oc = Collect-Observer $oc
  if ($null -ne $oc.parsed) {
    Add-Check "c_joined" ([bool]$oc.parsed.summary.joined) ("joined={0}" -f $oc.parsed.summary.joined)
    Add-Check "c_saw_self" ([bool]$oc.parsed.summary.saw_self) ("saw_self={0}" -f $oc.parsed.summary.saw_self)
    Add-Check "c_decode_failures_zero" ($oc.parsed.decode_failures -eq 0) ("decode_failures={0}" -f $oc.parsed.decode_failures)
    $cInfo = @(Get-EventsOf $oc.parsed "room_information") | Select-Object -First 1
    $cJoin = @(Get-EventsOf $oc.parsed "join_success") | Select-Object -First 1
    $cSelf = $null
    if ($null -ne $cInfo) { $cSelf = $cInfo.members | Where-Object { $_.nickname -eq $cNick } | Select-Object -First 1 }
    Add-Check "c_sees_itself" (($null -ne $cSelf) -and ($null -ne $cJoin) -and ($cSelf.fake_ip -eq $cJoin.fake_ip)) ("join_success={0} table={1}" -f $cJoin.fake_ip, $cSelf.fake_ip)
    Add-Check "c_member_count_one" (($null -ne $cInfo) -and ($cInfo.member_count -eq 1)) ("member_count={0}" -f $cInfo.member_count)
  }
} finally {
  try { $server.proc.StandardInput.WriteLine("Q"); $server.proc.StandardInput.Flush() } catch { }
  $serverProc = Finish-Captured $server (Join-Path $runDir "server.out.txt") (Join-Path $runDir "server.err.txt")
}

# ---- server log + shutdown -------------------------------------------------
$serverOut = [IO.File]::ReadAllText((Join-Path $runDir "server.out.txt"))
$serverErr = [IO.File]::ReadAllText((Join-Path $runDir "server.err.txt"))
$roomLogPath = Join-Path $workDir "yuzu-room.log"
$roomLog = ""
if (Test-Path $roomLogPath) {
  Copy-Item -LiteralPath $roomLogPath -Destination (Join-Path $runDir "server.log") -Force
  $roomLog = [IO.File]::ReadAllText($roomLogPath)
}
$logText = $serverOut + $serverErr + $roomLog
$joinRe = [regex]::new("rri-obs-a has joined[\s\S]*rri-obs-b has joined[\s\S]*rri-obs-c has joined")
Add-Check "server_log_reports_all_three_joins" $joinRe.IsMatch($logText) "server log contains a/b/c has-joined lines"
Add-Check "server_private_room_no_external_service" ($logText -match "Hosting a private room") "no --token/--web-api-url; private-room line present"
Start-Sleep -Milliseconds 500
$epsAfter = @(Get-EndpointsByPid $serverProc.Id)
$afterByPort = @(Get-EndpointsByPort $Port)
Add-Check "server_stopped" ($serverProc.HasExited) ("exit={0}" -f $serverProc.ExitCode)
Add-Check "port_released_after_exit" ($afterByPort.Count -eq 0) ("port={0} endpoints={1}" -f $Port, (Describe-Endpoints $afterByPort))

$elapsed = (Get-Date) - $started
if (-not $loopbackOnly) {
  Add-Check "wildcard_run_under_60s" ($elapsed.TotalSeconds -lt 60) ("elapsed_s={0:N1}" -f $elapsed.TotalSeconds)
}

# ---- summary ---------------------------------------------------------------
$observerExe = @{}
if ($null -ne $oa.parsed) { $observerExe = @{ path = $oa.parsed.exe.path; bytes = $oa.parsed.exe.bytes; sha256 = $oa.parsed.exe.sha256 } }
$commands = @()
$commands += ("SERVER: " + $entry.path + " " + $serverArgs)
foreach ($o in @($oa, $ob, $oc)) { if ($null -ne $o) { $commands += ("OBSERVER " + $o.label + ": " + $exePath + " " + $o.argLine) } }
[IO.File]::WriteAllText((Join-Path $runDir "commands.txt"), (($commands -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
$failed = @($checks | Where-Object { -not $_.ok }).Count
$obsSummary = @()
foreach ($o in @($oa, $ob, $oc)) {
  if ($null -eq $o) { continue }
  $obsSummary += [ordered]@{
    label = $o.label; nickname = $o.nickname; exit = $o.exit; seconds = 0
    json = $o.json
    joined = if ($null -ne $o.parsed) { $o.parsed.summary.joined } else { $false }
    saw_self = if ($null -ne $o.parsed) { $o.parsed.summary.saw_self } else { $false }
    room_information = if ($null -ne $o.parsed) { $o.parsed.summary.room_information } else { 0 }
    errors = if ($null -ne $o.parsed) { $o.parsed.summary.errors } else { 0 }
    decode_failures = if ($null -ne $o.parsed) { $o.parsed.summary.decode_failures } else { 0 }
    max_member_count = if ($null -ne $o.parsed) { $o.parsed.summary.max_member_count } else { 0 }
    members_seen = if ($null -ne $o.parsed) { @($o.parsed.summary.members_seen) } else { @() }
  }
}
$summary = [ordered]@{
  tool = "real-room-interop"
  mode = "observe-real"
  server = [ordered]@{ tag = $entry.tag; path = $entry.path; bytes = $serverInfo.Length; sha256 = $serverHash;
    supports_bind_option = $entry.supportsBind; command = $serverArgs;
    bind = if ($loopbackOnly) { "127.0.0.1 (explicit --bind-address)" } else { "wildcard 0.0.0.0 (no bind option)" };
    loopback_only = $loopbackOnly; pid = $serverProc.Id; exit = $serverProc.ExitCode;
    endpoints_at_3s = @($epsAt3s | ForEach-Object { "{0}:{1}" -f $_.LocalAddress, $_.LocalPort });
    endpoints_after_exit = @($epsAfter | ForEach-Object { "{0}:{1}" -f $_.LocalAddress, $_.LocalPort });
    log_reports_private_room = ($logText -match "Hosting a private room") }
  observer_exe = $observerExe
  room = @{ address = "127.0.0.1"; port = $Port; name = $RoomName; slots = $Slots; password_set = $true }
  observers = $obsSummary
  checks_total = $checks.Count
  checks_failed = $failed
  checks = $checks
  started_utc = $started.ToUniversalTime().ToString("o")
  elapsed_ms = [int]$elapsed.TotalMilliseconds
  note = "member-table oracle only; this does not connect the gateway and is not a G-c verdict"
}
[IO.File]::WriteAllText((Join-Path $runDir "summary.json"), ($summary | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("OBSERVE_REAL_RESULT tag={0} checks={1} failed={2} elapsed_ms={3} bind={4}" -f $entry.tag, $checks.Count, $failed, $summary.elapsed_ms, $summary.server.bind)
if ($failed -gt 0) { exit 1 }
exit 0
