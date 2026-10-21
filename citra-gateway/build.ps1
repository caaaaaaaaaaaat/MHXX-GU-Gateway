# SPDX-License-Identifier: GPL-2.0-or-later
# G-b gateway build script (PowerShell 5.1).
#
# MinGW cannot create its assembler temporaries when the toolchain is handed the
# non ASCII workspace path, so every translation unit is compiled on its own with
# a relative ASCII source path and a relative ASCII object path, and the objects
# are linked explicitly afterwards. TMP/TEMP/PATH are never modified.
[CmdletBinding()]
param(
    [string]$Compiler = 'G:\msys64\mingw64\bin\g++.exe',
    [string]$Gcc = 'G:\msys64\mingw64\bin\gcc.exe',
    [switch]$RunTests,
    [int]$WatchdogMs = 150000,
    [switch]$SkipRepro,
    # -Clean: remove .build-direct before building. The script always starts from
    # a fresh output directory; the switch exists so the caller can ask for it
    # explicitly (and so the -Clean invocation is the documented one).
    [switch]$Clean,
    # Pure in-memory tests only; never starts CLI/harness or an ENet Runtime.
    [switch]$OfflineVerify,
    [string]$OfflineOutput = '.build-offline-verify'
)

$ErrorActionPreference = 'Stop'
if ($OfflineVerify -and $RunTests) { throw '-OfflineVerify and -RunTests are mutually exclusive' }
if ($OfflineOutput -cnotmatch '\A\.build-offline-[a-z0-9]+(-[a-z0-9]+)*\z') { throw 'OfflineOutput must be a local .build-offline-* ASCII leaf' }
if (-not $OfflineVerify -and $OfflineOutput -cne '.build-offline-verify') { throw 'OfflineOutput requires OfflineVerify' }
Push-Location -LiteralPath $PSScriptRoot

$Out = '.build-direct'
if ($OfflineVerify) {
    $Out = $OfflineOutput
    if (Test-Path -LiteralPath $Out) { throw "Offline output already exists; preserving it: $Out" }
}
$Enet = '../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
$Fmt = '../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
$Support = '../room-transport/support/include'
$Core = '../room-client'
$CitraRoom = '../citra-room'
$Control = '../citra-control'
$Transport = '../room-transport'
$Original = '../../01052024-yuzu-mirror-master/src'
$ZstdInclude = 'G:/msys64/mingw64/include'
$ZstdLib = 'G:/msys64/mingw64/lib/libzstd.a'
$CxxFlags = @('-pipe','-std=c++20','-O2','-g','-Wall','-Wextra','-Wpedantic','-DNOMINMAX',
    '-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY','-Iinclude',"-I$CitraRoom/include",
    "-I$Control/include",
    "-I$Core/include","-I$Transport/include","-I$Support","-I$Enet/include","-I$Fmt/include",
    "-I$Original","-I$ZstdInclude")
$LinkFlags = @('-pipe','-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp')
$LinkTail = @($ZstdLib,'-lws2_32','-lwinmm')
$EnetFiles = @('callbacks','compress','host','list','packet','peer','protocol','unix','win32')
$OriginalFiles = @(
    'network/room.h','network/room.cpp','network/packet.h','network/packet.cpp',
    'network/verify_user.h','network/verify_user.cpp','common/common_types.h',
    'common/socket_types.h','common/announce_multiplayer_room.h',
    'common/logging/log.h','common/string_util.h')
$Units = @(
    @('citra_protocol', "$CitraRoom/src/protocol.cpp"),
    @('citra_session', "$CitraRoom/src/session.cpp"),
    @('room_protocol', "$Core/src/protocol.cpp"),
    @('room_session', "$Core/src/session.cpp"),
    @('transport', "$Transport/src/transport.cpp"),
    @('original_room', "$Original/network/room.cpp"),
    @('original_packet', "$Original/network/packet.cpp"),
    @('original_verify', "$Original/network/verify_user.cpp"),
    @('control_bytes', "$Control/src/bytes.cpp"),
    @('control_crypto', "$Control/src/crypto.cpp"),
    @('control_ldn', "$Control/src/ldn_ctrl.cpp"),
    @('control_map', "$Control/src/map.cpp"),
    @('control_state', "$Control/src/state.cpp"),
    @('control_heartbeat', "$Control/src/heartbeat.cpp"),
    @('control_uds', "$Control/src/uds_frames.cpp"),
    @('trace', 'src/trace.cpp'),
    @('identity', 'src/identity.cpp'),
    @('control', 'src/control.cpp'),
    @('gateway', 'src/gateway.cpp'),
    @('main', 'src/main.cpp'),
    @('test_identity', 'tests/test_identity.cpp'),
    @('test_gateway', 'tests/test_gateway.cpp')
)
$Exes = @('citra-gateway.exe','citra-gateway-identity-tests.exe','citra-gateway-tests.exe')
if ($OfflineVerify) {
    $Units += ,@('test_offline', 'tests/test_offline.cpp')
    $Exes += 'citra-gateway-offline-tests.exe'
}

function Invoke-Compiler([string]$Tool, [string[]]$Arguments) {
    $line = $Tool + ' ' + ($Arguments -join ' ')
    Write-Host $line
    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "compiler exit=$LASTEXITCODE : $line"
    }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Build-All {
    # Verify the absolute intended child before either clean/repro build deletes it.
    $absoluteOut = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Out))
    if ($Out -cne '.build-direct' -and $Out -cnotmatch '\A\.build-offline-[a-z0-9]+(-[a-z0-9]+)*\z') { throw 'Unsafe build output' }
    Write-Host "BUILD OUTPUT $absoluteOut"
    if (Test-Path -LiteralPath $absoluteOut) {
        if ((Get-Item -LiteralPath $absoluteOut -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Refusing reparse-point build output' }
        Remove-Item -LiteralPath $absoluteOut -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    New-Item -ItemType Directory -Force -Path "$Out/evidence" | Out-Null
    $objects = @{}
    $enetObjects = @()
    foreach ($name in $EnetFiles) {
        $obj = "$Out/enet_$name.o"
        Invoke-Compiler $Gcc @('-pipe','-std=c99','-O2',"-I$Enet/include",'-c',"$Enet/$name.c",'-o',$obj)
        $objects["enet_$name"] = $obj
        $enetObjects += $obj
    }
    foreach ($unit in $Units) {
        $stem = $unit[0]
        $src = $unit[1]
        $obj = "$Out/$stem.o"
        Invoke-Compiler $Compiler ($CxxFlags + @('-c',$src,'-o',$obj))
        $objects[$stem] = $obj
    }
    $core = @($objects['citra_protocol'],$objects['room_protocol'],$objects['room_session'],
        $objects['transport'],$objects['control_bytes'],$objects['control_crypto'],
        $objects['control_ldn'],$objects['control_map'],$objects['control_state'],
        $objects['control_uds'],$objects['control_heartbeat']) + $enetObjects + $LinkTail
    Invoke-Compiler $Compiler ($LinkFlags + @($objects['main'],$objects['gateway'],
        $objects['identity'],$objects['control'],$objects['trace']) + $core +
        @('-o',"$Out/citra-gateway.exe"))
    Invoke-Compiler $Compiler ($LinkFlags + @($objects['test_identity'],$objects['identity'],
        '-o',"$Out/citra-gateway-identity-tests.exe"))
    Invoke-Compiler $Compiler ($LinkFlags + @($objects['test_gateway'],$objects['gateway'],
        $objects['identity'],$objects['control'],$objects['original_room'],
        $objects['original_packet'],$objects['original_verify'],$objects['citra_session'],
        $objects['trace']) + $core + @('-o',"$Out/citra-gateway-tests.exe"))
    if ($OfflineVerify) {
        Invoke-Compiler $Compiler ($LinkFlags + @($objects['test_offline'],$objects['gateway'],
            $objects['identity'],$objects['control'],$objects['trace']) + $core +
            @('-o',"$Out/citra-gateway-offline-tests.exe"))
    }
}

function Invoke-Test([string]$Exe, [string[]]$Arguments, [string]$Tag) {
    $stdout = "$Out/$Tag.stdout.txt"
    $stderr = "$Out/$Tag.stderr.txt"
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = (Resolve-Path -LiteralPath $Exe).Path
    $info.Arguments = ($Arguments -join ' ')
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = (Get-Location).Path
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    [void]$process.Start()
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($WatchdogMs)) {
        $process.Kill()
        $process.WaitForExit()
        throw "$Tag exceeded the $WatchdogMs ms watchdog; the process was terminated"
    }
    $outText = $outTask.Result
    $errText = $errTask.Result
    $code = $process.ExitCode
    Set-Content -LiteralPath $stdout -Value $outText -Encoding ASCII
    Set-Content -LiteralPath $stderr -Value $errText -Encoding ASCII
    Set-Content -LiteralPath "$Out/$Tag.exit.txt" -Value $code -Encoding ASCII
    Write-Host "TEST $Tag exit=$code"
    return $code
}

$assertTotal = 0
$assertFailed = 0

function Add-Assertion([string]$Name, [bool]$Ok, [string]$Detail) {
    $script:assertTotal++
    if ($Ok) {
        Write-Host "ASSERT-OK $Name $Detail"
    } else {
        $script:assertFailed++
        Write-Host "ASSERT-FAIL $Name $Detail"
    }
}

function Get-JsonNode([string]$File, [string]$Property) {
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    $node = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json
    if ([string]::IsNullOrEmpty($Property)) { return $node }
    $parts = $Property.Split('.')
    # counters.json is a flat document; accept a leading "counters." prefix.
    if ($parts.Length -gt 1 -and $parts[0] -eq 'counters' -and
        (($node.PSObject.Properties.Name) -notcontains 'counters')) {
        $parts = $parts[1..($parts.Length - 1)]
    }
    foreach ($part in $parts) {
        if ($null -eq $node) { break }
        $node = $node.$part
    }
    return $node
}

function Assert-Evidence([string]$Name, [string]$File, [string]$Property, [string]$Expected) {
    $actual = Get-JsonNode $File $Property
    Add-Assertion $Name ("$actual" -eq $Expected) "actual=$actual expected=$Expected"
}

function Expect-Exit([string]$Name, [int]$Actual, [int]$Expected) {
    Add-Assertion $Name ($Actual -eq $Expected) "actual=$Actual expected=$Expected"
    if ($Actual -eq $Expected) { return 0 }
    return 1
}

# ---------------------------------------------------------------------------
# Inputs that must not change while we build.
# ---------------------------------------------------------------------------
$originalBefore = @{}
foreach ($rel in $OriginalFiles) {
    $path = Join-Path $Original $rel
    if (Test-Path -LiteralPath $path) {
        $originalBefore[$rel] = Get-Sha256 $path
    }
}
Write-Host "original source files hashed: $($originalBefore.Count)"

$sourceBefore = @{}
$mySources = @('src/identity.cpp','src/control.cpp','src/gateway.cpp','src/main.cpp',
    'src/trace.cpp','tests/test_identity.cpp','tests/test_gateway.cpp','tests/game_return_runtime.inc',
    'include/citra_gateway/identity.hpp','include/citra_gateway/control.hpp',
    'include/citra_gateway/gateway.hpp','include/citra_gateway/trace.hpp',
    'include/citra_gateway/capabilities.hpp')
if ($OfflineVerify) { $mySources += 'tests/test_offline.cpp' }
foreach ($rel in $mySources) { $sourceBefore[$rel] = Get-Sha256 $rel }

$toolchain = [ordered]@{}
$toolchain['compiler'] = $Compiler
$toolchain['compiler_sha256'] = Get-Sha256 $Compiler
$toolchain['gcc_sha256'] = Get-Sha256 $Gcc
$toolchain['zstd_lib_sha256'] = Get-Sha256 $ZstdLib
$toolchain['zstd_header_sha256'] = Get-Sha256 "$ZstdInclude/zstd.h"
$toolchain['transport_header_sha256'] = Get-Sha256 "$Transport/include/room_transport/transport.hpp"
$toolchain['support_log_header_sha256'] = Get-Sha256 "$Support/common/logging/log.h"
$toolchain['citra_protocol_header_sha256'] = Get-Sha256 "$CitraRoom/include/citra_room/protocol.hpp"
$toolchain['citra_session_source_sha256'] = Get-Sha256 "$CitraRoom/src/session.cpp"
$toolchain['room_protocol_header_sha256'] = Get-Sha256 "$Core/include/room_client/protocol.hpp"
$toolchain['citra_control_state_header_sha256'] = Get-Sha256 "$Control/include/citra_control/state.hpp"
$toolchain['citra_control_ldn_ctrl_header_sha256'] = Get-Sha256 "$Control/include/citra_control/ldn_ctrl.hpp"
$toolchain['citra_control_uds_frames_header_sha256'] = Get-Sha256 "$Control/include/citra_control/uds_frames.hpp"
$toolchain['citra_control_map_header_sha256'] = Get-Sha256 "$Control/include/citra_control/map.hpp"
$toolchain['citra_control_state_source_sha256'] = Get-Sha256 "$Control/src/state.cpp"
$toolchain['citra_control_heartbeat_source_sha256'] = Get-Sha256 "$Control/src/heartbeat.cpp"
$toolchain['citra_control_ldn_ctrl_source_sha256'] = Get-Sha256 "$Control/src/ldn_ctrl.cpp"
$toolchain['citra_control_uds_frames_source_sha256'] = Get-Sha256 "$Control/src/uds_frames.cpp"
$toolchain['citra_control_map_source_sha256'] = Get-Sha256 "$Control/src/map.cpp"
foreach ($name in $EnetFiles) {
    $toolchain["enet_$name.c"] = Get-Sha256 "$Enet/$name.c"
}

# ---------------------------------------------------------------------------
# Build 1, hash, then an independent clean rebuild and hash again.
# ---------------------------------------------------------------------------
Build-All
$first = @{}
foreach ($exe in $Exes) { $first[$exe] = Get-Sha256 "$Out/$exe" }
foreach ($exe in $Exes) { Write-Host "BUILD1 $exe $($first[$exe])" }

$reproducible = $null
$reproStatus = 'not_checked'
if (-not $SkipRepro) {
    Build-All
    $second = @{}
    foreach ($exe in $Exes) { $second[$exe] = Get-Sha256 "$Out/$exe" }
    foreach ($exe in $Exes) { Write-Host "BUILD2 $exe $($second[$exe])" }
    $reproducible = $true
    foreach ($exe in $Exes) {
        if ($first[$exe] -ne $second[$exe]) { $reproducible = $false }
    }
    $reproStatus = "$reproducible"
    if (-not $reproducible) { throw 'the two independent builds produced different artifacts' }
}
Write-Host "REPRODUCIBLE=$reproStatus"

$originalChanged = $false
foreach ($rel in $originalBefore.Keys) {
    if ($originalBefore[$rel] -ne (Get-Sha256 (Join-Path $Original $rel))) {
        $originalChanged = $true
        Write-Host "ORIGINAL-CHANGED $rel"
    }
}
if ($originalChanged) { throw 'an unmodified upstream source changed during the build' }

$artifacts = [ordered]@{}
foreach ($key in $toolchain.Keys) { $artifacts["toolchain.$key"] = $toolchain[$key] }
foreach ($rel in $originalBefore.Keys) { $artifacts["original.$rel"] = $originalBefore[$rel] }
foreach ($rel in $sourceBefore.Keys) { $artifacts["source.$rel"] = $sourceBefore[$rel] }
foreach ($name in $EnetFiles) { $artifacts["source.enet/$name.c"] = Get-Sha256 "$Enet/$name.c" }
foreach ($exe in $Exes) { $artifacts["artifact.$exe"] = $first[$exe] }
$artifacts['reproducible'] = $reproducible
$artifacts['reproducibility_checked'] = (-not $SkipRepro)
$artifacts | ConvertTo-Json | Set-Content -LiteralPath "$Out/artifacts-sha256.json" -Encoding ASCII

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("reproducible=$reproStatus")
foreach ($exe in $Exes) { $summary.Add("sha256.$exe=$($first[$exe])") }

# ---------------------------------------------------------------------------
# Tests (the watchdog is enforced by Invoke-Test).
# ---------------------------------------------------------------------------
if ($RunTests) {
    $failures = 0
    $failures += (Expect-Exit 'cli.identity_tests_exit' (Invoke-Test "$Out/citra-gateway-identity-tests.exe" @() 'identity-tests') 0)
    $failures += (Expect-Exit 'cli.help_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--help') 'cli-help') 0)
    $failures += (Expect-Exit 'cli.self_check_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--self-check') 'cli-self-check') 0)
    $failures += (Expect-Exit 'cli.usage_error_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--unknown-option') 'cli-usage-error') 2)
    $failures += (Expect-Exit 'cli.non_loopback_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--listen','8.8.8.8') 'cli-non-loopback') 3)
    $failures += (Expect-Exit 'cli.peer_relay_control_plane_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--citra-peer-relay','--control-plane') 'cli-peer-relay-control-plane') 2)
    New-Item -ItemType Directory -Force -Path "$Out/cli-dump" | Out-Null
    $failures += (Expect-Exit 'cli.run_exit' (Invoke-Test "$Out/citra-gateway.exe" @('--listen-port','39999','--room-port','39998','--seconds','1','--quiet','--dump',"$Out/cli-dump") 'cli-run') 0)
    $harnessExit = Invoke-Test "$Out/citra-gateway-tests.exe" @("$Out/evidence") 'harness'
    $failures += (Expect-Exit 'cli.harness_exit' $harnessExit 0)

    $missing = 0
    foreach ($name in @('counters.json','clients.json','identities.json','captures.json','events.json','snapshot.json','emitted.json')) {
        if (-not (Test-Path -LiteralPath "$Out/cli-dump/$name")) { $missing++ }
    }
    Add-Assertion 'cli.dump_files' ($missing -eq 0) "missing=$missing"
    Assert-Evidence 'cli.dump_listen_port' "$Out/cli-dump/counters.json" 'listen_port' '39999'
    $cli_counters_text = Get-Content -LiteralPath "$Out/cli-dump/counters.json" -Raw
    Add-Assertion 'cli.citra_transport_enet' ($cli_counters_text -match '"citra_transport":"enet"') 'the CLI gateway binds the Citra side as ENet/UDP'
    $cli_help_text = Get-Content -LiteralPath "$Out/cli-help.stdout.txt" -Raw
    Add-Assertion 'cli.peer_relay_flag' ($cli_help_text -match '--citra-peer-relay') 'the help text advertises --citra-peer-relay'
    Assert-Evidence 'a1.evidence_listen_port' "$Out/evidence/a1_members.counters.json" 'listen_port' '39574'

    $stdout = Get-Content -LiteralPath "$Out/harness.stdout.txt"
    $result = $stdout | Select-String -Pattern '^RESULT cases=(\d+) failed=(\d+) groups=(\d+) exit=(\d+)'
    if ($null -eq $result) {
        Add-Assertion 'harness.result_line' $false 'RESULT line missing'
        $failures++
    } else {
        $failedCount = [int]$result.Matches[0].Groups[2].Value
        Add-Assertion 'harness.failed_zero' ($failedCount -eq 0) $result.Matches[0].Value
        Write-Host "HARNESS $($result.Matches[0].Value)"
        if ($failedCount -ne 0) { $failures++ }
    }
    foreach ($line in ($stdout | Select-String -Pattern '^NOTE a7\.')) {
        Write-Host "HARNESS-NOTE $($line.Line)"
        $value = [int](($line.Line -split '=')[1])
        Add-Assertion "harness.release_time" ($value -le 1000) $line.Line
        if ($value -gt 1000) { $failures++ }
    }
    foreach ($line in ($stdout | Select-String -Pattern '^NOTE b2\.')) {
        Write-Host "HARNESS-NOTE $($line.Line)"
        $value = [int](($line.Line -split '=')[1])
        Add-Assertion "harness.control_time" ($value -le 1000) $line.Line
        if ($value -gt 1000) { $failures++ }
    }

    Assert-Evidence 'a1.clients_joined' "$Out/evidence/a1_members.counters.json" 'counters.clients_joined' '2'
    Assert-Evidence 'a1.clients_left' "$Out/evidence/a1_members.counters.json" 'counters.clients_left' '1'
    Assert-Evidence 'a1.mac_generated' "$Out/evidence/a1_members.counters.json" 'counters.mac_generated' '2'
    Assert-Evidence 'a1.members_peak' "$Out/evidence/a1_members.counters.json" 'counters.max_members_in_room' '2'
    Assert-Evidence 'a2.local_version' "$Out/evidence/a2_handshake.counters.json" 'counters.local_version_rejections' '1'
    Assert-Evidence 'a2.room_joins' "$Out/evidence/a2_handshake.counters.json" 'counters.room_join_successes' '1'
    Assert-Evidence 'a2.room_version' "$Out/evidence/a2_handshake.counters.json" 'counters.room_version_forwarded' '1'
    Assert-Evidence 'a2.citra_version' "$Out/evidence/a2_handshake.counters.json" 'counters.citra_version_served' '4'
    Assert-Evidence 'a3.password' "$Out/evidence/a3_password.counters.json" 'counters.error_map_hits.WrongPassword' '1'
    Assert-Evidence 'a3.version' "$Out/evidence/a3_version.counters.json" 'counters.error_map_hits.VersionMismatch' '1'
    Assert-Evidence 'a3.name' "$Out/evidence/a3_name.counters.json" 'counters.error_map_hits.NameCollision' '1'
    Assert-Evidence 'a3.mac' "$Out/evidence/a3_mac.counters.json" 'counters.error_map_hits.MacCollision' '1'
    Assert-Evidence 'a3.full' "$Out/evidence/a3_full.counters.json" 'counters.error_map_hits.RoomIsFull' '1'
    Assert-Evidence 'a3.close' "$Out/evidence/a3_close.counters.json" 'counters.error_map_hits.CloseRoom' '1'
    Assert-Evidence 'a3.console' "$Out/evidence/a3_console_id.counters.json" 'counters.error_map_hits.ConsoleIdCollision' '1'
    Assert-Evidence 'a3.no_correspondence' "$Out/evidence/a3_console_id.counters.json" 'counters.no_correspondence_rejections' '1'
    Assert-Evidence 'a3.console_not_mapped' "$Out/evidence/a3_console_id.counters.json" 'counters.room_errors_mapped' '0'
    Assert-Evidence 'a3.password_local' "$Out/evidence/a3_password.counters.json" 'counters.local_wrong_password_rejections' '1'
    Assert-Evidence 'a3.password_not_room' "$Out/evidence/a3_password.counters.json" 'counters.room_errors_mapped' '0'
    Assert-Evidence 'a3.name_local' "$Out/evidence/a3_name.counters.json" 'counters.local_name_collision_rejections' '1'
    Assert-Evidence 'a3.name_not_room' "$Out/evidence/a3_name.counters.json" 'counters.room_errors_mapped' '0'
    Assert-Evidence 'a3.full_local' "$Out/evidence/a3_full.counters.json" 'counters.local_room_full_rejections' '1'
    Assert-Evidence 'a3.full_not_room' "$Out/evidence/a3_full.counters.json" 'counters.room_errors_mapped' '0'
    Assert-Evidence 'a3.close_room_mapped' "$Out/evidence/a3_close.counters.json" 'counters.room_errors_mapped' '1'
    Assert-Evidence 'a3c.full_version' "$Out/evidence/a3c_full_version.counters.json" 'counters.local_room_full_rejections' '1'
    Assert-Evidence 'a3c.full_version_shadowed' "$Out/evidence/a3c_full_version.counters.json" 'counters.local_version_rejections' '0'
    Assert-Evidence 'a3c.password_version' "$Out/evidence/a3c_password_version.counters.json" 'counters.local_wrong_password_rejections' '1'
    Assert-Evidence 'a3c.password_version_shadowed' "$Out/evidence/a3c_password_version.counters.json" 'counters.local_version_rejections' '0'
    Assert-Evidence 'a3c.password_name' "$Out/evidence/a3c_password_name.counters.json" 'counters.local_wrong_password_rejections' '1'
    Assert-Evidence 'a3c.name_mac' "$Out/evidence/a3c_name_mac.counters.json" 'counters.local_name_collision_rejections' '1'
    Assert-Evidence 'a3c.name_mac_shadowed' "$Out/evidence/a3c_name_mac.counters.json" 'counters.local_mac_collision_rejections' '0'
    Assert-Evidence 'a3c.mac_console' "$Out/evidence/a3c_mac_console.counters.json" 'counters.local_mac_collision_rejections' '1'
    Assert-Evidence 'a3c.mac_console_shadowed' "$Out/evidence/a3c_mac_console.counters.json" 'counters.local_console_id_collision_rejections' '0'
    Assert-Evidence 'a3c.console_version' "$Out/evidence/a3c_console_version.counters.json" 'counters.local_console_id_collision_rejections' '1'
    Assert-Evidence 'a3c.console_version_shadowed' "$Out/evidence/a3c_console_version.counters.json" 'counters.local_version_rejections' '0'
    Assert-Evidence 'a3c.version_only' "$Out/evidence/a3c_version_only.counters.json" 'counters.local_version_rejections' '1'
    Assert-Evidence 'a3c.invalid_nickname' "$Out/evidence/a3c_invalid_nickname.counters.json" 'counters.local_name_collision_rejections' '1'
    Assert-Evidence 'a4.emitted' "$Out/evidence/a4_payload.counters.json" 'counters.proxy_frames_emitted' '2'
    Assert-Evidence 'a4.consumed' "$Out/evidence/a4_payload.counters.json" 'counters.proxy_frames_consumed' '2'
    Assert-Evidence 'a4.forwarded' "$Out/evidence/a4_payload.counters.json" 'counters.payload_forwarded' '4'
    Assert-Evidence 'a4.unknown_categories' "$Out/evidence/a4_payload.counters.json" 'counters.payload_rejected_unknown_category' '6'
    Assert-Evidence 'a5.unknown_source' "$Out/evidence/a5_fail_closed.counters.json" 'counters.unknown_source_rejections' '1'
    Assert-Evidence 'a5.self_echo' "$Out/evidence/a5_fail_closed.counters.json" 'counters.self_echo_rejections' '1'
    Assert-Evidence 'a5.sentinel' "$Out/evidence/a5_fail_closed.counters.json" 'counters.sentinel_mac_rejections' '1'
    Assert-Evidence 'a5.destination_unmapped' "$Out/evidence/a5_fail_closed.counters.json" 'counters.destination_unmapped_rejections' '1'
    Assert-Evidence 'a6.unknown_ids' "$Out/evidence/a6_negative.counters.json" 'counters.unknown_id_rejections' '8'
    Assert-Evidence 'a6.unknown_enums' "$Out/evidence/a6_negative.counters.json" 'counters.unknown_enum_rejections' '1'
    Assert-Evidence 'a6.wrong_direction' "$Out/evidence/a6_negative.counters.json" 'counters.wrong_direction_rejections' '3'
    Assert-Evidence 'a6.trailing_bytes' "$Out/evidence/a6_negative.counters.json" 'counters.trailing_byte_rejections' '1'
    Assert-Evidence 'a6.limit_exceeded' "$Out/evidence/a6_negative.counters.json" 'counters.limit_exceeded_rejections' '2'
    Assert-Evidence 'a6.large_payload_forwarded' "$Out/evidence/a6_negative.counters.json" 'counters.payload_forwarded' '4'
    Assert-Evidence 'a6.no_pre_decode_drop' "$Out/evidence/a6_negative.counters.json" 'counters.oversize_rejections' '1'
    Assert-Evidence 'a8.outbox' "$Out/evidence/a8_bounds.counters.json" 'counters.outbox_overflows' '1'
    Assert-Evidence 'a8.inbox' "$Out/evidence/a8_bounds.counters.json" 'counters.inbox_overflows' '1'
    Assert-Evidence 'a10.port_conflicts' "$Out/evidence/a10_port_conflict.counters.json" 'counters.port_conflicts' '1'
    Assert-Evidence 'a11.relay_emitted' "$Out/evidence/a11_peer_relay.counters.json" 'counters.peer_relay_frames_emitted' '2'
    Assert-Evidence 'a11.relay_consumed' "$Out/evidence/a11_peer_relay.counters.json" 'counters.peer_relay_frames_consumed' '2'
    Assert-Evidence 'a11.relay_bad_wrapper' "$Out/evidence/a11_peer_relay.counters.json" 'counters.peer_relay_bad_wrapper' '1'

    # --- G-b' control plane bridging (section 7 of docs/M4-CONTROL-PLANE.md) ---
    Assert-Evidence 'b1.ap_started' "$Out/evidence/b1_control.counters.json" 'counters.control.ap_started' '2'
    Assert-Evidence 'b1.ap_created' "$Out/evidence/b1_control.counters.json" 'counters.control.ap_created' '2'
    Assert-Evidence 'b1.beacon_skipped' "$Out/evidence/b1_control.counters.json" 'counters.control.beacon_skipped' '0'
    Assert-Evidence 'b1.auth_refused' "$Out/evidence/b1_control.counters.json" 'counters.control.auth_refused' '1'
    Assert-Evidence 'b1.auth_rejected' "$Out/evidence/b1_control.counters.json" 'counters.control.auth_rejected' '1'
    Assert-Evidence 'b1.auth_seq1_fold' "$Out/evidence/b1_control.counters.json" 'counters.control.auth_seq2_emitted' '1'
    Assert-Evidence 'b1.assoc_response' "$Out/evidence/b1_control.counters.json" 'counters.control.assoc_response_emitted' '1'
    Assert-Evidence 'b1.eapol_fold' "$Out/evidence/b1_control.counters.json" 'counters.control.eapol_start_accepted' '1'
    Assert-Evidence 'b1.eapol_rejected' "$Out/evidence/b1_control.counters.json" 'counters.control.eapol_rejected' '1'
    Assert-Evidence 'b1.node_map' "$Out/evidence/b1_control.counters.json" 'counters.control.node_map_emitted' '1'
    Assert-Evidence 'b1.logoff' "$Out/evidence/b1_control.counters.json" 'counters.control.logoff_frame_emitted' '1'
    Assert-Evidence 'b1.wrong_direction' "$Out/evidence/b1_control.counters.json" 'counters.control.citra_wrong_direction' '1'
    Assert-Evidence 'b1.data_accepted' "$Out/evidence/b1_control.counters.json" 'counters.control.citra_data_accepted' '1'
    Assert-Evidence 'b1.data_not_connected' "$Out/evidence/b1_control.counters.json" 'counters.control.citra_data_not_connected' '1'
    # Includes the sparse-slot departure/rejoin scenario: three extra connects,
    # one disconnect and one scan. Sync emits once per currently live station.
    Assert-Evidence 'b1.scan_accepted' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_scan_accepted' '2'
    Assert-Evidence 'b1.scan_resp' "$Out/evidence/b1_control.counters.json" 'counters.control.scan_resp_emitted' '2'
    Assert-Evidence 'b1.connect_accepted' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_connect_accepted' '4'
    Assert-Evidence 'b1.sync_network' "$Out/evidence/b1_control.counters.json" 'counters.control.sync_network_emitted' '7'
    Assert-Evidence 'b1.connect_rejected' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_connect_rejected' '1'
    Assert-Evidence 'b1.disconnect' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_disconnect_accepted' '2'
    Assert-Evidence 'b1.unknown_source' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_unknown_source' '1'
    Assert-Evidence 'b1.destroy' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_destroy_accepted' '1'
    Assert-Evidence 'b1.bad_length' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_bad_length' '1'
    Assert-Evidence 'b1.bad_source' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_bad_source' '1'
    Assert-Evidence 'b1.ldn_direction' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_direction_rejected' '1'
    Assert-Evidence 'b1.non_owner' "$Out/evidence/b1_control.counters.json" 'counters.control.ldn_non_owner_ignored' '1'
    Assert-Evidence 'b1.mirrored_sessions' "$Out/evidence/b1_control.counters.json" 'counters.control.mirror_applied' '5'
    Assert-Evidence 'b1.outbox_valid' "$Out/evidence/b1_control.counters.json" 'counters.control.outbox_invalid' '0'
    Assert-Evidence 'b1.emit_ok' "$Out/evidence/b1_control.counters.json" 'counters.control.emit_failed' '0'
    Assert-Evidence 'b1.ssid' "$Out/evidence/b1_control.counters.json" 'counters.control.ssid_fallback' '0'
    $b1_invented = [int](Get-JsonNode "$Out/evidence/b1_control.counters.json" 'counters.control.invented_fields')
    Add-Assertion 'b1.invented_fields' ($b1_invented -gt 0) "invented=$b1_invented"
    $b1_undefined = [int](Get-JsonNode "$Out/evidence/b1_control.counters.json" 'counters.control.undefined_fields')
    Add-Assertion 'b1.undefined_fields' ($b1_undefined -gt 0) "undefined=$b1_undefined"
    $b1_beacons = [int](Get-JsonNode "$Out/evidence/b1_control.counters.json" 'counters.control.beacon_emitted')
    Add-Assertion 'b1.beacons_emitted' ($b1_beacons -ge 2) "beacons=$b1_beacons"
    Assert-Evidence 'b2.ap_started' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.ap_started' '1'
    Assert-Evidence 'b2.ap_created' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.ap_created' '1'
    Assert-Evidence 'b2.beacon_skipped' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.beacon_skipped' '0'
    Assert-Evidence 'b2.scan_accepted' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.ldn_scan_accepted' '1'
    Assert-Evidence 'b2.scan_resp' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.scan_resp_emitted' '1'
    Assert-Evidence 'b2.connect_accepted' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.ldn_connect_accepted' '1'
    Assert-Evidence 'b2.sync_network' "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.sync_network_emitted' '1'
    Assert-Evidence 'b2.room_frames' "$Out/evidence/b2_control_loopback.counters.json" 'counters.room_frames_rejected' '0'
    Assert-Evidence 'b2.transport_boundaries' "$Out/evidence/b2_control_loopback.counters.json" 'counters.transport_boundary_rejections' '0'
    $b2_beacons = [int](Get-JsonNode "$Out/evidence/b2_control_loopback.counters.json" 'counters.control.beacon_emitted')
    Add-Assertion 'b2.beacons_emitted' ($b2_beacons -ge 1) "beacons=$b2_beacons"

    # M4 section 7.4: the emitted byte sequence (hex) is exported next to the
    # per event counters, so an independent reader can re-check the bytes.
    $b1_emitted = @(Get-JsonNode "$Out/evidence/b1_control.emitted.json" '')
    Add-Assertion 'b1.emitted_export' ($b1_emitted.Count -ge 8) "count=$($b1_emitted.Count)"
    $b1_beacon = $b1_emitted | Where-Object { $_.kind -eq 'citra.beacon' } | Select-Object -First 1
    $b1_beacon_head = '00e9a435000000006400310400080000000000000000dd07001f32140a0000'
    Add-Assertion 'b1.emitted_beacon_golden' ($null -ne $b1_beacon -and $b1_beacon.direction -eq 'citra' -and $b1_beacon.hex.StartsWith($b1_beacon_head)) "kind=$($b1_beacon.kind)"
    $b1_assoc = $b1_emitted | Where-Object { $_.kind -eq 'citra.assoc_response' } | Select-Object -First 1
    Add-Assertion 'b1.emitted_assoc_golden' ($null -ne $b1_assoc -and $b1_assoc.direction -eq 'citra' -and $b1_assoc.hex.StartsWith('3104000001c00008')) "kind=$($b1_assoc.kind)"
    $b1_node_map = $b1_emitted | Where-Object { $_.kind -eq 'citra.node_map' } | Select-Object -First 1
    Add-Assertion 'b1.emitted_node_map_size' ($null -ne $b1_node_map -and [int]$b1_node_map.bytes -eq 16) "bytes=$($b1_node_map.bytes)"
    $b1_logoff = $b1_emitted | Where-Object { $_.kind -eq 'citra.eapol_logoff' } | Select-Object -First 1
    Add-Assertion 'b1.emitted_logoff_size' ($null -ne $b1_logoff -and [int]$b1_logoff.bytes -eq 672) "bytes=$($b1_logoff.bytes)"
    $b1_scan_resp = $b1_emitted | Where-Object { $_.kind -eq 'room.scan_resp' } | Select-Object -First 1
    Add-Assertion 'b1.emitted_scan_resp_size' ($null -ne $b1_scan_resp -and [int]$b1_scan_resp.bytes -eq 1152) "bytes=$($b1_scan_resp.bytes)"
    $b1_sync = $b1_emitted | Where-Object { $_.kind -eq 'room.sync_network' } | Select-Object -First 1
    Add-Assertion 'b1.emitted_sync_size' ($null -ne $b1_sync -and [int]$b1_sync.bytes -eq 1152) "bytes=$($b1_sync.bytes)"
    $b1_leak = @($b1_emitted | Where-Object { ($_.direction -eq 'citra' -and $_.kind -like 'room.*') -or ($_.direction -eq 'room' -and $_.kind -like 'citra.*') })
    Add-Assertion 'b1.emitted_side_isolation' ($b1_leak.Count -eq 0) "leaks=$($b1_leak.Count)"
    $b2_emitted = @(Get-JsonNode "$Out/evidence/b2_control_loopback.emitted.json" '')
    $b2_scan_resp = $b2_emitted | Where-Object { $_.kind -eq 'room.scan_resp' } | Select-Object -First 1
    $b2_sync = $b2_emitted | Where-Object { $_.kind -eq 'room.sync_network' } | Select-Object -First 1
    Add-Assertion 'b2.emitted_wire' ($null -ne $b2_scan_resp -and [int]$b2_scan_resp.bytes -eq 1152 -and $null -ne $b2_sync -and [int]$b2_sync.bytes -eq 1152) "scan=$($b2_scan_resp.bytes) sync=$($b2_sync.bytes)"

    # G-c / V-027: the Citra-side deliverable transport is an ENet/UDP host.
    # The TCP + 4 byte length prefix listener stays reachable through a
    # harness-only option and is labelled tcp-test, never as the delivery path.
    $b3_counters_text = Get-Content -LiteralPath "$Out/evidence/b3_citra_enet.counters.json" -Raw
    Add-Assertion 'b3.citra_transport_enet' ($b3_counters_text -match '"citra_transport":"enet"') 'expected enet'
    Assert-Evidence 'b3.tcp_accepts' "$Out/evidence/b3_citra_enet.counters.json" 'counters.citra_tcp_accepts' '0'
    Assert-Evidence 'b3.port_conflicts' "$Out/evidence/b3_citra_enet_portconflict.counters.json" 'counters.port_conflicts' '1'
    $b3_enet_connects = [int](Get-JsonNode "$Out/evidence/b3_citra_enet.counters.json" 'counters.citra_enet_connects')
    Add-Assertion 'b3.enet_connects' ($b3_enet_connects -ge 3) "connects=$b3_enet_connects"
    $b3_enet_receives = [int](Get-JsonNode "$Out/evidence/b3_citra_enet.counters.json" 'counters.citra_enet_receives')
    Add-Assertion 'b3.enet_receives' ($b3_enet_receives -ge 3) "receives=$b3_enet_receives"
    $b3_clients = @(Get-JsonNode "$Out/evidence/b3_citra_enet.clients.json" '')
    Add-Assertion 'b3.client_transport_enet' (@($b3_clients | Where-Object { $_.transport -eq 'enet' }).Count -ge 1) "clients=$($b3_clients.Count)"
    Add-Assertion 'b3.no_tcp_client' (@($b3_clients | Where-Object { $_.transport -eq 'tcp' }).Count -eq 0) "clients=$($b3_clients.Count)"
    $b3_tcp_text = Get-Content -LiteralPath "$Out/evidence/b3_citra_enet_tcp.counters.json" -Raw
    Add-Assertion 'b3.tcp_test_label' ($b3_tcp_text -match '"citra_transport":"tcp-test"') 'expected tcp-test'
    Assert-Evidence 'b3.tcp_accepts_harness' "$Out/evidence/b3_citra_enet_tcp.counters.json" 'counters.citra_tcp_accepts' '1'
    $b3_join_golden = @($stdout | Where-Object { $_ -match '^NOTE b3\.join_success_hex=02[0-9a-f]{12}$' })
    Add-Assertion 'b3.join_success_golden' ($b3_join_golden.Count -eq 1) "matches=$($b3_join_golden.Count)"

    # V-028: the --dump documents keep departed sessions (so a client that left
    # before the dump still shows its identity and fake IPv4), the control
    # counters are cumulative across departed sessions, and a v4 SetGameInfo is
    # a declared category with an ADR-009 translation rather than an unknown one.
    $b4_counters_path = "$Out/evidence/b4_session_ledger.counters.json"
    $b4_counters_text = Get-Content -LiteralPath $b4_counters_path -Raw
    $b4_accepted = [int](Get-JsonNode $b4_counters_path 'counters.set_game_info_accepted')
    Add-Assertion 'b4.set_game_info_accepted' ($b4_accepted -eq 2) "accepted=$b4_accepted"
    $b4_unknown = [int](Get-JsonNode $b4_counters_path 'counters.payload_rejected_unknown_category')
    Add-Assertion 'b4.set_game_info_unknown' ($b4_unknown -eq 0) "unknown=$b4_unknown"
    $b4_placeholder = [int](Get-JsonNode $b4_counters_path 'counters.set_game_info_version_placeholder')
    Add-Assertion 'b4.set_game_info_version_placeholder' ($b4_placeholder -eq 2) "placeholder=$b4_placeholder"
    Add-Assertion 'b4.control_scope_cumulative' ($b4_counters_text -match '"control_scope":"cumulative"') 'expected cumulative'
    $b4_beacons = [int](Get-JsonNode $b4_counters_path 'counters.control.beacon_emitted')
    Add-Assertion 'b4.control_survives_departure' ($b4_beacons -ge 1) "beacon_emitted=$b4_beacons"
    $b4_departed_sessions = [int](Get-JsonNode $b4_counters_path 'counters.control_sessions_departed')
    Add-Assertion 'b4.control_departed_sessions' ($b4_departed_sessions -ge 1) "departed_sessions=$b4_departed_sessions"
    $b4_clients = @(Get-JsonNode "$Out/evidence/b4_session_ledger.clients.json" '')
    $b4_departed = @($b4_clients | Where-Object { $_.departed -eq $true -and $_.nickname -eq 'b4-alpha' -and $_.fake_ip -match '^192\.168\.1\.\d+$' })
    Add-Assertion 'b4.departed_client_present' ($b4_departed.Count -eq 1) "departed=$($b4_departed.Count) clients=$($b4_clients.Count)"
    $b4_live = @($b4_clients | Where-Object { -not $_.departed })
    Add-Assertion 'b4.departed_left_live_list' ($b4_live.Count -eq 1) "live=$($b4_live.Count)"
    $b4_identities = @(Get-JsonNode "$Out/evidence/b4_session_ledger.identities.json" '')
    $b4_departed_identity = @($b4_identities | Where-Object { $_.departed -eq $true -and $_.nickname -eq 'b4-alpha' -and $_.fake_ip -match '^192\.168\.1\.\d+$' })
    Add-Assertion 'b4.departed_identity_present' ($b4_departed_identity.Count -eq 1) "departed=$($b4_departed_identity.Count) identities=$($b4_identities.Count)"
    $b4_note_ip = @($stdout | Where-Object { $_ -match '^NOTE b4\.departed_fake_ip=192\.168\.1\.\d+$' })
    Add-Assertion 'b4.departed_fake_ip_note' ($b4_note_ip.Count -eq 1) "matches=$($b4_note_ip.Count)"

    $captures = @(Get-JsonNode "$Out/evidence/a4_payload.captures.json" '')
    $captureOk = ($captures.Count -ge 2) -and ($captures[0].direction -eq 'citra_to_room') -and ($captures[1].direction -eq 'room_to_citra')
    Add-Assertion 'a4.capture_directions' $captureOk "count=$($captures.Count)"
    $events = @(Get-JsonNode "$Out/evidence/a1_members.events.json" '')
    Add-Assertion 'a1.events_recorded' ($events.Count -gt 0) "count=$($events.Count)"
    $identities = @(Get-JsonNode "$Out/evidence/a1_members.identities.json" '')
    # V-028: identities.json now appends the departed-session ledger, so the
    # live projection has to be filtered before comparing with the live count.
    $live_identities = @($identities | Where-Object { -not $_.departed })
    Add-Assertion 'a1.identities_after_disconnect' ($live_identities.Count -eq 1) "live=$($live_identities.Count) total=$($identities.Count)"

    $summary.Add("assertions.total=$assertTotal")
    $summary.Add("assertions.failed=$assertFailed")
    $summary.Add("harness.exit=$harnessExit")
    $summary.Add("process_failures=$failures")
    Write-Host '=== SUMMARY ==='
    foreach ($line in $summary) { Write-Host $line }
    $summary | Set-Content -LiteralPath "$Out/build-summary.txt" -Encoding ASCII
    if ($failures -ne 0 -or $assertFailed -ne 0) {
        throw "test failures: process=$failures assertions=$assertFailed"
    }
} elseif ($OfflineVerify) {
    $identityExit = Invoke-Test "$Out/citra-gateway-identity-tests.exe" @() 'identity-offline'
    $codecExit = Invoke-Test "$Out/citra-gateway-offline-tests.exe" @() 'codec-offline'
    $summary.Add("offline.identity.exit=$identityExit")
    $summary.Add("offline.codec.exit=$codecExit")
    $summary.Add('integration_harness=not_run')
    foreach ($line in $summary) { Write-Host $line }
    $summary | Set-Content -LiteralPath "$Out/build-summary.txt" -Encoding ASCII
    if ($identityExit -ne 0 -or $codecExit -ne 0) { throw 'Offline verification failed' }
} else {
    $summary.Add('run_tests=skipped')
    Write-Host '=== SUMMARY ==='
    foreach ($line in $summary) { Write-Host $line }
    $summary | Set-Content -LiteralPath "$Out/build-summary.txt" -Encoding ASCII
}

Pop-Location
