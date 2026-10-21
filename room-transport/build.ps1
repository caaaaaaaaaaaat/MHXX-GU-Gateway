# SPDX-License-Identifier: GPL-2.0-or-later
param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $Gcc = 'G:/msys64/mingw64/bin/gcc.exe'
    $Cxx = 'G:/msys64/mingw64/bin/g++.exe'
    $Objdump = 'G:/msys64/mingw64/bin/objdump.exe'
    $Enet = 'vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
    $Fmt = 'vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
    $Original = '../../01052024-yuzu-mirror-master/src'
    $Core = '../room-client'
    $Out = 'build-mingw'
    New-Item -ItemType Directory -Force $Out | Out-Null
    $Commands = New-Object System.Collections.Generic.List[string]
    function Invoke-Compiler([string]$Tool, [string[]]$Arguments) {
        $line = $Tool + ' ' + ($Arguments -join ' ')
        $Commands.Add($line)
        Write-Host $line
        & $Tool @Arguments
        if ($LASTEXITCODE -ne 0) { throw "compiler exit=$LASTEXITCODE : $line" }
    }
    & $Cxx --version | Out-File "$Out/toolchain.txt" -Encoding utf8
    & $Cxx -dumpmachine | Out-File "$Out/toolchain.txt" -Append -Encoding utf8
    & $Gcc --version | Out-File "$Out/toolchain.txt" -Append -Encoding utf8
    # Integrity check every vendored file before building. No network/install.
    $Manifest = Get-Content 'vendor/manifest.json' -Raw | ConvertFrom-Json
    foreach ($item in $Manifest.files) {
        $actual = (Get-FileHash $item.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $item.sha256) { throw "vendor hash mismatch: $($item.path)" }
    }
    $OriginalFiles = @('network/room.cpp','network/room.h','network/packet.cpp','network/packet.h','network/verify_user.cpp','network/verify_user.h','common/common_types.h','common/socket_types.h','common/announce_multiplayer_room.h','web_service/web_result.h')
    $Before = @{}
    foreach ($file in $OriginalFiles) { $Before[$file] = (Get-FileHash "$Original/$file" -Algorithm SHA256).Hash }
    $Objects = @()
    foreach ($name in @('callbacks','compress','host','list','packet','peer','protocol','unix','win32')) {
        $obj = "$Out/enet_$name.o"
        Invoke-Compiler $Gcc @('-pipe','-std=c99','-O2',"-I$Enet/include",'-c',"$Enet/$name.c",'-o',$obj)
        $Objects += $obj
    }
    # Shared library objects (no main): production sources + unmodified original room sources.
    $Sources = @(
        @('transport','src/transport.cpp'),
        @('core_protocol',"$Core/src/protocol.cpp"),
        @('core_session',"$Core/src/session.cpp"),
        @('original_room',"$Original/network/room.cpp"),
        @('original_packet',"$Original/network/packet.cpp"),
        @('original_verify',"$Original/network/verify_user.cpp")
    )
    $CxxFlags = @('-pipe','-std=c++20','-O2','-g','-Wall','-Wextra','-Wpedantic','-DNOMINMAX','-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY',
        '-Iinclude',"-I$Core/include",'-Isupport/include',"-I$Enet/include", "-I$Fmt/include", "-I$Original",'-IG:/msys64/mingw64/include')
    foreach ($source in $Sources) {
        $obj = "$Out/$($source[0]).o"
        Invoke-Compiler $Cxx ($CxxFlags + @('-c',$source[1],'-o',$obj))
        $Objects += $obj
    }
    $LinkFlags = @('-pipe','-static','-static-libgcc','-static-libstdc++')
    $LinkTail = @('G:/msys64/mingw64/lib/libzstd.a','-lws2_32','-lwinmm')
    function Build-Executable([string]$Name, [string]$TestSource) {
        $obj = "$Out/$Name.o"
        Invoke-Compiler $Cxx ($CxxFlags + @('-c',$TestSource,'-o',$obj))
        Invoke-Compiler $Cxx ($LinkFlags + $Objects + @($obj) + $LinkTail + @('-o',"$Out/$Name.exe"))
    }
    Build-Executable 'room_transport_loopback' 'tests/loopback.cpp'
    Build-Executable 'room_transport_slots_probe' 'tests/slots_probe.cpp'
    $Commands | Out-File "$Out/commands.txt" -Encoding utf8
    & $Objdump -p "$Out/room_transport_loopback.exe" | Out-File "$Out/pe-dependencies.txt" -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "objdump exit=$LASTEXITCODE" }
    $Hashes = @()
    foreach ($file in $OriginalFiles) {
        $after = (Get-FileHash "$Original/$file" -Algorithm SHA256).Hash
        if ($Before[$file] -ne $after) { throw "original source changed during build: $file" }
        $Hashes += [pscustomobject]@{path="$Original/$file";sha256=$after.ToLowerInvariant();unchanged=$true}
    }
    foreach ($file in @("$Core/src/protocol.cpp","$Core/src/session.cpp","$Core/include/room_client/protocol.hpp","$Core/include/room_client/session.hpp",'src/transport.cpp','include/room_transport/transport.hpp','support/include/common/logging/log.h','tests/loopback.cpp','tests/slots_probe.cpp','build.ps1',"$Out/room_transport_loopback.exe","$Out/room_transport_slots_probe.exe",'G:/msys64/mingw64/lib/libzstd.a','G:/msys64/mingw64/include/zstd.h')) {
        $Hashes += [pscustomobject]@{path=$file;sha256=(Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    $Hashes | ConvertTo-Json -Depth 4 | Out-File "$Out/artifacts-sha256.json" -Encoding utf8
    if ($RunTests) {
        # OS watchdog bounds even an unexpected failure inside upstream Destroy.
        function Invoke-Harness([string]$Exe, [string]$Tag, [int]$WatchdogMs) {
            $Executable = Join-Path (Get-Location) "$Out/$Exe.exe"
            $Process = Start-Process -FilePath $Executable -WindowStyle Hidden -PassThru -RedirectStandardOutput "$Out/$Tag.stdout.log" -RedirectStandardError "$Out/$Tag.stderr.log"
            $null = $Process.Handle
            if (-not $Process.WaitForExit($WatchdogMs)) { $Process.Kill(); $Process.WaitForExit(); throw "$Exe exceeded $WatchdogMs ms; terminated" }
            $Process.Refresh()
            $Exit = $Process.ExitCode
            ($Exe + '_exit=' + $Exit) | Out-File "$Out/$Tag.exit.txt" -Encoding utf8
            return $Exit
        }
        $LoopExit = Invoke-Harness 'room_transport_loopback' 'test' 45000
        $ProbeExit = Invoke-Harness 'room_transport_slots_probe' 'probe' 60000
        if ($LoopExit -ne 0) { throw "harness exit=$LoopExit; read build-mingw/test.stdout.log and test.stderr.log" }
        if ($ProbeExit -ne 0) { throw "probe exit=$ProbeExit; read build-mingw/probe.stdout.log and probe.stderr.log" }
    }
    Write-Host 'Build completed (GCC direct compile/link, no CMake/Ninja).'
} finally { Pop-Location }
