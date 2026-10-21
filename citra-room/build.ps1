# SPDX-License-Identifier: GPL-2.0-or-later
# Offline build + test driver for crossplay/citra-room.
#
# OFFLINE ONLY: no network, no ENet, no emulator, no sockets.
#
# The workspace path contains non-ASCII characters. GCC on this machine fails
# to create its assembler temporary file when it absolutizes an object path
# into that directory, so every translation unit is compiled from the project
# directory using RELATIVE source and object paths with -pipe, and the objects
# are linked explicitly by relative path.
[CmdletBinding()]
param(
    [string]$Compiler = 'G:\msys64\mingw64\bin\g++.exe',
    [string]$Objdump = 'G:\msys64\mingw64\bin\objdump.exe'
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) {
    $Compiler = (Get-Command g++ -ErrorAction Stop).Source
}
$oldPath = $env:PATH
Push-Location -LiteralPath $PSScriptRoot
try {
    $env:PATH = (Split-Path -Parent $Compiler) + [IO.Path]::PathSeparator + $env:PATH
    New-Item -ItemType Directory -Force -Path '.build-direct' | Out-Null
    $common = @('-std=c++20','-O2','-Wall','-Wextra','-Wpedantic','-Wconversion','-Wsign-conversion','-I','include','-I','tests')
    & $Compiler --version
    if ($LASTEXITCODE -ne 0) { throw "Compiler version query failed: $LASTEXITCODE" }
    $units = @(
        @('src/protocol.cpp','protocol'),
        @('src/session.cpp','session'),
        @('src/main.cpp','main'),
        @('tests/test_protocol.cpp','test_protocol'),
        @('tests/test_session.cpp','test_session')
    )
    foreach ($unit in $units) {
        Write-Output ("compile: " + $Compiler + " " + ($common -join ' ') + " -pipe -c " + $unit[0] + " -o .build-direct/" + $unit[1] + ".o")
        & $Compiler @common '-pipe' '-c' $unit[0] '-o' ('.build-direct/' + $unit[1] + '.o')
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $($unit[0]): $LASTEXITCODE" }
    }
    $links = @(
        @(@('protocol','test_protocol'), 'citra-room-protocol-tests.exe'),
        @(@('protocol','session','test_session'), 'citra-room-session-tests.exe'),
        @(@('protocol','session','main'), 'citra-room.exe')
    )
    foreach ($link in $links) {
        $objects = @()
        foreach ($stem in $link[0]) { $objects += ('.build-direct/' + $stem + '.o') }
        Write-Output ("link: " + $Compiler + " " + ($objects -join ' ') + " -Wl,--no-insert-timestamp -o .build-direct/" + $link[1])
        & $Compiler @objects '-Wl,--no-insert-timestamp' '-o' ('.build-direct/' + $link[1])
        if ($LASTEXITCODE -ne 0) { throw "Linking failed for $($link[1]): $LASTEXITCODE" }
    }

    Write-Output '--- protocol tests ---'
    & '.\.build-direct\citra-room-protocol-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Protocol tests failed: $LASTEXITCODE" }
    Write-Output '--- session tests ---'
    & '.\.build-direct\citra-room-session-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Session tests failed: $LASTEXITCODE" }

    Write-Output '--- CLI smoke ---'
    & '.\.build-direct\citra-room.exe' 'emit-join' 'Nick'
    if ($LASTEXITCODE -ne 0) { throw "emit-join smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\citra-room.exe' 'decode' 'c2s' '01 00000004 4e69636b 00000004 63696430 ffffffffffff 00000004 00000002 7077 00000002 746b'
    if ($LASTEXITCODE -ne 0) { throw "decode smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\citra-room.exe' 'replay' 'Nick' 'fixtures/join-replay.hex'
    if ($LASTEXITCODE -ne 0) { throw "Replay CLI smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\citra-room.exe' 'decode' 's2c' '09'
    if ($LASTEXITCODE -ne 1) { throw "Invalid fixture must return 1; got $LASTEXITCODE" }
    # A nickname the real room rejects (room.cpp:566-576) is refused by the emitter.
    & '.\.build-direct\citra-room.exe' 'emit-join' 'ab'
    if ($LASTEXITCODE -ne 2) { throw "Invalid nickname must return 2; got $LASTEXITCODE" }
    # A replay that never reaches membership must report failure.
    & '.\.build-direct\citra-room.exe' 'replay' 'Nick' 'fixtures/nojoin.hex'
    if ($LASTEXITCODE -ne 1) { throw "Incomplete replay must return 1; got $LASTEXITCODE" }
    Write-Output 'CLI smoke: 6/6 passed (includes expected rejection exit 1 and usage exit 2)'

    if (Test-Path -LiteralPath $Objdump -PathType Leaf) {
        Write-Output '--- objdump -f (PE architecture) ---'
        & $Objdump '-f' '.build-direct/citra-room.exe'
        Write-Output '--- objdump -p imports ---'
        & $Objdump '-p' '.build-direct/citra-room.exe' | Select-String -Pattern 'DLL Name|Subsystem|file format|Magic'
    } else {
        Write-Output "objdump not found at $Objdump"
    }
} finally {
    $env:PATH = $oldPath
    Pop-Location
}
exit 0
