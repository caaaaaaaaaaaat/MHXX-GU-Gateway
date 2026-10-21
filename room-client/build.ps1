# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param([string]$Compiler = 'G:\msys64\mingw64\bin\g++.exe')
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) {
    $Compiler = (Get-Command g++ -ErrorAction Stop).Source
}
$oldPath = $env:PATH
Push-Location -LiteralPath $PSScriptRoot
try {
    $env:PATH = (Split-Path -Parent $Compiler) + [IO.Path]::PathSeparator + $env:PATH
    New-Item -ItemType Directory -Force -Path '.build-direct' | Out-Null
    $common = @('-std=c++20','-O2','-Wall','-Wextra','-Wpedantic','-Wconversion','-Wsign-conversion','-I','include')
    & $Compiler --version
    if ($LASTEXITCODE -ne 0) { throw "Compiler version query failed: $LASTEXITCODE" }
    # Explicit relative object paths plus -pipe avoid GCC absolutizing a temporary object
    # into the non-ASCII workspace path before launching the assembler.
    $units = @(@('src/protocol.cpp','protocol'), @('src/session.cpp','session'), @('tests/test_protocol.cpp','tests'), @('src/main.cpp','main'))
    foreach ($unit in $units) {
        & $Compiler @common '-pipe' '-c' $unit[0] '-o' ('.build-direct/' + $unit[1] + '.o')
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $($unit[0]): $LASTEXITCODE" }
    }
    & $Compiler '.build-direct/protocol.o' '.build-direct/session.o' '.build-direct/tests.o' '-Wl,--no-insert-timestamp' '-o' '.build-direct/room-protocol-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Test linking failed: $LASTEXITCODE" }
    & $Compiler '.build-direct/protocol.o' '.build-direct/session.o' '.build-direct/main.o' '-Wl,--no-insert-timestamp' '-o' '.build-direct/room-fixture.exe'
    if ($LASTEXITCODE -ne 0) { throw "CLI linking failed: $LASTEXITCODE" }
    & '.\.build-direct\room-protocol-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Protocol tests failed: $LASTEXITCODE" }
    & '.\.build-direct\room-fixture.exe' 'emit-join' 'Test'
    if ($LASTEXITCODE -ne 0) { throw "Join CLI smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\room-fixture.exe' 'decode' 's2c' '02c0a80102'
    if ($LASTEXITCODE -ne 0) { throw "Decode CLI smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\room-fixture.exe' 'replay' 'Test' 'fixtures/join-success.hex'
    if ($LASTEXITCODE -ne 0) { throw "Replay CLI smoke failed: $LASTEXITCODE" }
    & '.\.build-direct\room-fixture.exe' 'decode' 's2c' '02c0a8'
    if ($LASTEXITCODE -ne 1) { throw "Invalid fixture must return 1; got $LASTEXITCODE" }
    Write-Output 'CLI smoke: 4/4 passed (includes expected rejection exit 1)'
} finally {
    $env:PATH = $oldPath
    Pop-Location
}
exit 0
