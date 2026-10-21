# SPDX-License-Identifier: GPL-2.0-or-later
# Offline build + test + smoke + PE-evidence driver for crossplay/yuzu-room.
#
# OFFLINE ONLY: no network, no ENet, no emulator, no sockets, no threads.
#
# The workspace path contains non-ASCII characters. GCC on this machine fails
# to create its assembler temporary file when it absolutizes an object path
# into that directory, so every translation unit is compiled from the project
# directory using RELATIVE source and object paths with -pipe, and the objects
# are linked explicitly by relative path. No global TMP/PATH/registry change
# survives the run.
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
        @(@('protocol','test_protocol'), 'yuzu-room-protocol-tests.exe'),
        @(@('protocol','session','test_session'), 'yuzu-room-session-tests.exe'),
        @(@('protocol','session','main'), 'yuzu-room.exe')
    )
    foreach ($link in $links) {
        $objects = @()
        foreach ($stem in $link[0]) { $objects += ('.build-direct/' + $stem + '.o') }
        Write-Output ("link: " + $Compiler + " " + ($objects -join ' ') + " -Wl,--no-insert-timestamp -o .build-direct/" + $link[1])
        & $Compiler @objects '-Wl,--no-insert-timestamp' '-o' ('.build-direct/' + $link[1])
        if ($LASTEXITCODE -ne 0) { throw "Linking failed for $($link[1]): $LASTEXITCODE" }
    }

    Write-Output '--- protocol tests ---'
    & '.\.build-direct\yuzu-room-protocol-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Protocol tests failed: $LASTEXITCODE" }
    Write-Output '--- session tests ---'
    & '.\.build-direct\yuzu-room-session-tests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Session tests failed: $LASTEXITCODE" }

    Write-Output '--- CLI smoke ---'
    $smoke = 0
    # Expected rejections write the protocol error to stderr. With
    # $ErrorActionPreference = 'Stop', PowerShell would turn that native stderr
    # into a terminating NativeCommandError before the exit code can be read,
    # so each case runs with stderr captured into the log as a smoke line.
    function Invoke-SmokeCase {
        param([string[]]$Arguments, [int]$Expect)
        $saved = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & '.\.build-direct\yuzu-room.exe' @Arguments 2>&1 | ForEach-Object { Write-Output ("smoke| " + $_) }
        } finally {
            $ErrorActionPreference = $saved
        }
        if ($LASTEXITCODE -ne $Expect) {
            throw ("smoke case [" + ($Arguments -join ' ') + "] expected exit " + $Expect + "; got " + $LASTEXITCODE)
        }
    }
    Invoke-SmokeCase @('emit-join','Test') 0
    $smoke++
    Invoke-SmokeCase @('decode','c2s','01 00000004 54657374 ffffffff 00000001 00000003 707731 00000000') 0
    $smoke++
    Invoke-SmokeCase @('decode','c2s','05 01 c0a82921 1388 01 c0a8200d 1389 03 00 00000010 444b525960676e757c838a91989fa6ad') 0
    $smoke++
    Invoke-SmokeCase @('replay','Test','fixtures/join-replay.hex') 0
    $smoke++
    Invoke-SmokeCase @('replay','rri-a1','fixtures/real-join.s2c.hex') 0
    $smoke++
    # A replay that never reaches membership must report failure.
    Invoke-SmokeCase @('replay','Test','fixtures/nojoin.hex') 1
    $smoke++
    # A captured VersionMismatch reply must fail closed with exit 1.
    Invoke-SmokeCase @('replay','rri-a1','fixtures/error-version-mismatch.hex') 1
    $smoke++
    # An unsupported (non-server) frame must be a protocol error: exit 1.
    Invoke-SmokeCase @('decode','s2c','11') 1
    $smoke++
    # A nickname the real room rejects (room.cpp:550-560) is refused by the emitter.
    Invoke-SmokeCase @('emit-join','abc') 2
    $smoke++
    Write-Output ("CLI smoke: " + $smoke + "/9 passed (includes expected rejection exit 1 and usage exit 2)")

    $artifacts = @('.build-direct/yuzu-room-protocol-tests.exe','.build-direct/yuzu-room-session-tests.exe','.build-direct/yuzu-room.exe')
    Write-Output '--- artifacts (sha256) ---'
    foreach ($artifact in $artifacts) {
        $info = Get-Item -LiteralPath $artifact
        $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output ("artifact " + $artifact + " bytes=" + $info.Length + " sha256=" + $hash)
    }

    if (Test-Path -LiteralPath $Objdump -PathType Leaf) {
        Write-Output '--- objdump -f (PE architecture) ---'
        & $Objdump '-f' '.build-direct/yuzu-room.exe'
        Write-Output '--- objdump -p imports ---'
        & $Objdump '-p' '.build-direct/yuzu-room.exe' | Select-String -Pattern 'DLL Name|Subsystem|file format|Magic'
    } else {
        Write-Output "objdump not found at $Objdump"
    }
    Write-Output ("yuzu-room build summary: artifacts=" + $artifacts.Count + " protocol_tests=passed session_tests=passed smoke=" + $smoke + "/9 ok=1")
} finally {
    $env:PATH = $oldPath
    Pop-Location
}
exit 0
