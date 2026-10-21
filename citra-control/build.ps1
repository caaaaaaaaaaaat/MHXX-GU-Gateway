# SPDX-License-Identifier: GPL-3.0-or-later
# citra-control - build script.  Direct g++ invocations only: this tree has no
# cmake / ninja / make / MSVC / clang.
#
# Every .cpp is compiled on its own with -pipe.  The workspace path contains
# non-ASCII characters and MinGW cannot create its assembler temporary files
# there; -pipe keeps the intermediate in memory, and all object files are
# written to the ASCII relative directory below.

[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $Root

$Gpp    = "G:/msys64/mingw64/bin/g++.exe"
$ObjDir = "crossplay/citra-control/.build-direct"
$Common = @(
    "-pipe", "-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2",
    "-Icrossplay/citra-control/include", "-Icrossplay/citra-control/tests"
)
# --no-insert-timestamp removes the wall-clock field GNU ld would otherwise put
# in the PE header, so two clean builds of the executables are byte identical.
$LinkCommon = @("-Wl,--no-insert-timestamp")
$LibSrcs  = @("bytes", "map", "state", "ldn_ctrl", "uds_frames", "crypto", "translate")
$TestSrcs = @("main", "test_crypto", "test_bytes", "test_ldn_ctrl", "test_uds_frames",
              "test_map", "test_state", "test_mirrors", "test_fixtures", "test_translate")

if ($Clean) {
    if (Test-Path -LiteralPath $ObjDir) {
        Remove-Item -LiteralPath $ObjDir -Recurse -Force
    }
}
if (-not (Test-Path -LiteralPath $ObjDir)) {
    New-Item -ItemType Directory -Path $ObjDir | Out-Null
}

function Invoke-Gpp {
    param([string[]]$GppArgs)
    & $Gpp @GppArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("FAILED: g++ " + ($GppArgs -join " "))
        exit $LASTEXITCODE
    }
}

$libObjects = @()
foreach ($s in $LibSrcs) {
    $obj = "$ObjDir/$s.o"
    Invoke-Gpp ($Common + @("-c", "crossplay/citra-control/src/$s.cpp", "-o", $obj))
    $libObjects += $obj
    Write-Host "  cc  src/$s.cpp -> $obj"
}

$testObjects = @()
foreach ($t in $TestSrcs) {
    $obj = "$ObjDir/$t.o"
    Invoke-Gpp ($Common + @("-c", "crossplay/citra-control/tests/$t.cpp", "-o", $obj))
    $testObjects += $obj
    Write-Host "  cc  tests/$t.cpp -> $obj"
}

Invoke-Gpp ($Common + @("-c", "crossplay/citra-control/tests/layout_report.cpp", "-o", "$ObjDir/layout_report.o"))
Write-Host "  cc  tests/layout_report.cpp -> $ObjDir/layout_report.o"

Invoke-Gpp ($LinkCommon + $libObjects + $testObjects + @("-o", "$ObjDir/test.exe"))
Write-Host "  ld  $ObjDir/test.exe"

Invoke-Gpp ($LinkCommon + $libObjects + @("$ObjDir/layout_report.o", "-o", "$ObjDir/layout.exe"))
Write-Host "  ld  $ObjDir/layout.exe"

Write-Host "build OK (g++ = $Gpp)"
exit 0
