# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
$compiler = 'G:/msys64/mingw64/bin/g++.exe'
$oldPath = $env:PATH
Push-Location -LiteralPath $PSScriptRoot
try {
    $env:PATH = 'G:/msys64/mingw64/bin;' + $env:PATH
    New-Item -ItemType Directory -Force -Path '.build' | Out-Null
    & $compiler --version
    if ($LASTEXITCODE -ne 0) { throw "Compiler version query failed: $LASTEXITCODE" }
    $common = @('-std=c++20','-O2','-pipe','-Wall','-Wextra','-Wpedantic','-Wconversion','-Wsign-conversion','-I','../../room-client/include','-I','../../../01052024-yuzu-mirror-master/src')
    $units = @(@('review_m1.cpp','review'),@('../../room-client/src/protocol.cpp','protocol'),@('../../room-client/src/session.cpp','session'),@('../../../01052024-yuzu-mirror-master/src/network/packet.cpp','original_packet'))
    foreach ($unit in $units) {
        & $compiler @common '-c' $unit[0] '-o' ('.build/' + $unit[1] + '.o')
        if ($LASTEXITCODE -ne 0) { throw "Compile failed for $($unit[0]): $LASTEXITCODE" }
    }
    & $compiler '.build/review.o' '.build/protocol.o' '.build/session.o' '.build/original_packet.o' '-lws2_32' '-Wl,--no-insert-timestamp' '-o' '.build/review-m1.exe'
    if ($LASTEXITCODE -ne 0) { throw "Link failed: $LASTEXITCODE" }
    & '.build/review-m1.exe'
    if ($LASTEXITCODE -ne 0) { throw "Independent probe failed: $LASTEXITCODE" }
} finally {
    $env:PATH = $oldPath
    Pop-Location
}
exit 0
