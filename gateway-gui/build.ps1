# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $out = '.build-desktop'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $cxx = 'G:/msys64/mingw64/bin/g++.exe'
    $cc = 'G:/msys64/mingw64/bin/gcc.exe'
    $enet = '../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
    $fmt = '../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
    $original = '../../01052024-yuzu-mirror-master/src'
    $flags = @('-pipe','-std=c++20','-O2','-Wall','-Wextra','-Wpedantic','-finput-charset=UTF-8','-fexec-charset=UTF-8','-DNOMINMAX','-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY','-Iinclude','-I../citra-gateway/include','-I../citra-room/include','-I../citra-control/include','-I../room-client/include','-I../room-transport/include','-I../room-transport/support/include',"-I$enet/include","-I$fmt/include","-I$original",'-IG:/msys64/mingw64/include')
    $link = @('-pipe','-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp')
    $tail = @('G:/msys64/mingw64/lib/libzstd.a','-lws2_32','-lwinmm','-liphlpapi')
    function Compile([string]$tool, [string[]]$arguments) {
        & $tool @arguments
        if ($LASTEXITCODE -ne 0) { throw "Compiler failed: $($arguments -join ' ')" }
    }
    $core = @()
    foreach ($name in @('callbacks','compress','host','list','packet','peer','protocol','unix','win32')) {
        $obj = "$out/enet_$name.o"
        Compile $cc @('-pipe','-O2',"-I$enet/include",'-c',"$enet/$name.c",'-o',$obj)
        $core += $obj
    }
    $units = @(
        @('citra_protocol','../citra-room/src/protocol.cpp'),
        @('room_protocol','../room-client/src/protocol.cpp'),
        @('room_session','../room-client/src/session.cpp'),
        @('transport','../room-transport/src/transport.cpp'),
        @('identity','../citra-gateway/src/identity.cpp'),
        @('trace','../citra-gateway/src/trace.cpp'),
        @('control','../citra-gateway/src/control.cpp'),
        @('gateway','../citra-gateway/src/gateway.cpp'),
        @('backend','src/backend.cpp')
    )
    foreach ($name in @('bytes','crypto','ldn_ctrl','map','state','uds_frames','heartbeat')) {
        $units += ,@("control_$name", "../citra-control/src/$name.cpp")
    }
    foreach ($unit in $units) {
        Write-Output "Compiling $($unit[0])"
        $obj = "$out/$($unit[0]).o"
        Compile $cxx ($flags + @('-c',$unit[1],'-o',$obj))
        $core += $obj
    }
    Compile $cxx ($flags + @('-c','src/main.cpp','-o',"$out/main.o"))
    $package = "$out/XXGU-Gateway"
    New-Item -ItemType Directory -Force -Path $package | Out-Null
    Compile $cxx ($link + @('-mwindows','-municode',"$out/main.o") + $core + $tail + @('-lcomctl32','-lgdi32','-o',"$package/XXGU-Gateway.exe"))
    Copy-Item -LiteralPath 'USER-GUIDE.md' -Destination "$package/USER-GUIDE.md"
    Copy-Item -LiteralPath '../../01052024-yuzu-mirror-master/LICENSE.txt' -Destination "$package/LICENSE-GPL.txt"
    Copy-Item -LiteralPath '../room-transport/LICENSE.txt' -Destination "$package/LICENSE-GPL3.txt"
    Copy-Item -LiteralPath '../citra-control/NOTICE' -Destination "$package/NOTICE-citra-control.txt"
    foreach ($name in @('citra-gateway','citra-room','citra-control','room-client','room-transport')) {
        $notice = "../$name/NOTICE.md"
        if (Test-Path -LiteralPath $notice) { Copy-Item -LiteralPath $notice -Destination "$package/NOTICE-$name.md" }
    }
    Copy-Item -LiteralPath "$enet/LICENSE" -Destination "$package/LICENSE-ENet.txt"
    Copy-Item -LiteralPath "$fmt/LICENSE" -Destination "$package/LICENSE-fmt.txt"
    Copy-Item -LiteralPath '../room-transport/vendor/zstd-installed/LICENSE' -Destination "$package/LICENSE-zstd.txt"
    if ($RunTests) {
        & './tests/verify.ps1'
    }
    $inputs = @('src/backend.cpp','src/main.cpp','include/gateway_gui/backend.hpp','build.ps1','USER-GUIDE.md') + @($units | ForEach-Object { $_[1] })
    $hashes = @($inputs | Sort-Object -Unique | ForEach-Object { [pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLower()} })
    [pscustomobject]@{version='V334';executable_sha256=(Get-FileHash -LiteralPath "$package/XXGU-Gateway.exe").Hash.ToLower();inputs=$hashes} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$out/artifacts.json" -Encoding UTF8
    python package.py
    if ($LASTEXITCODE) { throw 'Packaging failed' }
    Write-Output "READY: $PSScriptRoot/$package/XXGU-Gateway.exe"
} finally { Pop-Location }
