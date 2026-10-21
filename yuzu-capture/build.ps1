# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param([switch]$RunTests)
$ErrorActionPreference='Stop'
$compiler='G:/msys64/mingw64/bin/g++.exe'
$gcc='G:/msys64/mingw64/bin/gcc.exe'
Push-Location -LiteralPath $PSScriptRoot
try {
    $out='.build-direct'
    New-Item -ItemType Directory -Path "$out/evidence" -Force | Out-Null
    $enet='../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
    $fmt='../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
    $original='../../01052024-yuzu-mirror-master/src'
    $guard=@{}
    foreach($file in @('network/room.cpp','network/room.h','network/packet.cpp','network/verify_user.cpp')) {
        $guard[$file]=(Get-FileHash "$original/$file").Hash
    }
    $flags=@('-pipe','-std=c++20','-O2','-g','-Wall','-Wextra','-Wpedantic','-DNOMINMAX','-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY',
        '-Iinclude','-I../yuzu-room/include','-I../citra-gateway/include','-I../citra-control/include',
        '-I../room-transport/support/include',"-I$enet/include","-I$fmt/include","-I$original",'-IG:/msys64/mingw64/include')
    function Compile([string]$tool,[string[]]$argsList) {
        & $tool @argsList
        if($LASTEXITCODE -ne 0) {throw "compile/link failed: exit=$LASTEXITCODE"}
    }
    $enetObjects=@()
    foreach($name in @('callbacks','compress','host','list','packet','peer','protocol','unix','win32')) {
        $obj="$out/enet_$name.o"
        Compile $gcc @('-pipe','-std=c99','-O2',"-I$enet/include",'-c',"$enet/$name.c",'-o',$obj)
        $enetObjects+=$obj
    }
    $units=@(
        @('relay','src/relay.cpp'),@('main','src/main.cpp'),@('test','tests/test_relay.cpp'),
        @('protocol','../yuzu-room/src/protocol.cpp'),@('trace','../citra-gateway/src/trace.cpp'),
        @('control_bytes','../citra-control/src/bytes.cpp'),@('control_crypto','../citra-control/src/crypto.cpp'),
        @('control_uds','../citra-control/src/uds_frames.cpp'),@('control_ldn','../citra-control/src/ldn_ctrl.cpp'),
        @('original_room',"$original/network/room.cpp"),@('original_packet',"$original/network/packet.cpp"),
        @('original_verify',"$original/network/verify_user.cpp")
    )
    foreach($unit in $units) {
        Write-Host "COMPILE $($unit[1])"
        Compile $compiler ($flags+@('-c',$unit[1],'-o',"$out/$($unit[0]).o"))
    }
    $link=@('-pipe','-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp')
    $common=@('relay','protocol','trace','control_bytes','control_crypto','control_uds','control_ldn') | ForEach-Object {"$out/$_.o"}
    $tail=@('G:/msys64/mingw64/lib/libzstd.a','-lws2_32','-lwinmm')
    Compile $compiler ($link+@("$out/main.o")+$common+$enetObjects+$tail+@('-o',"$out/yuzu-capture.exe"))
    Compile $compiler ($link+@("$out/test.o","$out/original_room.o","$out/original_packet.o","$out/original_verify.o")+$common+$enetObjects+$tail+@('-o',"$out/yuzu-capture-tests.exe"))
    foreach($file in $guard.Keys) {
        if((Get-FileHash "$original/$file").Hash -ne $guard[$file]) {throw "original source changed: $file"}
    }
    if($RunTests) {
        $p=Start-Process -FilePath (Join-Path (Get-Location) "$out/yuzu-capture-tests.exe") -ArgumentList "$out/evidence" -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out/test.stdout.log" -RedirectStandardError "$out/test.stderr.log"
        $null=$p.Handle
        if(-not $p.WaitForExit(45000)) { $p.Kill(); $p.WaitForExit(); throw 'capture tests exceeded watchdog' }
        if($p.ExitCode -ne 0) {throw "capture tests failed: $($p.ExitCode); see $out/test.stderr.log"}
        Get-Content -LiteralPath "$out/test.stdout.log"
        $auditLines=& node ../tools/trace-audit.mjs "$out/evidence/relay.jsonl"
        $auditExit=$LASTEXITCODE
        $auditReport=($auditLines -join "`n") | ConvertFrom-Json
        # The negative fixture deliberately records one malformed LDN body.
        # Keep strict production auditing; require exactly that failure here.
        if($auditExit -ne 1 -or $auditReport.passed -ne $false -or $auditReport.errors -ne 1 -or
           $auditReport.error_reasons.'invalid LdnPacket type, body size or broadcast' -ne 1) {
            throw 'independent trace audit did not identify exactly the injected malformed LDN body'
        }
        [IO.File]::WriteAllText((Join-Path (Get-Location) "$out/trace-audit.json"),(($auditLines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
        & "$out/yuzu-capture.exe" --help
        if($LASTEXITCODE -ne 0) {throw 'CLI help failed'}
        foreach($case in @(
            @('--seconds','0'),@('--room-port','65536'),@('--trace-raw'),@('--unknown','x')
        )) {
            $previousPreference=$ErrorActionPreference
            try {
                $ErrorActionPreference='Continue'
                & "$out/yuzu-capture.exe" @case 2> "$out/cli-negative.stderr.log"
                $negativeExit=$LASTEXITCODE
            } finally {$ErrorActionPreference=$previousPreference}
            if($negativeExit -ne 2) {throw "CLI negative exit mismatch: $negativeExit"}
        }
    }
    $artifacts=@(Get-ChildItem -LiteralPath $out -Filter '*.exe' | ForEach-Object {
        [ordered]@{path=$_.FullName;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
    })
    $artifacts | ConvertTo-Json -Depth 4 | Set-Content "$out/artifacts.json" -Encoding UTF8
    Write-Host 'YUZU-CAPTURE BUILD PASS'
} finally {Pop-Location}
