# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $out = '.build-desktop'
    $cxx = 'G:/msys64/mingw64/bin/g++.exe'
    $enet = '../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
    $fmt = '../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
    $original = '../../01052024-yuzu-mirror-master/src'
    $flags = @('-pipe','-std=c++20','-O0','-DNOMINMAX','-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY','-Iinclude','-I../citra-gateway/include','-I../citra-room/include','-I../citra-control/include','-I../room-client/include','-I../room-transport/include','-I../room-transport/support/include',"-I$enet/include","-I$fmt/include","-I$original",'-IG:/msys64/mingw64/include')
    $link = @('-pipe','-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp')
    $tail = @('G:/msys64/mingw64/lib/libzstd.a','-lws2_32','-lwinmm','-liphlpapi')
    function Compile-Test([string[]]$arguments) {
        & $cxx @arguments
        if ($LASTEXITCODE) { throw 'Test compilation/link failed' }
    }
    function Run-Test([string]$executable, [string]$arguments, [string]$label) {
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = (Resolve-Path -LiteralPath $executable).Path
        $info.Arguments = $arguments
        $info.WorkingDirectory = (Get-Location).Path
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $info
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(180000)) { $process.Kill(); throw "$label test watchdog expired" }
        $output = $stdout.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path (Get-Location) "$out/$label.stdout.txt"), $output)
        [IO.File]::WriteAllText((Join-Path (Get-Location) "$out/$label.stderr.txt"), $stderr.GetAwaiter().GetResult())
        if ($process.ExitCode) { throw "$label failed exit=$($process.ExitCode); inspect logs" }
        ($output.TrimEnd() -split "`n" | Select-Object -Last 1) | Write-Output
    }
    $names = @('citra_protocol','room_protocol','room_session','transport','identity','trace','control','gateway','backend','control_bytes','control_crypto','control_ldn_ctrl','control_map','control_state','control_uds_frames','control_heartbeat','enet_callbacks','enet_compress','enet_host','enet_list','enet_packet','enet_peer','enet_protocol','enet_unix','enet_win32')
    $core = @($names | ForEach-Object { "$out/$_.o" })
    $originalObjects = @()
    foreach ($unit in @(@('original_room',"$original/network/room.cpp"),@('original_packet',"$original/network/packet.cpp"),@('original_verify',"$original/network/verify_user.cpp"),@('citra_session','../citra-room/src/session.cpp'))) {
        $obj = "$out/$($unit[0]).o"
        Compile-Test ($flags + @('-c',$unit[1],'-o',$obj))
        $originalObjects += $obj
    }
    Compile-Test ($flags + @('-c','tests/test_backend.cpp','-o',"$out/test_backend.o"))
    Compile-Test ($link + @("$out/test_backend.o") + $core + $originalObjects + $tail + @('-o',"$out/backend-tests.exe"))
    Run-Test "$out/backend-tests.exe" '' 'backend'
    Compile-Test ($flags + @('-c','../citra-gateway/tests/test_gateway.cpp','-o',"$out/test_gateway.o"))
    Compile-Test ($link + @("$out/test_gateway.o") + $core + $originalObjects + $tail + @('-o',"$out/gateway-tests.exe"))
    Run-Test "$out/gateway-tests.exe" "$out/evidence" 'regression'
    Compile-Test ($flags + @('-c','../citra-gateway/src/main.cpp','-o',"$out/cli_main.o"))
    Compile-Test ($link + @("$out/cli_main.o") + $core + $tail + @('-o',"$out/gateway-cli.exe"))
    $oldExecutable = $env:CITRA_GATEWAY_TEST_EXE
    try {
        $env:CITRA_GATEWAY_TEST_EXE = (Resolve-Path "$out/gateway-cli.exe").Path
        Run-Test (Get-Command python).Source '../citra-gateway/tests/test_cli.py' 'cli'
    } finally { $env:CITRA_GATEWAY_TEST_EXE = $oldExecutable }
} finally { Pop-Location }
