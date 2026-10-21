# Relink the UI after editing main.cpp; production objects must come from build.ps1.
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $out='.build-desktop'
    $cxx='G:/msys64/mingw64/bin/g++.exe'
    & $cxx '-pipe' '-std=c++20' '-O2' '-DNOMINMAX' '-DWIN32_LEAN_AND_MEAN' '-Iinclude' '-I../citra-gateway/include' '-I../citra-room/include' '-I../citra-control/include' '-I../room-client/include' '-I../room-transport/include' '-c' 'src/main.cpp' '-o' "$out/main.o"
    if ($LASTEXITCODE) { throw 'UI compilation failed' }
    $names=@('citra_protocol','room_protocol','room_session','transport','identity','trace','control','gateway','backend','control_bytes','control_crypto','control_ldn_ctrl','control_map','control_state','control_uds_frames','control_heartbeat','enet_callbacks','enet_compress','enet_host','enet_list','enet_packet','enet_peer','enet_protocol','enet_unix','enet_win32')
    $objects=@($names | ForEach-Object { "$out/$_.o" })
    & $cxx '-pipe' '-static' '-static-libgcc' '-static-libstdc++' '-Wl,--no-insert-timestamp' '-mwindows' '-municode' "$out/main.o" @objects 'G:/msys64/mingw64/lib/libzstd.a' '-lws2_32' '-lwinmm' '-liphlpapi' '-lcomctl32' '-lgdi32' '-o' "$out/XXGU-Gateway/XXGU-Gateway.exe"
    if ($LASTEXITCODE) { throw 'UI link failed' }
} finally { Pop-Location }
