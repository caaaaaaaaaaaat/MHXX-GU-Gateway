# Local focused integration test after build.ps1 has compiled current sources.
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $out='.build-desktop'
    $enet='../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
    $fmt='../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281'
    $flags=@('-pipe','-std=c++20','-O2','-DNOMINMAX','-DWIN32_LEAN_AND_MEAN','-DFMT_HEADER_ONLY','-Iinclude','-I../citra-gateway/include','-I../citra-room/include','-I../citra-control/include','-I../room-client/include','-I../room-transport/include','-I../room-transport/support/include',"-I$enet/include","-I$fmt/include",'-I../../01052024-yuzu-mirror-master/src','-IG:/msys64/mingw64/include')
    $cxx='G:/msys64/mingw64/bin/g++.exe'
    & $cxx @flags '-c' 'tests/test_backend.cpp' '-o' "$out/test_backend.o"
    if ($LASTEXITCODE) { throw 'test compilation failed' }
    $objects=@(Get-ChildItem -LiteralPath $out -Filter '*.o' | Where-Object { $_.BaseName -notin @('main','cli_main','test_gateway','test_settings','app_res') } | ForEach-Object { "$out/$($_.Name)" })
    & $cxx '-pipe' '-static' '-static-libgcc' '-static-libstdc++' @objects 'G:/msys64/mingw64/lib/libzstd.a' '-lws2_32' '-lwinmm' '-liphlpapi' '-o' "$out/backend-tests.exe"
    if ($LASTEXITCODE) { throw 'test link failed' }
    & "$out/backend-tests.exe"
    if ($LASTEXITCODE) { throw 'test failed' }
} finally { Pop-Location }
