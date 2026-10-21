$ErrorActionPreference='Continue'
$gpp='G:\msys64\mingw64\bin\g++.exe'
$out='reverify\build'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$flags=@('-std=c++20','-O2','-Wall','-Wextra','-Wpedantic','-Wconversion','-Wsign-conversion','-Wno-mismatched-new-delete',
         '-I','..\..\room-client\include','-I','..\..\room-client\tests','-I','..\..\..\01052024-yuzu-mirror-master\src')
$ok=$true
function Compile($src,$obj) {
  & $gpp @flags -pipe -c $src -o $obj 2>&1 | Out-String | Write-Host
  Write-Host "compile $obj exit=$LASTEXITCODE"
  if ($LASTEXITCODE -ne 0) { $script:ok=$false }
}
Compile 'reverify\reverify_probe.cpp' "$out\probe.o"
Compile '..\..\room-client\src\protocol.cpp' "$out\protocol.o"
Compile '..\..\room-client\src\session.cpp' "$out\session.o"
Compile '..\..\..\01052024-yuzu-mirror-master\src\network\packet.cpp' "$out\packet.o"
if ($ok) {
  $linkFlags=@('-lws2_32','-Wl,--no-insert-timestamp')
  & $gpp "$out\probe.o" "$out\protocol.o" "$out\session.o" "$out\packet.o" @linkFlags -o "$out\reverify-probe.exe" 2>&1 | Out-String | Write-Host
  Write-Host "link exit=$LASTEXITCODE"
  if ($LASTEXITCODE -eq 0) {
    & "$out\reverify-probe.exe" 2>&1 | Out-String | Write-Host
    Write-Host "run exit=$LASTEXITCODE"
  }
}
