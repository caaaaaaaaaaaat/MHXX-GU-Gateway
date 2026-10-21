# SPDX-License-Identifier: GPL-2.0-or-later
# real-room-interop build script (PowerShell 5.1, MinGW g++ only).
#
# Hard environment rules this script obeys:
#   * the only compiler is G:/msys64/mingw64/bin/g++.exe (GCC 16.1.0);
#   * no cmake / ninja / make / MSVC / clang / downloads;
#   * MinGW cannot generate temporary assembly when a non-ASCII path reaches the
#     compiler, so every translation unit is compiled separately with
#     "g++ -pipe -c <ASCII relative source> -o <ASCII relative object>" and the
#     objects are linked explicitly.  TMP/TEMP/PATH are never touched.
[CmdletBinding()]
param(
  [switch]$Clean,
  [switch]$RunSelf,
  [switch]$RunInventory,
  [switch]$RunDryRun,
  [switch]$RunReal,
  [switch]$AllowRun,
  [switch]$AllowWildcardBind,
  [string]$RoomExe = '',
  [string]$RoomArgsFile = '',
  [string]$Protocol = 'v1',
  [string]$ServerTag = '',
  [string]$Cases = 'core',
  # Output directory.  It exists so a reproducibility check can build the exact same
  # sources twice even while another process holds (and therefore locks) a running
  # image in the default build-mingw directory.
  [string]$Out = 'build-mingw'
)

$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
$Gxx = 'G:/msys64/mingw64/bin/g++.exe'
$ObjectDir = "$Out/obj"
$EnetSrc = '../room-transport/vendor/enet-2662c0de09e36f2a2030ccc2c528a3e4c9e8138a'
$FmtInc = '../room-transport/vendor/fmt-e69e5f977d458f2650bb346dadf2ad30c5320281/include'
$Mirror = '../../01052024-yuzu-mirror-master/src'
$ZstdLib = 'G:/msys64/mingw64/lib/libzstd.a'
$NL = [Environment]::NewLine

Push-Location $Root
try {
  if (-not (Test-Path $Gxx)) { throw "compiler not found: $Gxx" }
  New-Item -ItemType Directory -Force -Path $ObjectDir | Out-Null
  if ($Clean -and (Test-Path $Out)) {
    Get-ChildItem $Out -Recurse -File | Remove-Item -Force
  }

  # ---- original sources must stay byte-identical across the build -----------
  $OriginalFiles = @(
    "$Mirror/network/room.cpp", "$Mirror/network/room.h",
    "$Mirror/network/packet.cpp", "$Mirror/network/packet.h",
    "$Mirror/network/verify_user.cpp", "$Mirror/network/verify_user.h",
    "$Mirror/common/common_types.h", "$Mirror/common/socket_types.h",
    "$Mirror/common/announce_multiplayer_room.h", "$Mirror/web_service/web_result.h"
  )
  $before = @{}
  foreach ($f in $OriginalFiles) {
    $abs = (Get-Item $f).FullName
    $before[$abs] = (Get-FileHash $f -Algorithm SHA256).Hash
  }
  Write-Host "original-source guard: $($OriginalFiles.Count) file(s) recorded"

  # ---- ENet (C, compiled through the g++ driver with -x c) ------------------
  $EnetNames = @('callbacks','compress','host','list','packet','peer','protocol','unix','win32')
  $EnetObjs = @()
  foreach ($n in $EnetNames) {
    $src = "$EnetSrc/$n.c"
    if (-not (Test-Path $src)) { throw "missing ENet source: $src" }
    $objFile = "$ObjectDir/enet_$n.o"
    $o = & $Gxx -x c -pipe -std=c99 -O2 -I"$EnetSrc/include" -c $src -o $objFile 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host ($o -join $NL); throw "compile failed: $src" }
    $EnetObjs += $objFile
  }
  Write-Host "enet: $($EnetObjs.Count) object(s)"

  # ---- translation-unit lists ----------------------------------------------
  $ClientSources = @(
    'src/main.cpp', 'src/harness.cpp', 'src/raw_client.cpp', 'src/subprocess.cpp',
    'src/win_net.cpp', 'src/cases_common.cpp', 'src/cases_v1.cpp', 'src/cases_v4.cpp',
    'src/observe.cpp',
    '../room-client/src/protocol.cpp', '../room-client/src/session.cpp',
    '../room-transport/src/transport.cpp',
    '../citra-room/src/protocol.cpp', '../citra-room/src/session.cpp'
  )
  $SelfSources = @(
    'src/self_server_main.cpp',
    "$Mirror/network/room.cpp", "$Mirror/network/packet.cpp", "$Mirror/network/verify_user.cpp"
  )

  function Get-ObjName([string]$rel) {
    $s = $rel -replace '^\.\./', ''
    $s = $s -replace '^\.\./\.\./', 'mirror_'
    $s = $s -replace '[\\/]', '_'
    $s = $s -replace '\.(cpp|c)$', ''
    return $s
  }

  $CommonFlags = @(
    '-pipe', '-std=c++20', '-O2', '-g', '-Wall', '-Wextra', '-Wpedantic',
    '-DNOMINMAX', '-DWIN32_LEAN_AND_MEAN', '-DFMT_HEADER_ONLY',
    '-finput-charset=UTF-8', '-fexec-charset=UTF-8'
  )
  $ClientInc = @(
    '-Isrc', '-I../room-transport/include', '-I../room-client/include',
    '-I../citra-room/include', '-I../room-transport/support/include',
    "-I$EnetSrc/include", "-I$FmtInc", "-I$Mirror", '-IG:/msys64/mingw64/include'
  )
  $SelfInc = @(
    '-Isrc', '-I../room-transport/support/include',
    "-I$EnetSrc/include", "-I$FmtInc", "-I$Mirror", '-IG:/msys64/mingw64/include'
  )
  $LinkFlags = @('-pipe', '-static', '-static-libgcc', '-static-libstdc++', '-Wl,--no-insert-timestamp')
  $LinkTail = @($ZstdLib, '-lws2_32', '-lwinmm', '-liphlpapi')

  function Compile-Set([string[]]$sources, [string[]]$includes, [string]$label) {
    $objs = @()
    foreach ($src in $sources) {
      $objFile = "$ObjectDir/$(Get-ObjName $src).o"
      $o = & $Gxx @CommonFlags @includes -c $src -o $objFile 2>&1
      if ($LASTEXITCODE -ne 0) { Write-Host ($o -join $NL); throw "compile failed: $src" }
      $warn = @($o | Select-String 'warning:')
      if ($warn.Count -gt 0) {
        Write-Host "  $($warn.Count) warning(s) in $src"
        $warn | Select-Object -First 8 | ForEach-Object { Write-Host "    $_" }
      }
      $objs += $objFile
    }
    Write-Host "${label}: $($objs.Count) object(s)"
    return ,$objs
  }

  $ClientObjs = Compile-Set $ClientSources $ClientInc 'client'
  $SelfObjs = Compile-Set $SelfSources $SelfInc 'self-server'

  # ---- link ----------------------------------------------------------------
  $o = & $Gxx @LinkFlags -o "$Out/real_room_interop.exe" @ClientObjs @EnetObjs @LinkTail 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host ($o -join $NL); throw 'link failed: real_room_interop.exe' }
  $o = & $Gxx @LinkFlags -o "$Out/real_room_self_server.exe" @SelfObjs @EnetObjs @LinkTail 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host ($o -join $NL); throw 'link failed: real_room_self_server.exe' }

  # ---- original-source guard, second half ----------------------------------
  $changed = @()
  foreach ($f in $OriginalFiles) {
    $abs = (Get-Item $f).FullName
    if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $before[$abs]) { $changed += $f }
  }
  if ($changed.Count -gt 0) { throw "original sources changed during the build: $($changed -join ', ')" }

  foreach ($exe in @("$Out/real_room_interop.exe", "$Out/real_room_self_server.exe")) {
    $item = Get-Item $exe
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    Write-Host ("BUILT {0} bytes={1} sha256={2}" -f $exe, $item.Length, $hash)
  }

  if ($RunInventory) {
    & './tools/static-inventory.ps1' -OutJson 'evidence/static-inventory.json' -OutText 'evidence/static-inventory.txt'
    if (-not $?) { throw 'static inventory failed' }
  }
  if ($RunDryRun) {
    & "$Out/real_room_interop.exe" dryrun -Evidence evidence -Work work
    if ($LASTEXITCODE -ne 0) { throw "dryrun failed: exit=$LASTEXITCODE" }
  }
  if ($RunSelf) {
    & "$Out/real_room_interop.exe" self -Evidence evidence -Work work -Cases all
    if ($LASTEXITCODE -ne 0) { throw "self interoperability failed: exit=$LASTEXITCODE" }
  }
  if ($RunReal) {
    $a = @('real', '-Evidence', 'evidence', '-Work', 'work', '-RoomExe', $RoomExe,
           '-RoomArgsFile', $RoomArgsFile, '-Protocol', $Protocol, '-Cases', $Cases)
    if ($ServerTag -ne '') { $a += @('-ServerTag', $ServerTag) }
    if ($AllowRun) { $a += '-AllowRun' }
    if ($AllowWildcardBind) { $a += '-AllowWildcardBind' }
    & "$Out/real_room_interop.exe" @a
    if ($LASTEXITCODE -ne 0) { throw "real interoperability failed: exit=$LASTEXITCODE" }
  }
} finally {
  Pop-Location
}
