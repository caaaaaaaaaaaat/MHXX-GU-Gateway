# SPDX-License-Identifier: GPL-2.0-or-later
# real-room-interop: dry run helper.
#
# Prints (and records) the exact command lines real mode would use for every known room
# server. It never starts a server binary and never touches the network.
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$OutJson = "",
    [string]$OutText = ""
)

$ErrorActionPreference = 'Continue'
$exe = Join-Path $Root 'build-mingw/real_room_interop.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Error "missing $exe - build first with build.ps1"
    exit 2
}
if ($OutJson -eq '') { $OutJson = Join-Path $Root 'evidence/dry-run.json' }
if ($OutText -eq '') { $OutText = Join-Path $Root 'evidence/dry-run.txt' }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutJson) | Out-Null

Push-Location $Root
try {
    $lines = & $exe dryrun -Work work 2>&1 | ForEach-Object { $_.ToString() }
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
$lines | Set-Content -LiteralPath $OutText -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
# The tool writes the machine-readable object itself; copy it when a custom path was asked for.
$jsonFromTool = Join-Path $Root 'evidence/dry-run.json'
if ((Test-Path -LiteralPath $jsonFromTool) -and ($jsonFromTool -ne $OutJson)) {
    Copy-Item -LiteralPath $jsonFromTool -Destination $OutJson -Force
}
Write-Host "dry-run exit=$code text=$OutText json=$OutJson"
exit $code
