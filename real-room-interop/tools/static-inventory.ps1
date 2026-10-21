# SPDX-License-Identifier: GPL-2.0-or-later
# Static inventory of the candidate dedicated-room binaries.
#
# READ-ONLY: this script never loads and never executes the inspected binaries.
# It reads their bytes (SHA256) and extracts evidence from the file image:
#   * strings via the MinGW binutils reader G:/msys64/mingw64/bin/strings.exe (with a
#     pure byte-scan fallback), and
#   * the PE headers / import directory parsed in-process from the file bytes.
# Note: binutils objdump.exe cannot open paths containing non-ASCII characters
# (verified: "objdump.exe: C:\Users\<mangled>\yuzu-room.exe: No such file or
# directory"), while strings.exe can. That is why the PE image is parsed here in
# PowerShell instead of with objdump.
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$OutJson = '',
    [string]$OutText = ''
)
$ErrorActionPreference = 'Stop'
$StringsExe = 'G:/msys64/mingw64/bin/strings.exe'

# Targets come from docs/INPUT-INVENTORY.md plus the authorization identity table
# (docs/AUTHORIZATIONS.md "candidate room servers"). They live in a UTF-8 JSON file on
# purpose: PowerShell 5.1 reads a BOM-less script as ANSI, which mangles the non-ASCII
# paths, so this script stays pure ASCII and the paths are read with -Encoding UTF8.
$targetsPath = Join-Path $Root 'config/static-inventory-targets.json'
if (-not (Test-Path -LiteralPath $targetsPath)) { throw "missing $targetsPath" }
$targets = (Get-Content -LiteralPath $targetsPath -Encoding UTF8 -Raw | ConvertFrom-Json).targets

$symbolNeedles = @(
    'Network::Room', 'RoomMember', 'VerifyUser::NullBackend', 'WebService::RoomJson',
    'Room::Create', 'dedicated_room', 'yuzu_room.cpp', 'citra-room.cpp', 'room.cpp',
    'GenerateFakeIPAddress', 'HandleJoinRequest', 'BanListMagic', 'N7Network4RoomE'
)
$optionNeedles = @(
    'room-name', 'room-description', 'bind-address', 'max_members', 'password',
    'preferred-game', 'preferred-game-id', 'username', 'token', 'web-api-url',
    'ban-list-file', 'log-file', 'enable-citra-mods', 'enable-yuzu-mods'
)
$markerNeedles = @(
    'Room is open', 'Close with Q+Enter', 'has joined', 'Failed to create room',
    'max_members needs to be in the range', 'Token is empty', 'Bind address is empty',
    'Attempting to send to unknown'
)
# getopt short-option strings: the yuzu variant adds 's' for --bind-address.
$getoptNeedles = @('n:d:s:p:m:w:g:u:t:a:i:l:hv', 'n:d:p:m:w:g:u:t:a:i:l:hv')

function Get-PeImageInfo([byte[]]$bytes) {
    $info = [ordered]@{
        parsed = $false; machine = $null; is_64bit = $null; subsystem = $null
        link_timestamp_utc = $null; linker_version = $null; sections = @()
        import_dlls = @(); import_count = 0; error = ''
    }
    try {
        if ($bytes.Length -lt 0x40) { $info.error = 'file too small'; return $info }
        $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($e_lfanew -le 0 -or $e_lfanew + 24 -ge $bytes.Length) { $info.error = 'bad e_lfanew'; return $info }
        if (-not ($bytes[$e_lfanew] -eq 0x50 -and $bytes[$e_lfanew+1] -eq 0x45)) { $info.error = 'no PE signature'; return $info }
        $coff = $e_lfanew + 4
        $info.machine = [BitConverter]::ToUInt16($bytes, $coff)
        $numSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
        $stamp = [BitConverter]::ToUInt32($bytes, $coff + 4)
        $info.link_timestamp_utc = ([datetime]'1970-01-01T00:00:00Z').AddSeconds([double]$stamp).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $sizeOfOptional = [BitConverter]::ToUInt16($bytes, $coff + 16)
        $opt = $coff + 20
        $magic = [BitConverter]::ToUInt16($bytes, $opt)
        $info.is_64bit = ($magic -eq 0x20B)
        $info.linker_version = ("{0}.{1}" -f $bytes[$opt+2], $bytes[$opt+3])
        $info.subsystem = [BitConverter]::ToUInt16($bytes, $opt + 68)
        $ddOffset = if ($info.is_64bit) { 112 } else { 96 }
        $sections = @()
        for ($i = 0; $i -lt $numSections; $i++) {
            $s = $opt + $sizeOfOptional + ($i * 40)
            if ($s + 40 -gt $bytes.Length) { break }
            $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).TrimEnd([char]0)
            $sections += [pscustomobject]@{
                name = $name
                vsize = [BitConverter]::ToUInt32($bytes, $s + 8)
                vaddr = [BitConverter]::ToUInt32($bytes, $s + 12)
                rawsize = [BitConverter]::ToUInt32($bytes, $s + 16)
                rawptr = [BitConverter]::ToUInt32($bytes, $s + 20)
            }
        }
        $info.sections = ($sections | ForEach-Object { $_.name })
        $importRva = [BitConverter]::ToUInt32($bytes, $opt + $ddOffset + 8)
        $info.parsed = $true
        if ($importRva -eq 0) { return $info }
        $rvaToOff = {
            param($rva)
            foreach ($sec in $sections) {
                $span = [Math]::Max($sec.vsize, $sec.rawsize)
                if ($rva -ge $sec.vaddr -and $rva -lt ($sec.vaddr + $span)) {
                    return [int]($sec.rawptr + ($rva - $sec.vaddr))
                }
            }
            return -1
        }
        $off = & $rvaToOff $importRva
        $guard = 0
        $dlls = @()
        while ($off -gt 0 -and $off + 20 -le $bytes.Length -and $guard -lt 512) {
            $guard++
            $nameRva = [BitConverter]::ToUInt32($bytes, $off + 12)
            if ($nameRva -eq 0) { break }
            $nameOff = & $rvaToOff $nameRva
            if ($nameOff -le 0 -or $nameOff -ge $bytes.Length) { break }
            $end = $nameOff
            while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
            if ($end -gt $nameOff) {
                $dlls += [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
            }
            $off += 20
        }
        $info.import_dlls = @($dlls | Sort-Object -Unique)
        $info.import_count = $dlls.Count
    } catch {
        $info.error = $_.Exception.Message
    }
    return $info
}

$results = New-Object System.Collections.Generic.List[object]
$textLines = New-Object System.Collections.Generic.List[string]

foreach ($t in $targets) {
    $entry = [ordered]@{
        tag = $t.tag; kind = $t.kind; role = $t.role; path = $t.path; note = $t.note
        exists = $false; bytes = $null; sha256 = $null
        expected_bytes = $t.expected_bytes; expected_sha256 = $t.expected_sha256
        bytes_match_authorized = $false; identity_match = $false
        strings = [ordered]@{ method = $null; line_count = 0 }
        pe = $null
        symbols = [ordered]@{}; option_strings = [ordered]@{}; markers = [ordered]@{}
        getopt_short_strings = @()
        conclusion = [ordered]@{ supports_bind_address = $false; ready_marker = $null }
    }
    if (-not (Test-Path -LiteralPath $t.path)) {
        $textLines.Add("$($t.tag) MISSING $($t.path)")
        $results.Add([pscustomobject]$entry)
        continue
    }
    $entry.exists = $true
    $file = Get-Item -LiteralPath $t.path
    $entry.bytes = [int64]$file.Length
    $entry.sha256 = (Get-FileHash -LiteralPath $t.path -Algorithm SHA256).Hash
    $entry.bytes_match_authorized = ($entry.bytes -eq [int64]$t.expected_bytes)
    $entry.identity_match = ($entry.sha256 -eq $t.expected_sha256)

    $bytes = [System.IO.File]::ReadAllBytes($t.path)
    $lines = @()
    if (Test-Path -LiteralPath $StringsExe) {
        $lines = @(& $StringsExe -n 6 $t.path 2>$null)
        if ($lines.Count -gt 0) { $entry.strings.method = 'strings.exe -n 6' }
    }
    if ($lines.Count -eq 0) {
        $latin = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $lines = @([regex]::Matches($latin, '[\x20-\x7E]{6,}') | ForEach-Object { $_.Value })
        $entry.strings.method = 'in-process byte scan (strings.exe unavailable or empty)'
    }
    $entry.strings.line_count = $lines.Count
    $blob = ($lines -join "`n")

    foreach ($needle in $symbolNeedles) { $entry.symbols[$needle] = $blob.Contains($needle) }
    foreach ($needle in $optionNeedles) { $entry.option_strings[$needle] = $blob.Contains($needle) }
    foreach ($needle in $markerNeedles) { $entry.markers[$needle] = $blob.Contains($needle) }
    $found = @()
    foreach ($needle in $getoptNeedles) { if ($blob.Contains($needle)) { $found += $needle } }
    $entry.getopt_short_strings = $found
    $entry.conclusion.supports_bind_address = [bool]$entry.option_strings['bind-address']
    if ($blob.Contains('Room is open')) { $entry.conclusion.ready_marker = 'Room is open' }

    $entry.pe = Get-PeImageInfo $bytes

    $presentSymbols = @()
    foreach ($k in $entry.symbols.Keys) { if ($entry.symbols[$k]) { $presentSymbols += $k } }
    $presentOptions = @()
    foreach ($k in $entry.option_strings.Keys) { if ($entry.option_strings[$k]) { $presentOptions += $k } }
    $presentMarkers = @()
    foreach ($k in $entry.markers.Keys) { if ($entry.markers[$k]) { $presentMarkers += $k } }
    $textLines.Add("$($t.tag) kind=$($t.kind) bytes=$($entry.bytes) sha256=$($entry.sha256) identity_match=$($entry.identity_match)")
    $textLines.Add("  pe_machine=$($entry.pe.machine) is64=$($entry.pe.is_64bit) timestamp=$($entry.pe.link_timestamp_utc) imports=$($entry.pe.import_dlls -join ',')")
    $textLines.Add("  symbols: " + ($presentSymbols -join ', '))
    $textLines.Add("  options: " + ($presentOptions -join ', '))
    $textLines.Add("  markers: " + ($presentMarkers -join ' | '))
    $textLines.Add("  getopt: " + ($found -join ' | '))
    $textLines.Add("  supports_bind_address=$($entry.conclusion.supports_bind_address) ready_marker=$($entry.conclusion.ready_marker)")
    $results.Add([pscustomobject]$entry)
}

$document = [pscustomobject]@{
    generated_by = 'crossplay/real-room-interop/tools/static-inventory.ps1'
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    executes_inspected_binaries = $false
    method = 'Get-FileHash + MinGW strings.exe (fallback: in-process byte scan) + in-process PE header/import parsing'
    objdump_note = 'binutils objdump.exe fails to open non-ASCII paths on this host, so PE headers are parsed in-process instead'
    targets = $results
}

if ([string]::IsNullOrEmpty($OutJson)) { $OutJson = Join-Path $Root 'evidence/static-inventory.json' }
if ([string]::IsNullOrEmpty($OutText)) { $OutText = Join-Path $Root 'evidence/static-inventory.txt' }
foreach ($dir in @((Split-Path -Parent $OutJson), (Split-Path -Parent $OutText))) {
    if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
}
$json = $document | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($OutJson, $json, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($OutText, ($textLines -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "static-inventory: wrote $OutJson"
Write-Output "static-inventory: wrote $OutText"
foreach ($line in $textLines) { Write-Output $line }
