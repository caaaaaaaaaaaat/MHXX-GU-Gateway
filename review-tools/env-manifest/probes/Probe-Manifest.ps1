#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$collector = Join-Path (Split-Path $here -Parent) 'Collect-EnvironmentManifest.ps1'
if (-not (Test-Path -LiteralPath $collector)) { throw ('collector not found: ' + $collector) }
$toolRoot = Split-Path $collector -Parent
$runRoot = Join-Path $here ('run-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($runRoot)
$obs = New-Object 'Collections.Generic.List[object]'
function Obs([string]$id,[string]$status,[string]$detail) {
    $script:obs.Add([ordered]@{id=$id;status=$status;detail=$detail})
    Write-Output ('[' + $status + '] ' + $id + ' :: ' + $detail)
}
function New-MinimalPE([uint16]$Machine = 0x8664) {
    $b = New-Object byte[] 88
    $b[0] = 0x4D; $b[1] = 0x5A
    [BitConverter]::GetBytes([uint32]64).CopyTo($b,60)
    $b[64] = 0x50; $b[65] = 0x45
    [BitConverter]::GetBytes($Machine).CopyTo($b,68)
    [BitConverter]::GetBytes([uint16]0x0002).CopyTo($b,86)
    return ,$b
}
function WB([string]$name,[byte[]]$bytes) {
    $p = Join-Path $runRoot $name
    [IO.File]::WriteAllBytes($p,$bytes)
    return $p
}
function ReadM($path) { return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json) }
function RunC([hashtable]$a,[string]$name) {
    if (-not $a.ContainsKey('OutputPath')) { $a.OutputPath = Join-Path $runRoot ($name + '.json') }
    try {
        $printed = & $collector @a
        return [ordered]@{ok=$true;manifest=(ReadM $a.OutputPath);printed=[string]$printed;path=$a.OutputPath}
    } catch {
        return [ordered]@{ok=$false;error=$_.Exception.Message;path=$a.OutputPath}
    }
}

# ---- P01 offset == Length-24 boundary must be accepted (minimal 88-byte PE)
$p01 = WB 'p01-min.exe' (New-MinimalPE)
$r = RunC @{CitraExePath=$p01} 'p01'
if ($r.ok -and $r.manifest.citra.executable.pe.status -eq 'recognized') { Obs 'P01-minimal-accepted' 'PASS' ('status=' + $r.manifest.citra.executable.pe.status + ' machine=' + $r.manifest.citra.executable.pe.machine) } else { Obs 'P01-minimal-accepted' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P02 offset == Length-23 boundary must be rejected as truncated_pe_header
$p02bytes = New-Object byte[] 87
$p02bytes[0]=0x4D; $p02bytes[1]=0x5A
[BitConverter]::GetBytes([uint32]64).CopyTo($p02bytes,60)
$p02 = WB 'p02-87.exe' $p02bytes
$r = RunC @{CitraExePath=$p02} 'p02'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_pe_header') { Obs 'P02-87byte-rejected' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P02-87byte-rejected' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P03 optional boundary EXACT: optionalSize=2, length=90 -> recognized
function New-PEWithOptional([uint16]$optSize,[int]$pad,[uint16]$sections=0,[uint16]$magic=0x20B) {
    $len = 64 + 24 + [int]$optSize + ([int]$sections * 40) + [int]$pad
    $b = New-Object byte[] $len
    $b[0]=0x4D; $b[1]=0x5A
    [BitConverter]::GetBytes([uint32]64).CopyTo($b,60)
    $b[64]=0x50; $b[65]=0x45
    [BitConverter]::GetBytes([uint16]0x8664).CopyTo($b,68)
    [BitConverter]::GetBytes($sections).CopyTo($b,70)
    [BitConverter]::GetBytes($optSize).CopyTo($b,84)
    [BitConverter]::GetBytes([uint16]0x0002).CopyTo($b,86)
    if (($optSize -ge 2) -and ($b.Length -ge 90)) { [BitConverter]::GetBytes($magic).CopyTo($b,88) }
    return ,$b
}
$p03 = WB 'p03-opt-exact.exe' (New-PEWithOptional 2 0)
$r = RunC @{CitraExePath=$p03} 'p03'
if ($r.ok -and $r.manifest.citra.executable.pe.status -eq 'recognized' -and $r.manifest.citra.executable.pe.optional_magic -eq '0x020B') { Obs 'P03-optional-exact' 'PASS' ('optional_magic=' + $r.manifest.citra.executable.pe.optional_magic) } else { Obs 'P03-optional-exact' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P04 optional one byte short -> truncated_optional_header
$p04 = WB 'p04-opt-short.exe' (New-PEWithOptional 2 -1)
$r = RunC @{CitraExePath=$p04} 'p04'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_optional_header') { Obs 'P04-optional-short' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P04-optional-short' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P05 section table EXACT: sections=1,optSize=2,len=130 -> recognized
$p05 = WB 'p05-sect-exact.exe' (New-PEWithOptional 2 0 1)
$r = RunC @{CitraExePath=$p05} 'p05'
if ($r.ok -and $r.manifest.citra.executable.pe.status -eq 'recognized') { Obs 'P05-sections-exact' 'PASS' ('status=' + $r.manifest.citra.executable.pe.status) } else { Obs 'P05-sections-exact' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P06 section table one byte short -> truncated_section_table
$p06 = WB 'p06-sect-short.exe' (New-PEWithOptional 2 -1 1)
$r = RunC @{CitraExePath=$p06} 'p06'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_section_table') { Obs 'P06-sections-short' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P06-sections-short' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P07 optionalSize=0 accepted with optional_magic unknown (COFF object style)
$p07 = WB 'p07-opt0.exe' (New-PEWithOptional 0 0)
$r = RunC @{CitraExePath=$p07} 'p07'
if ($r.ok -and $r.manifest.citra.executable.pe.status -eq 'recognized' -and $r.manifest.citra.executable.pe.optional_magic -eq 'unknown') { Obs 'P07-opt0-recognized' 'OBSERVE' ('status=recognized optional_magic=' + $r.manifest.citra.executable.pe.optional_magic) } else { Obs 'P07-opt0-recognized' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P08 empty .exe -> truncated_dos_header
$p08 = WB 'p08-empty.exe' ([byte[]]@())
$r = RunC @{CitraExePath=$p08} 'p08'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_dos_header') { Obs 'P08-empty-exe' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P08-empty-exe' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P09 exactly 64 bytes with offset=64 -> truncated_pe_header
$p09bytes = New-Object byte[] 64
$p09bytes[0]=0x4D; $p09bytes[1]=0x5A
[BitConverter]::GetBytes([uint32]64).CopyTo($p09bytes,60)
$p09 = WB 'p09-64b.exe' $p09bytes
$r = RunC @{CitraExePath=$p09} 'p09'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_pe_header') { Obs 'P09-exactly64' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P09-exactly64' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P10 random garbage -> invalid_mz
$rand = New-Object byte[] 128
(New-Object System.Random -ArgumentList @(12345)).NextBytes($rand)
$p10 = WB 'p10-garbage.exe' $rand
$r = RunC @{CitraExePath=$p10} 'p10'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'invalid_mz') { Obs 'P10-garbage' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P10-garbage' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P11 MZ then PE offset pointing at 0xFFFFFFFF (uint32 max) -> bounded
$p11bytes = New-MinimalPE
[BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($p11bytes,60)
$p11 = WB 'p11-maxoff.exe' $p11bytes
$r = RunC @{CitraExePath=$p11} 'p11'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_pe_header') { Obs 'P11-uint32max-offset' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P11-uint32max-offset' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P35 sectionCount=0xFFFF, tiny file -> truncated_section_table, no read past buffer
$p35bytes = New-MinimalPE
[BitConverter]::GetBytes([uint16]0xFFFF).CopyTo($p35bytes,70)
$p35 = WB 'p35-maxsect.exe' $p35bytes
$r = RunC @{CitraExePath=$p35} 'p35'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_section_table') { Obs 'P35-max-sections' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P35-max-sections' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P36 optionalSize=0xFFF0, small file -> truncated_optional_header
$p36bytes = New-MinimalPE
[BitConverter]::GetBytes([uint16]0xFFF0).CopyTo($p36bytes,84)
$p36 = WB 'p36-hugeopt.exe' $p36bytes
$r = RunC @{CitraExePath=$p36} 'p36'
if ($r.ok -and $r.manifest.citra.executable.pe.error_code -eq 'truncated_optional_header') { Obs 'P36-huge-optional' 'PASS' ('error_code=' + $r.manifest.citra.executable.pe.error_code) } else { Obs 'P36-huge-optional' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P12 output with embedded .. that stays inside tree
$p12target = Join-Path $runRoot 'sub/../p12-inside.json'
$r = RunC @{OutputPath=$p12target} 'p12-ignored'
$resolved = [IO.Path]::GetFullPath($p12target)
if ($r.ok -and (Test-Path -LiteralPath $resolved)) { Obs 'P12-canonical-inside' 'PASS' ('created=' + $resolved) } else { Obs 'P12-canonical-inside' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P13 output traversal escaping the tool tree -> rejected, no file
$escape = Join-Path $runRoot '../../../../../../escaped-marker.json'
$resolvedEscape = [IO.Path]::GetFullPath($escape)
$r = RunC @{OutputPath=$escape;Force=$true} 'p13'
if (-not $r.ok -and $r.error.Contains('OUTPUT_OUTSIDE_TOOL_TREE') -and -not (Test-Path -LiteralPath $resolvedEscape)) { Obs 'P13-traversal-rejected' 'PASS' ('err=' + $r.error) } else { Obs 'P13-traversal-rejected' 'FAIL' (($r | ConvertTo-Json -Compress) + ' exists=' + (Test-Path -LiteralPath $resolvedEscape)) }

# ---- P14 -Force clobbers an arbitrary pre-existing non-manifest .json under tool tree
$canary = Join-Path $runRoot 'canary.json'
[IO.File]::WriteAllText($canary,'{"canary":true,"not":"a manifest"}')
$before = (Get-Content -LiteralPath $canary -Raw)
$r = RunC @{OutputPath=$canary;Force=$true} 'p14'
$after = (Get-Content -LiteralPath $canary -Raw)
if ($r.ok -and $after.Contains('crossplay.env-manifest/1') -and ($after -ne $before)) { Obs 'P14-force-clobbers-arbitrary-json' 'FINDING' ('pre-existing canary.json overwritten; pre_len=' + $before.Length + ' post_len=' + $after.Length) } else { Obs 'P14-force-clobbers-arbitrary-json' 'FAIL' (($r | ConvertTo-Json -Compress)) }

# ---- P14b default (no -Force) refuses and preserves file (independent recheck)
$canary2 = Join-Path $runRoot 'canary2.json'
[IO.File]::WriteAllText($canary2,'{"keep":1}')
$h1 = (Get-FileHash -LiteralPath $canary2 -Algorithm SHA256).Hash
$r = RunC @{OutputPath=$canary2} 'p14b'
$h2 = (Get-FileHash -LiteralPath $canary2 -Algorithm SHA256).Hash
if (-not $r.ok -and $r.error.Contains('OUTPUT_EXISTS_USE_FORCE') -and ($h1 -eq $h2)) { Obs 'P14b-default-no-clobber' 'PASS' ('refused and hash unchanged') } else { Obs 'P14b-default-no-clobber' 'FAIL' (($r | ConvertTo-Json -Compress) + ' h1=' + $h1 + ' h2=' + $h2) }

# ---- P17 label with JSON quote/newline/backslash is escaped, no key injection
$inject = '"key":"injected","x":' + [char]10 + '\' + [char]13 + 'end'
$r = RunC @{CitraGameLabel=$inject;OutputPath=(Join-Path $runRoot 'p17.json')} 'p17'
$raw = Get-Content -LiteralPath (Join-Path $runRoot 'p17.json') -Raw -Encoding UTF8
if ($r.ok -and $r.manifest.citra.manual.game_label -eq $inject -and $null -eq $r.manifest.PSObject.Properties['key']) { Obs 'P17-json-injection-escaped' 'PASS' ('roundtrip exact; no injected top-level key') } else { Obs 'P17-json-injection-escaped' 'FAIL' (($r | ConvertTo-Json -Compress)) }

# ---- P18 no BOM + trailing newline
$out18 = Join-Path $runRoot 'p18.json'
$r = RunC @{OutputPath=$out18} 'p18'
$bytes18 = [IO.File]::ReadAllBytes($out18)
$bom = (($bytes18.Length -ge 3) -and ($bytes18[0] -eq 0xEF) -and ($bytes18[1] -eq 0xBB) -and ($bytes18[2] -eq 0xBF))
$last = $bytes18[$bytes18.Length-1]
if (-not $bom -and ($last -eq 10)) { Obs 'P18-no-bom-trailing-newline' 'PASS' ('len=' + $bytes18.Length + ' last=0x' + ('{0:X2}' -f $last)) } else { Obs 'P18-no-bom-trailing-newline' 'FAIL' ('bom=' + $bom + ' last=' + $last) }

# ---- P20 independent SHA256 cross-check
$target = WB 'p20.bin' ([byte[]]@(1..255))
$expected = ''
$fs = [IO.File]::OpenRead($target)
try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $expected = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
} finally { $fs.Dispose() }
$r = RunC @{CitraExePath=([IO.Path]::ChangeExtension($target,'.exe'))} 'p20x'
$p20exe = WB 'p20.exe' ([byte[]]@(1..255))
$expected2 = ''
$fs2 = [IO.File]::OpenRead($p20exe)
try {
    $sha2 = [Security.Cryptography.SHA256]::Create()
    try { $expected2 = -join ($sha2.ComputeHash($fs2) | ForEach-Object { $_.ToString('x2') }) } finally { $sha2.Dispose() }
} finally { $fs2.Dispose() }
$r = RunC @{CitraExePath=$p20exe} 'p20'
if ($r.ok -and $r.manifest.citra.executable.sha256 -eq $expected2) { Obs 'P20-sha256-crosscheck' 'PASS' ('hash=' + $expected2.Substring(0,16) + '...') } else { Obs 'P20-sha256-crosscheck' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P21 exactly one new file appears under tool tree for one run
function Snapshot-Files($root) {
    return @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}
$beforeSet = @{}
foreach ($f in (Snapshot-Files $toolRoot)) { $beforeSet[$f] = $true }
$out21 = Join-Path $runRoot 'nested/a/b/p21.json'
$r = RunC @{OutputPath=$out21} 'p21'
$after = Snapshot-Files $toolRoot
$new = @($after | Where-Object { -not $beforeSet.ContainsKey($_) })
if ($r.ok -and $new.Count -eq 1 -and $new[0] -eq [IO.Path]::GetFullPath($out21)) { Obs 'P21-single-new-file' 'PASS' ('new=' + $new[0]) } else { Obs 'P21-single-new-file' 'FAIL' ('newCount=' + $new.Count + ' :: ' + ($new -join '; ')) }

# ---- P22 uppercase extensions accepted
$upex = Join-Path $runRoot 'UPPER.EXE'
Copy-Item -LiteralPath $p01 -Destination $upex -Force
$r = RunC @{CitraExePath=$upex} 'p22'
if ($r.ok -and $r.manifest.citra.executable.status -eq 'read_ok_pe_headers') { Obs 'P22-uppercase-exe' 'PASS' ('status=' + $r.manifest.citra.executable.status) } else { Obs 'P22-uppercase-exe' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P24 Win32 device namespace paths rejected before file access
$dev1 = '\\?\C:\Windows\notepad.exe'
$r1 = RunC @{CitraExePath=$dev1} 'p24a'
$dev2 = '\\.\C:\Windows\notepad.exe'
$r2 = RunC @{CitraExePath=$dev2} 'p24b'
if (-not $r1.ok -and $r1.error.Contains('UNC_OR_DEVICE_PATH_REJECTED') -and -not $r2.ok -and $r2.error.Contains('UNC_OR_DEVICE_PATH_REJECTED')) { Obs 'P24-device-namespace' 'PASS' ('both \\?\ and \\.\ rejected') } else { Obs 'P24-device-namespace' 'FAIL' (($r1 | ConvertTo-Json -Compress) + ' | ' + ($r2 | ConvertTo-Json -Compress)) }

# ---- P25 single-leading-backslash path: observe how it is resolved (must not silently become UNC)
$single = '\env-manifest.invalid\share\not-read.exe'
$r = RunC @{CitraExePath=$single} 'p25'
$detail = 'ok=' + $r.ok
if ($r.ok) { $detail = $detail + ' abs=' + $r.manifest.citra.executable.absolute_path + ' status=' + $r.manifest.citra.executable.status }
else { $detail = $detail + ' err=' + $r.error }
Obs 'P25-single-leading-backslash' 'OBSERVE' $detail

# ---- P31 fixed top-level + nested schema keys exactly as declared
$expectedTop = 'schema_version|generated_utc|purpose|collector|assessment|citra|yuzu|limitations'
$expectedFile = 'file_kind|user_supplied|supplied_path|absolute_path|status|size_bytes|sha256|last_write_utc|file_version|product_version|pe|error_codes|read_error_type|read_error_reason|identity|runtime'
$expectedPE = 'status|machine|architecture|optional_magic|is_dll_header|validation|error_code'
$expectedManual = 'source|version_label|game_label|region|update_label|patch_label|same_platform_local_baseline|baseline_notes'
$m31 = ReadM $out18
$top = (($m31.PSObject.Properties | ForEach-Object { $_.Name }) -join '|')
$file = (($m31.citra.executable.PSObject.Properties | ForEach-Object { $_.Name }) -join '|')
$pe = (($m31.citra.executable.pe.PSObject.Properties | ForEach-Object { $_.Name }) -join '|')
$manual = (($m31.citra.manual.PSObject.Properties | ForEach-Object { $_.Name }) -join '|')
if (($top -ceq $expectedTop) -and ($file -ceq $expectedFile) -and ($pe -ceq $expectedPE) -and ($manual -ceq $expectedManual)) { Obs 'P31-schema-allowlist' 'PASS' ('all key sets match declared allowlist') } else { Obs 'P31-schema-allowlist' 'FAIL' ('top=' + $top + ' file=' + $file + ' pe=' + $pe + ' manual=' + $manual) }

# ---- P32 independent AST scan for banned commands and $env: reads
$tokens = $null; $perrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($collector,[ref]$tokens,[ref]$perrors)
$banned = @('Start-Process','Invoke-WebRequest','Invoke-RestMethod','Add-Type','Get-Process','Get-ChildItem','Invoke-Expression','New-Object System.Net.WebClient','Register-ScheduledTask','Set-ItemProperty')
$found = @()
$cmds = @($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
foreach ($c in $cmds) { $n = $c.GetCommandName(); if ($banned -contains $n) { $found += $n } }
$src = Get-Content -LiteralPath $collector -Raw
$envReads = [regex]::Matches($src,'\$env:').Count
$netIdents = [regex]::IsMatch($src,'WebClient|HttpClient|TcpClient|Socket|OpenProcess|LoadLibrary|WriteProcessMemory|CreateRemoteThread|Start-Process')
if (($perrors.Count -eq 0) -and ($found.Count -eq 0) -and ($envReads -eq 0) -and (-not $netIdents)) { Obs 'P32-ast-no-network-no-env' 'PASS' ('commands=' + $cmds.Count + ' bannedFound=0 envReads=0') } else { Obs 'P32-ast-no-network-no-env' 'FAIL' ('parseErr=' + $perrors.Count + ' found=' + ($found -join ',') + ' env=' + $envReads + ' net=' + $netIdents) }

# ---- P37 invalid_pe carries the reason in error_codes too
$r = RunC @{CitraExePath=$p10} 'p37'
if ($r.ok -and $r.manifest.citra.executable.status -eq 'invalid_pe' -and ($r.manifest.citra.executable.error_codes -contains 'invalid_mz')) { Obs 'P37-error-codes-populated' 'PASS' ('error_codes=' + ($r.manifest.citra.executable.error_codes -join ',')) } else { Obs 'P37-error-codes-populated' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P28 empty pdb hashed as empty-string digest, never a PE parse
$p28 = WB 'p28.pdb' ([byte[]]@())
$r = RunC @{CitraPdbPath=$p28} 'p28'
$emptySha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
if ($r.ok -and $r.manifest.citra.pdb.status -eq 'read_ok_pdb_unverified' -and $r.manifest.citra.pdb.sha256 -eq $emptySha -and $r.manifest.citra.pdb.pe.status -eq 'not_applicable_pdb') { Obs 'P28-empty-pdb' 'PASS' ('sha256=e3b0...b855 size=' + $r.manifest.citra.pdb.size_bytes) } else { Obs 'P28-empty-pdb' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P29 garbage pdb still never PE-parsed
$p29 = WB 'p29.pdb' $rand
$r = RunC @{CitraPdbPath=$p29} 'p29'
if ($r.ok -and $r.manifest.citra.pdb.status -eq 'read_ok_pdb_unverified' -and $r.manifest.citra.pdb.pe.status -eq 'not_applicable_pdb') { Obs 'P29-garbage-pdb-not-parsed' 'PASS' ('status=' + $r.manifest.citra.pdb.status + ' pe=' + $r.manifest.citra.pdb.pe.status) } else { Obs 'P29-garbage-pdb-not-parsed' 'FAIL' ($r | ConvertTo-Json -Compress) }

# ---- P30 optional magic 0x0000 recorded, not rejected (validation absent)
$p30 = WB 'p30-magic0.exe' (New-PEWithOptional 2 0 0 0x0000)
$r = RunC @{CitraExePath=$p30} 'p30'
if ($r.ok -and $r.manifest.citra.executable.pe.status -eq 'recognized' -and $r.manifest.citra.executable.pe.optional_magic -eq '0x0000') { Obs 'P30-optional-magic-not-validated' 'OBSERVE' 'status=recognized optional_magic=0x0000 (recorded, not validated)' } else { Obs 'P30-optional-magic-not-validated' 'OBSERVE' ($r | ConvertTo-Json -Compress) }

# ---- P38 output path with uppercase root letters accepted (case-insensitive prefix)
$upRoot = $toolRoot.ToUpperInvariant()
$p38 = Join-Path $upRoot 'p38-upper.json'
$r = RunC @{OutputPath=$p38;Force=$true} 'p38'
if ($r.ok -and (Test-Path -LiteralPath ([IO.Path]::GetFullPath($p38)))) { Obs 'P38-uppercase-root-prefix' 'PASS' ('accepted=' + [IO.Path]::GetFullPath($p38)) } else { Obs 'P38-uppercase-root-prefix' 'FAIL' ($r | ConvertTo-Json -Compress) }

$summary = [ordered]@{
    produced_utc = [DateTime]::UtcNow.ToString('o')
    collector = $collector
    tool_root = $toolRoot
    run_root = $runRoot
    observations = @($obs.ToArray())
}
$summaryPath = Join-Path $runRoot 'probe-results.json'
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($summaryPath,($summary | ConvertTo-Json -Depth 8) + [Environment]::NewLine,$utf8)
Write-Output ('PROBE_RESULTS=' + $summaryPath)
