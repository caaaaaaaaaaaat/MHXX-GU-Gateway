#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$probeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$collector = Join-Path (Split-Path -Parent $probeDir) 'Collect-EnvironmentManifest.ps1'
$toolTree = Split-Path -Parent $collector
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $probeDir)))
$runId = [Guid]::NewGuid().ToString('N')
$runDir = Join-Path $probeDir ("run2-" + $runId)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$results = New-Object System.Collections.ArrayList
function Short([string]$s,[int]$n) { if ($null -eq $s) { return '' } ; $s = $s -replace "\r?\n",' ' ; if ($s.Length -le $n) { return $s } else { return $s.Substring(0,$n) } }
function Add-Result([string]$name,[string]$verdict,[string]$detail) {
  [void]$results.Add([pscustomobject]@{ name=$name; verdict=$verdict; detail=$detail })
  Write-Host ("[{0}] {1} :: {2}" -f $verdict,$name,$detail)
}
function New-MinimalPE([string]$Path) {
  $b = New-Object byte[] 88
  $b[0]=0x4D; $b[1]=0x5A; $b[60]=0x40
  $b[64]=0x50; $b[65]=0x45
  $b[68]=0x64; $b[69]=0x86
  $b[86]=0x22; $b[87]=0x00
  [IO.File]::WriteAllBytes($Path,$b)
}
function Run-Collector([hashtable]$Params) {
  $out = $null; $code = 0
  try { $out = & $collector @Params 2>&1 } catch { $code = 1; $out = $_.Exception.Message }
  return [pscustomobject]@{ code=$code; output=($out | Out-String) }
}
function Get-PEStatus([string]$OutFile) {
  if (-not (Test-Path -LiteralPath $OutFile)) { return 'NO_OUTPUT_FILE' }
  try {
    $j = Get-Content -LiteralPath $OutFile -Raw -Encoding UTF8 | ConvertFrom-Json
    return ($j.citra.executable.pe.status + '|' + $j.citra.executable.pe.error_code + '|exec_status=' + $j.citra.executable.status)
  } catch { return 'READ_ERROR:' + $_.Exception.Message }
}
Set-Location -LiteralPath $runDir
Write-Host ('RUN2_DIR=' + $runDir)

$p35 = Join-Path $runDir 'p35b-maxsect.exe'
New-MinimalPE $p35
$bytes = [IO.File]::ReadAllBytes($p35); $bytes[70]=0xFF; $bytes[71]=0xFF; [IO.File]::WriteAllBytes($p35,$bytes)
$o = Join-Path $runDir 'p35b.json'
$r = Run-Collector @{ CitraExePath=$p35; OutputPath=$o }
Add-Result 'P35b-tiny-88byte-max-sections' ("len=88 secCount=0xFFFF code=$($r.code) out=" + (Short $r.output.Trim() 120)) (Get-PEStatus $o)

$p36 = Join-Path $runDir 'p36b-hugeopt.exe'
New-MinimalPE $p36
$bytes = [IO.File]::ReadAllBytes($p36); $bytes[84]=0xF0; $bytes[85]=0xFF; [IO.File]::WriteAllBytes($p36,$bytes)
$o = Join-Path $runDir 'p36b.json'
$r = Run-Collector @{ CitraExePath=$p36; OutputPath=$o }
Add-Result 'P36b-tiny-88byte-huge-optional' ("len=88 optSize=0xFFF0 code=$($r.code) out=" + (Short $r.output.Trim() 120)) (Get-PEStatus $o)

$longPath = 'C:\' + ('a' * 4000) + '.exe'
$o = Join-Path $runDir 'p40.json'
$r = Run-Collector @{ CitraExePath=$longPath; OutputPath=$o }
$state = if (Test-Path -LiteralPath $o) { Get-PEStatus $o } else { 'NO_OUTPUT_FILE' }
Add-Result 'P40-very-long-input-path' ("len=$($longPath.Length) code=$($r.code) msg=" + (Short $r.output.Trim() 220)) $state

$o = Join-Path $runDir 'p41.json'
$r = Run-Collector @{ CitraExePath='NUL.exe'; OutputPath=$o }
$state = if (Test-Path -LiteralPath $o) { Get-PEStatus $o } else { 'NO_OUTPUT_FILE' }
Add-Result 'P41-NUL.exe-device-input' ("code=$($r.code) msg=" + (Short $r.output.Trim() 220)) $state

$o = Join-Path $runDir 'p42.json'
$r = Run-Collector @{ CitraExePath='AUX.exe'; OutputPath=$o }
$state = if (Test-Path -LiteralPath $o) { Get-PEStatus $o } else { 'NO_OUTPUT_FILE' }
Add-Result 'P42-AUX.exe-device-input' ("code=$($r.code) msg=" + (Short $r.output.Trim() 220)) $state

$o = Join-Path $toolTree 'NUL.json'
$ext = '\?' + $o
if ([IO.File]::Exists($ext)) { [IO.File]::Delete($ext) }
$r = Run-Collector @{ OutputPath=$o }
$realExists = [IO.File]::Exists($ext)
$realLen = 0
if ($realExists) { $realLen = ([IO.FileInfo]::new($ext)).Length }
$normalExists = Test-Path -LiteralPath $o
Add-Result 'P43-NUL.json-output' ("code=$($r.code) extExists=$realExists extLen=$realLen normalTestPath=$normalExists") 'Win32 reserved-name quirk: file is really written via normal File.Open; normal-path Test-Path maps to NUL device'
if ($realExists) { [IO.File]::Delete($ext) }

$juncErr = ''
$juncCreated = $false
$juncTarget = Join-Path $runDir 'junc-target'
New-Item -ItemType Directory -Path $juncTarget -Force | Out-Null
$junc = Join-Path $toolTree ('review-junction-' + $runId.Substring(0,8))
try { New-Item -ItemType Junction -Path $junc -Target $juncTarget -ErrorAction Stop | Out-Null; $juncCreated = $true } catch { $juncCreated = $false; $juncErr = $_.Exception.Message }
if ($juncCreated) {
  $o = Join-Path $junc 'p44-should-not-exist.json'
  $r = Run-Collector @{ OutputPath=$o }
  $outside = Test-Path -LiteralPath (Join-Path $juncTarget 'p44-should-not-exist.json')
  Add-Result 'P44-output-through-junction' ("code=$($r.code) msg=" + (Short $r.output.Trim() 200)) ("rejected=$($r.code -ne 0) outsideFile=$outside")
  cmd.exe /c rmdir $junc | Out-Null
} else {
  Add-Result 'P44-output-through-junction' 'UNTESTED' ("junction create failed: " + (Short $juncErr 200))
}

$juncInErr = ''
$juncInCreated = $false
$realDir = Join-Path $runDir 'real-in'
New-Item -ItemType Directory -Path $realDir -Force | Out-Null
$realExe = Join-Path $realDir 'real.exe'
New-MinimalPE $realExe
$juncIn = Join-Path $runDir 'junc-in'
try { New-Item -ItemType Junction -Path $juncIn -Target $realDir -ErrorAction Stop | Out-Null; $juncInCreated = $true } catch { $juncInCreated = $false; $juncInErr = $_.Exception.Message }
if ($juncInCreated) {
  $inViaJunc = Join-Path $juncIn 'real.exe'
  $o = Join-Path $runDir 'p45.json'
  $r = Run-Collector @{ CitraExePath=$inViaJunc; OutputPath=$o }
  Add-Result 'P45-input-through-junction' ("code=$($r.code) msg=" + (Short $r.output.Trim() 200)) ("rejected=$($r.code -ne 0)")
  cmd.exe /c rmdir $juncIn | Out-Null
} else {
  Add-Result 'P45-input-through-junction' 'UNTESTED' ("junction create failed: " + (Short $juncInErr 200))
}

$symErr = ''
$symCreated = $false
$sym = Join-Path $toolTree ('review-symlink-' + $runId.Substring(0,8))
try { New-Item -ItemType SymbolicLink -Path $sym -Target 'C:\Windows' -ErrorAction Stop | Out-Null; $symCreated = $true } catch { $symCreated = $false; $symErr = $_.Exception.Message }
if ($symCreated) {
  $o = Join-Path $sym 'p46-should-not-exist.json'
  $r = Run-Collector @{ OutputPath=$o }
  $outside = Test-Path -LiteralPath 'C:\Windows\p46-should-not-exist.json'
  Add-Result 'P46-output-through-dir-symlink-to-CWindows' ("code=$($r.code) msg=" + (Short $r.output.Trim() 200)) ("rejected=$($r.code -ne 0) outsideFile=$outside")
  cmd.exe /c rmdir $sym | Out-Null
} else {
  Add-Result 'P46-output-through-dir-symlink-to-CWindows' 'UNTESTED' ("symlink create failed (privilege?): " + (Short $symErr 200))
}

$nulChar = 'C:\bad' + [char]0 + 'name.exe'
$o = Join-Path $runDir 'p47.json'
$r = Run-Collector @{ CitraExePath=$nulChar; OutputPath=$o }
$state = if (Test-Path -LiteralPath $o) { Get-PEStatus $o } else { 'NO_OUTPUT_FILE' }
Add-Result 'P47-embedded-NUL-char-input' ("code=$($r.code) msg=" + (Short $r.output.Trim() 200)) $state

$o = Join-Path $runDir 'p48.json'
$r = Run-Collector @{ CitraExePath='   '; OutputPath=$o }
$state = if (Test-Path -LiteralPath $o) { Get-PEStatus $o } else { 'NO_OUTPUT_FILE' }
Add-Result 'P48-whitespace-input' ("code=$($r.code) msg=" + (Short $r.output.Trim() 200)) $state

$drives = @()
foreach ($d in [IO.DriveInfo]::GetDrives()) { $drives += ($d.Name + '=' + $d.DriveType) }
$netDrives = @($drives | Where-Object { $_ -like '*=Network' })
Add-Result 'P49-drive-enumeration' ("drives=" + ($drives -join ',')) ("networkMappedCount=$($netDrives.Count)")

$srcHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash
$origCollector = Join-Path $root 'crossplay\env-manifest\Collect-EnvironmentManifest.ps1'
$origTests = Join-Path $root 'crossplay\env-manifest\tests\Run-Tests.ps1'
$origCollectorHash = (Get-FileHash -LiteralPath $origCollector -Algorithm SHA256).Hash
$origTestsHash = (Get-FileHash -LiteralPath $origTests -Algorithm SHA256).Hash
Add-Result 'P50-source-hashes' ("copiedCollector=$srcHash") ("origCollector=$origCollectorHash origTests=$origTestsHash")
Add-Result 'P51-review-timestamp' ('reviewedUtc=' + [DateTime]::UtcNow.ToString('o')) ('localNow=' + (Get-Date).ToString('o'))

$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDir 'probe2-results.json') -Encoding UTF8
Write-Host ('PROBE2_RESULTS=' + (Join-Path $runDir 'probe2-results.json'))
