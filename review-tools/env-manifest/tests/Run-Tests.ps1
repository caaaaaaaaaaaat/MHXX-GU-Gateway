#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$collector = Join-Path (Split-Path $PSScriptRoot -Parent) 'Collect-EnvironmentManifest.ps1'
$runRoot = Join-Path $PSScriptRoot ('artifacts/run-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($runRoot)
$results = New-Object 'Collections.Generic.List[object]'
$fixtureHashes = @{}
$zh = -join ([char[]]@(0x4E2D,0x6587))

function Assert-True([bool]$Condition,[string]$Reason) {
    if (-not $Condition) { throw ('ASSERTION_FAILED: ' + $Reason) }
}
function Assert-Equal($Actual,$Expected,[string]$Reason) {
    if ($Actual -cne $Expected) { throw ('ASSERTION_FAILED: ' + $Reason + ' actual=[' + $Actual + '] expected=[' + $Expected + ']') }
}
function Write-Fixture([string]$Name,[byte[]]$Bytes) {
    $path = Join-Path $runRoot $Name
    [IO.File]::WriteAllBytes($path,$Bytes)
    $script:fixtureHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    return $path
}
function New-MinimalPE([uint16]$Machine = 0x8664) {
    # Synthetic 64-byte DOS + PE signature + COFF; NOT a loadable program.
    $b = New-Object byte[] 88
    $b[0] = 0x4D; $b[1] = 0x5A
    [BitConverter]::GetBytes([uint32]64).CopyTo($b,60)
    $b[64] = 0x50; $b[65] = 0x45
    [BitConverter]::GetBytes($Machine).CopyTo($b,68)
    [BitConverter]::GetBytes([uint16]0x0002).CopyTo($b,86)
    return ,$b
}
function Invoke-Collector([hashtable]$Arguments,[string]$Name) {
    $target = Join-Path $runRoot ($Name + '.json')
    $Arguments.OutputPath = $target
    [void](& $collector @Arguments)
    $m = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Equal $m.schema_version 'crossplay.env-manifest/1' 'fixed schema version'
    Assert-True (-not $m.assessment.is_emulator_validation) 'never emulator validation'
    Assert-Equal $m.assessment.g0_status 'unverified' 'G0 remains unverified'
    Assert-Equal $m.assessment.m4_status 'unverified' 'M4 remains unverified'
    Assert-True (-not $m.collector.executable_started_loaded_or_injected) 'no executable action claimed'
    return $m
}
function Assert-CollectorRejects([hashtable]$Arguments,[string]$ExpectedCode) {
    $caught = $null
    try { [void](& $collector @Arguments) } catch { $caught = $_ }
    Assert-True ($null -ne $caught) ('expected rejection ' + $ExpectedCode)
    if ($ExpectedCode) { Assert-True ($caught.ToString().Contains($ExpectedCode)) ('error contains ' + $ExpectedCode + ': ' + $caught) }
}
function Test-Case([string]$Name,[scriptblock]$Body) {
    try {
        & $Body
        $script:results.Add([ordered]@{name=$Name;status='passed';detail='none'})
        Write-Output ('PASS ' + $Name)
    } catch {
        $script:results.Add([ordered]@{name=$Name;status='failed';detail=$_.ToString()})
        Write-Output ('FAIL ' + $Name + ': ' + $_)
    }
}
$x64Bytes = New-MinimalPE
$x86Bytes = New-MinimalPE 0x014C
$x64 = Write-Fixture ('x64 ' + $zh + ' fixture.exe') $x64Bytes
$x86 = Write-Fixture 'x86 fixture.exe' $x86Bytes
$pdb = Write-Fixture ('optional ' + $zh + '.pdb') ([byte[]]@(0x50,0x44,0x42,0x00,0x7F))
$badMZBytes = New-MinimalPE; $badMZBytes[0] = 0
$badMZ = Write-Fixture 'bad-mz.exe' $badMZBytes
$badPEBytes = New-MinimalPE; $badPEBytes[64] = 0
$badPE = Write-Fixture 'bad-pe.exe' $badPEBytes
$short = Write-Fixture 'short-dos.exe' ([byte[]]@(0x4D,0x5A,0,0))
$pastBytes = New-MinimalPE; [BitConverter]::GetBytes([uint32]4096).CopyTo($pastBytes,60)
$past = Write-Fixture 'past-eof.exe' $pastBytes
$beforeBytes = New-MinimalPE; [BitConverter]::GetBytes([uint32]2).CopyTo($beforeBytes,60)
$before = Write-Fixture 'before-dos.exe' $beforeBytes
$optionalBytes = New-MinimalPE; [BitConverter]::GetBytes([uint16]240).CopyTo($optionalBytes,84)
$optional = Write-Fixture 'short-optional.exe' $optionalBytes
$sectionsBytes = New-MinimalPE; [BitConverter]::GetBytes([uint16]1).CopyTo($sectionsBytes,70)
$sections = Write-Fixture 'short-sections.exe' $sectionsBytes
$unknown = Write-Fixture 'unknown-machine.exe' (New-MinimalPE 0xFFFF)
$hugeBytes = New-MinimalPE; [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($hugeBytes,60)
$huge = Write-Fixture 'huge-offset.exe' $hugeBytes
$oneOptionalBytes = New-Object byte[] 89; $x64Bytes.CopyTo($oneOptionalBytes,0)
[BitConverter]::GetBytes([uint16]1).CopyTo($oneOptionalBytes,84)
$oneOptional = Write-Fixture 'one-byte-optional.exe' $oneOptionalBytes
$directory = Join-Path $runRoot 'directory.exe'; [void][IO.Directory]::CreateDirectory($directory)
$missing = Join-Path $runRoot 'missing.exe'

Test-Case '01-empty-inputs-unknown' {
    $m = Invoke-Collector @{} 'empty'
    Assert-Equal $m.citra.executable.status 'not_provided' 'empty Citra'
    Assert-Equal $m.yuzu.executable.status 'not_provided' 'empty Yuzu'
    Assert-Equal $m.citra.manual.game_label 'unknown' 'no game files'
    Assert-Equal $m.citra.executable.sha256 'unknown' 'no file hash fabricated'
}
Test-Case '02-citra-only-x64-unicode-space-path-sha256' {
    $m = Invoke-Collector @{CitraExePath=$x64} 'x64'
    Assert-Equal $m.citra.executable.pe.machine '0x8664' 'machine x64'
    Assert-Equal $m.citra.executable.pe.architecture 'x64' 'architecture x64'
    Assert-Equal $m.citra.executable.sha256 $fixtureHashes[$x64].ToLowerInvariant() 'correct SHA256'
    Assert-Equal $m.citra.executable.size_bytes 88 'correct fixture size'
    Assert-Equal $m.citra.executable.absolute_path $x64 'literal Unicode space path'
    Assert-Equal $m.yuzu.executable.status 'not_provided' 'one side is permitted'
    Assert-Equal $m.citra.executable.file_version 'unknown' 'no version resource'
}
Test-Case '03-yuzu-only-x86' {
    $m = Invoke-Collector @{YuzuExePath=$x86} 'x86'
    Assert-Equal $m.yuzu.executable.pe.machine '0x014C' 'machine x86'
    Assert-Equal $m.yuzu.executable.pe.architecture 'x86' 'architecture x86'
    Assert-Equal $m.citra.executable.status 'not_provided' 'other side absent'
}
Test-Case '04-both-and-optional-pdb-explicit-only' {
    $m = Invoke-Collector @{CitraExePath=$x64;YuzuExePath=$x86;CitraPdbPath=$pdb;YuzuPdbPath=$pdb} 'both'
    Assert-Equal $m.citra.pdb.status 'read_ok_pdb_unverified' 'PDB hash only'
    Assert-Equal $m.yuzu.pdb.pe.status 'not_applicable_pdb' 'PDB not PE'
    Assert-Equal $m.citra.pdb.sha256 $fixtureHashes[$pdb].ToLowerInvariant() 'PDB hash'
}
Test-Case '05-invalid-mz' {
    $m = Invoke-Collector @{CitraExePath=$badMZ} 'bad-mz'
    Assert-Equal $m.citra.executable.status 'invalid_pe' 'invalid status'
    Assert-Equal $m.citra.executable.pe.error_code 'invalid_mz' 'bad MZ reason'
}
Test-Case '06-invalid-pe-signature' {
    $m = Invoke-Collector @{CitraExePath=$badPE} 'bad-pe'
    Assert-Equal $m.citra.executable.pe.error_code 'bad_pe_signature' 'bad PE reason'
}
Test-Case '07-truncated-dos' {
    $m = Invoke-Collector @{CitraExePath=$short} 'short-dos'
    Assert-Equal $m.citra.executable.pe.error_code 'truncated_dos_header' 'short DOS reason'
}
Test-Case '08-truncated-pe' {
    $m = Invoke-Collector @{CitraExePath=$past} 'past-eof'
    Assert-Equal $m.citra.executable.pe.error_code 'truncated_pe_header' 'past EOF reason'
}
Test-Case '09-offset-before-dos' {
    $m = Invoke-Collector @{CitraExePath=$before} 'before-dos'
    Assert-Equal $m.citra.executable.pe.error_code 'invalid_pe_offset' 'offset lower bound'
}
Test-Case '10-truncated-optional-header' {
    $m = Invoke-Collector @{CitraExePath=$optional} 'short-optional'
    Assert-Equal $m.citra.executable.pe.error_code 'truncated_optional_header' 'optional size bound'
}
Test-Case '11-truncated-section-table' {
    $m = Invoke-Collector @{CitraExePath=$sections} 'short-sections'
    Assert-Equal $m.citra.executable.pe.error_code 'truncated_section_table' 'section table bound'
}
Test-Case '12-unknown-machine-not-guessed' {
    $m = Invoke-Collector @{CitraExePath=$unknown} 'unknown-machine'
    Assert-Equal $m.citra.executable.pe.machine '0xFFFF' 'raw machine kept'
    Assert-Equal $m.citra.executable.pe.architecture 'unknown' 'architecture unknown'
}
Test-Case '13-missing-explicit-path' {
    $m = Invoke-Collector @{CitraExePath=$missing} 'missing'
    Assert-Equal $m.citra.executable.status 'missing' 'missing status'
    Assert-Equal $m.citra.executable.sha256 'unknown' 'missing hash'
}
Test-Case '14-existing-output-rejected-and-unchanged' {
    $out = Join-Path $runRoot 'empty.json'
    $hash = (Get-FileHash -LiteralPath $out).Hash
    Assert-CollectorRejects @{OutputPath=$out} 'OUTPUT_EXISTS_USE_FORCE'
    Assert-Equal (Get-FileHash -LiteralPath $out).Hash $hash 'refusal preserved output'
}
Test-Case '15-force-own-output-manual-passed-still-unverified' {
    $m = Invoke-Collector @{Force=$true;CitraLocalBaseline='passed';CitraVersionLabel='test label'} 'empty'
    Assert-Equal $m.citra.manual.same_platform_local_baseline 'passed' 'manual baseline preserved'
    Assert-Equal $m.assessment.same_platform_baseline 'manual_only_unverified' 'not system verified'
}
Test-Case '16-baseline-invalid-parameter' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'invalid-baseline.json');CitraLocalBaseline='verified'} ''
}
Test-Case '17-purpose-invalid-parameter' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'invalid-purpose.json');Purpose='verified_emulator'} ''
}
Test-Case '18-wrong-input-extension' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'wrong-extension.json');CitraExePath=(Join-Path $runRoot 'secret.txt')} 'INPUT_EXTENSION_MUST_BE_.EXE'
}
Test-Case '19-explicit-empty-path-invalid-parameter' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'empty-param.json');CitraExePath=''} ''
}
Test-Case '20-label-too-long-invalid-parameter' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'long-label.json');CitraGameLabel=('x' * 513)} ''
}
Test-Case '21-output-extension-refused' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'bad-output.txt')} 'OUTPUT_EXTENSION_MUST_BE_JSON'
}
Test-Case '22-output-outside-tree-refused-even-force' {
    $outside = Join-Path ([IO.Path]::GetPathRoot($runRoot)) ('env-manifest-refused-' + [Guid]::NewGuid().ToString('N') + '.json')
    Assert-CollectorRejects @{OutputPath=$outside;Force=$true} 'OUTPUT_OUTSIDE_TOOL_TREE'
    Assert-True (-not (Test-Path -LiteralPath $outside)) 'did not create outside file'
}
Test-Case '23-input-directory-rejected' {
    Assert-CollectorRejects @{OutputPath=(Join-Path $runRoot 'input-dir.json');CitraExePath=$directory} 'INPUT_IS_DIRECTORY'
}
Test-Case '24-unsigned-huge-offset-bounded' {
    $m = Invoke-Collector @{CitraExePath=$huge} 'huge-offset'
    Assert-Equal $m.citra.executable.pe.error_code 'truncated_pe_header' 'uint32 offset safe'
}
Test-Case '25-utf8-chinese-json-roundtrip' {
    $label = $zh + ' MHXX 1.4 / ' + $zh
    $m = Invoke-Collector @{CitraGameLabel=$label;YuzuRegion=$zh;Purpose='tool_test'} ('roundtrip ' + $zh)
    Assert-Equal $m.citra.manual.game_label $label 'Chinese labels exact'
    Assert-Equal $m.yuzu.manual.region $zh 'Chinese region exact'
    Assert-Equal $m.purpose 'tool_test' 'fixture purpose explicit'
    $jsonPath = Join-Path $runRoot ('roundtrip ' + $zh + '.json')
    $bytes = [IO.File]::ReadAllBytes($jsonPath)
    $decoder = New-Object Text.UTF8Encoding($false,$true)
    [void]$decoder.GetString($bytes)
    Assert-True (-not (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF))) 'UTF8 without BOM'
}
Test-Case '26-collector-static-no-start-load-injection-network-scan' {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($collector,[ref]$tokens,[ref]$errors)
    Assert-Equal $errors.Count 0 'PowerShell parser clean'
    $banned = @('Start-Process','Invoke-WebRequest','Invoke-RestMethod','Add-Type','Get-Process','Get-ChildItem','reg.exe','Invoke-Expression')
    $commands = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
    foreach ($command in $commands) { Assert-True ($banned -notcontains $command.GetCommandName()) 'no banned command' }
    $source = Get-Content -LiteralPath $collector -Raw
    Assert-True (-not [regex]::IsMatch($source,'OpenProcess|LoadLibrary|WriteProcessMemory|CreateRemoteThread|System\.Diagnostics\.Process|System\.Reflection\.Assembly')) 'no native injection/loading identifiers'
}
Test-Case '27-input-fixtures-not-modified' {
    foreach ($path in $fixtureHashes.Keys) { Assert-Equal (Get-FileHash -LiteralPath $path).Hash $fixtureHashes[$path] 'input hash unchanged' }
}
Test-Case '28-short-optional-one-byte' {
    $m = Invoke-Collector @{CitraExePath=$oneOptional} 'one-byte-optional'
    Assert-Equal $m.citra.executable.pe.error_code 'short_optional_header' 'one-byte optional rejects'
}
Test-Case '29-pdb-only-no-emulator-claim' {
    $m = Invoke-Collector @{CitraPdbPath=$pdb} 'pdb-only'
    Assert-Equal $m.citra.executable.status 'not_provided' 'PDB does not stand in for EXE'
    Assert-Equal $m.citra.pdb.pe.status 'not_applicable_pdb' 'PDB not guessed'
}
Test-Case '30-relative-input-and-output-literal-resolution' {
    $original = Get-Location
    try {
        Set-Location -LiteralPath $runRoot
        $m = Invoke-Collector @{YuzuExePath='x86 fixture.exe'} 'relative-path'
        Assert-Equal $m.yuzu.executable.absolute_path $x86 'relative file resolved'
    } finally { Set-Location -LiteralPath $original.Path }
}
Test-Case '31-unc-input-rejected-before-file-access' {
    $unc = (-join ([char[]]@(92,92))) + 'env-manifest.invalid/share/not-read.exe'
    Assert-CollectorRejects @{CitraExePath=$unc;OutputPath=(Join-Path $runRoot 'unc-in.json')} 'UNC_OR_DEVICE_PATH_REJECTED'
}
Test-Case '32-unc-output-rejected-before-file-access' {
    $unc = (-join ([char[]]@(92,92))) + 'env-manifest.invalid/share/not-created.json'
    Assert-CollectorRejects @{OutputPath=$unc;Force=$true} 'UNC_OR_DEVICE_PATH_REJECTED'
}
Test-Case '33-forward-slash-unc-rejected' {
    Assert-CollectorRejects @{YuzuExePath='//env-manifest.invalid/share/not-read.exe';OutputPath=(Join-Path $runRoot 'slash-unc.json')} 'UNC_OR_DEVICE_PATH_REJECTED'
}
Test-Case '34-locked-input-read-error-retains-cause' {
    $lock = [IO.File]::Open($x64,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        $m = Invoke-Collector @{CitraExePath=$x64} 'locked-file'
        Assert-Equal $m.citra.executable.status 'read_error' 'locked file status'
        Assert-True ($m.citra.executable.read_error_type -ne 'unknown') 'concrete error type'
        Assert-True ($m.citra.executable.read_error_reason -ne 'unknown') 'concrete error message'
    } finally { $lock.Dispose() }
}
Test-Case '35-output-directory-rejected-even-force' {
    $dir = Join-Path $runRoot 'directory.json'; [void][IO.Directory]::CreateDirectory($dir)
    Assert-CollectorRejects @{OutputPath=$dir;Force=$true} 'OUTPUT_IS_DIRECTORY'
}
Test-Case '36-output-canonical-traversal-rejected' {
    $outside = Join-Path (Split-Path $PSScriptRoot -Parent) '../env-manifest-refused.json'
    Assert-CollectorRejects @{OutputPath=$outside;Force=$true} 'OUTPUT_OUTSIDE_TOOL_TREE'
}
Test-Case '37-existing-input-parent-junction-rejected' {
    $target = Join-Path $runRoot 'junction-target'
    [void][IO.Directory]::CreateDirectory($target)
    [IO.File]::WriteAllBytes((Join-Path $target 'fixture.exe'),$x64Bytes)
    $link = Join-Path $runRoot 'input-junction'
    [void](New-Item -Path $link -ItemType Junction -Target $target)
    Assert-CollectorRejects @{CitraExePath=(Join-Path $link 'fixture.exe');OutputPath=(Join-Path $runRoot 'junction-in.json')} 'INPUT_REPARSE_POINT_REJECTED'
}
Test-Case '38-existing-output-parent-junction-rejected' {
    $link = Join-Path $runRoot 'output-junction'
    [void](New-Item -Path $link -ItemType Junction -Target $runRoot)
    Assert-CollectorRejects @{OutputPath=(Join-Path $link 'junction-out.json');Force=$true} 'OUTPUT_REPARSE_POINT_REJECTED'
}
Test-Case '39-fixed-object-key-shape-across-empty-and-files' {
    function Get-KeyShape($Object,[string]$Prefix) {
        foreach ($property in $Object.PSObject.Properties) {
            $key = $Prefix + '.' + $property.Name
            Write-Output $key
            if ($property.Value -is [Management.Automation.PSCustomObject]) { Get-KeyShape $property.Value $key }
        }
    }
    $empty = Get-Content -LiteralPath (Join-Path $runRoot 'empty.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $both = Get-Content -LiteralPath (Join-Path $runRoot 'both.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Equal ((Get-KeyShape $empty '') -join '|') ((Get-KeyShape $both '') -join '|') 'fixed schema key shape'
}
Test-Case '40-case-insensitive-enum-normalized' {
    $m = Invoke-Collector @{Purpose='TOOL_TEST';CitraLocalBaseline='PASSED'} 'uppercase-enums'
    Assert-Equal $m.purpose 'tool_test' 'purpose normalized'
    Assert-Equal $m.citra.manual.same_platform_local_baseline 'passed' 'baseline normalized'
}
Test-Case '41-one-byte-pdb-is-unverified-not-a-symbol-match' {
    $tiny = Write-Fixture 'tiny.pdb' ([byte[]]@(1))
    $m = Invoke-Collector @{YuzuPdbPath=$tiny} 'tiny-pdb'
    Assert-Equal $m.yuzu.pdb.status 'read_ok_pdb_unverified' 'unverified PDB bytes only'
    Assert-Equal $m.yuzu.pdb.identity 'unverified_user_supplied' 'no PDB matching claim'
}
Test-Case '42-dll-characteristic-not-emulator-identity' {
    $bytes = New-MinimalPE
    [BitConverter]::GetBytes([uint16]0x2002).CopyTo($bytes,86)
    $dllHeader = Write-Fixture 'dll-header-not-emulator.exe' $bytes
    $m = Invoke-Collector @{CitraExePath=$dllHeader;Purpose='tool_test'} 'dll-characteristic'
    Assert-True $m.citra.executable.pe.is_dll_header 'DLL characteristic observed'
    Assert-Equal $m.citra.executable.identity 'unverified_user_supplied' 'DLL or EXE never emulator proof'
}
$failed = @($results | Where-Object { $_.status -eq 'failed' }).Count
$summary = [ordered]@{
    schema_version = 'crossplay.env-manifest-test/1'; generated_utc = [DateTime]::UtcNow.ToString('o')
    powershell_version = $PSVersionTable.PSVersion.ToString(); test_kind = 'synthetic_non_loadable_pe_fixtures'
    run_root = $runRoot; total = $results.Count; passed = ($results.Count - $failed); failed = $failed
    started_or_loaded_fixture_exe = $false; process_injected = $false; emulator_validation = $false
    tests = @($results.ToArray())
}
$summaryPath = Join-Path $runRoot 'test-results.json'
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($summaryPath,($summary | ConvertTo-Json -Depth 10) + [Environment]::NewLine,$utf8)
Write-Output ('RESULT total=' + $results.Count + ' passed=' + ($results.Count - $failed) + ' failed=' + $failed)
Write-Output ('RESULT_FILE=' + $summaryPath)
if ($failed -ne 0) { exit 1 }
exit 0
