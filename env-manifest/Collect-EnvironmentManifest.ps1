#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$CitraExePath,
    [ValidateNotNullOrEmpty()][string]$YuzuExePath,
    [ValidateNotNullOrEmpty()][string]$CitraPdbPath,
    [ValidateNotNullOrEmpty()][string]$YuzuPdbPath,
    [ValidateLength(1,512)][string]$CitraVersionLabel = 'unknown',
    [ValidateLength(1,512)][string]$YuzuVersionLabel = 'unknown',
    [ValidateLength(1,512)][string]$CitraGameLabel = 'unknown',
    [ValidateLength(1,512)][string]$YuzuGameLabel = 'unknown',
    [ValidateLength(1,512)][string]$CitraRegion = 'unknown',
    [ValidateLength(1,512)][string]$YuzuRegion = 'unknown',
    [ValidateLength(1,512)][string]$CitraUpdateLabel = 'unknown',
    [ValidateLength(1,512)][string]$YuzuUpdateLabel = 'unknown',
    [ValidateLength(1,512)][string]$CitraPatchLabel = 'unknown',
    [ValidateLength(1,512)][string]$YuzuPatchLabel = 'unknown',
    [ValidateSet('unknown','not_tested','passed','failed')][string]$CitraLocalBaseline = 'unknown',
    [ValidateSet('unknown','not_tested','passed','failed')][string]$YuzuLocalBaseline = 'unknown',
    [ValidateLength(1,2048)][string]$CitraBaselineNotes = 'unknown',
    [ValidateLength(1,2048)][string]$YuzuBaselineNotes = 'unknown',
    [ValidateSet('environment_inventory','tool_test')][string]$Purpose = 'environment_inventory',
    [ValidateNotNullOrEmpty()][string]$OutputPath = 'output/environment-manifest.json',
    [switch]$Force
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-AbsoluteFilePath([string]$Value) {
    if ((Get-Location).Provider.Name -ne 'FileSystem') { throw 'CURRENT_LOCATION_NOT_FILESYSTEM' }
    if ($Value.Replace([char]47,[char]92).StartsWith((-join ([char[]]@(92,92))))) { throw 'UNC_OR_DEVICE_PATH_REJECTED' }
    $path = $null
    if ([IO.Path]::IsPathRooted($Value)) { $path = [IO.Path]::GetFullPath($Value) }
    else { $path = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Value)) }
    $driveRoot = [IO.Path]::GetPathRoot($path)
    if (($driveRoot.Length -ne 3) -or ($driveRoot[1] -ne [char]58) -or ($driveRoot[2] -ne [char]92) -or ($driveRoot.Substring(0,1) -notmatch '^[A-Za-z]$')) { throw 'NON_LOCAL_DRIVE_PATH_REJECTED' }
    $drive = New-Object IO.DriveInfo($driveRoot)
    if ($drive.DriveType -eq [IO.DriveType]::Network) { throw 'MAPPED_NETWORK_DRIVE_REJECTED' }
    return $path
}

function Assert-NoExistingReparse([string]$Target,[string]$Role) {
    # Check parents before children; no directory contents are enumerated.
    $ancestors = New-Object 'Collections.Generic.List[string]'
    $walk = $Target
    while ($walk) {
        $ancestors.Insert(0,$walk)
        $parent = [IO.Path]::GetDirectoryName($walk)
        if ($parent -eq $walk) { break }
        $walk = $parent
    }
    foreach ($entryPath in $ancestors) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop }
        catch [Management.Automation.ItemNotFoundException] { continue }
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ($Role + '_REPARSE_POINT_REJECTED')
        }
        if (($entryPath -eq $Target) -and ($Role -eq 'OUTPUT') -and $entry.PSIsContainer) {
            throw 'OUTPUT_IS_DIRECTORY'
        }
    }
}

function Test-OutputTarget([string]$Target) {
    $root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([char[]]'\/')
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $Target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OUTPUT_OUTSIDE_TOOL_TREE'
    }
    if ([IO.Path]::GetExtension($Target) -ine '.json') { throw 'OUTPUT_EXTENSION_MUST_BE_JSON' }
    Assert-NoExistingReparse $Target 'OUTPUT'
    if ((Test-Path -LiteralPath $Target) -and -not $Force) { throw 'OUTPUT_EXISTS_USE_FORCE' }
}

function Get-TreeRelativePath([string]$Target) {
    # The collector emits only tool-relative, workspace-local output paths.
    # $Target has already been proven inside this tool tree by Test-OutputTarget.
    $root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([char[]]'\/')
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if ($Target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $Target.Substring($prefix.Length)
    }
    return $Target
}

function Get-PEHeader([string]$Path) {
    $result = [ordered]@{
        status = 'unknown'; machine = 'unknown'; architecture = 'unknown'
        optional_magic = 'unknown'; is_dll_header = 'unknown'
        validation = 'headers_only_not_loader_validated'; error_code = 'unknown'
    }
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $reader = New-Object IO.BinaryReader($stream)
        if ($stream.Length -lt 64) { $result.status = 'invalid'; $result.error_code = 'truncated_dos_header'; return $result }
        $dos = $reader.ReadBytes(64)
        if (($dos[0] -ne 0x4D) -or ($dos[1] -ne 0x5A)) {
            $result.status = 'invalid'; $result.error_code = 'invalid_mz'; return $result
        }
        $offset = [long][BitConverter]::ToUInt32($dos, 60)
        if ($offset -lt 64) { $result.status = 'invalid'; $result.error_code = 'invalid_pe_offset'; return $result }
        if ($offset -gt ($stream.Length - 24)) {
            $result.status = 'invalid'; $result.error_code = 'truncated_pe_header'; return $result
        }
        [void]$stream.Seek($offset, [IO.SeekOrigin]::Begin)
        $header = $reader.ReadBytes(24)
        if (($header[0] -ne 0x50) -or ($header[1] -ne 0x45) -or ($header[2] -ne 0) -or ($header[3] -ne 0)) {
            $result.status = 'invalid'; $result.error_code = 'bad_pe_signature'; return $result
        }
        $machine = [BitConverter]::ToUInt16($header, 4)
        $sectionCount = [BitConverter]::ToUInt16($header, 6)
        $optionalSize = [BitConverter]::ToUInt16($header, 20)
        $characteristics = [BitConverter]::ToUInt16($header, 22)
        if (($offset + 24 + $optionalSize) -gt $stream.Length) {
            $result.status = 'invalid'; $result.error_code = 'truncated_optional_header'; return $result
        }
        if (($offset + 24 + $optionalSize + ([long]$sectionCount * 40)) -gt $stream.Length) {
            $result.status = 'invalid'; $result.error_code = 'truncated_section_table'; return $result
        }
        if ($optionalSize -eq 1) { $result.status = 'invalid'; $result.error_code = 'short_optional_header'; return $result }
        if ($optionalSize -ge 2) { $result.optional_magic = ('0x{0:X4}' -f $reader.ReadUInt16()) }
        $result.machine = ('0x{0:X4}' -f $machine)
        switch ($machine) {
            0x8664 { $result.architecture = 'x64' }
            0x014C { $result.architecture = 'x86' }
            0xAA64 { $result.architecture = 'arm64' }
            0x0200 { $result.architecture = 'ia64' }
            0x01C4 { $result.architecture = 'armv7' }
            default { $result.architecture = 'unknown' }
        }
        $result.is_dll_header = (($characteristics -band 0x2000) -ne 0)
        $result.status = 'recognized'
        $result.error_code = 'none'
        return $result
    } finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Get-ExplicitFile([string]$Value, [string]$Kind) {
    $emptyPE = [ordered]@{
        status = 'not_provided'; machine = 'unknown'; architecture = 'unknown'
        optional_magic = 'unknown'; is_dll_header = 'unknown'
        validation = 'not_run'; error_code = 'unknown'
    }
    $result = [ordered]@{
        file_kind = $Kind; user_supplied = $false; supplied_path = 'unknown'; absolute_path = 'unknown'
        status = 'not_provided'; size_bytes = 'unknown'; sha256 = 'unknown'; last_write_utc = 'unknown'
        file_version = 'unknown'; product_version = 'unknown'; pe = $emptyPE; error_codes = @()
        read_error_type = 'unknown'; read_error_reason = 'unknown'
        identity = 'unverified_user_supplied'; runtime = 'not_executed'
    }
    if ([string]::IsNullOrEmpty($Value)) { return $result }
    $result.user_supplied = $true
    $result.supplied_path = $Value
    $path = Get-AbsoluteFilePath $Value
    $result.absolute_path = $path
    $expected = '.exe'
    if ($Kind -eq 'pdb') { $expected = '.pdb' }
    if ([IO.Path]::GetExtension($path) -ine $expected) { throw ('INPUT_EXTENSION_MUST_BE_' + $expected.ToUpperInvariant()) }
    Assert-NoExistingReparse $path 'INPUT'
    if (-not (Test-Path -LiteralPath $path)) {
        $result.status = 'missing'; $result.error_codes = @('explicit_path_missing'); return $result
    }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw 'INPUT_IS_DIRECTORY' }
    try {
        $result.size_bytes = [long]$item.Length
        $result.last_write_utc = $item.LastWriteTimeUtc.ToString('o')
        $result.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Kind -eq 'pdb') {
            $result.pe.status = 'not_applicable_pdb'
            $result.status = 'read_ok_pdb_unverified'
        } else {
            $result.pe = Get-PEHeader $path
            $result.status = 'read_ok_pe_headers'
            if ($result.pe.status -ne 'recognized') {
                $result.status = 'invalid_pe'; $result.error_codes = @($result.pe.error_code)
            }
            $info = $item.VersionInfo
            if (-not [string]::IsNullOrWhiteSpace($info.FileVersion)) { $result.file_version = $info.FileVersion }
            if (-not [string]::IsNullOrWhiteSpace($info.ProductVersion)) { $result.product_version = $info.ProductVersion }
        }
        $after = Get-Item -LiteralPath $path -Force
        if (($after.Length -ne $item.Length) -or ($after.LastWriteTimeUtc -ne $item.LastWriteTimeUtc)) {
            $result.status = 'changed_during_read'; $result.error_codes = @('file_changed_during_read')
        }
    } catch {
        $result.status = 'read_error'; $result.error_codes = @('explicit_file_read_failed')
        $result.read_error_type = $_.Exception.GetType().FullName
        $result.read_error_reason = $_.Exception.Message
    }
    return $result
}

function Get-ManualLabels([string]$Version, [string]$Game, [string]$Region, [string]$Update, [string]$Patch, [string]$Baseline, [string]$Notes) {
    return [ordered]@{
        source = 'user_entered_not_verified'; version_label = $Version; game_label = $Game
        region = $Region; update_label = $Update; patch_label = $Patch
        same_platform_local_baseline = $Baseline.ToLowerInvariant(); baseline_notes = $Notes
    }
}

# Relative output paths resolve against THIS tool tree, never the caller's working directory.
$outputValue = $OutputPath
if (-not [IO.Path]::IsPathRooted($outputValue)) { $outputValue = Join-Path $PSScriptRoot $outputValue }
$output = Get-AbsoluteFilePath $outputValue
Test-OutputTarget $output
$manifest = [ordered]@{
    schema_version = 'crossplay.env-manifest/1'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    purpose = $Purpose.ToLowerInvariant()
    collector = [ordered]@{
        name = 'offline-explicit-file-env-manifest'; version = '1.0.0'
        powershell_version = $PSVersionTable.PSVersion.ToString(); platform = 'Windows'
        input_policy = 'explicit_exe_pdb_only'; game_files_read = $false
        executable_started_loaded_or_injected = $false; process_attached = $false
        network_used = $false; registry_written = $false; user_configuration_read = $false
        filesystem_scanned = $false
    }
    assessment = [ordered]@{
        g0_status = 'unverified'; m4_status = 'unverified'; emulator_identity = 'unverified'
        same_platform_baseline = 'manual_only_unverified'; crossplay = 'not_tested'
        is_emulator_validation = $false; tool_test_is_not_emulator_validation = $true
    }
    citra = [ordered]@{
        executable = (Get-ExplicitFile $CitraExePath 'exe')
        pdb = (Get-ExplicitFile $CitraPdbPath 'pdb')
        manual = (Get-ManualLabels $CitraVersionLabel $CitraGameLabel $CitraRegion $CitraUpdateLabel $CitraPatchLabel $CitraLocalBaseline $CitraBaselineNotes)
    }
    yuzu = [ordered]@{
        executable = (Get-ExplicitFile $YuzuExePath 'exe')
        pdb = (Get-ExplicitFile $YuzuPdbPath 'pdb')
        manual = (Get-ManualLabels $YuzuVersionLabel $YuzuGameLabel $YuzuRegion $YuzuUpdateLabel $YuzuPatchLabel $YuzuLocalBaseline $YuzuBaselineNotes)
    }
    limitations = @(
        'No emulator was executed, loaded, attached to, or injected.'
        'PE recognition is a bounded header check, not a loader-validity or emulator-identity proof.'
        'PDB identity and RSDS GUID/age matching are not checked; only explicitly supplied PDB bytes are hashed.'
        'Version resources and user labels are not trusted emulator fingerprints or game compatibility evidence.'
        'Unknown is explicit; manual baseline labels do not verify G0/M4 or crossplay.'
    )
}
# Never overwrite an input even with -Force.
foreach ($candidate in @($CitraExePath,$YuzuExePath,$CitraPdbPath,$YuzuPdbPath)) {
    if ($candidate -and $output.Equals((Get-AbsoluteFilePath $candidate),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'OUTPUT_EQUALS_INPUT'
    }
}
$json = $manifest | ConvertTo-Json -Depth 12
$encoding = New-Object Text.UTF8Encoding($false)
$bytes = $encoding.GetBytes($json + [Environment]::NewLine)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
# Recheck before opening, after parent directories have been created.
Test-OutputTarget $output
$mode = [IO.FileMode]::CreateNew
if ($Force) { $mode = [IO.FileMode]::Create }
$writer = $null
try {
    $writer = [IO.File]::Open($output,$mode,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $writer.Write($bytes,0,$bytes.Length)
    $writer.Flush()
} finally {
    if ($writer) { $writer.Dispose() }
}
Write-Output (Get-TreeRelativePath $output)
