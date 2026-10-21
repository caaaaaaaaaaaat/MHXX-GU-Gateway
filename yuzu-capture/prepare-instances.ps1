# SPDX-License-Identifier: GPL-3.0-or-later
# Copies only the pinned emulator program/resources into new private portable
# instances. Never copies or reads keys, NAND, saves, games or original config.
[CmdletBinding()]
param(
    [string]$Source=(Join-Path $env:LOCALAPPDATA 'yuzu/yuzu-windows-msvc'),
    [string]$Destination=(Join-Path ([IO.Path]::GetTempPath()) ('crossplay-runtime-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')))
)
$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
$sourceRoot=[IO.Path]::GetFullPath($Source).TrimEnd('\')
$targetRoot=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
function Within([string]$Child,[string]$Parent){
    return $Child.Equals($Parent,[StringComparison]::OrdinalIgnoreCase) -or $Child.StartsWith($Parent+'\',[StringComparison]::OrdinalIgnoreCase)
}
$localPrivate=Join-Path $workspace '.private-runtime'
$approvedLocal=(Within $targetRoot $localPrivate) -and $targetRoot -ne $localPrivate
if(((Within $targetRoot $workspace) -and -not $approvedLocal) -or (Within $workspace $targetRoot)){throw 'Private instances must be outside workspace or inside its dedicated .private-runtime directory'}
if((Within $targetRoot $sourceRoot) -or (Within $sourceRoot $targetRoot)){throw 'Source and destination must be disjoint'}
if(Test-Path -LiteralPath $targetRoot){throw 'Destination must not exist; no existing instance is overwritten'}
$ancestor=$targetRoot
while($ancestor){
    if(Test-Path -LiteralPath $ancestor){if((Get-Item -Force -LiteralPath $ancestor).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Destination ancestry contains a link'}}
    $ancestor=[IO.Path]::GetDirectoryName($ancestor)
}
$main=Join-Path $sourceRoot 'yuzu.exe'
$expected='60ba9d59347e9bab68fd670ecd990c3b03b5bd14e221cf38cb28a802a8b7679a'
if((Get-FileHash -LiteralPath $main).Hash.ToLowerInvariant() -ne $expected){throw 'Source is not the pinned 2022 main build'}
$programFiles=New-Object System.Collections.Generic.List[object]
foreach($entry in Get-ChildItem -Force -LiteralPath $sourceRoot){
    if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Source has a link; refusing to follow it'}
    if($entry.PSIsContainer){
        if($entry.Name -notin @('plugins','mediaservice')){continue}
        foreach($child in Get-ChildItem -Force -LiteralPath $entry.FullName -Recurse){
            if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Program resource tree has a link'}
            if(-not $child.PSIsContainer){$programFiles.Add($child)}
        }
    }elseif($entry.Extension -in @('.dll','.exe','.dat','.pak','.conf')){$programFiles.Add($entry)}
}
if($programFiles.Count -lt 2){throw 'Incomplete emulator distribution'}
$requiredBytes=2*($programFiles|Measure-Object -Property Length -Sum).Sum+268435456
$drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($targetRoot))
if($drive.AvailableFreeSpace -lt $requiredBytes){throw 'Insufficient space for two program copies and private runtime overhead'}
New-Item -ItemType Directory -Path $targetRoot | Out-Null
$records=New-Object System.Collections.Generic.List[object]
$instances=@()
foreach($slot in @('a','b')){
    $instance=Join-Path $targetRoot "yuzu-$slot"
    New-Item -ItemType Directory -Path $instance | Out-Null
    foreach($file in $programFiles){
        $relative=$file.FullName.Substring($sourceRoot.Length).TrimStart('\')
        $copy=Join-Path $instance $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($copy))
        $before=(Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $file.FullName -Destination $copy
        $after=(Get-FileHash -LiteralPath $copy).Hash.ToLowerInvariant()
        if($before -ne $after){throw "Program copy hash mismatch: $relative"}
        $records.Add([ordered]@{slot=$slot;relative_path=$relative;bytes=$file.Length;sha256=$after})
    }
    foreach($folder in @('config','keys','nand','sdmc','load','dump','tas','log')){
        [void][IO.Directory]::CreateDirectory((Join-Path $instance "user/$folder"))
    }
    $nickname=if($slot -eq 'a'){'g2b-alpha'}else{'g2b-beta'}
    $ini=@"
[WebService]
enable_telemetry=false
enable_telemetry\default=false
[UI]
calloutFlags=1
calloutFlags\default=false
[Multiplayer]
nickname=$nickname
nickname\default=false
ip=127.0.0.1
ip\default=false
port=24940
port\default=false
"@
    [IO.File]::WriteAllText((Join-Path $instance 'user/config/qt-config.ini'),$ini,(New-Object Text.UTF8Encoding($false)))
    $instances+=$instance
}
if((Get-FileHash -LiteralPath $main).Hash.ToLowerInvariant() -ne $expected){throw 'Source executable changed during preparation'}
$report=[ordered]@{schema='crossplay.yuzu-preparation/1';created_utc=[DateTime]::UtcNow.ToString('o');
    program_copies_verified=$true;runtime_root=$targetRoot;instances=$instances;
    copied_private_data=$false;game_verified=$false;game_ready=$false;
    missing=@('private_keys','installed_update_v262144','player_profiles','game_saves','actual_game_baseline');program_files=$records.ToArray()}
[IO.File]::WriteAllText((Join-Path $targetRoot 'preparation.json'),(($report|ConvertTo-Json -Depth 6)+"`n"),(New-Object Text.UTF8Encoding($false)))
Write-Host "PREPARED_RUNTIME $targetRoot"
Write-Host 'Program copies verified. Private keys/profiles/saves/update are still required; no game was started.'
