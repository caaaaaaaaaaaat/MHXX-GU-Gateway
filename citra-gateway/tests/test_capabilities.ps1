# SPDX-License-Identifier: GPL-2.0-or-later
# Controlled probes of a source-matched build. No successful gateway open.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Exe,
      [Parameter(Mandatory=$true)][string]$ExpectedExeSha256,
      [Parameter(Mandatory=$true)][string]$Evidence)
$ErrorActionPreference='Stop'
$exePath=(Resolve-Path -LiteralPath $Exe).Path
if($ExpectedExeSha256 -notmatch '\A[0-9a-fA-F]{64}\z' -or (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash -ine $ExpectedExeSha256){throw 'Executable fingerprint mismatch'}
if(Test-Path -LiteralPath $Evidence){throw 'Evidence path exists; preserve previous results and choose a fresh path'}
New-Item -ItemType Directory -Path $Evidence | Out-Null
$evidencePath=(Resolve-Path -LiteralPath $Evidence).Path
$sentinel=Join-Path $evidencePath 'existing-synthetic.trace'
$newTrace=Join-Path $evidencePath 'must-not-create.trace'
$dump=Join-Path $evidencePath 'must-not-create-dump'
'SYNTHETIC sentinel: not a game trace' | Set-Content -LiteralPath $sentinel -Encoding ASCII
$sentinelHash=(Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
$cases=0
function Probe([string]$Name,[string[]]$Argv,[int]$Expected,[string]$Diagnostic){
    $info=New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName=$exePath
    foreach($arg in $Argv){if($arg.Contains('"') -or $arg.Contains([char]10) -or $arg.Contains([char]13)){throw 'Test argument quoting outside supported fixture subset'}}
    $info.Arguments=(($Argv | ForEach-Object {'"'+$_+'"'}) -join ' ')
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $p=New-Object System.Diagnostics.Process;$p.StartInfo=$info
    [void]$p.Start();$outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
    if(-not $p.WaitForExit(5000)){$p.Kill();$p.WaitForExit();throw ('Probe timed out: '+$Name)}
    $stdout=$outTask.Result;$stderr=$errTask.Result;$code=$p.ExitCode;$p.Dispose()
    $stdout | Out-File -LiteralPath (Join-Path $evidencePath ($Name+'.stdout.txt')) -Encoding utf8
    $stderr | Out-File -LiteralPath (Join-Path $evidencePath ($Name+'.stderr.txt')) -Encoding utf8
    if($code -ne $Expected -or ($Diagnostic -and $stderr -notmatch [regex]::Escape($Diagnostic))){throw ('Unexpected result: '+$Name+' exit='+$code+' stderr='+$stderr)}
    if($Expected -ne 0 -and -not [string]::IsNullOrWhiteSpace($stdout)){throw ('Unexpected stdout/capability JSON on rejected request: '+$Name)}
    if((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -ne $sentinelHash -or (Test-Path -LiteralPath $newTrace) -or (Test-Path -LiteralPath $dump)){throw ('Unexpected trace/dump side effect: '+$Name)}
    $script:cases++
    Write-Host ('PASS '+$Name+' exit='+$code)
    return $stdout
}
$cap=(Probe 'capabilities' @('--capabilities') 0 '') | ConvertFrom-Json
$fields=@('schema','defaultApplicationMode','proxyWireProfile','mhxxMhguApplicationConversion','installedBinaryProfileVerified','applicationConverted','productionReady')
if((($cap.PSObject.Properties.Name | Sort-Object) -join ',') -cne (($fields | Sort-Object) -join ',')){throw 'Unexpected capability field set'}
if($cap.schema -ne 1 -or $cap.defaultApplicationMode -cne 'legacy-transport' -or $cap.proxyWireProfile -cne 'yuzu-mirror-01052024'){throw 'Wrong capability schema/profile'}
foreach($name in @('mhxxMhguApplicationConversion','installedBinaryProfileVerified','applicationConverted','productionReady')){if($cap.$name -isnot [bool] -or $cap.$name){throw ('Dishonest capability: '+$name)}}
foreach($argsPair in @(@('--capabilities','--help'),@('--help','--capabilities'),@('--capabilities','--self-check'),@('--self-check','--capabilities'),@('--capabilities','--capabilities'))){
    [void](Probe ('exclusive-'+$cases) $argsPair 2 'must be used alone')
}
[void](Probe 'reserved-password-value' @('--password','--capabilities') 2 'must be used alone')
[void](Probe 'reserved-manifest-value' @('--trace-manifest','--capabilities') 2 'must be used alone')
[void](Probe 'exclusive-trace' @('--capabilities','--trace-out',$sentinel) 2 'must be used alone')
[void](Probe 'exclusive-dump' @('--dump',$dump,'--capabilities') 2 'must be used alone')
[void](Probe 'mh-mode' @('--application-mode','mhxx-mhgu','--listen','not-an-ip','--trace-out',$sentinel) 2 'gateway_application_mode_unavailable')
[void](Probe 'old-profile' @('--proxy-profile','yuzu-2022-7edc31be2','--listen','not-an-ip','--trace-out',$newTrace) 2 'gateway_proxy_profile_unavailable')
[void](Probe 'unknown-mode' @('--application-mode','auto','--listen','not-an-ip') 2 'unknown application mode')
[void](Probe 'unknown-profile' @('--proxy-profile','ea','--listen','not-an-ip') 2 'unknown proxy profile')
[void](Probe 'duplicate-mode' @('--application-mode','mhxx-mhgu','--application-mode','legacy-transport','--listen','not-an-ip') 2 '')
[void](Probe 'duplicate-profile' @('--proxy-profile','yuzu-2022-7edc31be2','--proxy-profile','yuzu-mirror-01052024','--listen','not-an-ip') 2 '')
[void](Probe 'missing-mode' @('--application-mode') 2 '')
[void](Probe 'missing-profile' @('--proxy-profile') 2 '')
[void](Probe 'explicit-legacy-safety-fence' @('--application-mode','legacy-transport','--proxy-profile','yuzu-mirror-01052024','--listen','not-an-ip','--trace-out',$sentinel) 3 'listen address is not a numeric IPv4 literal')
[void](Probe 'default-legacy-safety-fence' @('--listen','not-an-ip','--trace-out',$sentinel) 3 'listen address is not a numeric IPv4 literal')
Write-Output ('RESULT cases='+$cases+' failed=0 traceSentinelUnchanged=true newTraceAbsent=true dumpAbsent=true')
