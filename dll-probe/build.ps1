# SPDX-License-Identifier: GPL-2.0-or-later
# Original direct build/evidence driver; ASCII relative objects and -pipe, no global changes.
[CmdletBinding()]
param(
    [string]$Compiler = 'G:\msys64\mingw64\bin\g++.exe',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = $PSScriptRoot
if ($Compiler -notmatch '^[A-Za-z]:[\\/]') { throw 'Compiler must be an absolute local-drive path' }
$compilerDir = Split-Path -Parent $Compiler
$gcc = Join-Path $compilerDir 'gcc.exe'
$objdump = Join-Path $compilerDir 'objdump.exe'
foreach ($tool in @($Compiler, $gcc, $objdump)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Missing tool: $tool" }
}
$out = Join-Path $root 'build-mingw'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'build.log'
"UTC=$([DateTime]::UtcNow.ToString('o'))" | Set-Content -LiteralPath $log -Encoding utf8
"OS=$([Environment]::OSVersion.VersionString)" | Add-Content -LiteralPath $log -Encoding utf8
function Write-Log {
    param([object]$Line)
    $text = $Line.ToString()
    $text | Add-Content -LiteralPath $log -Encoding utf8
    Write-Host $text
}
function Invoke-Logged {
    param([string]$Executable, [string[]]$Arguments)
    Write-Log ('"' + $Executable + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '))
    $ErrorActionPreference = 'Continue' # Native stderr must be logged, not abort PS 5.1 early.
    & $Executable @Arguments 2>&1 | ForEach-Object { Write-Log $_ }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Write-Log "exit=$code"
    if ($code -ne 0) { throw "Native step failed with exit=$code : $Executable" }
}
Push-Location -LiteralPath $root
try {
    # A relative TMP alone fails: GCC canonicalizes it to the non-ASCII workspace.
    # -pipe plus explicit -c/-o relative objects avoids assembler temp-file names.
    Write-Log 'WORKAROUND=-pipe; explicit relative objects; no TEMP/TMP/PATH changes'
    Invoke-Logged $Compiler @('--version')
    Invoke-Logged $gcc @('-dumpmachine')
    $dll = Join-Path $out 'dll_probe.dll'
    $hostExe = Join-Path $out 'loader_host.exe'
    $common = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-D_WIN32_WINNT=0x0601', '-I', 'include')
    Invoke-Logged $Compiler ($common + @('-pipe', '-DDP_BUILD_DLL', '-c', 'src/dll_probe.cpp', '-o', 'build-mingw/dll_probe.o'))
    Invoke-Logged $Compiler @('-shared', 'build-mingw/dll_probe.o', '-static', '-static-libgcc', '-static-libstdc++',
        '-Wl,--exclude-all-symbols', '-o', 'build-mingw/dll_probe.dll')
    Invoke-Logged $Compiler ($common + @('-pipe', '-c', 'tests/loader_host.cpp', '-o', 'build-mingw/loader_host.o'))
    Invoke-Logged $Compiler @('-municode', 'build-mingw/loader_host.o', '-static', '-static-libgcc', '-static-libstdc++',
        '-o', 'build-mingw/loader_host.exe')
    Invoke-Logged $gcc @('-pipe', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', 'include', '-c',
        'tests/header_c_smoke.c', '-o', 'build-mingw/header_c_smoke.o')
    foreach ($name in @('dll_probe.dll', 'loader_host.exe')) {
        $binary = "build-mingw/$name"
        $format = & $objdump -f $binary 2>&1
        if ($LASTEXITCODE -ne 0) { throw "objdump -f failed for $binary" }
        $format | Set-Content -LiteralPath (Join-Path $out "$name.format.txt") -Encoding utf8
        if (($format -join [Environment]::NewLine) -notmatch 'file format pei-x86-64') { throw "Not PE x64: $binary" }
        $details = & $objdump -p $binary 2>&1
        if ($LASTEXITCODE -ne 0) { throw "objdump -p failed for $binary" }
        $details | Set-Content -LiteralPath (Join-Path $out "$name.pe.txt") -Encoding utf8
        $imports = @([regex]::Matches(($details -join [Environment]::NewLine), 'DLL Name:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
        foreach ($dependency in $imports) {
            if ($dependency -notin @('KERNEL32.dll', 'msvcrt.dll')) { throw "Unexpected deployment dependency: $dependency" }
        }
        Write-Log "PE-x86-64 $name imports=$($imports -join ',')"
        if ($name -eq 'dll_probe.dll') {
            $exports = @([regex]::Matches(($details -join [Environment]::NewLine), '(?m)^\s*\[\s*\d+\]\s+(?:\+base\[\s*\d+\]\s+[0-9a-fA-F]+\s+)?(dp_\w+)\s*$') | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
            $expected = @('dp_get_abi_version', 'dp_get_limits', 'dp_snapshot_read', 'dp_start', 'dp_stop', 'dp_submit')
            if (($exports -join ',') -ne ($expected -join ',')) { throw "Unexpected exports: $($exports -join ',')" }
            if (($details -join [Environment]::NewLine) -notmatch 'Export Address Table\s+00000006') { throw 'Expected exactly six export addresses' }
            Write-Log "EXPORTS=$($exports -join ',')"
        }
    }
    if (-not $SkipTests) {
        $testLog = Join-Path $out 'tests.log'
        'COMMAND: loader_host.exe <absolute dll_probe.dll>' | Set-Content -LiteralPath $testLog -Encoding utf8
        & $hostExe $dll 2>&1 | ForEach-Object {
            $_.ToString() | Add-Content -LiteralPath $testLog -Encoding utf8
            Write-Host $_
        }
        $code = $LASTEXITCODE
        "exit=$code" | Add-Content -LiteralPath $testLog -Encoding utf8
        if ($code -ne 0) { throw "Host tests failed: exit=$code" }
    }
    Get-FileHash -Algorithm SHA256 -LiteralPath $dll, $hostExe |
        Format-List | Out-String | Set-Content -LiteralPath (Join-Path $out 'sha256.txt') -Encoding utf8
    Write-Log 'BUILD SUCCESS (CMake was not invoked)'
} finally {
    Pop-Location
}
