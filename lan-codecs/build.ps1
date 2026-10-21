# SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Windows PowerShell 5.1 and PowerShell 7; no installation or environment mutation.
param([string]$ToolchainRoot = 'G:/msys64/mingw64')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Push-Location $PSScriptRoot
try {
    $Compiler = Join-Path $ToolchainRoot 'bin/g++.exe'
    $ZstdInclude = Join-Path $ToolchainRoot 'include'
    $ZstdLibrary = Join-Path $ToolchainRoot 'lib/libzstd.a'
    foreach ($Dependency in @($Compiler, (Join-Path $ZstdInclude 'zstd.h'), $ZstdLibrary)) {
        if (-not (Test-Path -LiteralPath $Dependency)) { throw "Missing dependency: $Dependency" }
    }
    New-Item -ItemType Directory -Force -Path 'build' | Out-Null
    Start-Transcript -Path 'build/build.log' -Force | Out-Null
    try {
        Write-Output 'Build: -pipe with ASCII relative source/object paths; separate compile and link.'
        Write-Output 'No TEMP/TMP/PATH changes; static local Zstd; no network operations.'
        & $Compiler --version
        if ($LASTEXITCODE -ne 0) { throw 'Compiler version query failed' }
        $Flags = @('-std=c++20','-O2','-g','-Wall','-Wextra','-Wconversion','-Wsign-conversion','-Werror','-pipe','-Iinclude', ('-I' + $ZstdInclude))
        foreach ($Unit in @('src/lan_codecs.cpp','src/zstd_codec.cpp','src/main.cpp','tests/codec_tests.cpp')) {
            $Name = [System.IO.Path]::GetFileNameWithoutExtension($Unit)
            $Object = 'build/' + $Name + '.o'
            Write-Output ('COMPILE ' + $Unit + ' -> ' + $Object)
            & $Compiler @Flags -c $Unit -o $Object
            if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $Unit) }
        }
        $LinkFlags = @('-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp')
        Write-Output 'LINK build/lan-codecs.exe'
        & $Compiler @LinkFlags 'build/lan_codecs.o' 'build/zstd_codec.o' 'build/main.o' $ZstdLibrary '-lwinpthread' -o 'build/lan-codecs.exe'
        if ($LASTEXITCODE -ne 0) { throw 'CLI link failed' }
        Write-Output 'LINK build/codec-tests.exe'
        & $Compiler @LinkFlags 'build/lan_codecs.o' 'build/zstd_codec.o' 'build/codec_tests.o' $ZstdLibrary '-lwinpthread' -o 'build/codec-tests.exe'
        if ($LASTEXITCODE -ne 0) { throw 'Test link failed' }
        Write-Output 'BUILD PASS'
    } finally { Stop-Transcript | Out-Null }
} finally { Pop-Location }
