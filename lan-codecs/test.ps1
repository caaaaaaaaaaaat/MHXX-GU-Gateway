# SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Run locally from Windows PowerShell 5.1 or PowerShell 7 after build.ps1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Push-Location $PSScriptRoot
try {
    $Cli = './build/lan-codecs.exe'
    if (-not (Test-Path './build/codec-tests.exe') -or -not (Test-Path $Cli)) { throw 'Run build.ps1 first' }
    Start-Transcript -Path 'build/verification.log' -Force | Out-Null
    try {
        Write-Output ('PowerShell version: ' + $PSVersionTable.PSVersion.ToString())
        Write-Output 'No sockets, emulators or game inputs. Synthetic fixtures only.'
        $SuiteLines = & './build/codec-tests.exe'
        $SuiteCode = $LASTEXITCODE
        $SuiteLines | Set-Content -Encoding UTF8 -LiteralPath 'build/tests.log'
        $SuiteLines | Write-Output
        if ($SuiteCode -ne 0) { throw 'Offline suite failed' }
        $script:CliCases = 0
        function Check-Cli([string[]]$Arguments, [int]$ExpectedCode, [string]$ExpectedText) {
            $PreviousPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $Lines = & $Cli @Arguments 2>&1
                $Code = $LASTEXITCODE
            } finally { $ErrorActionPreference = $PreviousPreference }
            $Text = ($Lines | ForEach-Object { $_.ToString() }) -join " "
            if ($Code -ne $ExpectedCode -or -not $Text.Contains($ExpectedText)) {
                throw ('CLI mismatch code=' + $Code + ' args=' + ($Arguments -join ' ') + ' output=' + $Text)
            }
            $script:CliCases++
            Write-Output ('CLI PASS ' + ($Arguments -join ' ') + ' exit=' + $Code + ' output=' + $Text)
        }
        Check-Cli @('--help') 0 'NOT a game translator'
        Check-Cli @('uds-decode','@fixtures/uds-golden.hex') 0 'opaque_application=deadbeef'
        Check-Cli @('uds-encode','7','65535','1','4660','deadbeef') 0 'aaaa03000000876d00120000000e00071234ffff0001deadbeef'
        Check-Cli @('node-decode','@fixtures/nodeinfo-golden.hex') 0 'node_ipv4_bytes=01020304 room_ipv4_bytes=04030201'
        Check-Cli @('network-decode','@fixtures/networkinfo-golden.hex') 0 'nodes=2 max_nodes=8'
        Check-Cli @('ldn-decode','0',' ') 0 'body_size=0'
        Check-Cli @('ldn-decode','1','@fixtures/networkinfo-golden.hex') 0 'body_size=1152'
        Check-Cli @('ldn-decode','2','@fixtures/nodeinfo-golden.hex') 0 'body_size=64'
        Check-Cli @('ldn-decode','3','@fixtures/networkinfo-golden.hex') 0 'body_size=1152'
        Check-Cli @('ldn-decode','4','@fixtures/nodeinfo-golden.hex') 0 'body_size=64'
        Check-Cli @('ldn-decode','5',' ') 0 'body_size=0'
        Check-Cli @('zstd-decode','@fixtures/zstd-raw-abc.hex') 0 '616263'
        Check-Cli @('zstd-encode','616263') 0 '28b52ffd2003190000616263'
        Check-Cli @('uds-decode','00') 2 'error=truncated'
        Check-Cli @('ldn-decode','255',' ') 2 'error=invalid_enum'
        Check-Cli @('network-decode',' ') 2 'error=truncated'
        Check-Cli @('zstd-decode','00000000') 2 'error=invalid_zstd'
        Check-Cli @('node-decode','gg') 1 'invalid hex character'
        Check-Cli @('uds-encode','-1','2','1','0',' ') 1 'numeric argument outside range'
        Write-Output ('CLI RESULT PASS cases=' + $script:CliCases)
        Write-Output 'VERIFICATION PASS'
    } finally { Stop-Transcript | Out-Null }
} finally { Pop-Location }
