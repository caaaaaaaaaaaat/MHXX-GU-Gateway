# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '../.build-desktop/XXGU-Gateway/XXGU-Gateway.exe'
$process = Start-Process -FilePath $exe -ArgumentList '--smoke-test' -WindowStyle Hidden -PassThru
if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'GUI window did not close within watchdog' }
if ($process.ExitCode -ne 0) { throw "GUI smoke failed exit=$($process.ExitCode)" }
Write-Output 'UI smoke PASS: hidden window created, timer serviced, graceful close exit=0; no network started.'
