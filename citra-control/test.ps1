# SPDX-License-Identifier: GPL-3.0-or-later
# citra-control - test script.  Builds (unless -SkipBuild) and runs the offline
# test binary; the last line of the output is the machine-readable summary
#   RESULT cases=N checks=M failed=K
# and the process exit code is 0 only when failed=0.

[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $Root

if (-not $SkipBuild) {
    & "$PSScriptRoot/build.ps1"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& "crossplay/citra-control/.build-direct/test.exe"
exit $LASTEXITCODE
