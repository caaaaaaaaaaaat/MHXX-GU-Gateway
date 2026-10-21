# SPDX-License-Identifier: GPL-2.0-or-later
# Generates app.ico (multi-size PNG-compressed ICO) from logo.jpg.
# Run after replacing logo.jpg:  powershell -NoProfile -ExecutionPolicy Bypass -File .\gen-ico.ps1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Set-Location -LiteralPath $PSScriptRoot
$src = [System.Drawing.Image]::FromFile((Join-Path $PSScriptRoot 'logo.jpg'))
try {
    $entries = @()
    foreach ($size in @(16, 24, 32, 48, 64, 128, 256)) {
        $bitmap = New-Object System.Drawing.Bitmap($size, $size)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.Clear([System.Drawing.Color]::White)
        $ratio = [Math]::Min($size / $src.Width, $size / $src.Height)
        $width = [int][Math]::Round($src.Width * $ratio)
        $height = [int][Math]::Round($src.Height * $ratio)
        $graphics.DrawImage($src, [int](($size - $width) / 2), [int](($size - $height) / 2), $width, $height)
        $graphics.Dispose()
        $stream = New-Object System.IO.MemoryStream
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        $entries += ,@($stream.ToArray(), $size)
    }
} finally { $src.Dispose() }
$output = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter($output)
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$entries.Count)
$offset = 6 + 16 * $entries.Count
foreach ($entry in $entries) {
    $side = [byte]$(if ($entry[1] -ge 256) { 0 } else { $entry[1] })
    $writer.Write($side); $writer.Write($side)
    $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32)
    $writer.Write([uint32]$entry[0].Length)
    $writer.Write([uint32]$offset)
    $offset += $entry[0].Length
}
foreach ($entry in $entries) { $writer.Write($entry[0]) }
$writer.Flush()
[IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'app.ico'), $output.ToArray())
Write-Output ("app.ico written: {0} bytes, {1} sizes" -f $output.Length, $entries.Count)
