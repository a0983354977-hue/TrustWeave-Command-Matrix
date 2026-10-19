# Generates the TrustWeave Command Matrix icon set without external tooling.
# Draws the hexagon + check mark motif in neon cyan on obsidian black.
Add-Type -AssemblyName System.Drawing

$outDir = $PSScriptRoot
$cyan = [System.Drawing.Color]::FromArgb(255, 57, 228, 225)
$bg = [System.Drawing.Color]::FromArgb(255, 7, 10, 13)

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear($bg)

    $pad = [double]$size * 0.16
    $cx = [double]$size / 2.0
    $cy = [double]$size / 2.0
    $r = ([double]$size / 2.0) - $pad

    # Hexagon vertices (flat-top rotated to point-up).
    $points = New-Object 'System.Collections.Generic.List[System.Drawing.PointF]'
    for ($i = 0; $i -lt 6; $i++) {
        $angle = ([Math]::PI / 180.0) * (60.0 * $i - 90.0)
        $points.Add((New-Object System.Drawing.PointF(
            ([single]($cx + $r * [Math]::Cos($angle))),
            ([single]($cy + $r * [Math]::Sin($angle))))))
    }

    $stroke = [single]([Math]::Max(1.0, [double]$size * 0.075))
    $pen = New-Object System.Drawing.Pen($cyan, $stroke)
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPolygon($pen, $points.ToArray())

    # Check mark inside the hexagon.
    $checkPen = New-Object System.Drawing.Pen($cyan, $stroke)
    $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $p1 = New-Object System.Drawing.PointF(([single]($cx - $r * 0.42)), ([single]($cy + $r * 0.02)))
    $p2 = New-Object System.Drawing.PointF(([single]($cx - $r * 0.10)), ([single]($cy + $r * 0.36)))
    $p3 = New-Object System.Drawing.PointF(([single]($cx + $r * 0.47)), ([single]($cy - $r * 0.36)))
    $g.DrawLines($checkPen, @($p1, $p2, $p3))

    $g.Dispose()
    return $bmp
}

function Save-Png([System.Drawing.Bitmap]$bmp, [string]$name) {
    $path = Join-Path $outDir $name
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    return $path
}

# Standard Tauri icon set.
$pngTargets = @{
    '32x32.png'        = 32
    '128x128.png'      = 128
    '128x128@2x.png'   = 256
    'icon.png'         = 512
    'Square30x30Logo.png' = 30
    'Square44x44Logo.png' = 44
    'Square71x71Logo.png' = 71
    'Square89x89Logo.png' = 89
    'Square107x107Logo.png' = 107
    'Square142x142Logo.png' = 142
    'Square150x150Logo.png' = 150
    'Square284x284Logo.png' = 284
    'Square310x310Logo.png' = 310
    'StoreLogo.png'    = 50
}

$pngPaths = @{}
foreach ($name in $pngTargets.Keys) {
    $bmp = New-IconBitmap $pngTargets[$name]
    $pngPaths[$name] = Save-Png $bmp $name
    $bmp.Dispose()
}

# Build a multi-resolution .ico that embeds PNG payloads (Vista+ format).
$icoSizes = @(16, 24, 32, 48, 64, 128, 256)
$icoEntries = @()
foreach ($s in $icoSizes) {
    $bmp = New-IconBitmap $s
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $icoEntries += ,@{ Size = $s; Data = $ms.ToArray() }
}

$icoPath = Join-Path $outDir 'icon.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)

# ICONDIR
$bw.Write([UInt16]0)                        # reserved
$bw.Write([UInt16]1)                        # type: icon
$bw.Write([UInt16]$icoEntries.Count)        # image count

$offset = 6 + (16 * $icoEntries.Count)
foreach ($entry in $icoEntries) {
    $dim = if ($entry.Size -ge 256) { 0 } else { $entry.Size }
    $bw.Write([Byte]$dim)                   # width
    $bw.Write([Byte]$dim)                   # height
    $bw.Write([Byte]0)                      # color palette
    $bw.Write([Byte]0)                      # reserved
    $bw.Write([UInt16]1)                    # color planes
    $bw.Write([UInt16]32)                   # bits per pixel
    $bw.Write([UInt32]$entry.Data.Length)   # payload size
    $bw.Write([UInt32]$offset)              # payload offset
    $offset += $entry.Data.Length
}
foreach ($entry in $icoEntries) {
    $bw.Write($entry.Data)
}
$bw.Flush()
$bw.Close()

Write-Output "icons written: $($pngTargets.Count) png + icon.ico ($($icoEntries.Count) sizes)"
