param([string]$OutputDirectory = "$PSScriptRoot\..\src\SshSpeedDownloader.Desktop\Assets")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory)) | Out-Null
$images = [Collections.Generic.List[byte[]]]::new()
foreach ($size in @(32, 48, 256)) {
    $bitmap = [Drawing.Bitmap]::new($size, $size)
    $g = [Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.ScaleTransform($size / 256.0, $size / 256.0)
    $paper = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#F4F1E7'))
    $green = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#47937F'), 16)
    $orange = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#E8863C'), 16)
    $water = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#86BFD8'), 9)
    foreach ($pen in @($green, $orange, $water)) {
        $pen.StartCap = [Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [Drawing.Drawing2D.LineCap]::Round
        $pen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
    }
    $outline = [Drawing.Drawing2D.GraphicsPath]::new()
    $outline.AddArc(8,8,64,64,180,90)
    $outline.AddArc(184,8,64,64,270,90)
    $outline.AddArc(184,184,64,64,0,90)
    $outline.AddArc(8,184,64,64,90,90)
    $outline.CloseFigure()
    $g.FillPath($paper, $outline)
    $g.DrawArc($green, 43, 111, 170, 130, 184, 172)
    $g.DrawLine($green, 43, 177, 43, 194)
    $g.DrawLine($green, 213, 177, 213, 194)
    $g.DrawLine($orange, 128, 53, 128, 137)
    $g.DrawLines($orange, [Drawing.PointF[]]@([Drawing.PointF]::new(103,114), [Drawing.PointF]::new(128,140), [Drawing.PointF]::new(153,114)))
    $g.DrawLine($water, 80, 207, 176, 207)
    $stream = [IO.MemoryStream]::new()
    $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
    $images.Add($stream.ToArray())
    if ($size -eq 256) { [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'modi-downloader.png'), $stream.ToArray()) }
    foreach ($object in @($stream, $outline, $paper, $green, $orange, $water, $g, $bitmap)) { $object.Dispose() }
}
$file = [IO.File]::Create((Join-Path $OutputDirectory 'modi-downloader.ico'))
$writer = [IO.BinaryWriter]::new($file)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]3)
    $offset = 6 + 16 * 3
    for ($i = 0; $i -lt 3; $i++) {
        $dimension = @(32,48,0)[$i]
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$images[$i].Length); $writer.Write([uint32]$offset)
        $offset += $images[$i].Length
    }
    foreach ($bytes in $images) { $writer.Write($bytes) }
} finally { $writer.Dispose(); $file.Dispose() }
