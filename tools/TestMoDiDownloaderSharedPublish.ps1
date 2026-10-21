$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SharedPublishValidation.psm1') -Force
$root = Join-Path $env:TEMP ('MoDiDownloader-PublishValidation-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    [IO.File]::WriteAllBytes((Join-Path $root 'MoDiDownloader.exe'), [byte[]](0x4D,0x5A))
    Assert-MoDiSharedPublishDirectory $root | Out-Null
    $nested = Join-Path $root 'identity'
    [IO.Directory]::CreateDirectory($nested) | Out-Null
    [IO.File]::WriteAllText((Join-Path $nested 'PrivateIdentity.key'), 'test-only placeholder')
    $rejected = $false
    try { Assert-MoDiSharedPublishDirectory $root | Out-Null }
    catch [InvalidOperationException] { $rejected = $true }
    if (-not $rejected) { throw 'A nested identity payload was accepted.' }
    'SHARED_SINGLE_FILE=PASS NESTED_PAYLOAD_REJECTED=PASS'
} finally {
    # Delete only the randomly named directory created by this invocation.
    if ([IO.Path]::GetFullPath($root).StartsWith([IO.Path]::GetFullPath($env:TEMP) + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
