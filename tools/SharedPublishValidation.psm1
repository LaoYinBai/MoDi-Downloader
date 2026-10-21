function Assert-MoDiSharedPublishDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PublishDirectory)
    if (-not (Test-Path -LiteralPath $PublishDirectory -PathType Container)) {
        throw [InvalidOperationException]::new('The Shared publish directory does not exist.')
    }
    $entries = @(Get-ChildItem -LiteralPath $PublishDirectory -Force -Recurse)
    if ($entries.Count -ne 1 -or $entries[0].PSIsContainer -or
        $entries[0].Name -cne 'MoDiDownloader.exe' -or
        ($entries[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw [InvalidOperationException]::new('The Shared publish directory must contain only one regular MoDiDownloader.exe file.')
    }
    return $entries[0].FullName
}
Export-ModuleMember -Function Assert-MoDiSharedPublishDirectory
