param([string]$InnoCompiler = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SharedPublishValidation.psm1') -Force
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$publish = Join-Path $root 'artifacts\publish\win-x64'
& dotnet publish (Join-Path $root 'src\SshSpeedDownloader.Desktop\SshSpeedDownloader.Desktop.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:MoDiPrivateBuild=false -o $publish --nologo
if ($LASTEXITCODE -ne 0) { throw "Shared publish failed ($LASTEXITCODE)." }
$assembly = [Reflection.Assembly]::LoadFrom((Join-Path $root 'src\SshSpeedDownloader.Desktop\bin\Release\net10.0-windows\win-x64\MoDiDownloader.dll'))
$audience = $assembly.GetCustomAttributesData() | Where-Object {
    $_.AttributeType.FullName -eq 'System.Reflection.AssemblyMetadataAttribute' -and
    $_.ConstructorArguments[0].Value -eq 'MoDiBuildAudience'
} | Select-Object -First 1
if (-not $audience -or $audience.ConstructorArguments[1].Value -ne 'Shared') { throw 'Assembly is not marked Shared.' }
$resources = $assembly.GetManifestResourceNames()
if ($resources | Where-Object { $_ -match 'PrivateIdentity|PrivateBuild' }) { throw 'Private identity resource detected.' }
if ('MoDiDownloader.CompletionSound.wav' -notin $resources) { throw 'Packaged completion sound missing.' }
Assert-MoDiSharedPublishDirectory $publish | Out-Null
if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) { throw 'Inno Setup was not found.' }
& $InnoCompiler '/DSharedAudienceVerified=1' "/DPublishDir=$publish" (Join-Path $root 'installer\MoDiDownloader.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($LASTEXITCODE)." }
'SHARED_AUDIENCE=PASS PRIVATE_RESOURCES_ABSENT=PASS SINGLE_FILE=PASS COMPLETION_SOUND=PASS'
