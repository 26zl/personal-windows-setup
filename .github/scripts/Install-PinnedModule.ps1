<#
  Downloads one PowerShell Gallery package, checks it against a pinned SHA-256 and returns the
  path of its module manifest for Import-Module. Nothing is installed into a module path.

  Import-Module (./.github/scripts/Install-PinnedModule.ps1 -Name Pester -Version 5.7.1 -Sha256 <hash>)
#>
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$Sha256,
    [string]$WorkRoot = [IO.Path]::GetTempPath()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$work = Join-Path $WorkRoot ('module-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
# A .nupkg is a zip file; Expand-Archive in Windows PowerShell 5.1 accepts only the .zip extension.
$package = Join-Path $work "$Name.$Version.zip"
Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/$Name/$Version" -OutFile $package -UseBasicParsing
$actual = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash
if ($actual -ne $Sha256) { throw "$Name $Version package SHA-256 is $actual, the pin is $Sha256" }

$moduleDir = Join-Path $work $Name
Expand-Archive -LiteralPath $package -DestinationPath $moduleDir
Join-Path $moduleDir "$Name.psd1"
