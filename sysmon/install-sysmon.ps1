<#
  Sysmon installer - system activity logging to the Windows event log.
  Run standalone in an ELEVATED PowerShell (also invoked by setup.ps1):
    irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex
  Pinned to a tag or commit (the config is then fetched from the same ref):
    & ([scriptblock]::Create((irm https://github.com/26zl/personal-windows-setup/raw/<ref>/sysmon/install-sysmon.ps1))) -RepoRef <ref>
  Safe to re-run: an existing install only gets its configuration reapplied.
  On a machine without Sysmon, preference order per Microsoft docs (built-in and
  standalone Sysmon must never coexist):
    1. Built-in Sysmon (Windows 11 24H2+ / Server 2025) - System32\sysmon.exe,
       enabling the "Sysmon" optional feature through DISM when needed.
    2. Standalone Sysinternals Sysmon from download.sysinternals.com, unpacked in an
       admin-only folder and Authenticode-verified before it runs as admin.
       Sysinternals lists Windows 11 and Server 2019 or later as supported.
  Config: sysmonconfig-export.xml, pinned by SHA-256. A copy next to this script
  wins (cloned repo); otherwise it is fetched from this repo at $RepoRef. .gitattributes
  keeps the XML LF-normalized, so the same hash matches a download from raw and a clone.
  If you edit the XML, refresh $configSha256 with Get-FileHash, commit both together,
  and reload with: sysmon -c <config.xml>

  The config is a fork of SwiftOnSecurity sysmon-config v74 (2021-07-08, CC BY 4.0);
  the README's supply-chain section lists every change from upstream. Limitations:
    - Requires Sysmon 14 or later: schemaversion 4.81 (needed for FileDeleteDetected)
      makes an older Sysmon refuse the file instead of silently dropping that group.
    - Include rules are drive-relative, so detection works with Windows on any drive.
      The 153 upstream exclude rules still name C:\ and only cost noise elsewhere.
    - Event 26 excludes __PSScriptPolicyTest_*.ps1, which Windows writes and deletes
      on every execution-policy check.
    - The ImageLoad (event 7) exclusions cover the author's software. A burst of
      event 7 after deploying means something you run lives in a user-writable
      directory and belongs in the exclude list.
#>
param(
    # Branch, tag or commit of this repo to fetch the config from when no local copy exists.
    [ValidatePattern('^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')]
    [string]$RepoRef = 'main'
)

if ($env:NO_COLOR) {
    # https://no-color.org: the same output without colours.
    function Write-Host {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Forwards to the real Write-Host without colours when NO_COLOR is set.')]
        param(
            [Parameter(Position = 0, ValueFromPipeline, ValueFromRemainingArguments)][object]$Object,
            [switch]$NoNewline, [object]$Separator,
            [System.ConsoleColor]$ForegroundColor, [System.ConsoleColor]$BackgroundColor
        )
        process {
            $null = $PSBoundParameters.Remove('ForegroundColor')
            $null = $PSBoundParameters.Remove('BackgroundColor')
            Microsoft.PowerShell.Utility\Write-Host @PSBoundParameters
        }
    }
}

try   { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# Return instead of exiting because the script is commonly invoked with iex.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this in an ELEVATED PowerShell (right-click > Run as administrator)." -ForegroundColor Red
    return
}
# Restored at the end: with iex this is the caller's own session.
$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

function New-StagingDirectory {
    # Admin-only folder under %SystemRoot%\Temp, so a non-elevated process cannot swap a
    # verified file before it runs.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $path = Join-Path $env:SystemRoot ('Temp\windows-setup-' + [guid]::NewGuid().ToString('N'))
    if (-not $PSCmdlet.ShouldProcess($path, 'create admin-only staging folder')) { return $null }
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    foreach ($sid in $admins, $system) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    if ($PSVersionTable.PSEdition -eq 'Core') { $null = [System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $path) }
    else { $null = [System.IO.Directory]::CreateDirectory($path, $acl) }
    $path
}

$configSha256 = 'AF0648C0A496D874360A1DE584DEE224211C56F9152DDDC93E82479A4545A67B'
$configUrl    = "https://github.com/26zl/personal-windows-setup/raw/$RepoRef/sysmon/sysmonconfig-export.xml"
$stagedConfig = Join-Path $env:ProgramData 'Sysmon\sysmonconfig-export.xml'
$logChannel   = 'Microsoft-Windows-Sysmon/Operational'
# Minimum log size: about a week at roughly 150 MB a day; 30 days needs 4-5 GB. The script
# only ever raises the size, so a larger value set by hand survives a re-run:
#   wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296
$logMaxBytes  = 1GB

try {

# Verify in a unique staging file before replacing the kept copy, so a failed run never
# leaves an unverified file at the path a later run trusts and reloads.
Write-Host "==> Sysmon config" -ForegroundColor Cyan
$configDir = Split-Path $stagedConfig
$null = New-Item $configDir -ItemType Directory -Force
$stagingConfig = Join-Path $configDir ("sysmonconfig.{0}.staging" -f [guid]::NewGuid().ToString('N'))
try {
    $localConfig = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'sysmonconfig-export.xml' } else { $null }
    if ($localConfig -and (Test-Path $localConfig)) {
        Copy-Item $localConfig $stagingConfig -Force
        Write-Host "    using repo copy: $localConfig" -ForegroundColor DarkGray
    } else {
        Invoke-WebRequest $configUrl -OutFile $stagingConfig -UseBasicParsing -TimeoutSec 300
        Write-Host "    downloaded from repo" -ForegroundColor DarkGray
    }
    if ((Get-FileHash $stagingConfig -Algorithm SHA256).Hash -ne $configSha256) {
        throw 'config SHA256 mismatch - refresh $configSha256 if you replaced the config on purpose'
    }
    $null = [xml](Get-Content $stagingConfig -Raw)   # parse guard: fail here, not mid-install
    Move-Item $stagingConfig $stagedConfig -Force
} finally {
    if (Test-Path $stagingConfig) { Remove-Item $stagingConfig -Force -ErrorAction SilentlyContinue }
}

# Built-in and standalone Sysmon use different service names.
$svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" |
       Select-Object -First 1
if ($null -ne $svc) {
    $sysmonExe = if ($svc.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($svc.PathName -split '\s+', 2)[0] }
    Write-Host "==> Sysmon already installed ($($svc.Name)) - reapplying configuration" -ForegroundColor Cyan
    & $sysmonExe -accepteula -c $stagedConfig
    if ($LASTEXITCODE -ne 0) { throw "sysmon -c failed (exit $LASTEXITCODE)" }
} else {
    # Built-in and standalone Sysmon must not coexist.
    $sysmonExe = $null
    $staging   = $null
    $builtin   = Join-Path $env:SystemRoot 'System32\sysmon.exe'
    if (Test-Path $builtin) {
        $sysmonExe = $builtin
        Write-Host "==> using built-in Sysmon ($builtin)" -ForegroundColor Cyan
    } else {
        dism.exe /online /enable-feature /featurename:Sysmon /norestart | Out-Null
        $dismExit = $LASTEXITCODE
        if (($dismExit -eq 0 -or $dismExit -eq 3010) -and (Test-Path $builtin)) {
            $sysmonExe = $builtin
            Write-Host "==> built-in Sysmon feature enabled" -ForegroundColor Cyan
        } elseif ($dismExit -eq 0 -or $dismExit -eq 3010) {
            # Feature staged but binary absent: never fall back to standalone, it would collide after reboot.
            Write-Host "    built-in Sysmon staged but not active yet - reboot, then re-run this script" -ForegroundColor Yellow
            return
        }
    }
    try {
        if (-not $sysmonExe) {
            # Older Windows use the Authenticode-verified Sysinternals package.
            Write-Host "==> downloading standalone Sysmon (no built-in support on this Windows)" -ForegroundColor Cyan
            if ((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -eq 1 -and [Environment]::OSVersion.Version.Build -lt 22000) {
                Write-Host "    note: Sysinternals lists Windows 11 or later for current Sysmon builds; this may fail on Windows 10" -ForegroundColor Yellow
            }
            $staging = New-StagingDirectory
            $zip = Join-Path $staging 'Sysmon.zip'
            $dir = Join-Path $staging 'Sysmon'
            Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing -TimeoutSec 300
            Expand-Archive $zip -DestinationPath $dir -Force
            $exeName = switch ($env:PROCESSOR_ARCHITECTURE) {
                'ARM64' { 'Sysmon64a.exe' }
                'x86'   { 'Sysmon.exe' }
                default { 'Sysmon64.exe' }
            }
            $sysmonExe = Join-Path $dir $exeName
            $sig = Get-AuthenticodeSignature $sysmonExe
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation(,|$)') {
                throw "Sysmon download failed signature check (status $($sig.Status))"
            }
        }
        Write-Host "==> installing Sysmon service + driver" -ForegroundColor Cyan
        & $sysmonExe -accepteula -i $stagedConfig
        if ($LASTEXITCODE -ne 0) { throw "sysmon -i failed (exit $LASTEXITCODE)" }
    } finally {
        # sysmon -i copies itself and its driver into the Windows directory, so the download can go.
        if ($staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# Retain more events than the default channel size permits; never shrink a larger log.
$currentMaxBytes = (Get-WinEvent -ListLog $logChannel -ErrorAction SilentlyContinue).MaximumSizeInBytes
if ($currentMaxBytes -lt $logMaxBytes) {
    wevtutil.exe sl $logChannel "/ms:$logMaxBytes"
    if ($LASTEXITCODE -ne 0) { Write-Host "    could not raise event log size (wevtutil exit $LASTEXITCODE)" -ForegroundColor Yellow }
}

# Verify the service, driver, and event channel independently.
Write-Host "==> verifying" -ForegroundColor Cyan
Start-Sleep -Seconds 2
$svcNow = Get-CimInstance Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" |
          Select-Object -First 1
$drvNow = Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'"
$chan   = Get-WinEvent -ListLog $logChannel -ErrorAction SilentlyContinue
$svcOk  = ($null -ne $svcNow) -and ($svcNow.State -eq 'Running') -and ($svcNow.StartMode -eq 'Auto')
$drvOk  = ($null -ne $drvNow) -and ($drvNow.State -eq 'Running')
$chanOk = ($null -ne $chan) -and $chan.IsEnabled
if ($svcOk)  { Write-Host "    service $($svcNow.Name): running, autostart" -ForegroundColor DarkGray }
if ($drvOk)  { Write-Host "    driver SysmonDrv: running" -ForegroundColor DarkGray }
if ($chanOk) { Write-Host "    log: $($chan.RecordCount) events, max $([math]::Round($chan.MaximumSizeInBytes / 1MB)) MB" -ForegroundColor DarkGray }
if ($svcOk -and $drvOk -and $chanOk) {
    Write-Host "Sysmon is installed and logging. View events in Event Viewer under" -ForegroundColor Green
    Write-Host "Applications and Services Logs > Microsoft > Windows > Sysmon > Operational." -ForegroundColor Green
} else {
    throw "verification failed (service=$svcOk driver=$drvOk channel=$chanOk)"
}

} catch {
    Write-Host "Sysmon setup failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
} finally {
    $ErrorActionPreference = $previousErrorAction
}
