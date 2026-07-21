<#
  Sysmon installer - system activity logging to the Windows event log.
  Run standalone in an ELEVATED PowerShell (also invoked by setup.ps1):
    irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex
  Safe to re-run: an existing install only gets its configuration reapplied.
  On a machine without Sysmon, preference order per Microsoft docs (built-in and
  standalone Sysmon must never coexist):
    1. Built-in Sysmon (Windows 11 24H2+ / Server 2025) - System32\sysmon.exe,
       enabling the "Sysmon" optional feature through DISM when needed.
    2. Standalone Sysinternals Sysmon from download.sysinternals.com,
       Authenticode-verified before it runs as admin.
  Config: SwiftOnSecurity sysmon-config, pinned by SHA-256. A copy next to this
  script wins (cloned repo); otherwise it is fetched from this repo. The repo
  normalizes the XML to LF (.gitattributes), so the same hash matches whether the
  file is downloaded from raw or read from a clone. If you replace
  sysmon\sysmonconfig-export.xml, refresh $configSha256 with Get-FileHash - and
  commit it so the LF blob that GitHub serves matches the pin.
#>

$ErrorActionPreference = 'Stop'
try   { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# Return instead of exiting because the script is commonly invoked with iex.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this in an ELEVATED PowerShell (right-click > Run as administrator)." -ForegroundColor Red
    return
}

$configSha256 = 'AF4C914DAC315FD36288A8CE3C346490D8F737AAAA87E83EA96DFF893AC6E053'
$configUrl    = 'https://github.com/26zl/personal-windows-setup/raw/main/sysmon/sysmonconfig-export.xml'
$stagedConfig = 'C:\ProgramData\Sysmon\sysmonconfig-export.xml'
$logChannel   = 'Microsoft-Windows-Sysmon/Operational'
$logMaxBytes  = 512MB

try {

# Keep a verified config copy for later reconfiguration.
Write-Host "==> Sysmon config" -ForegroundColor Cyan
$null = New-Item (Split-Path $stagedConfig) -ItemType Directory -Force
$localConfig = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'sysmonconfig-export.xml' } else { $null }
if ($localConfig -and (Test-Path $localConfig)) {
    Copy-Item $localConfig $stagedConfig -Force
    Write-Host "    using repo copy: $localConfig" -ForegroundColor DarkGray
} else {
    Invoke-WebRequest $configUrl -OutFile $stagedConfig -UseBasicParsing
    Write-Host "    downloaded from repo" -ForegroundColor DarkGray
}
if ((Get-FileHash $stagedConfig -Algorithm SHA256).Hash -ne $configSha256) {
    throw 'config SHA256 mismatch - refresh $configSha256 if you replaced the config on purpose'
}
$null = [xml](Get-Content $stagedConfig -Raw)   # parse guard: fail here, not mid-install

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
    if (-not $sysmonExe) {
        # Older Windows use the Authenticode-verified Sysinternals package.
        Write-Host "==> downloading standalone Sysmon (no built-in support on this Windows)" -ForegroundColor Cyan
        $zip = Join-Path $env:TEMP 'Sysmon.zip'
        $dir = Join-Path $env:TEMP 'Sysmon-extracted'
        Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
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
}

# Retain more events than the default channel size permits.
wevtutil.exe sl $logChannel "/ms:$logMaxBytes"
if ($LASTEXITCODE -ne 0) { Write-Host "    could not raise event log size (wevtutil exit $LASTEXITCODE)" -ForegroundColor Yellow }

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
}
