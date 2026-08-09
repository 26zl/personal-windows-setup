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

  THIS IS A FORK, NOT A COPY. The base is SwiftOnSecurity sysmon-config source
  version 74 (2021-07-08, CC BY 4.0), which has not been updated since. What differs
  from it, in full, so nobody has to diff 1349 lines to find out:

    * schemaversion raised from 4.50 to 4.81 (see PORTABILITY below)
    * six added rule groups in a marked block at the end of the file: ProcessTampering,
      ImageLoad (include + exclude), FileDeleteDetected (include + exclude), and a
      RegistryEvent include for SilentProcessExit - 149 lines in total
    * 23 include-rule paths rewritten from absolute C:\ to drive-relative

  Everything else is upstream, untouched. Upstream leaves events 23, 24 and 25
  commented out; this fork makes a different call on two of them:
    - Event 25 ProcessTampering    ON. Process hollowing and herpaderping have no
      benign explanation on a personal machine, and the event is rare.
    - Event 26 FileDeleteDetected  ON, scoped to executables, scripts, .evtx and
      shadow copies. Records that a file was deleted without keeping a copy of it.
      One exclusion is not optional: Windows writes and deletes a
      __PSScriptPolicyTest_*.ps1 file every time PowerShell evaluates an execution
      policy. Measured at 4.5 per minute on an ordinary desktop, that is roughly
      45,000 events a week of Windows checking itself, in a channel with a size cap.
    - Event 23 FileDelete          OFF. It archives every deleted file to disk and
      fills a drive quietly. Event 26 covers the same ground without that.
    - Event 24 ClipboardChange     OFF. It captures clipboard CONTENT, so passwords
      and one-time codes would end up in an event log.
    - Event 7 ImageLoad            ON, narrowly. Upstream ships this as an empty
      include group, which matches nothing - so event 7 never fires at all and DLL
      side-loading is invisible. Unfiltered it is the highest-volume event Sysmon
      produces, so this copy includes only DLLs loading from user-writable
      directories and then excludes the package managers, editors and runtimes that
      legitimately live there.

  Not switched to olafhartong/sysmon-modular, and the reason is measured rather
  than assumed: it carries 246 RegistryEvent include rules against this file's
  114, and skews to "begin with" and "contains" where this one uses "end with".
  On a machine already dropping RegistryEvent under load - the common case, and
  the reason event 255 QUEUE exists - that is the wrong direction. sysmon-modular
  is the better base for anyone who wants to tune per module; it is not a drop-in
  improvement for a config that is flooding.

  PORTABILITY, HONESTLY. Three things are worth knowing before deploying this on a
  machine that is not the one it was tuned on:
    - REQUIRES SYSMON 14 OR LATER. The file declares schemaversion 4.81 because it
      uses FileDeleteDetected. A modern Sysmon also accepts the older 4.50 this file
      used to declare, but then an older Sysmon would apply the config while silently
      dropping that rule group - a gap that looks like a working install. Declaring
      the schema the features actually need turns that into a clear refusal instead.
    - WORKS WITH WINDOWS ON ANY DRIVE, for detection. Upstream hardcodes C:\ in 176
      places. 23 of those were in include rules, which is where it matters: on a
      machine with Windows on D: they would match nothing and the detection would be
      silently gone. Those 23 are now drive-relative, as are all the local additions.
      The remaining 153 are in exclude rules, where failing to match costs noise
      rather than coverage, and they are left as upstream wrote them - rewriting all
      of them would be a divergence to maintain forever for no gain in detection.
    - The ImageLoad exclusions are the software the author had installed. That list
      cannot be complete. A burst of event 7 after deploying this means something you
      run lives in a user-writable directory and belongs in the exclude list - it is
      tuning, not a detection. Everything else here is conservative enough to deploy
      unchanged.

  If you replace or edit the XML, refresh $configSha256 with Get-FileHash and
  reload with: sysmon -c <config.xml>. The health check reports which event IDs
  the channel is actually receiving, so a config collecting less than you think
  shows up as a finding.
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

$configSha256 = '8CC734ACBB607789ED957468CA5F20E9EC19DC47A05A37CBBD30EB5C84061DB2'
$configUrl    = 'https://github.com/26zl/personal-windows-setup/raw/main/sysmon/sysmonconfig-export.xml'
# $env:ProgramData, not a literal C:\ProgramData - Windows is not always on C:, and a
# hardcoded drive here would have the script write the config somewhere that does not
# exist and then fail on a machine that is otherwise fine.
$stagedConfig = Join-Path $env:ProgramData 'Sysmon\sysmonconfig-export.xml'
$logChannel   = 'Microsoft-Windows-Sysmon/Operational'
# 1 GB, not the 512 MB this used to be. Measured on an ordinary desktop running this
# configuration: roughly 150 MB a day, so 512 MB is about three days of history and 1 GB
# is about a week. Neither is the 30 days incident response actually wants - that would
# need 4-5 GB - but a week is the difference between "I noticed something on Monday and
# can still see Friday" and not. Raise it further with:
#   wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296
$logMaxBytes  = 1GB

try {

# Keep a verified config copy for later reconfiguration. Everything lands in a unique
# staging file first: writing straight to $stagedConfig would destroy the previously
# verified configuration before the new one has proved it matches the pin, and a failed
# run would leave an unverified file at the exact path a later run trusts and reloads.
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
        # Unique paths, not a predictable %TEMP%\Sysmon.zip: this binary is about to be
        # executed as administrator, so it must not land where an earlier run - or anything
        # else that can write there - has already placed a file with that name.
        $stagingId = [guid]::NewGuid().ToString('N')
        $zip = Join-Path $env:TEMP "Sysmon.$stagingId.zip"
        $dir = Join-Path $env:TEMP "Sysmon-extracted.$stagingId"
        Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing -TimeoutSec 300
        $null = New-Item $dir -ItemType Directory -Force
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
