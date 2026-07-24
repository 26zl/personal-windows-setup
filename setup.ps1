<#
  Personal Windows 11 Pro installer to run after a factory reset.
  Run in an ELEVATED PowerShell:
    irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1 | iex
  Add software by dropping its winget ID into a list below (winget search <name>).
  Re-running skips installed apps; failures are listed at the end. Every run writes a
  full transcript plus a timestamped event log to %LOCALAPPDATA%\windows-setup\logs.
  On a brand-new machine: run once, REBOOT (to finish Windows features + WSL2), then
  run again - the second pass completes steps that were waiting on PATH or WSL.
#>

$ErrorActionPreference = 'Continue'
try   { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# admin + winget guards
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this in an ELEVATED PowerShell (right-click > Run as administrator)." -ForegroundColor Red
    return
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget not found. Install 'App Installer' from the Microsoft Store, then re-run." -ForegroundColor Red
    return
}

# Persist a transcript and event summary outside the temporary directory.
$logDir = Join-Path $env:LOCALAPPDATA 'windows-setup\logs'
try { $null = New-Item $logDir -ItemType Directory -Force } catch { $logDir = $env:TEMP }
$stamp    = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$log      = Join-Path $logDir "transcript-$stamp.log"
$eventLog = Join-Path $logDir "events-$stamp.log"
$runStart = Get-Date
try { Start-Transcript -Path $log -Append | Out-Null } catch { $log = $null }

function Write-Event {
    param([string]$Level, [string]$Message)
    if (-not $script:eventLog) { return }
    try   { "[{0:yyyy-MM-dd HH:mm:ss}] [{1,-4}] {2}" -f (Get-Date), $Level, $Message | Add-Content $script:eventLog -Encoding UTF8 }
    catch { $script:eventLog = $null }   # never let logging break the run
}
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Event 'INFO' "run started - user=$env:USERNAME host=$env:COMPUTERNAME os=$osCaption"

$Failed = @()
$WingetOk = 0, -1978335189, -1978335135

function Install-App {
    param([string]$Id, [string]$Source = 'winget')
    Write-Host "==> $Id" -ForegroundColor Cyan
    winget install --id $Id --exact --source $Source --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -eq 0) { Write-Event 'OK' "$Id installed or updated"; return }
    if ($WingetOk -contains $LASTEXITCODE) { Write-Event 'SKIP' "$Id already installed (exit $LASTEXITCODE)"; return }
    Write-Host "    FAILED: $Id (exit $LASTEXITCODE)" -ForegroundColor Yellow
    Write-Event 'FAIL' "$Id (exit $LASTEXITCODE)"
    $script:Failed += $Id
}

function Invoke-Child {
    param([string]$Command)
    powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $Command"
}

function Invoke-Tool {
    param([string]$Name, [string]$Command)
    Write-Host ""
    Write-Host "  Tool: $Name" -ForegroundColor White
    if ((Read-Host "  Run it? Type y (anything else skips)") -notmatch '^(y|yes)$') {
        Write-Host "    skipped $Name" -ForegroundColor DarkGray; Write-Event 'SKIP' "$Name skipped by user"; return
    }
    Write-Host "    launching in a new window - this window's output is preserved..." -ForegroundColor DarkGray
    $full = "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $Command"
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($full))
    $proc = Start-Process powershell -PassThru -Wait -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc)
    if ($proc.ExitCode -ne 0) { Write-Host "    $Name reported exit $($proc.ExitCode)" -ForegroundColor Yellow; Write-Event 'FAIL' "$Name (exit $($proc.ExitCode))"; $script:Failed += "$Name (external)" }
    else { Write-Event 'OK' "$Name completed" }
}

function Set-WingetUpgradeDelay {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Days = 7)
    # Hold winget upgrades for packages newer than $Days days (supply-chain soak). settings.json
    # is JSONC, so strip comments/trailing commas before parsing and merge into existing settings.
    $schemaUrl = 'https://aka.ms/winget-settings.schema.json'
    $path = $null
    try { $path = (winget settings export 2>$null | ConvertFrom-Json).userSettingsFile } catch { $path = $null }
    if (-not $path) { $path = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json' }
    try {
        $obj = $null
        $raw = if (Test-Path $path) { Get-Content $path -Raw } else { $null }
        if ($raw -and $raw.Trim()) {
            $clean = [regex]::Replace($raw, '("(?:\\.|[^"\\])*")|/\*[\s\S]*?\*/|//[^\r\n]*', '$1')
            $clean = [regex]::Replace($clean, ',(?=\s*[}\]])', '')
            $obj   = $clean | ConvertFrom-Json
        }
        if ($null -eq $obj) { $obj = [pscustomobject]@{ '$schema' = $schemaUrl } }
        if ($null -eq $obj.installBehavior) { $obj | Add-Member -NotePropertyName installBehavior -NotePropertyValue ([pscustomobject]@{}) -Force }
        $obj.installBehavior | Add-Member -NotePropertyName upgradeDelayInDays -NotePropertyValue $Days -Force
        if ($PSCmdlet.ShouldProcess($path, "set upgradeDelayInDays=$Days")) {
            $null = New-Item (Split-Path $path) -ItemType Directory -Force
            [IO.File]::WriteAllText($path, ($obj | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
            Write-Host "    upgradeDelayInDays = $Days (supply-chain soak: skips packages newer than $Days days)" -ForegroundColor DarkGray
            Write-Event 'OK' "winget upgradeDelayInDays set to $Days"
        }
    } catch {
        Write-Host "    could not set upgradeDelayInDays: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    left settings.json untouched - set it yourself via 'winget settings'" -ForegroundColor DarkGray
        Write-Event 'WARN' "winget upgradeDelayInDays not set - $($_.Exception.Message)"
    }
}

function New-SetupRestorePoint {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Description)
    # System Restore checkpoint. Enables protection if off and lifts the 24h throttle so both
    # points get created, then restores it. Best-effort.
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "create System Restore point '$Description'")) { return }
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    } catch {
        Write-Host "    could not enable System Protection: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Event 'WARN' "restore point '$Description' - Enable-ComputerRestore failed: $($_.Exception.Message)"
        return
    }
    $hadFreq  = $false
    $prevFreq = $null
    try {
        $existing = Get-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue
        if ($null -ne $existing) { $hadFreq = $true; $prevFreq = $existing.SystemRestorePointCreationFrequency }
        Set-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Host "    restore point created: $Description" -ForegroundColor DarkGray
        Write-Event 'OK' "restore point created: $Description"
    } catch {
        Write-Host "    restore point failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Event 'WARN' "restore point '$Description' failed: $($_.Exception.Message)"
    } finally {
        # put the 24h throttle back the way we found it
        if ($hadFreq) { Set-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -Value $prevFreq -Type DWord -ErrorAction SilentlyContinue }
        else          { Remove-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue }
    }
}

try {

# Restore point before any changes.
Write-Host "`n=== System Restore point (before) ===" -ForegroundColor Magenta
New-SetupRestorePoint "Before windows-setup ($stamp)"

# winget apps
$winget = @(
    # core dev
    'Microsoft.PowerShell'            # PowerShell 7
    'Microsoft.WindowsTerminal'
    'Git.Git'
    'GitHub.cli'
    'GitHub.GitHubDesktop'
    'Microsoft.VisualStudioCode'
    'Neovim.Neovim'                   # Neovim (my config is cloned in below)
    '7zip.7zip'
    'Microsoft.VCRedist.2015+.x64'    # C++ runtimes many apps need
    'Casey.Just'                      # command runner (justfiles)
    'jqlang.jq'                       # JSON processor
    'BurntSushi.ripgrep.MSVC'         # ripgrep - Telescope live-grep (nvim)
    'sharkdp.fd'                      # fd - Telescope file finding (nvim)
    'Google.PlatformTools'           # Android adb + fastboot

    # languages
    'Python.Python.3.14'              # official python.org build (PSF) - not the choco wrapper
    'OpenJS.NodeJS.LTS'               # npm + corepack (yarn/pnpm)
    'GoLang.Go'
    'Rustlang.Rustup'
    'EclipseAdoptium.Temurin.21.JDK'  # Java 21 LTS
    'Microsoft.DotNet.SDK.8'
    'RubyInstallerTeam.Ruby.3.4'      # Ruby 3.4

    # native build toolchains (C/C++, Rust MSVC, native node/python modules)
    'Microsoft.VisualStudio.BuildTools'       # rolling latest (2022/2026/...); VCTools workload added below
    'LLVM.LLVM'
    # MSYS2.MSYS2 is installed after this loop (winget can't correlate C:\msys64 - see below)

    # package managers
    'pnpm.pnpm'
    'Oven-sh.Bun'
    'Chocolatey.Chocolatey'
    'astral-sh.uv'                    # fast Python package/project manager
    'Devolutions.UniGetUI'           # GUI for winget/scoop/choco/pip/npm (formerly WingetUI)

    # containers / virtualization / database / api
    'Docker.DockerDesktop'
    'Oracle.VirtualBox'
    'DBeaver.DBeaver.Community'
    'Bruno.Bruno'

    # ai / local llm
    'Ollama.Ollama'                   # local LLM runtime (listens on localhost:11434)

    # sysadmin / networking
    'Microsoft.PowerToys'
    'Microsoft.Sysinternals.Suite'
    'WinSCP.WinSCP'
    'PuTTY.PuTTY'
    'Mobatek.MobaXterm'
    'Tailscale.Tailscale'
    'WireGuard.WireGuard'
    'MullvadVPN.MullvadVPN'           # Mullvad VPN

    # cybersecurity
    'WiresharkFoundation.Wireshark'
    'Insecure.Nmap'
    'PortSwigger.BurpSuite.Community'
    'KeePassXCTeam.KeePassXC'

    # privacy / debloat
    'OO-Software.ShutUp10'            # run it afterwards to apply tweaks

    # browser
    'Google.Chrome'
    # Tor Browser is installed below.

    # cleanup / maintenance
    'Malwarebytes.Malwarebytes'       # anti-malware; free on-demand scanner after the trial
    'Malwarebytes.AdwCleaner'
    'BleachBit.BleachBit'
    'lostindark.DriverStoreExplorer'

    # usb imaging / apps
    'Rufus.Rufus'
    'Balena.Etcher'
    'Valve.Steam'

)
Write-Host "`n=== winget apps ($($winget.Count)) ===" -ForegroundColor Magenta
foreach ($pkg in $winget) { Install-App $pkg }

# MSYS2 installs to C:\msys64 via the Qt installer, which returns exit 1 when that directory
# already exists. winget can't correlate the existing install to the package either, so a plain
# Install-App retries (and "fails" with 0x8A150006) on every re-run. Treat a working bash.exe
# there as already installed, the same way Tor Browser and Discord are handled below.
Write-Host "==> MSYS2.MSYS2" -ForegroundColor Cyan
if (Test-Path 'C:\msys64\usr\bin\bash.exe') {
    Write-Host "    already installed (skipped; C:\msys64 present)" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'MSYS2.MSYS2 already installed (C:\msys64)'
} else {
    Install-App 'MSYS2.MSYS2'
}

# Tor Browser
Write-Host "==> TorProject.TorBrowser" -ForegroundColor Cyan
$torExe = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Tor Browser\Browser\firefox.exe'
if (Test-Path $torExe) {
    Write-Host "    already installed (skipped reinstall)" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'TorProject.TorBrowser already installed'
} else {
    Install-App 'TorProject.TorBrowser'
}

# Discord self-updates and reinstalls badly via winget while open, so only install when missing.
if (Test-Path (Join-Path $env:LOCALAPPDATA 'Discord\Update.exe')) {
    Write-Host "==> Discord.Discord" -ForegroundColor Cyan
    Write-Host "    already installed (skipped; Discord updates itself)" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Discord already installed'
} else {
    Install-App 'Discord.Discord'
}

# BuildTools ships no workloads, so add the VCTools workload (C++ compiler, linker, SDK).
Write-Host "`n=== MSVC C++ build toolset ===" -ForegroundColor Magenta
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
$vswhere     = Join-Path $vsInstaller 'vswhere.exe'
$vsSetup     = Join-Path $vsInstaller 'setup.exe'
$vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
if (-not (Test-Path $vswhere)) {
    Write-Host "    vswhere not found - BuildTools didn't install; re-run after it does" -ForegroundColor Yellow
    Write-Event 'FAIL' 'VC++ toolset - vswhere missing (BuildTools not installed)'
    $Failed += 'VC++ toolset (BuildTools missing)'
} else {
    $vcPath = & $vswhere -latest -products * -requires $vcComponent -property installationPath 2>$null
    if ($vcPath) {
        Write-Host "    already installed ($vcPath)" -ForegroundColor DarkGray
        Write-Event 'SKIP' "VC++ toolset already installed ($vcPath)"
    } elseif (-not (Test-Path $vsSetup)) {
        Write-Host "    VS setup.exe not found (skipped)" -ForegroundColor Yellow
        Write-Event 'FAIL' 'VC++ toolset - VS setup.exe missing'
        $Failed += 'VC++ toolset (setup.exe missing)'
    } else {
        $btPath = & $vswhere -products 'Microsoft.VisualStudio.Product.BuildTools' -property installationPath 2>$null |
                  Select-Object -First 1
        if (-not $btPath) {
            # No hardcoded path: the BuildTools directory tracks the year (2022 -> 2026 -> ...).
            # If vswhere can't report it, BuildTools isn't ready - re-run after it installs.
            Write-Host "    BuildTools install path not found via vswhere - skipping VCTools (re-run after BuildTools installs)" -ForegroundColor Yellow
            Write-Event 'FAIL' 'VC++ toolset - BuildTools installationPath not found via vswhere'
            $Failed += 'VC++ toolset (BuildTools path not found)'
        } else {
            Write-Host "==> adding VCTools workload to $btPath (compiler + linker + SDK, multi-GB download)" -ForegroundColor Cyan
            # no --wait: installer 4.x rejects it (exit 87); Start-Process -Wait blocks instead.
            # quote the path: Start-Process space-joins its args without quoting.
            $vsArgs = @(
                'modify', '--installPath', ('"{0}"' -f $btPath),
                '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended',
                '--passive', '--norestart'
            )
            $proc = Start-Process $vsSetup -ArgumentList $vsArgs -Wait -PassThru
            # trust vswhere over the exit code - it reflects what actually got installed
            $vcNow = & $vswhere -latest -products * -requires $vcComponent -property installationPath 2>$null
            if ($vcNow) {
                Write-Host "    MSVC C++ toolset installed (cl.exe, link.exe, CRT, Windows SDK)" -ForegroundColor DarkGray
                Write-Event 'OK' 'VC++ toolset (VCTools workload) installed'
                if ($proc.ExitCode -eq 3010) { Write-Host "    reboot required to finish" -ForegroundColor Yellow }
            } else {
                Write-Host "    VCTools install failed (exit $($proc.ExitCode)) - component still missing" -ForegroundColor Yellow
                Write-Event 'FAIL' "VC++ toolset (exit $($proc.ExitCode))"
                $Failed += 'VC++ toolset (VCTools workload)'
            }
        }
    }
}

Write-Host "`n=== Store apps ===" -ForegroundColor Magenta
Install-App '9P7GGFL7DX57' 'msstore'   # Harden System Security
Install-App '9MSMLRH6LZF3' 'msstore'   # Windows Notepad
# AppControl Manager (same author): Install-App '9PNG1JDDTGP8' 'msstore'

# Microsoft Office
Write-Host "`n=== Microsoft Office ===" -ForegroundColor Magenta
$word = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\WINWORD.EXE'
if (Test-Path $word) {
    Write-Host "    already installed (skipped)" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Microsoft Office already installed'
} else {
    $office = Join-Path $env:TEMP 'OfficeSetup.exe'
    # pinned hash of office/OfficeSetup.exe in this repo; refresh with Get-FileHash if the stub is replaced
    $officeSha256 = 'C0ED5DC2C0ABBE023684B1B4A4E3229D5E678D2FF30F5C147044D7AFBA88B04E'
    try {
        Invoke-WebRequest 'https://github.com/26zl/personal-windows-setup/raw/main/office/OfficeSetup.exe' -OutFile $office -UseBasicParsing -TimeoutSec 300
        # verify pinned hash + Microsoft's Authenticode signature before running as admin
        if ((Get-FileHash $office -Algorithm SHA256).Hash -ne $officeSha256) {
            throw 'SHA256 mismatch - update $officeSha256 if you replaced the stub'
        }
        $sig = Get-AuthenticodeSignature $office
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation(,|$)') {
            throw "signature check failed (status $($sig.Status))"
        }
        Write-Host "==> running OfficeSetup.exe" -ForegroundColor Cyan
        $officeProc = Start-Process $office -Wait -PassThru
        # the stub can hand off and exit early, so trust the installed binary over the exit code
        if (Test-Path $word) {
            Write-Event 'OK' "Microsoft Office installed (setup exit $($officeProc.ExitCode))"
        } else {
            Write-Host "    Office setup exited ($($officeProc.ExitCode)) but WINWORD.EXE isn't there yet - check manually" -ForegroundColor Yellow
            Write-Event 'WARN' "Microsoft Office not verified (setup exit $($officeProc.ExitCode))"
            $Failed += 'Microsoft Office (verify manually)'
        }
    } catch {
        Write-Host "    Office install failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Event 'FAIL' "Microsoft Office - $($_.Exception.Message)"
        $Failed += 'Microsoft Office'
    }
}

Write-Host "`n=== Desktop shortcuts (portable apps) ===" -ForegroundColor Magenta
$desktop = [Environment]::GetFolderPath('Desktop')
$pkgRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
$portables = @{
    'OO-Software.ShutUp10'            = 'shutup10.exe'   # O&O ShutUp10++ renamed the exe from OOSU10.exe
    'lostindark.DriverStoreExplorer' = 'RAPR.exe'
    'Malwarebytes.AdwCleaner'        = 'adwcleaner.exe'
    'Rufus.Rufus'                    = 'rufus*.exe'
}
$shell = New-Object -ComObject WScript.Shell
foreach ($id in $portables.Keys) {
    $exe = Get-ChildItem $pkgRoot -Recurse -Filter $portables[$id] -ErrorAction SilentlyContinue |
           Where-Object FullName -like "*$id*" | Select-Object -First 1
    if (-not $exe) { Write-Host "    $id : exe not found (skipped)" -ForegroundColor DarkGray; continue }
    $name = ($id -split '\.')[-1]
    $lnk = $shell.CreateShortcut((Join-Path $desktop "$name.lnk"))
    $lnk.TargetPath = $exe.FullName
    $lnk.Save()
    Write-Host "    $name -> Desktop" -ForegroundColor DarkGray
}
# Sysinternals
$sysDir = Get-ChildItem $pkgRoot -Directory -ErrorAction SilentlyContinue |
          Where-Object Name -like 'Microsoft.Sysinternals.Suite*' | Select-Object -First 1
if ($sysDir) {
    $lnk = $shell.CreateShortcut((Join-Path $desktop 'Sysinternals.lnk'))
    $lnk.TargetPath = $sysDir.FullName
    $lnk.Save()
    Write-Host "    Sysinternals -> Desktop" -ForegroundColor DarkGray
} else {
    Write-Host "    Sysinternals : folder not found (skipped)" -ForegroundColor DarkGray
}

Write-Host "`n=== Scoop ===" -ForegroundColor Magenta
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Host "    already installed" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Scoop already installed'
} else {
    Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://get.scoop.sh))) -RunAsAdmin"
    if ($LASTEXITCODE -ne 0) { Write-Host "    Scoop reported exit $LASTEXITCODE" -ForegroundColor Yellow; Write-Event 'FAIL' "Scoop (exit $LASTEXITCODE)"; $Failed += 'Scoop' }
    else { Write-Event 'OK' 'Scoop installed' }
}

Write-Host "`n=== pipx ===" -ForegroundColor Magenta
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m pip install --user --upgrade pipx
    if ($LASTEXITCODE -eq 0) { python -m pipx ensurepath; Write-Event 'OK' 'pipx installed' }
    else { Write-Host "    pipx install failed (exit $LASTEXITCODE)" -ForegroundColor Yellow; Write-Event 'FAIL' "pipx (exit $LASTEXITCODE)"; $Failed += 'pipx' }
} else {
    Write-Host "    python not on PATH yet - after reboot run: python -m pip install --user pipx" -ForegroundColor Yellow
    Write-Event 'WARN' 'pipx deferred - python not on PATH this run'
    $Failed += 'pipx (python not found this run)'
}

# GitHub sign-in + git identity (opt in). Safe under elevation on Windows (same user).
Write-Host "`n=== GitHub sign-in & git identity (opt in) ===" -ForegroundColor Magenta
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "    gh not on PATH yet - after reboot run: gh auth login --web; gh auth setup-git" -ForegroundColor Yellow
    Write-Event 'WARN' 'GitHub sign-in deferred - gh not on PATH this run'
} elseif ((Read-Host "Sign in to GitHub and set your git identity now? Type y (anything else skips)") -match '^(y|yes)$') {
    gh auth status 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    opening your browser to log in..." -ForegroundColor DarkGray
        gh auth login --hostname github.com --git-protocol https --web
    } else {
        Write-Host "    already logged in to GitHub" -ForegroundColor DarkGray
    }
    if ($LASTEXITCODE -eq 0) {
        gh auth setup-git
        git config --global init.defaultBranch main
        git config --global pull.rebase false
        git config --global push.autoSetupRemote true
        $login = (gh api user --jq .login              2>$null); $login = "$login".Trim()
        $ghId  = (gh api user --jq .id                  2>$null); $ghId  = "$ghId".Trim()
        $email = (gh api user --jq '.email // empty'    2>$null); $email = "$email".Trim()
        if ($login) {
            if (-not $email) { $email = "$ghId+$login@users.noreply.github.com" }
            git config --global user.name  $login
            git config --global user.email $email
            Write-Host "    git identity: $(git config --global user.name) <$(git config --global user.email)>" -ForegroundColor DarkGray
            Write-Event 'OK' "GitHub sign-in + git identity set ($login)"
        } else {
            Write-Host "    signed in, but couldn't read the account - git identity left unchanged" -ForegroundColor Yellow
            Write-Event 'WARN' 'GitHub signed in but gh api user returned empty - identity unchanged'
        }
    } else {
        Write-Host "    GitHub login not completed - git identity left unchanged" -ForegroundColor Yellow
        Write-Event 'WARN' 'GitHub login not completed'
    }
} else {
    Write-Host "    skipped GitHub sign-in" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'GitHub sign-in skipped by user'
}

# Neovim config: run the repo's install.ps1 (backs up existing, or git pulls). Needs a C compiler.
Write-Host "`n=== Neovim config ===" -ForegroundColor Magenta
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$nvimCfg = Join-Path $env:LOCALAPPDATA 'nvim'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "    git not on PATH yet - after reboot run: irm https://github.com/26zl/nvim/raw/main/install.ps1 | iex" -ForegroundColor Yellow
    Write-Event 'WARN' 'Neovim config deferred - git not on PATH this run'
    $Failed += 'Neovim config (git not found this run)'
} else {
    Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://github.com/26zl/nvim/raw/main/install.ps1)))"
    if (Test-Path (Join-Path $nvimCfg 'init.lua')) {
        Write-Host "    Neovim config ready -> $nvimCfg (plugins install on first 'nvim' launch)" -ForegroundColor DarkGray
        Write-Event 'OK' 'Neovim config installed via install.ps1'
    } else {
        Write-Host "    Neovim config install failed - see output above" -ForegroundColor Yellow
        Write-Event 'FAIL' 'Neovim config (install.ps1)'
        $Failed += 'Neovim config'
    }
}
# Same config in WSL Debian (opt in): official Neovim tarball + deps + clone, run as root
# via a temp /mnt script to avoid wsl.exe arg-quoting issues.
$wslReady = $false
try { wsl.exe -d Debian -u root -- true 2>$null; $wslReady = ($LASTEXITCODE -eq 0) } catch { $wslReady = $false }
if (-not $wslReady) {
    Write-Host "    WSL Debian not ready yet (finishes after reboot) - re-run to set up Neovim there, or see the nvim README" -ForegroundColor DarkGray
    Write-Event 'INFO' 'Neovim/WSL skipped - Debian not ready this run'
} elseif ((Read-Host "Set up the same Neovim in WSL Debian too? Type y (anything else skips)") -match '^(y|yes)$') {
    $wslScript = @'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ripgrep fd-find build-essential unzip ca-certificates >/dev/null
if ! command -v nvim >/dev/null 2>&1 || ! nvim --version | head -1 | grep -qE 'v0\.(1[1-9]|[2-9][0-9])'; then
  curl -fsSLo /tmp/nvim.tar.gz https://github.com/neovim/neovim/releases/download/stable/nvim-linux-x86_64.tar.gz
  rm -rf /opt/nvim-linux-x86_64
  tar -C /opt -xzf /tmp/nvim.tar.gz
  ln -sf /opt/nvim-linux-x86_64/bin/nvim /usr/local/bin/nvim
  rm -f /tmp/nvim.tar.gz
fi
command -v fdfind >/dev/null 2>&1 && ln -sf "$(command -v fdfind)" /usr/local/bin/fd || true
u=$(getent passwd 1000 | cut -d: -f1)
h=$(getent passwd 1000 | cut -d: -f6)
if [ -n "$u" ] && [ ! -f "$h/.config/nvim/init.lua" ]; then
  runuser -u "$u" -- git clone https://github.com/26zl/nvim "$h/.config/nvim"
fi
echo "WSL_NVIM_DONE $(nvim --version | head -1)"
'@ -replace "`r`n", "`n"
    $wslSh = Join-Path $env:TEMP 'wsl-nvim-setup.sh'
    [IO.File]::WriteAllText($wslSh, $wslScript, (New-Object Text.UTF8Encoding($false)))
    $wslPath = '/mnt/' + $wslSh.Substring(0,1).ToLower() + ($wslSh.Substring(2) -replace '\\','/')
    wsl.exe -d Debian -u root -- bash $wslPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Neovim set up in WSL Debian (run 'nvim' inside WSL; plugins install on first launch)" -ForegroundColor DarkGray
        Write-Event 'OK' 'Neovim installed + configured in WSL Debian'
    } else {
        Write-Host "    WSL Neovim setup reported exit $LASTEXITCODE" -ForegroundColor Yellow
        Write-Event 'FAIL' "Neovim/WSL setup (exit $LASTEXITCODE)"
        $Failed += 'Neovim (WSL)'
    }
    Remove-Item $wslSh -ErrorAction SilentlyContinue
} else {
    Write-Host "    skipped WSL Neovim setup" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Neovim/WSL skipped by user'
}

Write-Host "`n=== Windows features ===" -ForegroundColor Magenta
if ($osCaption -match 'Home') {
    Write-Host "    Sandbox + Hyper-V skipped - need Windows Pro/Enterprise/Education" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Sandbox + Hyper-V skipped (Windows Home)'
} else {
    foreach ($f in 'Containers-DisposableClientVM','Microsoft-Hyper-V-All') {
        $info = dism.exe /online /get-featureinfo "/featurename:$f" 2>&1 | Out-String
        if ($info -match 'State\s*:\s*Enable') {
            Write-Host "    $f already enabled" -ForegroundColor DarkGray
            Write-Event 'SKIP' "feature $f already enabled"
            continue
        }
        dism.exe /online /enable-feature "/featurename:$f" /all /norestart | Out-Null
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-Host "    $f enabled (reboot to finish)" -ForegroundColor DarkGray
            Write-Event 'OK' "feature $f enabled (reboot to finish)"
        } else {
            Write-Host "    feature failed: $f (dism exit $LASTEXITCODE)" -ForegroundColor Yellow
            Write-Event 'FAIL' "feature $f (dism exit $LASTEXITCODE)"
            $Failed += "feature: $f"
        }
    }
}
# WSL2 with Debian (wsl --install errors with ERROR_ALREADY_EXISTS on re-runs)
$env:WSL_UTF8 = '1'   # wsl.exe emits UTF-16 by default, which garbles captured output
$wslDistros = (wsl.exe --list --quiet 2>$null) -replace "`0", '' |
              ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($wslDistros -contains 'Debian') {
    Write-Host "    Debian (WSL) already installed" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Debian (WSL) already installed'
} else {
    wsl --install -d Debian
    if ($LASTEXITCODE -ne 0) { Write-Host "    WSL/Debian returned exit $LASTEXITCODE - verify after reboot: wsl -l -v" -ForegroundColor Yellow; Write-Event 'FAIL' "WSL2/Debian (exit $LASTEXITCODE)"; $Failed += 'WSL2/Debian' }
    else { Write-Event 'OK' 'WSL2/Debian install initiated (finishes after reboot)' }
}

# Verify Sysmon by service state because fetched scripts may not preserve exit codes.
Write-Host "`n=== Sysmon (system activity logging) ===" -ForegroundColor Magenta
Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1)))"
$sysmonSvc = Get-CimInstance Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" -ErrorAction SilentlyContinue |
             Select-Object -First 1
if ($null -ne $sysmonSvc -and $sysmonSvc.State -eq 'Running') {
    Write-Host "    Sysmon running (service $($sysmonSvc.Name))" -ForegroundColor DarkGray
    Write-Event 'OK' "Sysmon running (service $($sysmonSvc.Name))"
} else {
    Write-Host "    Sysmon not running after setup - see output above" -ForegroundColor Yellow
    Write-Event 'FAIL' 'Sysmon not running after install-sysmon.ps1'
    $Failed += 'Sysmon'
}

# ConfigureDefender (AndyFul): Defender settings GUI. Installed + verified only, never auto-run.
Write-Host "`n=== ConfigureDefender (Defender settings GUI) ===" -ForegroundColor Magenta
$cdDir = Join-Path $env:LOCALAPPDATA 'windows-setup\tools'
$cdExe = Join-Path $cdDir 'ConfigureDefender.exe'
$cdUrl = 'https://github.com/AndyFul/ConfigureDefender/raw/master/ConfigureDefender.exe'
# pinned hash of AndyFul's signed build; refresh with Get-FileHash if he ships a new one
$cdSha256 = 'BD7630B6AD94F8ED2024E5E98A24B6FEDBB5F2B8A058B70C8FFEEFE98A7DCCA2'
try {
    $null = New-Item $cdDir -ItemType Directory -Force
    Invoke-WebRequest $cdUrl -OutFile $cdExe -UseBasicParsing -TimeoutSec 300
    # verify the pinned hash + the author's Authenticode signature before keeping it
    if ((Get-FileHash $cdExe -Algorithm SHA256).Hash -ne $cdSha256) {
        throw 'SHA256 mismatch - refresh $cdSha256 if AndyFul published a new build'
    }
    $sig = Get-AuthenticodeSignature $cdExe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Andrzej Pluta') {
        throw "signature check failed (status $($sig.Status))"
    }
    if (-not $desktop) { $desktop = [Environment]::GetFolderPath('Desktop') }
    if (-not $shell)   { $shell   = New-Object -ComObject WScript.Shell }
    $lnk = $shell.CreateShortcut((Join-Path $desktop 'ConfigureDefender.lnk'))
    $lnk.TargetPath = $cdExe
    $lnk.Save()
    Write-Host "    installed (not configured) -> $cdExe" -ForegroundColor DarkGray
    Write-Host "    Desktop shortcut added; open it and choose a protection level yourself." -ForegroundColor DarkGray
    Write-Event 'OK' 'ConfigureDefender installed (verified, not configured)'
} catch {
    Write-Host "    ConfigureDefender failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Event 'FAIL' "ConfigureDefender - $($_.Exception.Message)"
    $Failed += 'ConfigureDefender'
}

# Claude Code - the native installer keeps itself updated, so only run it when claude is missing.
Write-Host "`n=== Claude Code (official native installer) ===" -ForegroundColor Magenta
$claudeExe = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
if ((Get-Command claude -ErrorAction SilentlyContinue) -or (Test-Path $claudeExe)) {
    Write-Host "    already installed (skipped; it self-updates)" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'Claude Code already installed'
} else {
    Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://claude.ai/install.ps1)))"
    if ($LASTEXITCODE -ne 0) { Write-Host "    Claude Code reported exit $LASTEXITCODE" -ForegroundColor Yellow; Write-Event 'FAIL' "Claude Code (exit $LASTEXITCODE)"; $Failed += 'Claude Code' }
    else { Write-Event 'OK' 'Claude Code installed (native installer)' }
}

# System integrity: DISM first (repairs the component store), then SFC (uses it).
Write-Host "`n=== System integrity (DISM + SFC) ===" -ForegroundColor Magenta
Write-Host "==> DISM /ScanHealth (checking the component store - can take a few minutes)" -ForegroundColor Cyan
$dismScan = dism.exe /online /cleanup-image /scanhealth 2>&1 | Out-String
$scanExit = $LASTEXITCODE
($dismScan -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) |
    ForEach-Object { Write-Host "    $($_.Trim())" -ForegroundColor DarkGray }
if ($scanExit -eq 0 -and $dismScan -match 'No component store corruption detected') {
    Write-Host "    component store is healthy" -ForegroundColor DarkGray
    Write-Event 'OK' 'DISM ScanHealth - no corruption'
} else {
    Write-Host "==> corruption indicated - DISM /RestoreHealth (may download from Windows Update)" -ForegroundColor Cyan
    dism.exe /online /cleanup-image /restorehealth
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    component store repaired" -ForegroundColor DarkGray
        Write-Event 'OK' 'DISM RestoreHealth succeeded'
    } else {
        Write-Host "    DISM RestoreHealth exit $LASTEXITCODE - see %WINDIR%\Logs\DISM\dism.log" -ForegroundColor Yellow
        Write-Event 'FAIL' "DISM RestoreHealth (exit $LASTEXITCODE)"
        $Failed += 'DISM RestoreHealth'
    }
}
Write-Host "==> sfc /scannow (verifying system files)" -ForegroundColor Cyan
sfc.exe /scannow
$sfcExit = $LASTEXITCODE
if ($sfcExit -eq 0) {
    Write-Host "    SFC finished" -ForegroundColor DarkGray
    Write-Event 'OK' 'sfc /scannow finished (exit 0)'
} else {
    Write-Host "    sfc /scannow exit $sfcExit - review %WINDIR%\Logs\CBS\CBS.log if it could not fix a file" -ForegroundColor Yellow
    Write-Event 'WARN' "sfc /scannow (exit $sfcExit)"
}

# Dual-boot checks & tweaks (opt in). Read-only report first, then each change is its own y/n.
Write-Host "`n=== Dual-boot checks & tweaks (opt in) ===" -ForegroundColor Magenta
if ((Read-Host "Check dual-boot settings? Type y (anything else skips)") -match '^(y|yes)$') {
    $powerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    $tzKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    $hiberboot    = (Get-ItemProperty $powerKey -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    $hiberEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue).HibernateEnabled
    $rtcUtc       = (Get-ItemProperty $tzKey -Name RealTimeIsUniversal -ErrorAction SilentlyContinue).RealTimeIsUniversal

    # boot store: how many Windows OS loaders, plus non-Windows firmware boot entries
    $winLoaders = ([regex]::Matches((bcdedit /enum osloader 2>$null | Out-String), '(?im)^\s*description\s+.+$')).Count
    $fwDescs = [regex]::Matches((bcdedit /enum firmware 2>$null | Out-String), '(?im)^\s*description\s+(.+?)\s*$') |
               ForEach-Object { $_.Groups[1].Value.Trim() } |
               Where-Object { $_ -and $_ -notmatch '^Windows Boot Manager$' } | Select-Object -Unique
    $secureBoot = try { if (Confirm-SecureBootUEFI) { 'ON' } else { 'OFF' } } catch { 'n/a (legacy BIOS or unsupported)' }
    $blOn = try { @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.ProtectionStatus -eq 'On' }).Count } catch { 0 }

    Write-Host "  --- current state ---" -ForegroundColor White
    Write-Host ("  Windows installs in boot store : {0}" -f $winLoaders) -ForegroundColor Gray
    if ($fwDescs) { Write-Host ("  Other firmware boot entries    : {0}" -f ($fwDescs -join ', ')) -ForegroundColor Gray }
    else          { Write-Host  "  Other firmware boot entries    : none (only Windows Boot Manager)" -ForegroundColor Gray }
    Write-Host ("  Fast Startup                   : {0}" -f $(if ($hiberboot -eq 0) { 'OFF (good)' } elseif ($null -eq $hiberboot) { 'not set' } else { 'ON (locks NTFS while hibernation is on)' })) -ForegroundColor Gray
    Write-Host ("  Hibernation                    : {0}" -f $(if ($hiberEnabled -eq 0) { 'OFF' } elseif ($null -eq $hiberEnabled) { 'unknown' } else { 'ON (hiberfil.sys uses ~RAM-sized disk)' })) -ForegroundColor Gray
    Write-Host ("  Hardware clock                 : {0}" -f $(if ($rtcUtc -eq 1) { 'UTC (matches Linux)' } else { 'local time (Windows default)' })) -ForegroundColor Gray
    Write-Host ("  Secure Boot                    : {0}" -f $secureBoot) -ForegroundColor Gray
    if ($blOn -gt 0) {
        Write-Host ("  BitLocker                      : ON ({0} volume(s)) - back up your recovery key before Secure Boot / firmware changes" -f $blOn) -ForegroundColor Yellow
    } else {
        Write-Host  "  BitLocker                      : off / none" -ForegroundColor Gray
    }
    if ($winLoaders -gt 1) {
        Write-Host "  Note: multiple Windows installs detected - Fast Startup must be OFF in EACH so they don't lock each other's NTFS." -ForegroundColor Yellow
    }

    Write-Host "  --- changes (each is optional) ---" -ForegroundColor White
    $offered = $false
    # Disabling hibernation also clears Fast Startup and frees hiberfil.sys (good for dual boot).
    if ($hiberEnabled -ne 0) {
        $offered = $true
        Write-Host "  Turning hibernation off also removes Fast Startup and frees a RAM-sized hiberfil.sys. Keep it only if you use Hibernate/sleep-to-disk." -ForegroundColor DarkGray
        if ((Read-Host "  Disable hibernation entirely? (powercfg /h off) Type y") -match '^(y|yes)$') {
            powercfg.exe /hibernate off
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    hibernation disabled (hiberfil.sys removed; Fast Startup off too)" -ForegroundColor DarkGray
                Write-Event 'OK' 'dual-boot: hibernation disabled (powercfg /h off)'
            } else {
                Write-Host "    powercfg /h off exit $LASTEXITCODE" -ForegroundColor Yellow
                Write-Event 'WARN' "dual-boot: powercfg /h off (exit $LASTEXITCODE)"
            }
        } else { Write-Event 'SKIP' 'dual-boot: hibernation left enabled' }
    }
    # RTC as UTC - only right when the OTHER OS uses UTC (Linux/macOS), NOT Windows+Windows
    if ($rtcUtc -ne 1) {
        $offered = $true
        Write-Host "  Set the hardware clock to UTC only if your other OS is Linux/macOS. Skip it for Windows + Windows." -ForegroundColor DarkGray
        if ((Read-Host "  Set hardware clock to UTC? Type y") -match '^(y|yes)$') {
            Set-ItemProperty $tzKey -Name RealTimeIsUniversal -Value 1 -Type DWord
            Write-Host "    RealTimeIsUniversal=1 (Windows now reads the RTC as UTC)" -ForegroundColor DarkGray
            Write-Event 'OK' 'dual-boot: RTC set to UTC'
        } else { Write-Event 'SKIP' 'dual-boot: RTC left as local time' }
    }
    if (-not $offered) { Write-Host "  nothing to change - already dual-boot friendly" -ForegroundColor DarkGray }
    Write-Event 'INFO' "dual-boot state: winLoaders=$winLoaders fastStartup=$hiberboot hibernation=$hiberEnabled rtcUtc=$rtcUtc secureBoot=$secureBoot bitlocker=$blOn"
} else {
    Write-Host "    skipped dual-boot checks" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'dual-boot checks skipped by user'
}

# winget update policy: hold back packages released in the last 7 days (supply-chain soak).
Write-Host "`n=== winget update policy ===" -ForegroundColor Magenta
Set-WingetUpgradeDelay -Days 7

# Update installed apps (opt in)
Write-Host "`n=== Update installed apps (opt in) ===" -ForegroundColor Magenta
if ((Read-Host "Update all installed apps now? (winget upgrade --all) Type y (anything else skips)") -match '^(y|yes)$') {
    winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { Write-Host "    some upgrades reported issues (exit $LASTEXITCODE)" -ForegroundColor DarkGray }
    Write-Event 'INFO' "winget upgrade --all finished (exit $LASTEXITCODE)"
} else {
    Write-Host "    skipped app updates" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'winget upgrade --all skipped by user'
}

# Disk cleanup: superseded components, Windows Update cache, temp folders, Recycle Bin.
Write-Host "`n=== Disk cleanup ===" -ForegroundColor Magenta
$freeBefore = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
# 1) component store: drop superseded update payloads
Write-Host "==> DISM /StartComponentCleanup" -ForegroundColor Cyan
dism.exe /online /cleanup-image /startcomponentcleanup | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "    component cleanup exit $LASTEXITCODE (continuing)" -ForegroundColor DarkGray }
# 2) Windows Update download cache
Write-Host "==> Windows Update cache" -ForegroundColor Cyan
try {
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    $wuCache = Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
    if (Test-Path $wuCache) { Get-ChildItem $wuCache -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
    Start-Service wuauserv -ErrorAction SilentlyContinue
} catch { Write-Host "    update-cache step skipped ($($_.Exception.Message))" -ForegroundColor DarkGray }
# 3) temp folders (anything a running process holds open is skipped)
Write-Host "==> temp folders" -ForegroundColor Cyan
foreach ($t in @($env:TEMP, (Join-Path $env:SystemRoot 'Temp'))) {
    if ($t -and (Test-Path $t)) { Get-ChildItem $t -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
}
# 4) Recycle Bin
Write-Host "==> Recycle Bin" -ForegroundColor Cyan
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
$freeAfter = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
$freed = [math]::Round((($freeAfter - $freeBefore) / 1GB), 2)
if ($freed -gt 0) { Write-Host ("    freed about {0} GB on {1}" -f $freed, $env:SystemDrive) -ForegroundColor DarkGray }
else              { Write-Host  "    cleanup done" -ForegroundColor DarkGray }
Write-Event 'INFO' ("disk cleanup done (freed ~{0} GB)" -f $freed)

# External tweak tools
Write-Host "`n=== External tweak tools (opt in) ===" -ForegroundColor Magenta
Write-Host "Optional. Each runs in its own new window, so it can't clear or overwrite this one." -ForegroundColor DarkGray
if ((Read-Host "Configure any tweak tools? Type y to choose them one by one (anything else skips all)") -match '^(y|yes)$') {
    Invoke-Tool 'Win11Debloat (Raphire)' "& ([scriptblock]::Create((Invoke-RestMethod 'https://debloat.raphi.re/')))"
    Invoke-Tool 'Winhance'               "& ([scriptblock]::Create((Invoke-RestMethod 'https://get.winhance.net')))"
    Invoke-Tool 'PowerShellPerfect (your profile)' "& ([scriptblock]::Create((Invoke-RestMethod 'https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1'))) -SkipHashCheck"
} else {
    Write-Host "    skipped all tweak tools" -ForegroundColor DarkGray
    Write-Event 'SKIP' 'all tweak tools skipped'
}

# Restore point after setup.
Write-Host "`n=== System Restore point (after) ===" -ForegroundColor Magenta
New-SetupRestorePoint "After windows-setup ($stamp)"

# Summary
Write-Host "`n=====================================================" -ForegroundColor Green
if ($Failed.Count -eq 0) {
    Write-Host "No tracked failures." -ForegroundColor Green
} else {
    Write-Host "These need a manual look:" -ForegroundColor Yellow
    $Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
Write-Host "Reboot to finish Windows features + WSL2, then RE-RUN this script to complete any steps that were waiting on PATH/WSL." -ForegroundColor Cyan
Write-Host "After the reboot, verify: Windows features, 'wsl -l -v', and that the tweak tools ran." -ForegroundColor Cyan
if ($log) { Write-Host "Transcript: $log" -ForegroundColor DarkGray }
if ($eventLog) { Write-Host "Event log:  $eventLog" -ForegroundColor DarkGray }
Write-Host "=====================================================" -ForegroundColor Green

} finally {
    $mins = [Math]::Round(((Get-Date) - $runStart).TotalMinutes, 1)
    $tail = if ($Failed.Count) { ": $($Failed -join ', ')" } else { '' }
    Write-Event 'INFO' "run ended after $mins min - $($Failed.Count) tracked failure(s)$tail"
    if ($log) { Stop-Transcript | Out-Null }
}
