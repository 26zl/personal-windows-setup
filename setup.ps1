<#
  Personal Windows 11 Pro installer to run after a factory reset.
  Run in an ELEVATED PowerShell:
    irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1 | iex
  Add software by dropping its winget ID into a list below (winget search <name>).
  Re-running skips installed apps; failures are listed at the end and logged to %TEMP%.
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

# Run log
$log = Join-Path $env:TEMP ("windows-setup-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $log -Append | Out-Null } catch { $log = $null }

$Failed = @()
$WingetOk = 0, -1978335189, -1978335135

function Install-App {
    param([string]$Id, [string]$Source = 'winget')
    Write-Host "==> $Id" -ForegroundColor Cyan
    winget install --id $Id --exact --source $Source --silent --accept-source-agreements --accept-package-agreements
    if ($WingetOk -contains $LASTEXITCODE) { return }
    Write-Host "    FAILED: $Id (exit $LASTEXITCODE)" -ForegroundColor Yellow
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
        Write-Host "    skipped $Name" -ForegroundColor DarkGray; return
    }
    Write-Host "    launching in a new window - this window's output is preserved..." -ForegroundColor DarkGray
    $full = "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $Command"
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($full))
    $proc = Start-Process powershell -PassThru -Wait -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc)
    if ($proc.ExitCode -ne 0) { Write-Host "    $Name reported exit $($proc.ExitCode)" -ForegroundColor Yellow; $script:Failed += "$Name (external)" }
}

try {

# winget apps
$winget = @(
    # core dev
    'Microsoft.PowerShell'            # PowerShell 7
    'Microsoft.WindowsTerminal'
    'Git.Git'
    'GitHub.cli'
    'GitHub.GitHubDesktop'
    'Microsoft.VisualStudioCode'
    '7zip.7zip'
    'Microsoft.VCRedist.2015+.x64'    # C++ runtimes many apps need
    'Casey.Just'                      # command runner (justfiles)
    'jqlang.jq'                       # JSON processor
    'Google.PlatformTools'           # Android adb + fastboot

    # languages
    'Python.Python.3.13'
    'OpenJS.NodeJS.LTS'               # npm + corepack (yarn/pnpm)
    'GoLang.Go'
    'Rustlang.Rustup'
    'EclipseAdoptium.Temurin.21.JDK'  # Java 21 LTS
    'Microsoft.DotNet.SDK.8'
    'RubyInstallerTeam.Ruby.3.4'      # Ruby 3.4
    'StrawberryPerl.StrawberryPerl'

    # native build toolchains (C/C++, Rust MSVC, native node/python modules)
    'Microsoft.VisualStudio.2022.BuildTools'  # C++ toolset (VCTools workload) added below
    'LLVM.LLVM'
    'MSYS2.MSYS2'

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
    'Malwarebytes.AdwCleaner'
    'BleachBit.BleachBit'
    'lostindark.DriverStoreExplorer'

    # usb imaging / apps
    'Rufus.Rufus'
    'Balena.Etcher'
    'Valve.Steam'

    # communication
    'Discord.Discord'
)
Write-Host "`n=== winget apps ($($winget.Count)) ===" -ForegroundColor Magenta
foreach ($pkg in $winget) { Install-App $pkg }

# Tor Browser
Write-Host "==> TorProject.TorBrowser" -ForegroundColor Cyan
$torExe = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Tor Browser\Browser\firefox.exe'
if (Test-Path $torExe) {
    Write-Host "    already installed (skipped reinstall)" -ForegroundColor DarkGray
} else {
    Install-App 'TorProject.TorBrowser'
}

# MSVC C++ build toolset - the winget BuildTools package ships no workloads, so
# add VCTools here. --includeRecommended pulls the full native toolchain
# (cl.exe compiler, link.exe linker, CRT/STL, CMake/MSBuild, Windows SDK) that
# Rust MSVC, node-gyp and native Python modules all build against.
Write-Host "`n=== MSVC C++ build toolset ===" -ForegroundColor Magenta
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
$vswhere     = Join-Path $vsInstaller 'vswhere.exe'
$vsSetup     = Join-Path $vsInstaller 'setup.exe'
$vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
if (-not (Test-Path $vswhere)) {
    Write-Host "    vswhere not found - BuildTools didn't install; re-run after it does" -ForegroundColor Yellow
    $Failed += 'VC++ toolset (BuildTools missing)'
} else {
    $vcPath = & $vswhere -latest -products * -requires $vcComponent -property installationPath 2>$null
    if ($vcPath) {
        Write-Host "    already installed ($vcPath)" -ForegroundColor DarkGray
    } elseif (-not (Test-Path $vsSetup)) {
        Write-Host "    VS setup.exe not found (skipped)" -ForegroundColor Yellow
        $Failed += 'VC++ toolset (setup.exe missing)'
    } else {
        $btPath = & $vswhere -products 'Microsoft.VisualStudio.Product.BuildTools' -property installationPath 2>$null |
                  Select-Object -First 1
        if (-not $btPath) { $btPath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools' }
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
            if ($proc.ExitCode -eq 3010) { Write-Host "    reboot required to finish" -ForegroundColor Yellow }
        } else {
            Write-Host "    VCTools install failed (exit $($proc.ExitCode)) - component still missing" -ForegroundColor Yellow
            $Failed += 'VC++ toolset (VCTools workload)'
        }
    }
}

# Microsoft Store apps via winget
Write-Host "`n=== Store apps ===" -ForegroundColor Magenta
Install-App '9P7GGFL7DX57' 'msstore'   # Harden System Security
Install-App '9MSMLRH6LZF3' 'msstore'   # Windows Notepad
# AppControl Manager (same author): Install-App '9PNG1JDDTGP8' 'msstore'

# Microsoft Office
Write-Host "`n=== Microsoft Office ===" -ForegroundColor Magenta
$word = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\WINWORD.EXE'
if (Test-Path $word) {
    Write-Host "    already installed (skipped)" -ForegroundColor DarkGray
} else {
    $office = Join-Path $env:TEMP 'OfficeSetup.exe'
    try {
        Invoke-WebRequest 'https://github.com/26zl/personal-windows-setup/raw/main/office/OfficeSetup.exe' -OutFile $office -UseBasicParsing
        # verify Microsoft's Authenticode signature before running as admin
        $sig = Get-AuthenticodeSignature $office
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
            throw "signature check failed (status $($sig.Status))"
        }
        Write-Host "==> running OfficeSetup.exe" -ForegroundColor Cyan
        Start-Process $office -Wait
    } catch {
        Write-Host "    Office install failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $Failed += 'Microsoft Office'
    }
}

# Desktop shortcuts for portable GUI apps
Write-Host "`n=== Desktop shortcuts (portable apps) ===" -ForegroundColor Magenta
$desktop = [Environment]::GetFolderPath('Desktop')
$pkgRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
$portables = @{
    'OO-Software.ShutUp10'            = 'OOSU10.exe'
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

# Scoop
Write-Host "`n=== Scoop ===" -ForegroundColor Magenta
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Host "    already installed" -ForegroundColor DarkGray
} else {
    Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://get.scoop.sh))) -RunAsAdmin"
    if ($LASTEXITCODE -ne 0) { Write-Host "    Scoop reported exit $LASTEXITCODE" -ForegroundColor Yellow; $Failed += 'Scoop' }
}

# pipx
Write-Host "`n=== pipx ===" -ForegroundColor Magenta
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m pip install --user --upgrade pipx
    if ($LASTEXITCODE -eq 0) { python -m pipx ensurepath }
    else { Write-Host "    pipx install failed (exit $LASTEXITCODE)" -ForegroundColor Yellow; $Failed += 'pipx' }
} else {
    Write-Host "    python not on PATH yet - after reboot run: python -m pip install --user pipx" -ForegroundColor Yellow
    $Failed += 'pipx (python not found this run)'
}

# Windows features
Write-Host "`n=== Windows features ===" -ForegroundColor Magenta
if ((Get-CimInstance Win32_OperatingSystem).Caption -match 'Home') {
    Write-Host "    Sandbox + Hyper-V skipped - need Windows Pro/Enterprise/Education" -ForegroundColor DarkGray
} else {
    foreach ($f in 'Containers-DisposableClientVM','Microsoft-Hyper-V-All') {
        $info = dism.exe /online /get-featureinfo "/featurename:$f" 2>&1 | Out-String
        if ($info -match 'State\s*:\s*Enable') {
            Write-Host "    $f already enabled" -ForegroundColor DarkGray
            continue
        }
        dism.exe /online /enable-feature "/featurename:$f" /all /norestart | Out-Null
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-Host "    $f enabled (reboot to finish)" -ForegroundColor DarkGray
        } else {
            Write-Host "    feature failed: $f (dism exit $LASTEXITCODE)" -ForegroundColor Yellow
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
} else {
    wsl --install -d Debian
    if ($LASTEXITCODE -ne 0) { Write-Host "    WSL/Debian returned exit $LASTEXITCODE - verify after reboot: wsl -l -v" -ForegroundColor Yellow; $Failed += 'WSL2/Debian' }
}

# Claude Code
Write-Host "`n=== Claude Code (official native installer) ===" -ForegroundColor Magenta
Invoke-Child "& ([scriptblock]::Create((Invoke-RestMethod https://claude.ai/install.ps1)))"
if ($LASTEXITCODE -ne 0) { Write-Host "    Claude Code reported exit $LASTEXITCODE" -ForegroundColor Yellow; $Failed += 'Claude Code' }

# Update installed apps
Write-Host "`n=== Updating installed apps ===" -ForegroundColor Magenta
winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
if ($LASTEXITCODE -ne 0) { Write-Host "    some upgrades reported issues (exit $LASTEXITCODE)" -ForegroundColor DarkGray }

# Summary
Write-Host "`n=====================================================" -ForegroundColor Green
if ($Failed.Count -eq 0) {
    Write-Host "No tracked failures." -ForegroundColor Green
} else {
    Write-Host "These need a manual look:" -ForegroundColor Yellow
    $Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
Write-Host "Reboot to finish features and WSL2, then verify: Windows features, 'wsl -l -v', and that the tweak tools ran." -ForegroundColor Cyan
if ($log) { Write-Host "Full log: $log" -ForegroundColor DarkGray }
Write-Host "=====================================================" -ForegroundColor Green

# External tweak tools
Write-Host "`n=== External tweak tools (opt in) ===" -ForegroundColor Magenta
Write-Host "Optional. Each runs in its own new window, so it can't clear or overwrite this one." -ForegroundColor DarkGray
if ((Read-Host "Configure any tweak tools? Type y to choose them one by one (anything else skips all)") -match '^(y|yes)$') {
    Invoke-Tool 'Win11Debloat (Raphire)' "& ([scriptblock]::Create((Invoke-RestMethod 'https://debloat.raphi.re/')))"
    Invoke-Tool 'Winhance'               "& ([scriptblock]::Create((Invoke-RestMethod 'https://get.winhance.net')))"
    Invoke-Tool 'PowerShellPerfect (your profile)' "& ([scriptblock]::Create((Invoke-RestMethod 'https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1'))) -SkipHashCheck"
} else {
    Write-Host "    skipped all tweak tools" -ForegroundColor DarkGray
}

} finally {
    if ($log) { Stop-Transcript | Out-Null }
}
