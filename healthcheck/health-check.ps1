<#
  Windows health check - read-only diagnostics for any Windows 10/11 machine,
  laptop or desktop, physical or virtual. It changes NOTHING: every check is a
  Get-/Test-/query call, and every finding carries the command you would run to
  fix it yourself.

  Run it plain (more checks unlock when elevated, and it says which ones it skipped):
    irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1 | iex

  With options, or from a clone:
    & ([scriptblock]::Create((irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1))) -Category Security,Privacy
    .\health-check.ps1 -ReportPath .\health.md

  Categories: System Stability Drivers Storage Performance Power Network
              Security Privacy Updates Logging Software

  Severity means: Critical = acting now avoids data loss or an active compromise.
  High = a real hole or a fault you will notice. Medium = fix when convenient.
  Low = hygiene. Info = worth knowing, no action implied.

  OPTIONAL, OFF BY DEFAULT: -DeepBlueCliPath and -PrivescCheckPath delegate to two
  third-party audit tools, if you already have them. Nothing is downloaded and neither
  tool ships with this script. Passing a path is the point where "this changes nothing"
  stops being a promise about code you can read here and becomes a promise about
  someone else's - both are read-only by design, but you are the one choosing to trust
  them. PrivescCheck also writes a CSV report; it goes to a uniquely named temporary
  file and is deleted again when the run ends. That is the only disk write in this file.
#>

[CmdletBinding()]
# PSScriptAnalyzer cannot follow a script-scope parameter into a function defined later
# in the same file, so it reports these two as unused. They are read in
# Test-LoggingHealth and Test-SecurityHealth respectively.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeepBlueCliPath')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'PrivescCheckPath')]
param(
    # Which groups to run. 'All' is everything.
    [ValidateSet('All', 'System', 'Stability', 'Drivers', 'Storage', 'Performance',
        'Power', 'Network', 'Security', 'Privacy', 'Updates', 'Logging', 'Software')]
    [string[]]$Category = 'All',

    # Write a Markdown report here in addition to the console output.
    [string]$ReportPath,

    # Hide the per-check "OK" lines; show only findings and the summary.
    [switch]$FindingsOnly,

    # Skip the handful of checks that take several seconds each (SMART counters,
    # component store analysis, folder sizing).
    [switch]$Fast,

    # Path to a copy of DeepBlueCLI's DeepBlue.ps1 that you obtained and vetted yourself.
    # When given, it is run against the Security, System and PowerShell logs and its
    # findings are folded into the Logging category. Nothing is downloaded, and nothing
    # from DeepBlueCLI ships with this script - it is GPL-3.0 and this project is MIT,
    # so it is invoked as a separate program, which GPL explicitly permits.
    #   https://github.com/sans-blue-team/DeepBlueCLI
    [string]$DeepBlueCliPath,

    # Path to a copy of PrivescCheck.ps1 that you obtained and vetted yourself. When
    # given, it is run in -Audit mode and its findings are folded into the Security
    # category. Note that PrivescCheck deliberately skips many of its checks when run
    # elevated, so it gives more when this script is run as an ordinary user.
    #   https://github.com/itm4n/PrivescCheck
    [string]$PrivescCheckPath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Evidence comes from Windows, and on a non-English installation that text carries
# characters the console's default code page cannot render. A Norwegian update title
# came back as "Defender Antivirus a EUR" instead of an en dash, which makes the finding
# look corrupted and, worse, unsearchable. This is process-scoped - it changes the
# encoding of this PowerShell host's output stream and nothing on the machine - and it is
# wrapped because a redirected or non-interactive host has no console to configure.
try {
    if ([Console]::OutputEncoding.CodePage -ne 65001) {
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    }
} catch {
    Write-Verbose -Message 'Console output encoding could not be set; non-ASCII evidence may render incorrectly.'
}

# state

$script:Findings = New-Object System.Collections.ArrayList
$script:Healthy = New-Object System.Collections.ArrayList
$script:Skipped = New-Object System.Collections.ArrayList
$script:CurrentCategory = 'General'
$script:Ctx = @{}

# Copied to script scope so the helpers and checks can read them without depending
# on the caller's scope chain.
$script:QuietMode = $FindingsOnly.IsPresent
$script:FastMode = $Fast.IsPresent

$script:SeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$script:SeverityColor = @{ Critical = 'Magenta'; High = 'Red'; Medium = 'Yellow'; Low = 'DarkYellow'; Info = 'Gray' }

# helpers

function Add-Finding {
    <#
      Record one problem. Evidence must be the actual observed value, never a
      restatement of the title - a reader has to be able to check it themselves.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [string]$Impact = '',
        [string]$Fix = '',
        [ValidateSet('Certain', 'Likely', 'Uncertain')][string]$Confidence = 'Certain'
    )
    $null = $script:Findings.Add([PSCustomObject]@{
            Severity   = $Severity
            Category   = $script:CurrentCategory
            Title      = $Title
            Evidence   = $Evidence
            Impact     = $Impact
            Fix        = $Fix
            Confidence = $Confidence
        })
}

function Add-Ok {
    # Something explicitly verified as healthy. Users want to see what was cleared,
    # not just what failed.
    param([Parameter(Mandatory)][string]$Message)
    $null = $script:Healthy.Add([PSCustomObject]@{ Category = $script:CurrentCategory; Message = $Message })
    if (-not $script:QuietMode) { Write-Host "    OK  $Message" -ForegroundColor DarkGray }
}

function Add-Skip {
    # A check that could not run. Never silently drop one - an unrun check is not a pass.
    param([Parameter(Mandatory)][string]$Message)
    $null = $script:Skipped.Add([PSCustomObject]@{ Category = $script:CurrentCategory; Message = $Message })
    if (-not $script:QuietMode) { Write-Host "    --  $Message" -ForegroundColor DarkGray }
}

function Get-RegValue {
    # Registry read that returns $null instead of throwing when the key or value is absent.
    # -LiteralPath, not -Path: -Path treats [ and ] as wildcard character classes, and real
    # machines have registry keys with brackets in the name - Image File Execution Options
    # ships a subkey called "[.exe". With -Path those keys throw and the catch below turns
    # the failure into $null, so a check that walks them silently skips exactly the entries
    # an attacker would most like it to skip. No caller passes a wildcard.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Test-RegValue {
    # True when a registry value equals the expected value.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Expected)
    $v = Get-RegValue -Path $Path -Name $Name
    return ($null -ne $v -and $v -eq $Expected)
}

function Get-ServiceState {
    # Service state without the noise when the service does not exist on this SKU.
    param([Parameter(Mandatory)][string]$Name)
    try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
}

function Invoke-ExternalAudit {
    <#
      Runs a third-party read-only audit script the user pointed at, in a child
      PowerShell process, and hands back its output as lines.

      A child process rather than dot-sourcing, for three reasons: the other script's
      $ErrorActionPreference, its functions and any name collisions cannot reach into
      this run; a terminating error over there cannot take this run down; and its
      output cannot end up in one of our return values by accident. The cost is a few
      seconds of startup, which is acceptable for something that is opt-in anyway.

      This is the one place where the "changes nothing" promise stops being ours.
      Everything else here is a read the reader can verify in this file; this runs a
      program written by someone else. Both supported tools are read-only by design,
      but the caller is the one who decided to trust them, which is why nothing runs
      unless a path is passed explicitly and nothing is ever downloaded.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$Expression,
        [int]$TimeoutSeconds = 300
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        return [PSCustomObject]@{ Ok = $false; Reason = "the file does not exist: $ScriptPath"; Lines = @() }
    }

    # Windows PowerShell, not pwsh: both tools target 5.1 and neither is verified on 7.
    $hostExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $hostExe)) {
        return [PSCustomObject]@{ Ok = $false; Reason = 'Windows PowerShell was not found to run it in'; Lines = @() }
    }

    $stdOut = Join-Path ([IO.Path]::GetTempPath()) ("healthcheck-ext-{0}.out" -f [guid]::NewGuid().ToString('N'))
    $stdErr = [IO.Path]::ChangeExtension($stdOut, '.err')
    try {
        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', $Expression)
        $process = Start-Process -FilePath $hostExe -ArgumentList $arguments -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr -ErrorAction Stop
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { Write-Verbose -Message 'The external audit process had already exited.' }
            return [PSCustomObject]@{ Ok = $false; Reason = "it did not finish within $TimeoutSeconds seconds and was stopped"; Lines = @() }
        }
        $lines = @()
        if (Test-Path -LiteralPath $stdOut) { $lines = @(Get-Content -LiteralPath $stdOut -ErrorAction SilentlyContinue) }
        $errorText = ''
        if (Test-Path -LiteralPath $stdErr) { $errorText = (Get-Content -LiteralPath $stdErr -Raw -ErrorAction SilentlyContinue) }
        if ($process.ExitCode -ne 0 -and @($lines).Count -eq 0) {
            $firstError = (($errorText -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 1)
            return [PSCustomObject]@{ Ok = $false; Reason = "it exited with code $($process.ExitCode). $firstError"; Lines = @() }
        }
        return [PSCustomObject]@{ Ok = $true; Reason = ''; Lines = @($lines | Where-Object { $_ -and $_.Trim() }) }
    }
    catch {
        return [PSCustomObject]@{ Ok = $false; Reason = $_.Exception.Message; Lines = @() }
    }
    finally {
        foreach ($temp in @($stdOut, $stdErr)) {
            if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Format-Size {
    param([Parameter(Mandatory)][double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentCategory = $Name
    Write-Host ''
    Write-Host "== $Name " -NoNewline -ForegroundColor Cyan
    Write-Host ('=' * [Math]::Max(4, 62 - $Name.Length)) -ForegroundColor DarkCyan
}

function Invoke-Check {
    # Runs one category function. A crash inside a check must never abort the run -
    # it becomes a finding of its own so the gap stays visible.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    if ($script:Selected -notcontains $Name) { return }
    Write-Section $Name
    try { & $Body }
    catch {
        Add-Finding -Severity 'Low' -Title "The '$Name' check failed" `
            -Evidence $_.Exception.Message `
            -Impact 'This area was not covered - treat it as unchecked, not as healthy.' `
            -Fix 'Run the script again, and report the error if it keeps happening.' -Confidence 'Certain'
    }
}

# context

function Initialize-Context {
    <#
      Everything the checks need to know about the machine, gathered once.
      Checks branch on this instead of re-querying WMI, and use it to stay
      hardware-neutral: laptop-only checks read HasBattery, VM-only checks read IsVM.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:Ctx.IsAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $script:Ctx.OS = $os
    $script:Ctx.ComputerSystem = $cs
    $script:Ctx.Caption = if ($os) { $os.Caption } else { 'unknown' }
    $script:Ctx.Build = if ($os) { [int]$os.BuildNumber } else { 0 }
    $script:Ctx.UBR = Get-RegValue -Path $cv -Name 'UBR'
    $script:Ctx.DisplayVersion = Get-RegValue -Path $cv -Name 'DisplayVersion'
    $script:Ctx.IsWin11 = ($script:Ctx.Build -ge 22000)
    $script:Ctx.IsServer = ($script:Ctx.Caption -match 'Server')
    $script:Ctx.LastBoot = if ($os) { $os.LastBootUpTime } else { $null }
    $script:Ctx.UptimeHours = if ($os) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } else { 0 }
    $script:Ctx.TotalRamGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { 0 }
    $script:Ctx.LogicalCpus = if ($cs) { $cs.NumberOfLogicalProcessors } else { 0 }

    # Portable chassis types per the SMBIOS spec, plus a battery as corroboration.
    $portable = 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32
    $chassis = @()
    try { $chassis = (Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes } catch { $chassis = @() }
    # A failed Win32_Battery query and a machine with no battery both leave $null behind,
    # and treating them the same turns "we could not tell" into the assertion "this machine
    # has no battery". On a laptop with a damaged WMI repository that silently skips every
    # battery check with a message that is simply untrue, so track the failure separately.
    $script:Ctx.BatteryQueryFailed = $false
    try {
        $script:Ctx.Battery = @(Get-CimInstance Win32_Battery -ErrorAction Stop)
    } catch {
        $script:Ctx.Battery = @()
        $script:Ctx.BatteryQueryFailed = $true
    }
    $script:Ctx.HasBattery = (@($script:Ctx.Battery).Count -gt 0)
    $script:Ctx.IsLaptop = ($script:Ctx.HasBattery -or ($chassis | Where-Object { $portable -contains $_ }))

    $model = ''
    if ($cs) { $model = "$($cs.Manufacturer) $($cs.Model)" }
    $script:Ctx.IsVM = ($model -match 'Virtual|VMware|VirtualBox|KVM|Xen|QEMU|Parallels|Hyper-V')
    $script:Ctx.Model = $model.Trim()

    $script:Ctx.DomainJoined = if ($cs) { $cs.PartOfDomain } else { $false }
    $script:Ctx.PSVersion = $PSVersionTable.PSVersion.ToString()
    $script:Ctx.SystemDrive = $env:SystemDrive
}

# report

function Write-FindingReport {
    $bySeverity = $script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Category, Title

    Write-Host ''
    Write-Host ('=' * 66) -ForegroundColor Cyan
    Write-Host ' FINDINGS' -ForegroundColor Cyan
    Write-Host ('=' * 66) -ForegroundColor Cyan

    if (-not $bySeverity) {
        Write-Host ''
        Write-Host '  No findings. Everything that was checked is in order.' -ForegroundColor Green
        return
    }

    $lastSev = $null
    foreach ($f in $bySeverity) {
        if ($f.Severity -ne $lastSev) {
            Write-Host ''
            Write-Host "  $($f.Severity.ToUpper())" -ForegroundColor $script:SeverityColor[$f.Severity]
            $lastSev = $f.Severity
        }
        $tag = ''
        if ($f.Confidence -ne 'Certain') { $tag = " [$($f.Confidence.ToLower())]" }
        Write-Host ''
        Write-Host "  - [$($f.Category)] $($f.Title)$tag" -ForegroundColor $script:SeverityColor[$f.Severity]
        Write-Host "      Found  : $($f.Evidence)" -ForegroundColor Gray
        if ($f.Impact) { Write-Host "      Means  : $($f.Impact)" -ForegroundColor DarkGray }
        if ($f.Fix) { Write-Host "      Do     : $($f.Fix)" -ForegroundColor DarkGray }
    }
}

function Write-Summary {
    $counts = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $counts[$s] = @($script:Findings | Where-Object Severity -eq $s).Count
    }

    Write-Host ''
    Write-Host ('=' * 66) -ForegroundColor Cyan
    Write-Host ' SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 66) -ForegroundColor Cyan
    Write-Host ''
    foreach ($s in $counts.Keys) {
        if ($counts[$s] -gt 0) {
            Write-Host ("  {0,-9} {1}" -f $s, $counts[$s]) -ForegroundColor $script:SeverityColor[$s]
        }
    }
    Write-Host ("  {0,-9} {1}" -f 'Healthy', $script:Healthy.Count) -ForegroundColor Green
    if ($script:Skipped.Count) {
        Write-Host ("  {0,-9} {1}" -f 'Skipped', $script:Skipped.Count) -ForegroundColor DarkGray
    }

    if (-not $script:Ctx.IsAdmin) {
        Write-Host ''
        Write-Host '  Ran without administrator rights - several checks were skipped.' -ForegroundColor Yellow
        Write-Host '  Run in an elevated PowerShell for full coverage.' -ForegroundColor Yellow
    }
}

function Export-Report {
    param([Parameter(Mandatory)][string]$Path)

    $formFactor = 'desktop'
    if ($script:Ctx.IsVM) { $formFactor = 'virtual machine' } elseif ($script:Ctx.IsLaptop) { $formFactor = 'laptop' }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("# Health check - $env:COMPUTERNAME")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Run $(Get-Date -Format 'yyyy-MM-dd HH:mm') - $($script:Ctx.Caption) build $($script:Ctx.Build).$($script:Ctx.UBR) - $formFactor")
    $null = $sb.AppendLine()
    # The evidence lines are what make a finding actionable, and they are also what makes
    # this file identifying. Say so here rather than leaving the reader to discover it
    # after pasting the report into a forum thread or a support ticket.
    $null = $sb.AppendLine('> **Before you share this file:** the evidence lines below quote the machine as it')
    $null = $sb.AppendLine('> actually is. Depending on which findings fired that can include the computer and')
    $null = $sb.AppendLine('> user names, profile paths, the local network and its addresses, the Wi-Fi network')
    $null = $sb.AppendLine('> name, listening ports with the process behind each one, members of the local')
    $null = $sb.AppendLine('> Administrators group, installed software, and browser extension counts. Read it')
    $null = $sb.AppendLine('> through and remove what you do not want to hand over.')
    $null = $sb.AppendLine()

    $counts = @{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $counts[$s] = @($script:Findings | Where-Object Severity -eq $s).Count
    }
    $null = $sb.AppendLine('| Severity | Count |')
    $null = $sb.AppendLine('|---|---|')
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        if ($counts[$s]) { $null = $sb.AppendLine("| $s | $($counts[$s]) |") }
    }
    $null = $sb.AppendLine("| Healthy | $($script:Healthy.Count) |")
    if ($script:Skipped.Count) { $null = $sb.AppendLine("| Skipped | $($script:Skipped.Count) |") }
    $null = $sb.AppendLine()

    if ($script:Findings.Count) {
        $null = $sb.AppendLine('## Findings')
        $null = $sb.AppendLine()
        foreach ($f in ($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Category)) {
            $conf = ''
            if ($f.Confidence -ne 'Certain') { $conf = " *($($f.Confidence.ToLower()))*" }
            $null = $sb.AppendLine("### [$($f.Severity)] $($f.Title)$conf")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("*$($f.Category)*")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Found:** $($f.Evidence)")
            if ($f.Impact) { $null = $sb.AppendLine(); $null = $sb.AppendLine("**Means:** $($f.Impact)") }
            if ($f.Fix) { $null = $sb.AppendLine(); $null = $sb.AppendLine("**Do:** $($f.Fix)") }
            $null = $sb.AppendLine()
        }
    }

    if ($script:Healthy.Count) {
        $null = $sb.AppendLine('## Confirmed healthy')
        $null = $sb.AppendLine()
        foreach ($g in ($script:Healthy | Group-Object Category | Sort-Object Name)) {
            $null = $sb.AppendLine("**$($g.Name)**")
            $null = $sb.AppendLine()
            foreach ($h in $g.Group) { $null = $sb.AppendLine("- $($h.Message)") }
            $null = $sb.AppendLine()
        }
    }

    if ($script:Skipped.Count) {
        $null = $sb.AppendLine('## Not checked')
        $null = $sb.AppendLine()
        foreach ($s in $script:Skipped) { $null = $sb.AppendLine("- [$($s.Category)] $($s.Message)") }
        $null = $sb.AppendLine()
    }

    try {
        [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
        Write-Host ''
        Write-Host "  Report written: $Path" -ForegroundColor Green
    } catch {
        Write-Host ''
        Write-Host "  Could not write the report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# checks
# One function per category. Each is read-only, never throws, and reports what
# it could not check instead of silently passing.

# Category "System": version and support window, activation, reboot state, uptime,
# time sync, page file, environment and user profile integrity.
# Version is taken from the build number, never ProductName - that value still reads
# "Windows 10 Pro" on build 26200. Time sync is read from the registry because
# "w32tm /query" prints failures to stdout and exits non-zero when the service is stopped.
function Test-SystemHealth {
    [CmdletBinding()]
    param()

    $ctx = $script:Ctx
    if ($null -eq $ctx) {
        Add-Skip -Message 'System: the precomputed machine context is missing, the whole category was skipped.'
        return
    }

    $now = Get-Date

    # 1. Windows version
    $build = 0
    if ($null -ne $ctx.Build) { $build = [int]$ctx.Build }
    $displayVersion = [string]$ctx.DisplayVersion
    if ([string]::IsNullOrWhiteSpace($displayVersion)) { $displayVersion = 'unknown release' }
    $ubrText = ''
    if ($null -ne $ctx.UBR) { $ubrText = ".$($ctx.UBR)" }
    $psVersionText = [string]$ctx.PSVersion
    if ([string]::IsNullOrWhiteSpace($psVersionText)) { $psVersionText = 'unknown version' }

    Add-Finding -Severity Info -Title 'Windows version and patch level' `
        -Evidence "$($ctx.Caption), $displayVersion, build $build$ubrText, PowerShell $psVersionText" `
        -Impact 'The build number decides which security updates the machine can still receive.' `
        -Confidence Certain

    # 2. Is the build still supported?
    # LTSC releases have their own, far longer lifecycles and share build numbers with
    # ordinary releases (19044 is both 21H2 and LTSC 2021), so they must stay out of the matrix.
    $editionId = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID')
    $isLtsc = ($editionId -match 'Enterprise' -and $editionId -match 'S[N]?$')

    # Enterprise, Education and IoT Enterprise get a longer lifecycle than Home and Pro on
    # the same build, so a single date per build would report a supported Enterprise machine
    # as expired. This table is the only lifecycle data in the script - the update check
    # deliberately does not carry a second copy.
    $eosTable = @{
        19041 = @{ Name = 'Windows 10 2004';  Client = '2021-12-14'; Long = '2021-12-14' }
        19042 = @{ Name = 'Windows 10 20H2';  Client = '2022-05-10'; Long = '2023-05-09' }
        19043 = @{ Name = 'Windows 10 21H1';  Client = '2022-12-13'; Long = '2022-12-13' }
        19044 = @{ Name = 'Windows 10 21H2';  Client = '2023-06-13'; Long = '2024-06-11' }
        19045 = @{ Name = 'Windows 10 22H2';  Client = '2025-10-14'; Long = '2025-10-14' }
        22000 = @{ Name = 'Windows 11 21H2';  Client = '2023-10-10'; Long = '2024-10-08' }
        22621 = @{ Name = 'Windows 11 22H2';  Client = '2024-10-08'; Long = '2025-10-14' }
        22631 = @{ Name = 'Windows 11 23H2';  Client = '2025-11-11'; Long = '2026-11-10' }
        26100 = @{ Name = 'Windows 11 24H2';  Client = '2026-10-13'; Long = '2027-10-12' }
        26200 = @{ Name = 'Windows 11 25H2';  Client = '2027-10-12'; Long = '2028-10-10' }
        # 26H1 ships only on new hardware - it is not offered as an in-place update from
        # 24H2 or 25H2 - so it turns up on new machines rather than through Windows Update.
        28000 = @{ Name = 'Windows 11 26H1';  Client = '2028-03-14'; Long = '2029-03-13' }
    }

    if ($ctx.IsServer) {
        Add-Skip -Message 'Support date: the machine runs Windows Server, and the client end-of-support matrix does not apply.'
    }
    elseif ($isLtsc) {
        Add-Skip -Message "Support date: LTSC release ($editionId) has its own, considerably longer lifecycle than ordinary releases, and was not evaluated."
    }
    elseif ($eosTable.ContainsKey($build)) {
        $entry = $eosTable[$build]
        $isLongLife = ($editionId -match 'Enterprise|Education|IoT')
        $eosText = if ($isLongLife) { $entry.Long } else { $entry.Client }
        $eosDate = $null
        try {
            $eosDate = [datetime]::ParseExact($eosText, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        }
        catch {
            $eosDate = $null  # an invalid table entry must never take down the check
        }

        if ($null -eq $eosDate) {
            Add-Skip -Message "Support date: could not parse the end-of-support date for build $build."
        }
        else {
            $daysLeft = [math]::Round(($eosDate - $now).TotalDays)
            $dateText = $eosDate.ToString('dd.MM.yyyy')
            $label = "$($entry.Name) (build $build, edition $editionId)"
            if ($daysLeft -lt 0) {
                Add-Finding -Severity High -Title 'This Windows version probably no longer gets security updates' `
                    -Evidence "$label - end-of-support date $dateText, that is $([math]::Abs($daysLeft)) days ago." `
                    -Impact 'New Windows vulnerabilities are not fixed, and the machine gets gradually easier to compromise.' `
                    -Fix 'Upgrade via Settings > Windows Update, or use the Windows Installation Assistant. Confirm the date at learn.microsoft.com/lifecycle - it moves now and then. If the machine has a paid ESU subscription, this finding does not apply.' `
                    -Confidence Likely
            }
            elseif ($daysLeft -lt 180) {
                Add-Finding -Severity Medium -Title 'This Windows version is approaching end of support' `
                    -Evidence "$label - end-of-support date $dateText, roughly $daysLeft days from now." `
                    -Impact 'After that date there are no more security updates for this release.' `
                    -Fix 'Plan an upgrade to the latest feature update via Settings > Windows Update. Confirm the date at learn.microsoft.com/lifecycle.' `
                    -Confidence Likely
            }
            else {
                Add-Ok -Message "$($entry.Name) is still supported for roughly $daysLeft more days (listed end date $dateText)."
            }
        }
    }
    else {
        Add-Skip -Message "Support date: build number $build is not in the built-in table (preview or newer release), and was not evaluated."
    }

    # 3. Activation
    # Filter on Windows' own ApplicationID: without it, Office licenses come along too.
    try {
        $winFilter = "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
        $licenses = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $winFilter -ErrorAction Stop)
        if ($licenses.Count -eq 0) {
            Add-Skip -Message 'Activation: found no Windows license with a product key to evaluate.'
        }
        else {
            $lic = $licenses[0]
            $status = [int]$lic.LicenseStatus
            $graceDays = [math]::Round(([double]$lic.GracePeriodRemaining) / 1440, 1)
            $licName = [string]$lic.Name
            switch ($status) {
                1 {
                    Add-Ok -Message "Windows is activated ($licName)."
                }
                0 {
                    Add-Finding -Severity High -Title 'Windows is not activated' `
                        -Evidence "LicenseStatus = 0 (Unlicensed) for $licName." `
                        -Impact 'Personalization is locked, a persistent activation notice is shown, and some updates may not arrive.' `
                        -Fix 'Settings > System > Activation. Check that the right product key or digital license is tied to the machine.' `
                        -Confidence Certain
                }
                5 {
                    Add-Finding -Severity High -Title 'Windows activation is in notification state' `
                        -Evidence "LicenseStatus = 5 (Notification) for $licName." `
                        -Impact 'Windows considers itself unactivated and shows persistent notifications.' `
                        -Fix 'Settings > System > Activation > Troubleshoot.' `
                        -Confidence Certain
                }
                4 {
                    Add-Finding -Severity High -Title 'The Windows license is not considered genuine' `
                        -Evidence "LicenseStatus = 4 (Non-Genuine Grace) for $licName, $graceDays days left of the grace period." `
                        -Impact 'The machine loses activation when the grace period runs out, and the license may be invalid.' `
                        -Fix 'Settings > System > Activation. Get a valid license, or contact the vendor of the machine.' `
                        -Confidence Certain
                }
                default {
                    Add-Finding -Severity Medium -Title 'Windows activation is in a temporary grace period' `
                        -Evidence "LicenseStatus = $status for $licName, $graceDays days left of the grace period." `
                        -Impact 'When the grace period runs out, the machine drops to unactivated state.' `
                        -Fix 'Settings > System > Activation, and complete the activation.' `
                        -Confidence Likely
                }
            }
        }
    }
    catch {
        Add-Skip -Message "Activation: could not read SoftwareLicensingProduct ($($_.Exception.Message))."
    }

    # 4. Pending reboot
    $rebootReasons = @()
    $hardPending = $false
    try {
        if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
            $rebootReasons += 'the component store (CBS RebootPending)'
            $hardPending = $true
        }
        if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
            $rebootReasons += 'Windows Update (RebootRequired)'
            $hardPending = $true
        }
    }
    catch {
        # missing read access to the key must not stop the rest of the category
        Write-Verbose "Could not read the pending reboot marker: $($_.Exception.Message)"
    }

    $pfroValue = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    $pfroCount = @($pfroValue | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
    if ($pfroCount -gt 0) { $rebootReasons += "$pfroCount queued file operation(s)" }

    $uptimeHours = 0.0
    if ($null -ne $ctx.UptimeHours) { $uptimeHours = [double]$ctx.UptimeHours }
    $uptimeText = "$([math]::Round($uptimeHours, 1)) hours"
    if ($uptimeHours -ge 48) { $uptimeText = "$([math]::Round($uptimeHours / 24, 1)) days" }

    if ($rebootReasons.Count -eq 0) {
        Add-Ok -Message 'No pending reboot: neither the component store, Windows Update nor the file queue needs a restart.'
    }
    elseif ($hardPending) {
        # The marker is set after the last boot, so uptime is the upper bound on the wait.
        $rebootSeverity = 'Medium'
        if ($uptimeHours -gt 72) { $rebootSeverity = 'High' }
        Add-Finding -Severity $rebootSeverity -Title 'The machine is waiting for a restart to finish updates' `
            -Evidence "Flagged by: $($rebootReasons -join ', '). Has been waiting up to $uptimeText, which is the time since the last boot." `
            -Impact 'Updates are only half installed. New updates can fail, and security fixes only take effect after a restart.' `
            -Fix 'Restart the machine via Start > Power > Restart.' `
            -Confidence Certain
    }
    else {
        # PendingFileRenameOperations on its own is very common after completely normal
        # installs, and rarely means anything is wrong.
        Add-Finding -Severity Low -Title 'File operations are queued for the next restart' `
            -Evidence "$pfroCount entry(ies) in PendingFileRenameOperations. No marker from CBS or Windows Update." `
            -Impact 'Normally harmless, and clears itself on the next restart. Some installers still refuse to run until the queue is empty.' `
            -Fix 'Restart the machine when it suits you.' `
            -Confidence Likely
    }

    # 5. Uptime
    if ($uptimeHours -le 0) {
        Add-Skip -Message 'Uptime: could not read the time of the last boot.'
    }
    elseif ($uptimeHours -gt 720) {
        Add-Finding -Severity Medium -Title 'Very long uptime without a restart' `
            -Evidence "The machine has been up for $uptimeText, since $($ctx.LastBoot)." `
            -Impact 'Cumulative updates need a restart to take effect, so the machine is probably running half-patched components.' `
            -Fix 'Restart the machine, then run Settings > Windows Update.' `
            -Confidence Certain
    }
    elseif ($uptimeHours -gt 336) {
        Add-Finding -Severity Low -Title 'Long uptime' `
            -Evidence "The machine has been up for $uptimeText, since $($ctx.LastBoot)." `
            -Impact 'Monthly updates only complete on a restart.' `
            -Fix 'Restart the machine at a suitable moment.' `
            -Confidence Likely
    }
    else {
        Add-Ok -Message "Uptime of $uptimeText is within the normal range."
    }

    # 6. Unexpected restarts
    if ($Fast) {
        Add-Skip -Message 'Unexpected restarts: the event log was not read because fast mode is selected.'
    }
    else {
        # Get-WinEvent also throws when the filter matches nothing, so "no crashes" and
        # "the log cannot be read" look exactly the same. The log must therefore be checked
        # separately, otherwise a healthy machine gets reported as "skipped".
        $systemLogReadable = $false
        try {
            $systemLogReadable = $null -ne (Get-WinEvent -ListLog 'System' -ErrorAction Stop)
        }
        catch {
            $systemLogReadable = $false  # the log does not exist or is unavailable
        }

        if (-not $systemLogReadable) {
            Add-Skip -Message 'Unexpected restarts: the System log could not be read, so Kernel-Power events were not evaluated.'
        }
        else {
            $crashCount = 0
            $lastCrash = $null
            try {
                $crashEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; StartTime = $now.AddDays(-14) } -MaxEvents 40 -ErrorAction Stop)
                $crashCount = $crashEvents.Count
                if ($crashCount -gt 0) { $lastCrash = $crashEvents[0].TimeCreated }
            }
            catch {
                $crashCount = 0  # no matches on the filter means no unexpected restarts
            }

            if ($crashCount -ge 3) {
                Add-Finding -Severity Medium -Title 'The machine has shut down unexpectedly several times' `
                    -Evidence "$crashCount events with ID 41 (Kernel-Power) in the System log over the last 14 days. Most recent: $lastCrash." `
                    -Impact 'Points to power loss, bluescreens or hardware faults. Repeated hard shutdowns can damage the file system over time.' `
                    -Fix 'See the details with: Get-WinEvent -FilterHashtable @{LogName="System";Id=41} -MaxEvents 10 | Format-List TimeCreated,Message' `
                    -Confidence Likely
            }
            else {
                Add-Ok -Message "No sign of repeated unexpected restarts ($crashCount Kernel-Power events over the last 14 days)."
            }
        }
    }

    # 7. System clock
    # Without a network there is no ground truth for the correct time, but the clock can be
    # held against the install date: it can never be older than the installation.
    $tzId = 'unknown time zone'
    try {
        $tzId = [string](Get-TimeZone -ErrorAction Stop).Id
    }
    catch {
        $tzId = 'unknown time zone'  # Get-TimeZone is missing in some stripped-down installs
    }

    $installDate = $null
    if ($null -ne $ctx.OS) { $installDate = $ctx.OS.InstallDate }
    if ($null -eq $installDate) {
        Add-Skip -Message 'System clock: the install date is missing, so the clock could not be sanity checked.'
    }
    elseif ($now -lt $installDate) {
        Add-Finding -Severity High -Title 'The system clock is earlier than the install date' `
            -Evidence "The clock reads $($now.ToString('dd.MM.yyyy HH:mm')), while Windows was installed $(([datetime]$installDate).ToString('dd.MM.yyyy'))." `
            -Impact 'A wrong clock causes certificate errors on websites, blocks Windows Update and can prevent sign-in to online services.' `
            -Fix 'Settings > Time & language > Date & time: turn on "Set time automatically". If the clock is wrong on every boot, the motherboard battery needs replacing.' `
            -Confidence Certain
    }
    else {
        Add-Ok -Message "The system clock is plausible: $($now.ToString('dd.MM.yyyy HH:mm')), time zone $tzId."
    }

    # 8. Time synchronization
    $w32 = Get-ServiceState -Name 'W32Time'
    if ($null -eq $w32) {
        Add-Skip -Message 'Time synchronization: the W32Time service does not exist on this machine.'
    }
    elseif ([string]$w32.StartType -eq 'Disabled') {
        Add-Finding -Severity Medium -Title 'Time synchronization is disabled' `
            -Evidence "The W32Time service has start type Disabled (status: $($w32.Status))." `
            -Impact 'The clock drifts freely. Over time that gives certificate errors and problems with sign-in and updates.' `
            -Fix 'Settings > Time & language > Date & time > "Set time automatically".' `
            -Confidence Certain
    }
    else {
        # W32Time is trigger started and normally sits stopped between synchronizations,
        # so the service status says nothing. The last successful sync is what counts.
        $lastGood = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name 'LastKnownGoodTime'
        $syncAgeDays = $null
        if ($null -ne $lastGood) {
            try {
                $syncAgeDays = [math]::Round(($now - [datetime]::FromFileTime([int64]$lastGood)).TotalDays, 1)
            }
            catch {
                $syncAgeDays = $null  # an invalid FILETIME is treated as unknown
            }
        }

        if ($null -eq $syncAgeDays) {
            Add-Skip -Message "Time synchronization: the service is available ($($w32.StartType)), but the time of the last successful synchronization could not be read."
        }
        elseif ($syncAgeDays -gt 60) {
            Add-Finding -Severity Low -Title 'The clock has not synchronized in a long time' `
                -Evidence "The last successful time synchronization was $syncAgeDays days ago (W32Time LastKnownGoodTime)." `
                -Impact 'The clock may have drifted noticeably. Large deviations give certificate and sign-in errors.' `
                -Fix 'Settings > Time & language > Date & time > "Sync now".' `
                -Confidence Uncertain
        }
        else {
            Add-Ok -Message "Time synchronization works: last successful synchronization $syncAgeDays days ago."
        }
    }

    # 9. Virtualization
    $hypervisorPresent = $false
    if ($null -ne $ctx.ComputerSystem -and $null -ne $ctx.ComputerSystem.HypervisorPresent) {
        $hypervisorPresent = [bool]$ctx.ComputerSystem.HypervisorPresent
    }

    if ($ctx.IsVM) {
        Add-Finding -Severity Info -Title 'The machine runs as a virtual machine' `
            -Evidence "Model: $($ctx.Model). Several hardware-level checks are not meaningful here." `
            -Impact 'Power management, disk health and firmware settings are controlled by the host, not by this installation.' `
            -Confidence Certain
        Add-Skip -Message 'Hardware virtualization: nested virtualization is reported unreliably inside a virtual machine, and was not evaluated.'
    }
    elseif ($hypervisorPresent) {
        # With a hypervisor active, Win32_Processor reports both SLAT and
        # virtualization status wrong, so the CPU fields are deliberately not read here.
        Add-Ok -Message 'Hardware virtualization is in use: a hypervisor is already running (Hyper-V, WSL2, VBS or Memory integrity).'
    }
    else {
        try {
            $cpu = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)[0]
            if ($null -eq $cpu.VirtualizationFirmwareEnabled) {
                Add-Skip -Message 'Hardware virtualization: the processor reports no firmware status for virtualization.'
            }
            elseif (-not $cpu.VirtualizationFirmwareEnabled) {
                Add-Finding -Severity Low -Title 'Hardware virtualization looks turned off in firmware' `
                    -Evidence "Win32_Processor.VirtualizationFirmwareEnabled = False on $($cpu.Name)." `
                    -Impact 'Without it, neither WSL2, Hyper-V, Android emulators nor Windows Memory integrity (VBS) can run.' `
                    -Fix 'Turn on SVM Mode (AMD) or Intel VT-x in UEFI/BIOS. If you need none of them, the finding can be ignored.' `
                    -Confidence Likely
            }
            else {
                Add-Ok -Message 'Hardware virtualization is available in firmware (VT-x/AMD-V).'
            }
        }
        catch {
            Add-Skip -Message 'Hardware virtualization: could not read Win32_Processor.'
        }
    }

    # 10. Page file
    try {
        $pageUsage = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)
        $autoManaged = $false
        if ($null -ne $ctx.ComputerSystem -and $null -ne $ctx.ComputerSystem.AutomaticManagedPagefile) {
            $autoManaged = [bool]$ctx.ComputerSystem.AutomaticManagedPagefile
        }
        $sysDrive = [string]$ctx.SystemDrive
        if ([string]::IsNullOrWhiteSpace($sysDrive)) { $sysDrive = 'C:' }

        if ($pageUsage.Count -eq 0) {
            if ($autoManaged) {
                Add-Skip -Message 'Page file: set to system managed, but no active file was reported yet (common right after boot).'
            }
            else {
                Add-Finding -Severity Medium -Title 'The machine has no page file' `
                    -Evidence 'Win32_PageFileUsage returned no page file, and automatic management is turned off.' `
                    -Impact 'Programs can crash with "out of memory" before RAM is actually full, and Windows cannot write a memory dump on a bluescreen.' `
                    -Fix 'System Properties > Advanced > Performance > Settings > Advanced > Virtual memory: tick "Automatically manage paging file size for all drives".' `
                    -Confidence Likely
            }
        }
        else {
            $pf = $pageUsage[0]
            $pfSize = Format-Size -Bytes ([double]$pf.AllocatedBaseSize * 1MB)
            $pfPeak = Format-Size -Bytes ([double]$pf.PeakUsage * 1MB)
            if (-not ([string]$pf.Name).StartsWith($sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
                Add-Finding -Severity Info -Title 'The page file is outside the system drive' `
                    -Evidence "Page file: $($pf.Name) at $pfSize. The system drive is $sysDrive" `
                    -Impact 'Windows needs a page file on the system drive to be able to write a memory dump after a bluescreen.' `
                    -Fix 'Add a system managed page file on the system drive under Virtual memory if you want to be able to debug bluescreens.' `
                    -Confidence Likely
            }
            elseif ($autoManaged) {
                Add-Ok -Message "The page file is system managed and sits on the system drive ($($pf.Name), $pfSize, peak usage $pfPeak)."
            }
            else {
                Add-Finding -Severity Info -Title 'The page file has a manually set size' `
                    -Evidence "$($pf.Name), allocated $pfSize, highest recorded usage $pfPeak." `
                    -Impact 'A manual size set too low gives memory errors under peak load, and Windows cannot grow it on its own.' `
                    -Fix 'Compare peak usage against the allocated size under Virtual memory, or let Windows manage the size.' `
                    -Confidence Likely
            }
        }
    }
    catch {
        Add-Skip -Message "Page file: could not read Win32_PageFileUsage ($($_.Exception.Message))."
    }

    # 11. User profiles
    # Status is a bit field: 1 = temporary, 2 = roaming, 4 = mandatory,
    # 8 = corrupt. Roaming and mandatory are normal choices, not faults, so a
    # test on "Status <> 0" would false alarm on every single roaming machine.
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })
        $badProfiles = @($profiles | Where-Object { ((([int]$_.Status) -band 1) -ne 0) -or ((([int]$_.Status) -band 8) -ne 0) })
        if ($badProfiles.Count -gt 0) {
            $profileDetail = ($badProfiles | ForEach-Object { "$($_.LocalPath) (Status=$($_.Status))" }) -join '; '
            Add-Finding -Severity High -Title 'A user profile is temporary or damaged' `
                -Evidence "$($badProfiles.Count) of $($profiles.Count) profiles: $profileDetail" `
                -Impact 'With a temporary profile, desktop, documents and settings disappear at every sign-out.' `
                -Fix 'Sign out and back in. If it persists, the profile entry under HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList has to be repaired by an administrator.' `
                -Confidence Certain
        }
        else {
            Add-Ok -Message "All $($profiles.Count) user profiles have normal status."
        }
    }
    catch {
        Add-Skip -Message "User profiles: could not read Win32_UserProfile ($($_.Exception.Message))."
    }

    try {
        $bakProfiles = @(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop |
                Where-Object { $_.PSChildName -like '*.bak' })
        if ($bakProfiles.Count -gt 0) {
            $bakNames = ($bakProfiles | ForEach-Object { $_.PSChildName }) -join ', '
            Add-Finding -Severity Medium -Title 'Leftover .bak entries for user profiles' `
                -Evidence "$($bakProfiles.Count) entry(ies) in ProfileList end in .bak: $bakNames" `
                -Impact 'Typically a trace of a profile Windows failed to load. The affected user can end up signed in with a temporary profile.' `
                -Fix 'Check that the affected user actually gets their own profile at sign-in. Cleaning up ProfileList should be done by an administrator with a backup.' `
                -Confidence Likely
        }
        else {
            Add-Ok -Message 'No leftover .bak profile entries in the registry.'
        }
    }
    catch {
        Add-Skip -Message 'User profiles: could not read ProfileList in the registry.'
    }

    # 12. System drive
    $sysDriveLetter = ([string]$ctx.SystemDrive).TrimEnd(':', '\')
    if ([string]::IsNullOrWhiteSpace($sysDriveLetter)) { $sysDriveLetter = 'C' }
    try {
        $vol = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$sysDriveLetter`:'" -ErrorAction Stop
        $fsName = ''
        $freeBytes = 0.0
        $totalBytes = 0.0
        if ($null -ne $vol) {
            $fsName = [string]$vol.FileSystem
            $freeBytes = [double]$vol.FreeSpace
            $totalBytes = [double]$vol.Size
        }

        if ([string]::IsNullOrWhiteSpace($fsName)) {
            Add-Skip -Message "System drive: could not read the file system on $sysDriveLetter`:."
        }
        elseif ($fsName -ne 'NTFS') {
            Add-Finding -Severity High -Title 'The system drive does not use NTFS' `
                -Evidence "$sysDriveLetter`: is formatted with $fsName." `
                -Impact 'Without NTFS there are no file permissions, no journaling and no BitLocker support, and Windows features can fail unpredictably.' `
                -Fix 'Check that the right drive is registered as the system drive. Changing the file system requires a reinstall.' `
                -Confidence Likely
        }
        elseif ($totalBytes -gt 0) {
            # Free space is judged once, in the Storage category, which grades every volume
            # against the same thresholds. Reporting it here as well produced two findings
            # for one fact on a machine that was actually short of space - a Critical from
            # Storage and a High from System, worded differently, both about the same drive.
            # The healthy line stays, because it names the file system as well.
            $freePct = [math]::Round(($freeBytes / $totalBytes) * 100, 1)
            if ($freePct -ge 15) {
                Add-Ok -Message "System drive $sysDriveLetter`: is NTFS with $(Format-Size -Bytes $freeBytes) free, that is $freePct percent."
            }
        }
        else {
            Add-Ok -Message "System drive $sysDriveLetter`: is formatted with NTFS."
        }
    }
    catch {
        Add-Skip -Message "System drive: could not read Win32_LogicalDisk for $sysDriveLetter`:."
    }

    # 13. Boot mode (UEFI or legacy BIOS)
    $firmwareType = [string]$env:firmware_type
    if ([string]::IsNullOrWhiteSpace($firmwareType)) {
        Add-Skip -Message 'Boot mode: the firmware_type environment variable is not set, so UEFI or BIOS could not be determined.'
    }
    elseif ($firmwareType -eq 'Legacy') {
        Add-Finding -Severity Medium -Title 'The machine boots in legacy BIOS mode, not UEFI' `
            -Evidence 'firmware_type = Legacy, so the partition layout is MBR.' `
            -Impact 'Secure Boot, TPM-based BitLocker and upgrading to Windows 11 all require UEFI. The machine is missing a whole layer of boot protection.' `
            -Fix 'Look into whether the disk can be converted with MBR2GPT (take a backup first), then select UEFI mode in firmware.' `
            -Confidence Likely
    }
    else {
        Add-Ok -Message "The machine boots in UEFI mode ($firmwareType)."
    }

    # 14. Runtime environment
    $netRelease = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release'
    if ($null -eq $netRelease) {
        Add-Skip -Message 'NET Framework: found no Release value for .NET Framework 4.x.'
    }
    elseif ([int]$netRelease -lt 528040) {
        Add-Finding -Severity Low -Title 'NET Framework is older than 4.8' `
            -Evidence "Release = $netRelease, where 4.8 means 528040 or higher." `
            -Impact '.NET Framework 4.8 is the version that still gets security updates. Older versions do not.' `
            -Fix 'Install .NET Framework 4.8 from Microsoft, or run Windows Update.' `
            -Confidence Likely
    }
    else {
        Add-Ok -Message "NET Framework 4.8 or newer is installed (Release $netRelease)."
    }

    $psMajor = 0
    if ($null -ne $ctx.PSVersion) {
        try {
            $psMajor = [int]([version][string]$ctx.PSVersion).Major
        }
        catch {
            $psMajor = 0  # an unexpected version format is treated as "not PowerShell 7"
        }
    }
    if ($psMajor -ge 7) {
        Add-Ok -Message "PowerShell $psVersionText is in use."
    }
    elseif ($null -ne (Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue)) {
        Add-Ok -Message "The tool runs under Windows PowerShell $psVersionText, and PowerShell 7 is also installed."
    }
    else {
        Add-Finding -Severity Info -Title 'Only Windows PowerShell 5.1 is installed' `
            -Evidence "PowerShell $psVersionText, and no pwsh.exe was found in PATH." `
            -Impact 'Windows PowerShell 5.1 is fully supported and safe to use, but gets no new features.' `
            -Fix 'If you want the newest version: winget install Microsoft.PowerShell' `
            -Confidence Certain
    }

    try {
        $policies = @(Get-ExecutionPolicy -List -ErrorAction Stop | Where-Object { $_.Scope -eq 'LocalMachine' -or $_.Scope -eq 'CurrentUser' })
        $loosePolicies = @($policies | Where-Object { [string]$_.ExecutionPolicy -eq 'Unrestricted' -or [string]$_.ExecutionPolicy -eq 'Bypass' })
        if ($loosePolicies.Count -gt 0) {
            $policyDetail = ($loosePolicies | ForEach-Object { "$($_.Scope) = $($_.ExecutionPolicy)" }) -join '; '
            $policySeverity = 'Low'
            if (@($loosePolicies | Where-Object { [string]$_.Scope -eq 'LocalMachine' }).Count -gt 0) { $policySeverity = 'Medium' }
            Add-Finding -Severity $policySeverity -Title 'Script execution policy is set low' `
                -Evidence $policyDetail `
                -Impact 'Downloaded PowerShell scripts run without a warning, so a script from email or the web can be started by accident.' `
                -Fix 'Set it back to the default in a PowerShell started as administrator: Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned' `
                -Confidence Likely
        }
        else {
            Add-Ok -Message 'Script execution policy is at the default or stricter.'
        }
    }
    catch {
        Add-Skip -Message 'Execution policy: the Microsoft.PowerShell.Security module could not be loaded, so the policy was not read.'
    }

    # 15. Domain membership
    if ($ctx.DomainJoined) {
        $domainName = 'unknown domain'
        if ($null -ne $ctx.ComputerSystem -and -not [string]::IsNullOrWhiteSpace([string]$ctx.ComputerSystem.Domain)) {
            $domainName = [string]$ctx.ComputerSystem.Domain
        }
        Add-Finding -Severity Info -Title 'The machine is a member of a domain' `
            -Evidence "Domain: $domainName" `
            -Impact 'Group Policy from the domain can override local settings, so several findings here may be deliberate choices by the IT department.' `
            -Confidence Certain
    }
    else {
        Add-Ok -Message 'The machine is a standalone workgroup machine with no domain policies.'
    }
}

<#
  Stability - blue screens, unexpected shutdowns, hardware faults and crashing
  software. Every value is read from event logs, crash-dump folders, the
  CrashControl key and the reliability provider; nothing is written or cleared.

  The checks deliberately separate one-off events from repeating patterns. A
  single dirty shutdown after a power cut is noise; the same application dying
  five times in two weeks is a fault worth naming. Counts and timestamps are
  always reported so the reader can verify each claim in Event Viewer.
#>
function Test-StabilityHealth {
    [CmdletBinding()]
    param()

    $now = Get-Date
    $since30 = $now.AddDays(-30)
    $since14 = $now.AddDays(-14)

    # Get-WinEvent writes a non-terminating error both when nothing matches and
    # when a provider is not registered on this SKU, and -ErrorAction
    # SilentlyContinue does not reliably suppress either. Worse, @($null).Count
    # is 1, so a swallowed error would silently read as "one event". Only
    # -ErrorAction Stop inside try/catch yields a trustworthy empty array.
    $getEvents = {
        param($Filter, $Max)
        try {
            if ($Max) {
                return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop)
            }
            return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
        } catch {
            # No matches, unknown provider or an unreadable log all mean "nothing
            # to report"; each caller decides whether that counts as healthy.
            return @()
        }
    }

    # Named EventData fields survive schema changes between Windows builds;
    # positional Properties[n] does not.
    $getData = {
        param($LogEvent, $FieldName)
        try {
            $xml = [xml]$LogEvent.ToXml()
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name -eq $FieldName) { return [string]$d.'#text' }
            }
            return $null
        } catch {
            # Some providers emit no structured EventData at all.
            return $null
        }
    }

    $formatTimes = {
        param($LogEvents, $HowMany)
        $stamps = @($LogEvents | Sort-Object TimeCreated -Descending |
            Select-Object -First $HowMany |
            ForEach-Object { $_.TimeCreated.ToString('dd.MM.yyyy HH:mm') })
        return ($stamps -join ', ')
    }

    # A "nothing found in 30 days" result only means something if the log
    # actually reaches back 30 days. A wrapped log would otherwise be reported
    # as a clean bill of health.
    $logStart = $null
    try {
        $firstSys = Get-WinEvent -LogName 'System' -MaxEvents 1 -Oldest -ErrorAction Stop
        if ($firstSys) { $logStart = $firstSys.TimeCreated }
    } catch {
        # System log empty or unreadable; the window simply stays unqualified.
        $logStart = $null
    }
    $windowNote = ''
    if ($logStart -and $logStart -gt $since30) {
        $windowNote = " (the System log only reaches back to $($logStart.ToString('dd.MM.yyyy')))"
    }

    # minidumps

    $dumpDir = Join-Path $env:SystemRoot 'Minidump'
    $dumpDirExists = Test-Path -LiteralPath $dumpDir
    $miniAll = @()
    $miniReadable = $true
    if ($dumpDirExists) {
        try {
            $miniAll = @(Get-ChildItem -LiteralPath $dumpDir -Filter '*.dmp' -File -ErrorAction Stop)
        } catch {
            # Folder is present but the ACL blocks a non-elevated read.
            $miniReadable = $false
        }
    }

    if (-not $miniReadable) {
        Add-Skip -Message "Could not read $dumpDir - the folder requires administrator rights. Blue screens have not been counted."
    } elseif (-not $dumpDirExists) {
        Add-Ok -Message 'No Minidump folder exists - Windows has never written a blue screen dump here.'
    } else {
        $miniRecent = @($miniAll | Where-Object { $_.LastWriteTime -ge $since30 })
        if ($miniAll.Count -eq 0) {
            Add-Ok -Message 'No minidumps in C:\Windows\Minidump - no recorded blue screens.'
        } elseif ($miniRecent.Count -eq 0) {
            $newestOld = @($miniAll | Sort-Object LastWriteTime -Descending)[0]
            Add-Finding -Severity 'Info' -Title 'Old blue screen dumps, but none in the last month' `
                -Evidence "$($miniAll.Count) minidump(s) in $dumpDir, newest $($newestOld.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))" `
                -Impact 'The machine has crashed before, but has been free of blue screens for at least 30 days.' `
                -Fix 'No action needed. If you want to analyze an old dump, open the .dmp file in WinDbg.' `
                -Confidence 'Certain'
        } else {
            $newestMini = @($miniRecent | Sort-Object LastWriteTime -Descending)[0]
            $miniSeverity = 'Medium'
            if ($miniRecent.Count -ge 8) { $miniSeverity = 'Critical' }
            elseif ($miniRecent.Count -ge 3) { $miniSeverity = 'High' }
            Add-Finding -Severity $miniSeverity -Title 'Blue screens in the last 30 days' `
                -Evidence "$($miniRecent.Count) minidump(s) in $dumpDir in the last 30 days, newest $($newestMini.LastWriteTime.ToString('dd.MM.yyyy HH:mm')) ($($newestMini.Name)). $($miniAll.Count) dump(s) in the folder in total." `
                -Impact 'The machine has stopped with a blue screen. If it keeps happening, it is most often a driver, faulty RAM or a disk that is failing.' `
                -Fix 'Analyze the newest dump: download WinDbg from the Microsoft Store, open the file and run !analyze -v. Then check the driver it points to.' `
                -Confidence 'Certain'
        }
    }

    # MEMORY.DMP

    $memDumpPath = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (Test-Path -LiteralPath $memDumpPath) {
        try {
            $memDump = Get-Item -LiteralPath $memDumpPath -ErrorAction Stop
            Add-Finding -Severity 'Info' -Title 'A kernel memory dump is left on the system drive' `
                -Evidence "$memDumpPath, $(Format-Size -Bytes ([double]$memDump.Length)), written $($memDump.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))" `
                -Impact 'The file documents the last blue screen and takes up space on the system drive.' `
                -Fix 'Keep it until the crash has been analyzed in WinDbg. After that it can be removed via Settings > System > Storage > Temporary files (System error memory dump files).' `
                -Confidence 'Certain'
        } catch {
            Add-Skip -Message "MEMORY.DMP exists, but could not be read: $($_.Exception.Message)"
        }
    } else {
        Add-Ok -Message 'No MEMORY.DMP on the system drive - no fresh kernel dump waiting to be analyzed.'
    }

    # bugcheck (ID 1001)

    $bugchecks = & $getEvents @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
        Id           = 1001
        StartTime    = $since30
    } 200

    if ($bugchecks.Count -eq 0) {
        Add-Ok -Message "No BugCheck events (ID 1001) in the System log in the last 30 days$windowNote."
    } else {
        # The bugcheck code is the only part that says *why* the machine stopped.
        # It sits in param1 as free text, so fall back to the rendered message.
        $codes = @()
        foreach ($bc in $bugchecks) {
            $raw = & $getData $bc 'param1'
            if (-not $raw) { $raw = [string]$bc.Message }
            $match = [regex]::Match([string]$raw, '0x[0-9A-Fa-f]{8}')
            if ($match.Success) { $codes += $match.Value.ToUpper().Replace('0X', '0x') }
        }
        $codeText = 'code not readable from the event'
        if ($codes.Count -gt 0) {
            $codeText = (@($codes | Group-Object | Sort-Object Count -Descending |
                    ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')
        }
        $bcSeverity = 'Medium'
        if ($bugchecks.Count -ge 8) { $bcSeverity = 'Critical' }
        elseif ($bugchecks.Count -ge 3) { $bcSeverity = 'High' }
        Add-Finding -Severity $bcSeverity -Title 'The system has stopped with a blue screen (BugCheck)' `
            -Evidence "$($bugchecks.Count) BugCheck event(s) in the last 30 days. Stop code: $codeText. Times: $(& $formatTimes $bugchecks 3)" `
            -Impact 'The stop code points at the cause - 0x0000009F and 0x000000EF are usually drivers, 0x0000001A and 0x0000004E faulty memory, 0x0000007A a disk that is not responding.' `
            -Fix 'Look up the stop code, then run "WinDbg > !analyze -v" on the newest file in C:\Windows\Minidump to see which driver failed.' `
            -Confidence 'Certain'
    }

    # unexpected shutdowns

    $kernelPower = & $getEvents @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Power'
        Id           = 41
        StartTime    = $since30
    } 200
    $dirtyShutdown = & $getEvents @{ LogName = 'System'; Id = 6008; StartTime = $since30 } 200

    # BugcheckCode 0 means the machine simply lost power or was reset; a non-zero
    # code means it blue-screened, which the checks above already cover.
    $hardResets = @()
    foreach ($kp in $kernelPower) {
        $code = & $getData $kp 'BugcheckCode'
        if (-not $code -or $code -eq '0') { $hardResets += $kp }
    }

    $unexpectedCount = $hardResets.Count + $dirtyShutdown.Count
    if ($unexpectedCount -eq 0) {
        Add-Ok -Message "No unexpected shutdowns (event 41 or 6008) in the last 30 days$windowNote."
    } else {
        $stampSource = $hardResets
        if ($stampSource.Count -eq 0) { $stampSource = $dirtyShutdown }
        $unexpectedSeverity = 'Low'
        if ($unexpectedCount -ge 5) { $unexpectedSeverity = 'High' }
        elseif ($unexpectedCount -ge 2) { $unexpectedSeverity = 'Medium' }
        Add-Finding -Severity $unexpectedSeverity -Title 'The machine has powered off unexpectedly' `
            -Evidence "$($hardResets.Count) x Kernel-Power 41 without a stop code and $($dirtyShutdown.Count) x event 6008 in the last 30 days. Last: $(& $formatTimes $stampSource 3)" `
            -Impact 'A power cut, the reset button, an unstable power supply or a freeze that never got to write a dump. The file system risks damage every time.' `
            -Fix 'Rule out the power side first (outlet, extension cord, power supply, UPS). See the details in Event Viewer > Windows Logs > System, filter on event ID 41.' `
            -Confidence 'Likely'
    }

    # WHEA

    $whea = & $getEvents @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-WHEA-Logger'
        StartTime    = $since30
    } 500

    if ($whea.Count -eq 0) {
        Add-Ok -Message "No WHEA hardware errors reported in the last 30 days$windowNote."
    } else {
        # Level 1/2 are uncorrected faults the CPU, memory or PCIe bus could not
        # recover from. Level 3 are corrected errors - real, but survivable, and
        # noisy on some platforms, so they get their own lower-severity finding.
        $wheaFatal = @($whea | Where-Object { @(1, 2) -contains $_.Level })
        $wheaCorrected = @($whea | Where-Object { $_.Level -eq 3 })

        if ($wheaFatal.Count -gt 0) {
            $wheaIds = (@($wheaFatal | Group-Object Id | Sort-Object Count -Descending |
                    ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', ')
            $wheaSeverity = 'High'
            if ($wheaFatal.Count -ge 3) { $wheaSeverity = 'Critical' }
            Add-Finding -Severity $wheaSeverity -Title 'WHEA reports hardware errors that could not be corrected' `
                -Evidence "$($wheaFatal.Count) event(s) from Microsoft-Windows-WHEA-Logger in the last 30 days ($wheaIds). Last: $(& $formatTimes $wheaFatal 3)" `
                -Impact 'WHEA reports physical hardware that is failing - CPU, memory, a PCIe device or the motherboard. This does not go away on its own and often ends in a blue screen or data loss.' `
                -Fix 'Read the full event text in Event Viewer > System (it names the component). Reset all overclocking and XMP/EXPO in the BIOS, and run a memory test (mdsched.exe).' `
                -Confidence 'Certain'
        }

        if ($wheaCorrected.Count -gt 0) {
            $correctedIds = (@($wheaCorrected | Group-Object Id | Sort-Object Count -Descending |
                    ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', ')
            $correctedSeverity = 'Medium'
            if ($wheaCorrected.Count -ge 20) { $correctedSeverity = 'High' }
            Add-Finding -Severity $correctedSeverity -Title 'WHEA reports corrected hardware errors' `
                -Evidence "$($wheaCorrected.Count) warning(s) from Microsoft-Windows-WHEA-Logger in the last 30 days ($correctedIds). Last: $(& $formatTimes $wheaCorrected 3)" `
                -Impact 'The errors were corrected on the fly, so the machine keeps running, but they are an early warning of memory or a PCIe link that is about to become unstable.' `
                -Fix 'Note which component the event names. Reset XMP/EXPO in the BIOS and run mdsched.exe. If the count climbs over time, replace the component.' `
                -Confidence 'Likely'
        }
    }

    # app crashes

    $appEvents = & $getEvents @{
        LogName      = 'Application'
        ProviderName = @('Application Error', 'Application Hang')
        Id           = @(1000, 1002)
        StartTime    = $since14
    } 500

    if ($appEvents.Count -eq 0) {
        Add-Ok -Message 'No application crashes or hangs in the Application log in the last 14 days.'
    } else {
        $byApp = @($appEvents | Group-Object { & $getData $_ 'AppName' } |
            Sort-Object Count -Descending)
        # Only an app that fails repeatedly is worth its own finding; a single
        # crash in two weeks is normal on any machine.
        $repeatOffenders = @($byApp | Where-Object { $_.Count -ge 5 })

        foreach ($offender in $repeatOffenders) {
            $appName = $offender.Name
            if (-not $appName) { $appName = 'unknown program' }
            $modules = @($offender.Group | ForEach-Object { & $getData $_ 'ModuleName' } |
                Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                Select-Object -First 2 | ForEach-Object { $_.Name })
            $moduleText = ''
            if ($modules.Count -gt 0) { $moduleText = " Faulting module: $($modules -join ', ')." }
            $appSeverity = 'Medium'
            if ($offender.Count -ge 15) { $appSeverity = 'High' }
            Add-Finding -Severity $appSeverity -Title "$appName crashes repeatedly" `
                -Evidence "$($offender.Count) crashes/hangs in the last 14 days.$moduleText Last: $(& $formatTimes $offender.Group 3)" `
                -Impact 'The program is unstable on this machine. If it is a background service or an OEM tool, it can drag other faults along with it.' `
                -Fix "Update $appName to the latest version - or uninstall it if you do not use it. The full error text is in Event Viewer > Windows Logs > Application, source 'Application Error'." `
                -Confidence 'Certain'
        }

        if ($repeatOffenders.Count -eq 0) {
            $topApps = (@($byApp | Select-Object -First 3 | ForEach-Object {
                        $n = $_.Name
                        if (-not $n) { $n = 'unknown' }
                        "$n ($($_.Count))"
                    }) -join ', ')
            Add-Finding -Severity 'Info' -Title 'Scattered app crashes in the last 14 days' `
                -Evidence "$($appEvents.Count) event(s) spread across $($byApp.Count) programs: $topApps" `
                -Impact 'No single app stands out. This is a normal level for a machine in daily use.' `
                -Fix 'No action. Keep an eye on it if one of the programs starts to dominate the list.' `
                -Confidence 'Certain'
        }
    }

    # services that crash

    $svcEvents = & $getEvents @{ LogName = 'System'; Id = @(7031, 7034); StartTime = $since30 } 500

    if ($svcEvents.Count -eq 0) {
        Add-Ok -Message "No services have terminated unexpectedly (event 7031/7034) in the last 30 days$windowNote."
    } else {
        # Service Control Manager puts the service display name first; it has no
        # named EventData field, so the position is the only handle we have.
        $bySvc = @($svcEvents | Group-Object {
                $n = $null
                if ($_.Properties -and $_.Properties.Count -gt 0) { $n = [string]$_.Properties[0].Value }
                if ($n) { $n } else { 'unknown service' }
            } | Sort-Object Count -Descending)
        $svcOffenders = @($bySvc | Where-Object { $_.Count -ge 3 })

        foreach ($svc in $svcOffenders) {
            $svcSeverity = 'Medium'
            if ($svc.Count -ge 10) { $svcSeverity = 'High' }
            Add-Finding -Severity $svcSeverity -Title "The service '$($svc.Name)' terminates unexpectedly over and over" `
                -Evidence "$($svc.Count) event(s) of type 7031/7034 in the last 30 days. Last: $(& $formatTimes $svc.Group 3)" `
                -Impact 'The service dies and is restarted by Windows. The function it provides is gone in the meantime, and the repetition points to a real bug in the software.' `
                -Fix "Check who supplies the service and update or uninstall the software. See details with: Get-WinEvent -FilterHashtable @{LogName='System';Id=7031,7034} -MaxEvents 20 | Format-List" `
                -Confidence 'Certain'
        }

        if ($svcOffenders.Count -eq 0) {
            $topSvc = (@($bySvc | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')
            Add-Finding -Severity 'Info' -Title 'Some services have terminated unexpectedly' `
                -Evidence "$($svcEvents.Count) event(s) spread across $($bySvc.Count) service(s) in the last 30 days: $topSvc" `
                -Impact 'No service repeats often enough to count as unstable.' `
                -Fix 'No action needed.' `
                -Confidence 'Certain'
        }
    }

    # disk-related errors

    $diskEvents = & $getEvents @{
        LogName      = 'System'
        ProviderName = @('disk', 'Ntfs', 'volmgr', 'storahci', 'stornvme')
        Level        = @(1, 2)
        StartTime    = $since30
    } 500

    # volmgr 45/46/49 are crash-dump plumbing failures, not disk faults. Lumping
    # them in with real I/O errors would produce a false "your disk is failing".
    $dumpPlumbing = @($diskEvents | Where-Object {
            $_.ProviderName -eq 'volmgr' -and @(45, 46, 49) -contains $_.Id
        })
    $realDiskErrors = @($diskEvents | Where-Object {
            -not ($_.ProviderName -eq 'volmgr' -and @(45, 46, 49) -contains $_.Id)
        })

    if ($realDiskErrors.Count -eq 0) {
        Add-Ok -Message "No I/O or file system errors from disk, Ntfs, storahci or stornvme in the last 30 days$windowNote."
    } else {
        $diskDetail = (@($realDiskErrors | Group-Object ProviderName, Id | Sort-Object Count -Descending |
                Select-Object -First 4 | ForEach-Object { "$($_.Name.Replace(', ', ' ID ')) x$($_.Count)" }) -join ', ')
        $diskSeverity = 'High'
        if ($realDiskErrors.Count -ge 5) { $diskSeverity = 'Critical' }
        Add-Finding -Severity $diskSeverity -Title 'Kernel errors from the disk or file system driver' `
            -Evidence "$($realDiskErrors.Count) errors in the last 30 days: $diskDetail. Last: $(& $formatTimes $realDiskErrors 3)" `
            -Impact 'The disk is not responding the way it should, or NTFS has found structural errors. This is the most common early warning of data loss.' `
            -Fix 'Take a backup first. Then check SMART status with: Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus - and run chkdsk on the volume if NTFS is reporting errors.' `
            -Confidence 'Likely'
    }

    # Warning-level storage events. The query above is deliberately Level 1-2, because an
    # Error from a storage driver is unambiguous. But the events that arrive FIRST are
    # warnings, and they can run for weeks before anything Error-level appears: disk 153
    # (an I/O was retried) and storahci/stornvme 129 (the controller had to be reset).
    # Those are what the user experiences as multi-second freezes while the machine still
    # reports healthy.
    #
    # StorPort 504 is deliberately NOT here. It looks like the obvious third signal, but the
    # Microsoft-Windows-StorPort provider is not linked to the System log at all and 504 is
    # Information rather than Warning, so a System/Level-3 query for it can never match. It
    # lives in Microsoft-Windows-Storage-Storport/Operational, and at ~90 events a month on
    # healthy hardware it is a volume counter, not a fault signal. Claiming to check it and
    # then never matching would be worse than not checking it.
    #
    # The Id filter belongs in the hashtable, not only in Where-Object: MaxEvents is applied
    # by the log reader before our filter runs, so leaving it out would let unrelated
    # warnings from the same providers consume the cap and push real 153/129 events out.
    $storageWarnings = & $getEvents @{
        LogName      = 'System'
        ProviderName = @('disk', 'storahci', 'stornvme')
        Id           = @(153, 129)
        Level        = @(3)
        StartTime    = $since30
    } 500
    $storageWarnings = @($storageWarnings | Where-Object {
            ($_.ProviderName -eq 'disk' -and $_.Id -eq 153) -or
            ($_.ProviderName -in @('storahci', 'stornvme') -and $_.Id -eq 129)
        })

    # Which disk the retry was on decides whether it means anything. Removable media retries
    # constantly for entirely mundane reasons - a USB drive pulled without ejecting, a card
    # reader, a drive on a hub - and reporting that as "the storage stack is retrying" next
    # to advice about SATA cables and NVMe temperatures is noise pointed at the wrong device.
    $removableDiskNumbers = @()
    try {
        $removableDiskNumbers = @(Get-Disk -ErrorAction Stop |
                Where-Object { $_.BusType -in @('USB', 'SD', 'MMC', '1394', 'Virtual') } |
                Select-Object -ExpandProperty Number)
    } catch {
        Write-Verbose -Message ("Get-Disk unavailable, so removable drives cannot be excluded: {0}" -f $_.Exception.Message)
    }
    $removableWarnings = @()
    if ($removableDiskNumbers.Count -gt 0) {
        $fixedWarnings = @()
        foreach ($warning in $storageWarnings) {
            $diskNumber = $null
            if ($warning.Message -match '(?i)\bdisk\s+(\d+)\b') { $diskNumber = [int]$Matches[1] }
            if ($null -ne $diskNumber -and $removableDiskNumbers -contains $diskNumber) { $removableWarnings += $warning }
            else { $fixedWarnings += $warning }
        }
        $storageWarnings = @($fixedWarnings)
    }

    if ($storageWarnings.Count -eq 0) {
        $removableNote = ''
        if ($removableWarnings.Count -gt 0) {
            $removableNote = " ($($removableWarnings.Count) retry event(s) on removable drives were ignored - normal for USB media)"
        }
        Add-Ok -Message "No I/O retries or controller resets from a fixed drive in the last 30 days$windowNote$removableNote."
    } else {
        $warnDetail = (@($storageWarnings | Group-Object ProviderName, Id | Sort-Object Count -Descending |
                Select-Object -First 4 | ForEach-Object { "$($_.Name.Replace(', ', ' ID ')) x$($_.Count)" }) -join ', ')
        # Name the disk. Advice about the wrong device is worse than no advice.
        $affectedDisks = @($storageWarnings | ForEach-Object {
                if ($_.Message -match '(?i)\bdisk\s+(\d+)\b') { "Disk $($Matches[1])" }
            } | Sort-Object -Unique)
        $diskNote = if ($affectedDisks.Count -gt 0) { " Affected: $($affectedDisks -join ', ')." } else { '' }
        # A handful over a month is normal on consumer hardware. A steady stream is not.
        $warnSeverity = if ($storageWarnings.Count -ge 20) { 'High' } elseif ($storageWarnings.Count -ge 5) { 'Medium' } else { 'Low' }
        Add-Finding -Severity $warnSeverity -Title 'A fixed drive is retrying reads or resetting its controller' `
            -Evidence "$($storageWarnings.Count) warning(s) in the last 30 days: $warnDetail.$diskNote Last: $(& $formatTimes $storageWarnings 3)" `
            -Impact 'These are warnings, not errors, so nothing has failed yet. They are the precursor: a drive that has to retry reads, or a controller that has to be reset, is what a freeze of several seconds looks like from the kernel side. On an NVMe drive this often shows up months before SMART reports anything.' `
            -Fix 'Take a backup first. Then identify the drive with: Get-Disk | Select-Object Number,FriendlyName,BusType - and check it with Get-PhysicalDisk and Get-StorageReliabilityCounter. On a SATA drive, reseat the data and power cable; on NVMe, check that it is not overheating. Update the storage driver and the drive firmware.' `
            -Confidence 'Likely'
    }

    if ($dumpPlumbing.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Title 'Windows could not prepare the crash dump' `
            -Evidence "$($dumpPlumbing.Count) event(s) from volmgr (ID $((@($dumpPlumbing | Group-Object Id | ForEach-Object { $_.Name }) -join ', '))) in the last 30 days. Last: $(& $formatTimes $dumpPlumbing 3)" `
            -Impact 'The next blue screen will not be written to disk, and then there is nothing to troubleshoot afterwards.' `
            -Fix 'Make sure the paging file is on the system drive and large enough: Settings > System > About > Advanced system settings > Performance > Advanced > Virtual memory - set "System managed size" on the system drive.' `
            -Confidence 'Likely'
    }

    # crash dump configuration

    $crashControl = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $dumpMode = Get-RegValue -Path $crashControl -Name 'CrashDumpEnabled'
    if ($null -eq $dumpMode) {
        Add-Skip -Message 'Could not find CrashDumpEnabled under CrashControl - the dump setting could not be assessed.'
    } elseif ([int]$dumpMode -eq 0) {
        Add-Finding -Severity 'High' -Title 'Crash dumps are turned off completely' `
            -Evidence "CrashDumpEnabled = 0 in $crashControl" `
            -Impact 'No dump file will be written at the next blue screen. Without a dump there is no way to find out which driver caused the crash.' `
            -Fix 'Settings > System > About > Advanced system settings > Startup and Recovery > Write debugging information: choose "Automatic memory dump".' `
            -Confidence 'Certain'
    } elseif ([int]$dumpMode -eq 3) {
        Add-Finding -Severity 'Low' -Title 'Only a small memory dump is written on a blue screen' `
            -Evidence "CrashDumpEnabled = 3 (small memory dump) in $crashControl. The Windows default is 7 (automatic memory dump)." `
            -Impact 'A 256 KB small dump gives you the stop code, but rarely enough context to convict a driver that sits deeper in the call stack.' `
            -Fix 'Settings > System > About > Advanced system settings > Startup and Recovery > Write debugging information: choose "Automatic memory dump".' `
            -Confidence 'Likely'
    } else {
        $dumpNames = @{ 1 = 'complete memory dump'; 2 = 'kernel memory dump'; 7 = 'automatic memory dump' }
        $dumpLabel = $dumpNames[[int]$dumpMode]
        if (-not $dumpLabel) { $dumpLabel = "mode $dumpMode" }
        Add-Ok -Message "Crash dumps are enabled ($dumpLabel) - the next blue screen will be possible to troubleshoot."
    }

    # LiveKernelReports

    $liveDir = Join-Path $env:SystemRoot 'LiveKernelReports'
    if (-not (Test-Path -LiteralPath $liveDir)) {
        Add-Ok -Message 'No LiveKernelReports folder - no driver timeouts have been logged.'
    } else {
        $liveAll = $null
        try {
            $liveAll = @(Get-ChildItem -LiteralPath $liveDir -Filter '*.dmp' -File -Recurse -ErrorAction Stop)
        } catch {
            # Access denied without elevation on some builds.
            $liveAll = $null
        }

        if ($null -eq $liveAll) {
            Add-Skip -Message "Could not read $liveDir - requires administrator rights."
        } else {
            $liveRecent = @($liveAll | Where-Object { $_.LastWriteTime -ge $since30 })
            if ($liveRecent.Count -eq 0) {
                Add-Ok -Message 'No LiveKernelReports in the last 30 days - no GPU or driver timeouts without a blue screen.'
            } else {
                # The report type (WATCHDOG, USBHUB3, PoW ...) names the subsystem
                # that hung, and is either the parent folder or the filename prefix.
                $kinds = @($liveRecent | Group-Object {
                        $parent = $_.Directory.Name
                        if ($parent -and $parent -ne 'LiveKernelReports') { $parent }
                        else { ($_.BaseName -split '-')[0] }
                    } | Sort-Object Count -Descending)
                $kindText = (@($kinds | Select-Object -First 3 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')
                $newestLive = @($liveRecent | Sort-Object LastWriteTime -Descending)[0]
                $liveSeverity = 'Low'
                if ($liveRecent.Count -ge 10) { $liveSeverity = 'High' }
                elseif ($liveRecent.Count -ge 3) { $liveSeverity = 'Medium' }
                Add-Finding -Severity $liveSeverity -Title 'Driver timeouts logged without a blue screen (LiveKernelReports)' `
                    -Evidence "$($liveRecent.Count) report(s) in $liveDir in the last 30 days: $kindText. Newest $($newestLive.LastWriteTime.ToString('dd.MM.yyyy HH:mm')) ($($newestLive.Name)). $($liveAll.Count) in the folder in total." `
                    -Impact 'A driver stopped responding and was reset without the machine going down. WATCHDOG almost always comes from the graphics driver and shows up as a black screen or a freeze of a few seconds.' `
                    -Fix 'Reinstall the graphics driver from the GPU vendor (clean install), and remove any OEM monitoring or overclocking tools that hook into the driver.' `
                    -Confidence 'Likely'
            }
        }
    }

    # reliability index

    if ($Fast) {
        Add-Skip -Message 'The reliability index was skipped because -Fast is set.'
    } else {
        $reliability = @()
        try {
            $reliability = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction Stop)
        } catch {
            # The RAC provider is absent or disabled on many images and on Server core.
            $reliability = @()
        }

        if ($reliability.Count -eq 0) {
            Add-Skip -Message 'Win32_ReliabilityStabilityMetrics returned no data - the reliability history is not available on this machine.'
        } else {
            $recentRows = @($reliability | Where-Object { $_.TimeGenerated -ge $now.AddDays(-7) })
            $priorRows = @($reliability | Where-Object {
                    $_.TimeGenerated -lt $now.AddDays(-7) -and $_.TimeGenerated -ge $now.AddDays(-28)
                })

            # A null average would round to 0 and read as a catastrophic index, so
            # the raw measurement is checked before it is turned into a verdict.
            $recentRaw = ($recentRows | Measure-Object -Property SystemStabilityIndex -Average).Average
            if ($recentRows.Count -lt 24 -or $null -eq $recentRaw) {
                Add-Skip -Message "The reliability history covers too short a period ($($recentRows.Count) measurement(s) in the last week) to say anything about the trend."
            } else {
                $recentAvg = [math]::Round($recentRaw, 2)
                $priorAvg = $null
                if ($priorRows.Count -ge 24) {
                    $priorRaw = ($priorRows | Measure-Object -Property SystemStabilityIndex -Average).Average
                    if ($null -ne $priorRaw) { $priorAvg = [math]::Round($priorRaw, 2) }
                }

                $trendText = "average over the last 7 days: $recentAvg out of 10"
                if ($null -ne $priorAvg) { $trendText = "$trendText, against $priorAvg for the three weeks before that" }

                if ($null -ne $priorAvg -and ($priorAvg - $recentAvg) -ge 1.5 -and $recentAvg -lt 7) {
                    Add-Finding -Severity 'Medium' -Title 'The reliability index is dropping' `
                        -Evidence "Windows' own reliability index: $trendText (based on $($recentRows.Count) measurements in the last week)." `
                        -Impact 'The machine has become noticeably more unstable over the last week than it was before. The index drops when apps crash, services die or the machine powers off unexpectedly.' `
                        -Fix 'Run perfmon /rel to see the timeline and which events pulled the index down, and match that against the findings above.' `
                        -Confidence 'Likely'
                } elseif ($recentAvg -lt 4) {
                    Add-Finding -Severity 'Medium' -Title 'Low reliability index' `
                        -Evidence "Windows' own reliability index: $trendText (based on $($recentRows.Count) measurements in the last week)." `
                        -Impact 'An index below 4 means Windows is recording crashes or errors almost every day.' `
                        -Fix 'Run perfmon /rel and look at the red markers in the timeline to find which app or driver keeps coming back.' `
                        -Confidence 'Likely'
                } else {
                    Add-Ok -Message "The reliability index is stable ($trendText)."
                }
            }
        }
    }
}

<#
  Drivers - device problem states, the driver store, and the kernel drivers that
  are actually loaded right now.

  Two traps shape this check. A device in "Error" state is usually nothing of the
  sort: on a normal machine every Error device is one the user disabled (CM_PROB_22)
  or one that is simply unplugged (CM_PROB_45), so both are counted separately and
  never reported as faults. And pnputil localises its output, so the driver store
  is parsed on shape - oemNN.inf, an original INF name, a four-part version -
  rather than on field labels that only exist in English.
#>
function Test-DriverHealth {

    # CM_PROB_* code as a plain integer. Newer builds expose Problem, older ones
    # only ConfigManagerErrorCode; both are enums over the same constants, so
    # whichever answers first wins. -1 means "could not tell".
    $getProblemCode = {
        param($Device)
        $code = -1
        foreach ($propName in 'Problem', 'ConfigManagerErrorCode') {
            if ($code -ge 0) { break }
            $prop = $Device.PSObject.Properties[$propName]
            if ($null -eq $prop -or $null -eq $prop.Value) { continue }
            try { $code = [int]$prop.Value }
            catch {
                # Property exists but is not numeric on this build - try the next name.
                $code = -1
            }
        }
        return $code
    }

    # A service PathName arrives in native NT spellings (\??\C:\..., \SystemRoot\...,
    # or a bare system32\...). Normalise so Test-Path and the signature check agree.
    $resolveDriverPath = {
        param([string]$RawPath)
        if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }
        $p = $RawPath.Trim().Trim('"')
        if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
        if ($p -like '\SystemRoot\*') { $p = Join-Path $env:SystemRoot $p.Substring(12) }
        elseif ($p -notmatch '^[A-Za-z]:\\' -and $p -notmatch '^\\\\') { $p = Join-Path $env:SystemRoot $p }
        return $p
    }

    # Sortable key for a driver version. Anything unparseable sorts last, which is
    # correct here because we only ever want to know which copy is the newest.
    $asVersion = {
        param([string]$Text)
        $parsed = [version]'0.0.0.0'
        try { $parsed = [version]$Text }
        catch {
            # Vendor used a non-numeric version string - treat it as the oldest.
            $parsed = [version]'0.0.0.0'
        }
        return $parsed
    }

    # Keeps evidence readable when a machine has dozens of hits.
    $summarise = {
        param([object[]]$Items, [int]$Keep)
        $shown = @($Items | Select-Object -First $Keep) -join '; '
        if ($Items.Count -gt $Keep) { $shown = '{0} ... and {1} more' -f $shown, ($Items.Count - $Keep) }
        return $shown
    }

    # devices

    if (-not (Get-Command -Name 'Get-PnpDevice' -ErrorAction SilentlyContinue)) {
        Add-Skip 'Device status was not checked - Get-PnpDevice does not exist on this Windows version.'
    }
    else {
        $devices = @()
        try { $devices = @(Get-PnpDevice -ErrorAction Stop) }
        catch {
            # The PnP provider can be missing or hang; an empty result is handled below.
            $devices = @()
        }

        if (-not $devices.Count) {
            Add-Skip 'Device status was not checked - Get-PnpDevice returned no devices.'
        }
        else {
            $faulted = New-Object System.Collections.ArrayList
            $noDriver = New-Object System.Collections.ArrayList
            $needRestart = New-Object System.Collections.ArrayList
            $disabledNames = New-Object System.Collections.ArrayList
            $phantomCount = 0

            foreach ($dev in $devices) {
                $code = & $getProblemCode $dev
                if ($code -le 0) { continue }

                $label = $dev.FriendlyName
                if (-not $label) { $label = $dev.Description }
                if (-not $label) { $label = $dev.InstanceId }

                # 22 is the user's own choice and 45/24 mean "not plugged in right now".
                # Neither is a fault, and counting them as one is the classic false alarm.
                if ($code -eq 22) { $null = $disabledNames.Add($label); continue }
                if ($code -eq 45 -or $code -eq 24) { $phantomCount++; continue }

                $present = $true
                $presentProp = $dev.PSObject.Properties['Present']
                if ($null -ne $presentProp -and $null -ne $presentProp.Value) { $present = [bool]$presentProp.Value }
                if (-not $present) { $phantomCount++; continue }

                if ($code -eq 28) {
                    # The hardware ID is the only thing the user can search on when no driver exists.
                    $hwid = ''
                    if ($dev.HardwareID) { $hwid = @($dev.HardwareID)[0] }
                    if (-not $hwid) { $hwid = $dev.InstanceId }
                    $null = $noDriver.Add(('{0} [{1}]' -f $label, $hwid))
                }
                elseif ($code -eq 14) { $null = $needRestart.Add($label) }
                else { $null = $faulted.Add([PSCustomObject]@{ Label = $label; Code = $code }) }
            }

            if ($faulted.Count) {
                # 10/31/43/52 = the driver will not start, will not load, the device reports
                # a fault, or the signature was rejected. Everything else is milder config noise.
                $severe = @($faulted | Where-Object { @(10, 31, 43, 52) -contains $_.Code })
                $severity = 'Medium'
                if ($severe.Count) { $severity = 'High' }
                $lines = @($faulted | ForEach-Object { '{0} (code {1})' -f $_.Label, $_.Code })
                Add-Finding -Severity $severity -Title ('{0} device(s) report an error in Device Manager' -f $faulted.Count) `
                    -Evidence (& $summarise $lines 6) `
                    -Impact 'The hardware does not work, or only partly. Code 10/31/43 means the driver does not start or the device reports a fault, code 52 that the signature was rejected.' `
                    -Fix 'Open devmgmt.msc, find the device with the exclamation mark and read the error text under Properties > General. Then get the driver from the PC or component manufacturer.'
            }
            else {
                Add-Ok ('None of the {0} devices report an error in Device Manager.' -f $devices.Count)
            }

            if ($noDriver.Count) {
                Add-Finding -Severity 'Medium' -Title ('{0} device(s) have no driver at all' -f $noDriver.Count) `
                    -Evidence (& $summarise $noDriver.ToArray() 5) `
                    -Impact 'The devices are connected, but Windows found no driver that fits. They are dead until they get one.' `
                    -Fix 'Search for the hardware ID above at the manufacturer, or see Settings > Windows Update > Advanced options > Optional updates > Driver updates.'
            }
            else {
                Add-Ok 'Every connected device has a driver installed.'
            }

            if ($needRestart.Count) {
                Add-Finding -Severity 'Low' -Title ('{0} device(s) are waiting for a restart to finish a driver change' -f $needRestart.Count) `
                    -Evidence (& $summarise $needRestart.ToArray() 5) `
                    -Impact 'The device runs on the old driver, or none at all, until the machine is restarted.' `
                    -Fix 'Restart the machine.'
            }

            if ($disabledNames.Count) {
                Add-Finding -Severity 'Info' -Title ('{0} device(s) are disabled' -f $disabledNames.Count) `
                    -Evidence (& $summarise $disabledNames.ToArray() 6) `
                    -Impact 'This is normally something done on purpose - the list is here in case one of them was turned off by accident.' `
                    -Fix 'Want one of them back: devmgmt.msc, right-click the device, Enable device.'
            }

            if ($phantomCount -gt 0) {
                Add-Ok ('{0} device(s) are registered but not connected right now (old USB devices and the like) - normal and of no consequence.' -f $phantomCount)
            }
        }
    }

    # driver store dupes

    $pnputil = Get-Command -Name 'pnputil.exe' -ErrorAction SilentlyContinue
    if (-not $script:Ctx.IsAdmin) {
        Add-Skip 'Duplicate driver packages were not checked - pnputil /enum-drivers requires administrator.'
    }
    elseif (-not $pnputil) {
        Add-Skip 'Duplicate driver packages were not checked - pnputil.exe was not found.'
    }
    else {
        $pnpText = ''
        try { $pnpText = (& $pnputil.Source '/enum-drivers' 2>$null | Out-String) }
        catch {
            # Older builds have a different switch set; empty text is caught below.
            $pnpText = ''
        }

        $packages = New-Object System.Collections.ArrayList
        if ($pnpText) {
            foreach ($block in ($pnpText -split '\r?\n\s*\r?\n')) {
                # The field names are translated on non-English Windows, but the shape of
                # the values is not: oemNN.inf, an original INF name and a four-part version.
                # A date can never be four-part, so the version is unambiguous.
                $published = [regex]::Match($block, '(?i)\b(oem\d+\.inf)\b')
                $version = [regex]::Match($block, '\b\d+\.\d+\.\d+\.\d+\b')
                if (-not $published.Success -or -not $version.Success) { continue }

                $original = ''
                foreach ($hit in [regex]::Matches($block, '(?i)\b([A-Za-z0-9_\-\.]+\.inf)\b')) {
                    $name = $hit.Groups[1].Value
                    if ($name -notmatch '(?i)^oem\d+\.inf$') { $original = $name.ToLowerInvariant(); break }
                }
                if (-not $original) { continue }

                $null = $packages.Add([PSCustomObject]@{
                        Published = $published.Groups[1].Value
                        Original  = $original
                        Version   = $version.Value
                    })
            }
        }

        if (-not $packages.Count) {
            Add-Skip 'Duplicate driver packages were not checked - could not parse the output from pnputil /enum-drivers.'
        }
        else {
            $dupeGroups = @($packages | Group-Object -Property Original | Where-Object { $_.Count -gt 1 })
            $staleCount = 0
            foreach ($grp in $dupeGroups) { $staleCount += ($grp.Count - 1) }

            if ($staleCount -gt 0) {
                $examples = @(
                    foreach ($grp in ($dupeGroups | Sort-Object -Property Count -Descending | Select-Object -First 4)) {
                        $ordered = @($grp.Group |
                                Sort-Object -Property @{ Expression = { & $asVersion $_.Version } } -Descending |
                                ForEach-Object { $_.Version })
                        '{0}: {1} copies ({2} in use, oldest {3})' -f $grp.Name, $grp.Count, $ordered[0], $ordered[$ordered.Count - 1]
                    }
                )
                $severity = 'Info'
                if ($staleCount -ge 5) { $severity = 'Low' }
                Add-Finding -Severity $severity -Title ('{0} outdated driver packages are left behind in the driver store' -f $staleCount) `
                    -Evidence (& $summarise $examples 4) `
                    -Impact 'Disk space only. Windows uses the newest copy - the older ones stay behind as a rollback option.' `
                    -Fix 'See the full list with "pnputil /enum-drivers". A single old package is removed with "pnputil /delete-driver oemNN.inf" - without /force, so a package that is in use stays put.' `
                    -Confidence 'Likely'
            }
            else {
                Add-Ok ('No duplicate driver packages in the driver store ({0} packages in total).' -f $packages.Count)
            }
        }
    }

    # driver store size

    $repository = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
    if ($Fast) {
        Add-Skip 'The size of the driver store was not measured (-Fast).'
    }
    elseif (-not (Test-Path -LiteralPath $repository)) {
        Add-Skip ('The size of the driver store was not measured - {0} was not found.' -f $repository)
    }
    else {
        $repoBytes = 0
        try {
            $measured = Get-ChildItem -LiteralPath $repository -Recurse -File -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
            if ($measured -and $measured.Sum) { $repoBytes = [double]$measured.Sum }
        }
        catch {
            # Deep or ACL-protected subtrees can still throw; 0 gives Add-Skip below.
            $repoBytes = 0
        }

        if ($repoBytes -le 0) {
            Add-Skip 'The size of the driver store could not be measured - no read access to FileRepository.'
        }
        elseif ($repoBytes -gt 25GB) {
            Add-Finding -Severity 'Low' -Title 'The driver store is unusually large' `
                -Evidence ('{0} uses {1}' -f $repository, (Format-Size -Bytes $repoBytes)) `
                -Impact 'Space tied up in old driver packages. No risk, but noticeable on a small system disk.' `
                -Fix 'Clear out the oldest packages with "pnputil /delete-driver oemNN.inf" using the list from "pnputil /enum-drivers".' `
                -Confidence 'Likely'
        }
        elseif ($repoBytes -gt 12GB) {
            Add-Finding -Severity 'Info' -Title 'The driver store is large' `
                -Evidence ('{0} uses {1}' -f $repository, (Format-Size -Bytes $repoBytes)) `
                -Impact 'Common on machines with graphics and chipset drivers that have been updated many times. No action needed.' `
                -Fix 'None. If you need the space, see "pnputil /enum-drivers".'
        }
        else {
            Add-Ok ('The driver store uses {0}.' -f (Format-Size -Bytes $repoBytes))
        }
    }

    # running kernel drivers

    $running = @()
    try { $running = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' }) }
    catch {
        # Win32_SystemDriver is missing on some stripped-down installations.
        $running = @()
    }

    if (-not $running.Count) {
        Add-Skip 'Running kernel drivers were not checked - Win32_SystemDriver returned nothing.'
    }
    else {
        $resolved = New-Object System.Collections.ArrayList
        foreach ($drv in $running) {
            $path = & $resolveDriverPath $drv.PathName
            if (-not $path) { continue }
            $null = $resolved.Add([PSCustomObject]@{ Name = $drv.Name; Path = $path })
        }

        # A kernel driver that loads from a folder the user can write to is a real
        # hole: whoever can replace the file can run code in the kernel.
        $userWritable = @($resolved | Where-Object { $_.Path -match '(?i)\\(Users|AppData|Temp|Downloads)\\' })
        if ($userWritable.Count) {
            $lines = @($userWritable | ForEach-Object { '{0} -> {1}' -f $_.Name, $_.Path })
            Add-Finding -Severity 'High' -Title ('{0} kernel driver(s) load from a user-writable folder' -f $userWritable.Count) `
                -Evidence (& $summarise $lines 5) `
                -Impact 'Any process that can write to the folder can swap out the driver file and get code into the kernel at the next boot.' `
                -Fix 'Work out which program owns the driver above. If you do not recognise it, uninstall the program and check the file on virustotal.com.'
        }
        else {
            Add-Ok ('None of the {0} running kernel drivers load from a user-writable folder.' -f $resolved.Count)
        }

        # Guard, not just -ErrorAction: with Microsoft.PowerShell.Security missing from the
        # session, the call throws CommandNotFoundException, which SilentlyContinue will not mute.
        if (-not (Get-Command -Name 'Get-AuthenticodeSignature' -ErrorAction SilentlyContinue)) {
            Add-Skip 'Driver signatures were not checked - Get-AuthenticodeSignature is not available in this session.'
        }
        else {
            # Drivers outside the Windows folder are few and the most interesting, so they
            # are always checked. The rest cost a few seconds and wait for a full run.
            $toCheck = $resolved
            if ($Fast) { $toCheck = @($resolved | Where-Object { $_.Path -notlike (Join-Path $env:SystemRoot '*') }) }

            $unsigned = New-Object System.Collections.ArrayList
            $checked = 0
            foreach ($item in $toCheck) {
                if (-not (Test-Path -LiteralPath $item.Path -PathType Leaf)) { continue }
                $sig = $null
                try { $sig = Get-AuthenticodeSignature -LiteralPath $item.Path -ErrorAction Stop }
                catch {
                    # Locked or unreachable file - counts as unchecked, not as unsigned.
                    $sig = $null
                }
                if ($null -eq $sig) { continue }
                $checked++
                if ($sig.Status -ne 'Valid') {
                    $null = $unsigned.Add(('{0} [{1}] {2}' -f $item.Name, $sig.Status, $item.Path))
                }
            }

            if (-not $checked) {
                Add-Skip 'Driver signatures were not checked - none of the driver files could be read.'
            }
            elseif ($unsigned.Count) {
                Add-Finding -Severity 'High' -Title ('{0} running kernel driver(s) do not have a valid signature' -f $unsigned.Count) `
                    -Evidence (& $summarise $unsigned.ToArray() 6) `
                    -Impact 'The driver runs with full rights in the kernel. HashMismatch means the file was changed after signing, NotSigned and NotTrusted that no signature chain can be verified.' `
                    -Fix 'Look up the file name above. If you do not recognise the driver, check the file on virustotal.com and uninstall the program that owns it.' `
                    -Confidence 'Likely'
            }
            elseif ($Fast) {
                Add-Ok ('The signature is valid for all {0} kernel drivers outside the Windows folder (the rest skipped with -Fast).' -f $checked)
            }
            else {
                Add-Ok ('The signature is valid for all {0} kernel drivers checked.' -f $checked)
            }
        }
    }

    # vulnerable driver blocklist

    $ciConfig = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $blocklist = Get-RegValue -Path $ciConfig -Name 'VulnerableDriverBlocklistEnable'
    if ($null -eq $blocklist) {
        # A missing value means "default", and the default is not the same everywhere:
        # on from 22H2, otherwise depending on whether memory integrity is on. Only the
        # first is safe to call clean.
        if ($script:Ctx.Build -ge 22621) {
            Add-Ok 'The vulnerable driver blocklist is on (Windows default from 22H2, no override in the registry).'
        }
        else {
            Add-Skip ('The vulnerable driver blocklist could not be determined - the value VulnerableDriverBlocklistEnable does not exist under {0}.' -f $ciConfig)
        }
    }
    elseif ($blocklist -eq 0) {
        Add-Finding -Severity 'High' -Title 'The Microsoft vulnerable driver blocklist is turned off' `
            -Evidence ('VulnerableDriverBlocklistEnable = 0 under {0}' -f $ciConfig) `
            -Impact 'Known vulnerable but signed drivers can load again. That is exactly the method attackers use to shut down antivirus from the kernel (BYOVD).' `
            -Fix 'Turn on Core isolation > Memory integrity under Windows Security > Device security, or set the value back to 1.'
    }
    else {
        Add-Ok ('The vulnerable driver blocklist is on (VulnerableDriverBlocklistEnable = {0}).' -f $blocklist)
    }

    # display adapters

    $adapters = @()
    try { $adapters = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop) }
    catch {
        # The class is missing on some server and VM installations.
        $adapters = @()
    }

    if (-not $adapters.Count) {
        Add-Skip 'The display adapter driver was not checked - Win32_VideoController returned nothing.'
    }
    elseif ($script:Ctx.IsVM) {
        Add-Skip 'The display adapter driver was not judged - virtual machine, where both a basic driver and an old date are normal.'
    }
    else {
        foreach ($adapter in $adapters) {
            $adapterName = $adapter.Name
            if (-not $adapterName) { $adapterName = 'unknown display adapter' }

            # The basic display driver means the real driver never got into place.
            if ($adapterName -match '(?i)Basic Display|Basic Render|Standard VGA') {
                Add-Finding -Severity 'Medium' -Title 'The display adapter is running on the Microsoft basic display driver' `
                    -Evidence ('Win32_VideoController reports "{0}", driver version {1}' -f $adapterName, $adapter.DriverVersion) `
                    -Impact 'No hardware acceleration, often the wrong resolution and higher power draw than necessary.' `
                    -Fix 'Install the display driver from Intel, AMD or NVIDIA, or see Windows Update > Advanced options > Optional updates > Driver updates.' `
                    -Confidence 'Likely'
                continue
            }

            $ageDays = -1
            $stamp = ''
            try {
                $driverDate = [datetime]$adapter.DriverDate
                $ageDays = [int][math]::Round(((Get-Date) - $driverDate).TotalDays)
                $stamp = $driverDate.ToString('yyyy-MM-dd')
            }
            catch {
                # DriverDate is missing or has an unexpected format on some OEM drivers.
                $ageDays = -1
            }

            if ($ageDays -lt 0) {
                Add-Skip ('The driver age for {0} could not be read - DriverDate is missing or invalid.' -f $adapterName)
            }
            elseif ($ageDays -ge 1095) {
                Add-Finding -Severity 'Low' -Title ('The display driver for {0} is very old' -f $adapterName) `
                    -Evidence ('DriverDate {0} ({1} days), version {2}' -f $stamp, $ageDays, $adapter.DriverVersion) `
                    -Impact 'Can mean missed bug fixes and no support in newer programs. On older hardware it is often just the last driver the manufacturer ever made.' `
                    -Fix 'Check whether the manufacturer has a newer driver for this exact model. If there is none, this is normal and can be ignored.' `
                    -Confidence 'Likely'
            }
            elseif ($ageDays -ge 365) {
                Add-Finding -Severity 'Info' -Title ('The display driver for {0} is over a year old' -f $adapterName) `
                    -Evidence ('DriverDate {0} ({1} days), version {2}' -f $stamp, $ageDays, $adapter.DriverVersion) `
                    -Impact 'Not a fault in itself - an old driver is often just a stable driver.' `
                    -Fix 'If you want to update, get the driver from Intel, AMD or NVIDIA rather than Device Manager.' `
                    -Confidence 'Likely'
            }
            else {
                Add-Ok ('The driver for {0} is from {1} ({2} days old), version {3}.' -f $adapterName, $stamp, $ageDays, $adapter.DriverVersion)
            }
        }
    }
}

<#
  Storage. Free space per volume, physical disk health and SMART wear, TRIM,
  fragmentation on spinning media only, the page and hibernation files, System
  Restore coverage, and the places that quietly eat a disk: the component store,
  Windows.old, temp trees and the recycle bin.

  Read-only throughout. The three external programs used - fsutil behavior query,
  defrag /A and dism /AnalyzeComponentStore - are analysis modes that report
  without writing anything. The expensive ones sit behind -not $Fast so a quick
  run stays quick, and behind IsAdmin so a plain user gets a skip, not an error.

  Number thresholds lean deliberately conservative: a large drive at 4 % free
  still has hundreds of gigabytes, so percentage alone never decides Critical.
#>
function Test-StorageHealth {
    [CmdletBinding()]
    param()

    # helpers

    # Walking a tree must never abort a check: reparse points, denied ACLs and
    # files disappearing mid-walk are all normal. $null means "could not size it",
    # which is different from zero and is reported differently.
    $measureTree = {
        param([string]$TreePath)
        if ([string]::IsNullOrWhiteSpace($TreePath)) { return $null }
        if (-not (Test-Path -LiteralPath $TreePath -ErrorAction SilentlyContinue)) { return $null }
        try {
            $sum = (Get-ChildItem -LiteralPath $TreePath -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
            if ($null -eq $sum) { return [double]0 }
            return [double]$sum
        } catch {
            # Unwalkable tree - report as unknown rather than pretend it is empty.
            return $null
        }
    }

    # Restore point timestamps arrive as DMTF strings on 5.1 and 7 alike. The
    # framework converter is exact but lives in System.Management, which is not
    # guaranteed to be loaded under PowerShell 7, hence the manual fallback.
    $parseCimDate = {
        param($Raw)
        if ($null -eq $Raw) { return $null }
        if ($Raw -is [datetime]) { return $Raw }
        $text = [string]$Raw
        try { return [Management.ManagementDateTimeConverter]::ToDateTime($text) } catch {
            # System.Management is not always loaded under PowerShell 7; the manual
            # prefix parse below handles that without failing the check.
            Write-Verbose "ToDateTime failed for '$text', falling back to manual parsing."
        }
        if ($text.Length -ge 14) {
            try {
                $utc = [datetime]::ParseExact($text.Substring(0, 14), 'yyyyMMddHHmmss',
                    [Globalization.CultureInfo]::InvariantCulture)
                return [datetime]::SpecifyKind($utc, 'Utc').ToLocalTime()
            } catch {
                # Not a DMTF timestamp after all - caller treats $null as "unknown age".
                Write-Verbose "Unknown time format: '$text'."
            }
        }
        return $null
    }

    $sysDrive = $script:Ctx.SystemDrive
    if ([string]::IsNullOrWhiteSpace($sysDrive)) { $sysDrive = 'C:' }

    # free space

    # Only lettered fixed volumes. EFI and recovery partitions are meant to sit
    # near full and would otherwise produce a guaranteed false Critical on every
    # machine that has them.
    $volumes = @()
    try {
        $volumes = @(Get-Volume -ErrorAction Stop |
                Where-Object { $_.DriveType -eq 'Fixed' -and "$($_.DriveLetter)" -match '^[A-Za-z]$' -and $_.Size -gt 0 } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Letter = "$($_.DriveLetter)"
                        FS     = "$($_.FileSystem)"
                        Free   = [double]$_.SizeRemaining
                        Size   = [double]$_.Size
                        Health = "$($_.HealthStatus)"
                    }
                })
    } catch {
        # Storage module absent or refusing - the CIM fallback below covers it.
        $volumes = @()
    }
    if ($volumes.Count -eq 0) {
        try {
            $volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                    Where-Object { $_.Size -gt 0 } |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Letter = "$($_.DeviceID)".TrimEnd(':')
                            FS     = "$($_.FileSystem)"
                            Free   = [double]$_.FreeSpace
                            Size   = [double]$_.Size
                            Health = ''
                        }
                    })
        } catch {
            # Neither source answered; the skip below makes the gap visible.
            $volumes = @()
        }
    }

    if ($volumes.Count -eq 0) {
        Add-Skip -Message 'Free space: neither Get-Volume nor Win32_LogicalDisk answered on this machine.'
    } else {
        foreach ($v in $volumes) {
            $pct = ($v.Free / $v.Size) * 100
            # Formatted through -f so the decimal separator matches Format-Size
            # rather than mixing invariant and local formatting in one sentence.
            $pctText = '{0:N1}' -f $pct
            $freeGb = $v.Free / 1GB
            $isSys = ("$($v.Letter):" -eq $sysDrive)
            $where = if ($isSys) { "System drive $($v.Letter):" } else { "Drive $($v.Letter):" }
            $ev = "$($v.Letter): has $(Format-Size -Bytes $v.Free) free of $(Format-Size -Bytes $v.Size) ($pctText %)"
            $fix = "Run 'cleanmgr.exe' or open Settings > System > Storage and see what is taking up space on $($v.Letter):"

            if ($pct -lt 5) {
                # Percent alone is a bad emergency signal: 4 % of 4 TB is 160 GB.
                # Critical requires that the absolute headroom is small too.
                if ($freeGb -lt 50) {
                    Add-Finding -Severity 'Critical' -Title "$where is nearly full" -Evidence $ev `
                        -Impact 'Windows needs free space for updates, the page file and temporary files. Below this limit programs start failing, and updates can abort halfway through and leave the system in a half-finished state.' `
                        -Fix $fix -Confidence 'Certain'
                } else {
                    Add-Finding -Severity 'High' -Title "$where has little free space as a percentage" -Evidence $ev `
                        -Impact 'The share of free space is very low, but the absolute number is still large. Worth clearing out before it turns critical.' `
                        -Fix $fix -Confidence 'Certain'
                }
            } elseif ($pct -lt 10) {
                Add-Finding -Severity 'High' -Title "$where has little free space" -Evidence $ev `
                    -Impact 'Below 10 % free makes writes noticeably slower, and large Windows updates can run out of room to unpack themselves.' `
                    -Fix $fix -Confidence 'Certain'
            } elseif ($pct -lt 20) {
                Add-Finding -Severity 'Low' -Title "$where is getting full" -Evidence $ev `
                    -Impact 'No immediate risk, but the margin is getting thin.' `
                    -Fix $fix -Confidence 'Certain'
            } else {
                Add-Ok -Message "$($v.Letter): has plenty of space - $(Format-Size -Bytes $v.Free) free ($pctText %)"
            }

            if ($v.Health -and $v.Health -ne 'Healthy') {
                Add-Finding -Severity 'High' -Title "The file system on $($v.Letter): is not reported as healthy" `
                    -Evidence "Get-Volume HealthStatus for $($v.Letter): = $($v.Health)" `
                    -Impact 'Windows thinks the volume has a fault. That can mean the start of file system corruption.' `
                    -Fix "Run 'chkdsk $($v.Letter): /scan' (scans without changing anything) and look at the result before you repair anything." `
                    -Confidence 'Likely'
            }
        }
    }

    # disk health

    $disks = @()
    try { $disks = @(Get-PhysicalDisk -ErrorAction Stop) } catch {
        # Storage module or the WMI provider is missing, common in minimal VMs.
        $disks = @()
    }

    if ($disks.Count -eq 0) {
        Add-Skip -Message 'Disk health: Get-PhysicalDisk returned no devices (common in some virtual machines).'
    } else {
        foreach ($d in $disks) {
            $name = "$($d.FriendlyName)".Trim()
            if (-not $name) { $name = "disk $($d.DeviceId)" }
            $media = "$($d.MediaType)"
            $health = "$($d.HealthStatus)"
            $opStatus = @($d.OperationalStatus) -join ', '

            if ($health -eq 'Unhealthy') {
                Add-Finding -Severity 'Critical' -Title "Disk $name is reported as faulty" `
                    -Evidence "HealthStatus = $health, OperationalStatus = $opStatus, $(Format-Size -Bytes ([double]$d.Size))" `
                    -Impact 'Windows has already concluded that the device is failing. Data loss may be imminent.' `
                    -Fix 'Back up everything important from this disk now, and plan a replacement. Check the details with "Get-PhysicalDisk | Get-StorageReliabilityCounter".' `
                    -Confidence 'Certain'
            } elseif ($health -eq 'Warning') {
                Add-Finding -Severity 'High' -Title "Disk $name has a health warning" `
                    -Evidence "HealthStatus = $health, OperationalStatus = $opStatus" `
                    -Impact 'The device works, but reports a problem. This rarely goes away on its own.' `
                    -Fix 'Make sure the backup is fresh, and read the SMART values with "Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List".' `
                    -Confidence 'Likely'
            } elseif ($health -eq 'Healthy') {
                Add-Ok -Message "$name ($media, $($d.BusType), $(Format-Size -Bytes ([double]$d.Size))) is healthy"
            } else {
                Add-Skip -Message "Disk health for ${name}: HealthStatus was '$health' - unknown state, not assessed."
            }

            # OperationalStatus can say OK while HealthStatus is Healthy; only an
            # actively degraded state is worth its own finding.
            if ($opStatus -match 'Degraded|Predictive Failure|Lost Communication|Stale Metadata') {
                Add-Finding -Severity 'High' -Title "Disk $name has an abnormal operational status" `
                    -Evidence "OperationalStatus = $opStatus" `
                    -Impact 'The device is not in normal operation. With "Predictive Failure" the disk itself has warned that it is on its way out.' `
                    -Fix 'Back up, and check cabling and power if it is an internal disk.' `
                    -Confidence 'Likely'
            }
        }
    }

    # SMART counters

    if ($disks.Count -eq 0) {
        Add-Skip -Message 'SMART counters: no physical disks to read from.'
    } elseif ($Fast) {
        Add-Skip -Message 'SMART counters (wear, temperature, read errors): skipped because -Fast is set.'
    } elseif (-not $script:Ctx.IsAdmin) {
        Add-Skip -Message 'SMART counters: Get-StorageReliabilityCounter requires administrator.'
    } else {
        $counterSeen = $false
        foreach ($d in $disks) {
            $name = "$($d.FriendlyName)".Trim()
            if (-not $name) { $name = "disk $($d.DeviceId)" }
            $rc = $null
            try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {
                # Many USB bridges and virtual disks pass no SMART data through.
                $rc = $null
            }
            if ($null -eq $rc) {
                Add-Skip -Message "SMART counters for ${name}: the device provides no wear data (common for USB enclosures and virtual disks)."
                continue
            }
            $counterSeen = $true

            $parts = @()
            if ($null -ne $rc.Wear) { $parts += "wear $($rc.Wear) %" }
            if ($null -ne $rc.Temperature -and $rc.Temperature -gt 0) { $parts += "$($rc.Temperature) C" }
            if ($null -ne $rc.PowerOnHours) { $parts += "$($rc.PowerOnHours) power-on hours" }
            $detail = if ($parts.Count -gt 0) { $parts -join ', ' } else { 'no numeric values reported' }

            $uncorrected = 0
            if ($null -ne $rc.ReadErrorsUncorrected) { $uncorrected += [double]$rc.ReadErrorsUncorrected }
            if ($null -ne $rc.WriteErrorsUncorrected) { $uncorrected += [double]$rc.WriteErrorsUncorrected }
            if ($uncorrected -gt 0) {
                Add-Finding -Severity 'Critical' -Title "Disk $name has uncorrectable read/write errors" `
                    -Evidence "ReadErrorsUncorrected = $($rc.ReadErrorsUncorrected), WriteErrorsUncorrected = $($rc.WriteErrorsUncorrected)" `
                    -Impact 'Uncorrectable errors mean data already could not be read or written back. This is real data loss, not a warning.' `
                    -Fix 'Copy out what you need immediately and replace the disk. Do not use it for new data.' `
                    -Confidence 'Certain'
            }

            # Wear is only meaningful on flash. Spinning and virtual disks report 0.
            if ($null -ne $rc.Wear -and $rc.Wear -gt 0) {
                $wear = [double]$rc.Wear
                if ($wear -gt 80) {
                    Add-Finding -Severity 'High' -Title "SSD $name is heavily worn" `
                        -Evidence "Wear = $wear % of the rated life used ($detail)" `
                        -Impact 'Over 80 % of the rated write endurance is used up. The disk normally goes into read-only mode when it reaches 100 %.' `
                        -Fix 'Plan a replacement and keep the backup fresh. Move heavy write workloads to another disk in the meantime.' `
                        -Confidence 'Likely'
                } elseif ($wear -gt 50) {
                    Add-Finding -Severity 'Medium' -Title "SSD $name has used more than half its life" `
                        -Evidence "Wear = $wear % ($detail)" `
                        -Impact 'Not urgent, but the disk is past the midpoint of its rated write endurance.' `
                        -Fix 'Watch the value over time: "Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object Wear, Temperature".' `
                        -Confidence 'Likely'
                }
            }

            if ($null -ne $rc.Temperature -and $rc.Temperature -gt 0 -and $rc.Temperature -lt 150) {
                $temp = [double]$rc.Temperature
                if ($temp -gt 70) {
                    Add-Finding -Severity 'High' -Title "Disk $name is running hot" `
                        -Evidence "Temperature = $temp C" `
                        -Impact 'Above 70 C most NVMe drives throttle themselves, and sustained heat shortens the life of the disk.' `
                        -Fix 'Check the airflow and that the heatsink or thermal pad is in contact with the disk.' `
                        -Confidence 'Likely'
                } elseif ($temp -gt 60) {
                    Add-Finding -Severity 'Low' -Title "Disk $name is running warm" `
                        -Evidence "Temperature = $temp C" `
                        -Impact 'Below the throttling threshold, but warmer than you want over time.' `
                        -Fix 'Check the case fans and the dust around the drive bay.' `
                        -Confidence 'Uncertain'
                }
            }

            # Only spinning disks wear out from hours alone; flash wears from writes.
            if ("$($d.MediaType)" -eq 'HDD' -and $null -ne $rc.PowerOnHours -and [double]$rc.PowerOnHours -gt 35000) {
                Add-Finding -Severity 'Low' -Title "Hard disk $name is old in power-on hours" `
                    -Evidence "PowerOnHours = $($rc.PowerOnHours) (about $('{0:N1}' -f ([double]$rc.PowerOnHours / 8760)) years of continuous operation)" `
                    -Impact 'Mechanical disks have a limited life. Age alone is not a fault, but the odds of a failure go up.' `
                    -Fix 'Make sure everything on this disk exists somewhere else too.' `
                    -Confidence 'Uncertain'
            }

            if ($uncorrected -eq 0 -and $parts.Count -gt 0) {
                Add-Ok -Message "SMART for ${name}: $detail, no uncorrectable errors"
            }
        }
        if (-not $counterSeen) {
            Add-Skip -Message 'SMART counters: none of the disks provided wear data.'
        }
    }

    # TRIM

    $hasFlash = @($disks | Where-Object { "$($_.MediaType)" -eq 'SSD' -or "$($_.MediaType)" -eq 'SCM' }).Count -gt 0
    try {
        $trimRaw = (& fsutil.exe behavior query DisableDeleteNotify 2>&1 | Out-String)
        # Newer builds print one line per filesystem (NTFS and ReFS); older builds
        # print a single unlabelled line. The token itself is never localised.
        $trimMatch = [regex]::Match($trimRaw, 'NTFS\s+DisableDeleteNotify\s*(?:=|:)\s*(\d+)')
        if (-not $trimMatch.Success) {
            $trimMatch = [regex]::Match($trimRaw, 'DisableDeleteNotify\s*(?:=|:)\s*(\d+)')
        }
        if (-not $trimMatch.Success) {
            Add-Skip -Message 'TRIM: could not parse the output from "fsutil behavior query DisableDeleteNotify".'
        } elseif ($trimMatch.Groups[1].Value -eq '0') {
            Add-Ok -Message 'TRIM is active (DisableDeleteNotify = 0)'
        } elseif (-not $hasFlash) {
            Add-Finding -Severity 'Info' -Title 'TRIM is turned off' `
                -Evidence "fsutil behavior query DisableDeleteNotify = $($trimMatch.Groups[1].Value)" `
                -Impact 'No SSD was detected on this machine, so the setting has no practical effect here.' `
                -Fix 'No action needed without an SSD.' -Confidence 'Likely'
        } else {
            Add-Finding -Severity 'Medium' -Title 'TRIM is turned off on a machine with an SSD' `
                -Evidence "fsutil behavior query DisableDeleteNotify = $($trimMatch.Groups[1].Value)" `
                -Impact 'Without TRIM the SSD is never told which blocks have been freed. Write speed drops off over time and wear goes up.' `
                -Fix 'Turn it back on with "fsutil behavior set DisableDeleteNotify 0" in an administrator PowerShell.' `
                -Confidence 'Certain'
        }
    } catch {
        Add-Skip -Message 'TRIM: fsutil.exe could not be run.'
    }

    # fragmentation

    # Fragmentation only costs anything on spinning media - on flash the seek is
    # free, and Windows deliberately does not defragment SSDs.
    $hddLetters = @()
    foreach ($pd in @($disks | Where-Object { "$($_.MediaType)" -eq 'HDD' })) {
        try {
            $hddLetters += @(Get-Disk -UniqueId $pd.UniqueId -ErrorAction Stop |
                    Get-Partition -ErrorAction Stop |
                    Where-Object { "$($_.DriveLetter)" -match '^[A-Za-z]$' } |
                    ForEach-Object { "$($_.DriveLetter)" })
        } catch {
            # Disk-to-partition mapping is unavailable on storage spaces and some
            # passthrough setups; the drive simply is not analysed.
            $hddLetters += @()
        }
    }

    if ($disks.Count -eq 0) {
        Add-Skip -Message 'Fragmentation: could not determine the disk type because no physical disks were listed.'
    } elseif ($hddLetters.Count -eq 0) {
        Add-Skip -Message 'Fragmentation: no mechanical hard disks with a drive letter found - irrelevant on SSD.'
    } elseif ($Fast) {
        Add-Skip -Message 'Fragmentation: skipped because -Fast is set (the analysis takes tens of seconds).'
    } elseif (-not $script:Ctx.IsAdmin) {
        Add-Skip -Message 'Fragmentation: "defrag /A" requires administrator.'
    } else {
        foreach ($letter in ($hddLetters | Sort-Object -Unique)) {
            try {
                # /A is analysis only - it reports and changes nothing on disk.
                $fragRaw = (& defrag.exe "${letter}:" /A 2>&1 | Out-String)
                # The only percentage in this report is the fragmented share, so
                # matching on the number avoids depending on the display language.
                $fragMatch = [regex]::Match($fragRaw, '=\s*(\d+)\s*%')
                if (-not $fragMatch.Success) {
                    Add-Skip -Message "Fragmentation on ${letter}: could not parse the output from defrag /A."
                    continue
                }
                $frag = [int]$fragMatch.Groups[1].Value
                if ($frag -ge 30) {
                    Add-Finding -Severity 'Medium' -Title "Hard disk ${letter}: is heavily fragmented" `
                        -Evidence "defrag ${letter}: /A reports $frag % fragmented space" `
                        -Impact 'On a mechanical disk fragmentation means the head has to jump around to read a single file. You notice it on boot and when opening files.' `
                        -Fix "Run 'Optimize-Volume -DriveLetter $letter -Defrag' when the machine is not in use, or let the scheduled Defrag task run." `
                        -Confidence 'Certain'
                } elseif ($frag -ge 10) {
                    Add-Finding -Severity 'Low' -Title "Hard disk ${letter}: is somewhat fragmented" `
                        -Evidence "defrag ${letter}: /A reports $frag % fragmented space" `
                        -Impact 'Below the level where you clearly notice it, but worth cleaning up when convenient.' `
                        -Fix 'Check that the scheduled task "Microsoft\Windows\Defrag\ScheduledDefrag" is enabled.' `
                        -Confidence 'Certain'
                } else {
                    Add-Ok -Message "Hard disk ${letter}: is barely fragmented ($frag %)"
                }
            } catch {
                Add-Skip -Message "Fragmentation on ${letter}: defrag.exe could not be run."
            }
        }
    }

    # page file

    $pageFiles = @()
    try { $pageFiles = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop) } catch {
        # Class can be absent in stripped-down images.
        $pageFiles = @()
    }
    $autoManaged = $false
    if ($null -ne $script:Ctx.ComputerSystem) { $autoManaged = [bool]$script:Ctx.ComputerSystem.AutomaticManagedPagefile }

    if ($pageFiles.Count -eq 0) {
        if ($autoManaged) {
            Add-Skip -Message 'Page file: Win32_PageFileUsage returned no hits even though automatic management is on - not assessed.'
        } else {
            Add-Finding -Severity 'Medium' -Title 'The page file is turned off completely' `
                -Evidence "Win32_PageFileUsage returned no hits, and AutomaticManagedPagefile = $autoManaged" `
                -Impact 'Without a page file, programs can hit "out of memory" long before RAM is actually full, and Windows cannot write a crash dump when the machine blue-screens.' `
                -Fix 'System Properties > Advanced > Performance > Settings > Advanced > Virtual memory - tick the box for automatic management.' `
                -Confidence 'Likely'
        }
    } else {
        foreach ($pf in $pageFiles) {
            # Win32_PageFileUsage reports megabytes; convert so Format-Size does the
            # formatting and the numbers read the same as everywhere else.
            $allocBytes = [double]$pf.AllocatedBaseSize * 1MB
            $peakBytes = [double]$pf.PeakUsage * 1MB
            $pfName = "$($pf.Name)"
            Add-Ok -Message "Page file $pfName is $(Format-Size -Bytes $allocBytes) (peak usage $(Format-Size -Bytes $peakBytes))$(if ($autoManaged) { ', automatically managed' })"

            if ($allocBytes -gt 0 -and ($peakBytes / $allocBytes) -gt 0.9) {
                Add-Finding -Severity 'Medium' -Title 'The page file has been almost completely full' `
                    -Evidence "$pfName : peak usage $(Format-Size -Bytes $peakBytes) of $(Format-Size -Bytes $allocBytes) allocated" `
                    -Impact 'The machine has run out of both RAM and swap space. At that point memory requests are refused and programs can close without warning.' `
                    -Fix "Let Windows manage the page file automatically under System Properties > Advanced > Performance > Settings > Advanced > Virtual memory, or consider more RAM (this machine has $($script:Ctx.TotalRamGB) GB)." `
                    -Confidence 'Likely'
            }

            if ($pfName -and -not $pfName.StartsWith($sysDrive, [StringComparison]::OrdinalIgnoreCase)) {
                Add-Finding -Severity 'Info' -Title 'The page file is not on the system drive' `
                    -Evidence "$pfName (system drive is $sysDrive)" `
                    -Impact 'A perfectly valid setup, but Windows cannot write a complete crash dump when the page file sits outside the system drive.' `
                    -Fix 'No action needed unless you need crash dumps for troubleshooting.' `
                    -Confidence 'Likely'
            }
        }
    }

    # hibernation file

    $hiberOn = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
    $hiberPath = Join-Path -Path $sysDrive -ChildPath 'hiberfil.sys'
    $hiberFile = $null
    try { $hiberFile = Get-Item -LiteralPath $hiberPath -Force -ErrorAction Stop } catch {
        # Absent hiberfil.sys is the normal case when hibernation is off.
        $hiberFile = $null
    }

    if ($null -eq $hiberFile) {
        Add-Ok -Message "No hiberfil.sys on $sysDrive - hibernation is not taking up space"
    } else {
        $hiberBytes = [double]$hiberFile.Length
        $hiberText = Format-Size -Bytes $hiberBytes
        # A desktop with no battery cannot meaningfully hibernate on power loss,
        # so a multi-gigabyte reserve there is pure waste. On a laptop it is not.
        if (-not $script:Ctx.IsLaptop -and -not $script:Ctx.HasBattery -and -not $script:Ctx.IsVM) {
            Add-Finding -Severity 'Low' -Title 'The hibernation file takes up space on a desktop machine' `
                -Evidence "$hiberPath is $hiberText (HibernateEnabled = $hiberOn)" `
                -Impact 'Hibernation is mainly useful on machines that run on battery. On a desktop without a UPS you rarely get to use it, and the file reserves space permanently.' `
                -Fix 'Turn it off with "powercfg /hibernate off" in an administrator PowerShell if you do not use hibernation or fast startup.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message "Hibernation file in place: $hiberText ($hiberPath)"
        }
    }

    # system restore

    $srDisabled = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'DisableSR'
    $srInterval = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'RPSessionInterval'
    $srOff = (($null -ne $srDisabled -and $srDisabled -eq 1) -or ($null -ne $srInterval -and $srInterval -eq 0))

    $restorePoints = @()
    try { $restorePoints = @(Get-ComputerRestorePoint -ErrorAction Stop) } catch {
        # Not available without admin, and not present on Server SKUs.
        $restorePoints = @()
    }

    $newestRp = $null
    foreach ($rp in $restorePoints) {
        $when = & $parseCimDate $rp.CreationTime
        if ($null -ne $when -and ($null -eq $newestRp -or $when -gt $newestRp)) { $newestRp = $when }
    }
    # Shadow copies carry a real DateTime, so they give a locale-proof age when
    # the DMTF string above could not be parsed.
    if ($null -eq $newestRp) {
        try {
            foreach ($sc in @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop)) {
                if ($sc.InstallDate -is [datetime] -and ($null -eq $newestRp -or $sc.InstallDate -gt $newestRp)) {
                    $newestRp = $sc.InstallDate
                }
            }
        } catch {
            # Win32_ShadowCopy needs admin; without it the age simply stays unknown.
            Write-Verbose "Win32_ShadowCopy unavailable: $($_.Exception.Message)"
        }
    }

    if ($srOff) {
        Add-Finding -Severity 'Low' -Title 'System Restore is turned off' `
            -Evidence "DisableSR = $srDisabled, RPSessionInterval = $srInterval in HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" `
            -Impact 'Without restore points there is no easy way back after a driver or update mistake. Note that this is the default on many clean Windows installations, not necessarily something you did.' `
            -Fix 'Control Panel > System > System Protection > Configure, and turn on protection for the system drive.' `
            -Confidence 'Likely'
    } elseif ($restorePoints.Count -eq 0 -and -not $script:Ctx.IsAdmin) {
        Add-Skip -Message 'Restore points: administrator is required to list them.'
    } elseif ($restorePoints.Count -eq 0) {
        Add-Finding -Severity 'Low' -Title 'System Restore is on, but there are no restore points' `
            -Evidence 'Get-ComputerRestorePoint returned zero points' `
            -Impact 'Protection is formally active, but there is nothing to roll back to.' `
            -Fix 'Create one manually: Control Panel > System > System Protection > Create.' `
            -Confidence 'Likely'
    } else {
        $ageDays = if ($null -ne $newestRp) { [math]::Round(((Get-Date) - $newestRp).TotalDays) } else { $null }
        if ($null -eq $ageDays) {
            Add-Ok -Message "System Restore is on with $($restorePoints.Count) restore point(s)"
        } elseif ($ageDays -gt 90) {
            Add-Finding -Severity 'Low' -Title 'The newest restore point is old' `
                -Evidence "$($restorePoints.Count) point(s), newest from $($newestRp.ToString('yyyy-MM-dd')) - $ageDays days old" `
                -Impact 'A restore point from more than half a year back rolls back a lot more than you probably want.' `
                -Fix 'Create a fresh point: Control Panel > System > System Protection > Create.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message "System Restore is on - $($restorePoints.Count) point(s), newest $($newestRp.ToString('yyyy-MM-dd'))"
        }
    }

    # VSS quota, read through CIM rather than "vssadmin list shadowstorage" so the
    # numbers do not have to be scraped out of localised text.
    try {
        $shadowStores = @(Get-CimInstance -ClassName Win32_ShadowStorage -ErrorAction Stop)
        if ($shadowStores.Count -eq 0) {
            if ($script:Ctx.IsAdmin) {
                Add-Skip -Message 'VSS quota: no shadow copy area is set aside on any drive.'
            } else {
                Add-Skip -Message 'VSS quota: requires administrator.'
            }
        } else {
            $cimVolumes = @()
            try { $cimVolumes = @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop) } catch {
                # Without Win32_Volume the store is still reported, just without a letter.
                $cimVolumes = @()
            }
            foreach ($store in $shadowStores) {
                $devId = "$($store.Volume.DeviceID)"
                $letter = ''
                foreach ($cv in $cimVolumes) {
                    if ("$($cv.DeviceID)" -eq $devId) { $letter = "$($cv.DriveLetter)"; break }
                }
                if (-not $letter) { $letter = 'unknown drive' }
                $used = [double]$store.UsedSpace
                $alloc = [double]$store.AllocatedSpace
                $max = [double]$store.MaxSpace
                Add-Finding -Severity 'Info' -Title "Shadow copies are using space on $letter" `
                    -Evidence "Used $(Format-Size -Bytes $used), allocated $(Format-Size -Bytes $alloc), cap $(Format-Size -Bytes $max)" `
                    -Impact 'This is the space restore points and previous file versions are allowed to use. Windows discards the oldest ones when the cap is reached.' `
                    -Fix 'The cap is adjusted under Control Panel > System > System Protection > Configure.' `
                    -Confidence 'Certain'
            }
        }
    } catch {
        Add-Skip -Message 'VSS quota: Win32_ShadowStorage could not be read (usually requires administrator).'
    }

    # BitLocker

    if ($null -eq (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue)) {
        Add-Skip -Message 'BitLocker: the Get-BitLockerVolume cmdlet does not exist (typical of Windows Home).'
    } else {
        $blVolumes = @()
        try { $blVolumes = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { "$($_.MountPoint)" -match '^[A-Za-z]:' }) } catch {
            # Service disabled or no rights - reported as a skip below.
            $blVolumes = @()
        }
        if ($blVolumes.Count -eq 0) {
            Add-Skip -Message 'BitLocker: got no volumes from Get-BitLockerVolume (usually requires administrator).'
        } else {
            $encrypted = @($blVolumes | Where-Object { "$($_.ProtectionStatus)" -eq 'On' })
            $plain = @($blVolumes | Where-Object { "$($_.ProtectionStatus)" -ne 'On' })
            foreach ($bv in $encrypted) {
                Add-Ok -Message "BitLocker is on for $($bv.MountPoint) ($($bv.EncryptionMethod), $($bv.EncryptionPercentage) % encrypted)"
            }
            if ($plain.Count -gt 0) {
                $list = ($plain | ForEach-Object { "$($_.MountPoint) ($($_.VolumeType))" }) -join ', '
                Add-Finding -Severity 'Info' -Title 'Disk encryption is not active on all volumes' `
                    -Evidence "Without BitLocker protection: $list" `
                    -Impact 'Data on these volumes can be read by anyone who gets physical access to the disk. Many people choose this deliberately - it is not a fault in itself.' `
                    -Fix 'If you want to encrypt: Settings > Privacy & security > Device encryption, or "manage-bde -status" for details. Save the recovery key first.' `
                    -Confidence 'Certain'
            }
        }
    }

    # Windows.old

    $winOldPath = Join-Path -Path $sysDrive -ChildPath 'Windows.old'
    if (Test-Path -LiteralPath $winOldPath -ErrorAction SilentlyContinue) {
        $winOldBytes = $null
        if (-not $Fast) { $winOldBytes = & $measureTree -TreePath $winOldPath }
        $winOldEv = if ($null -ne $winOldBytes) { "$winOldPath is $(Format-Size -Bytes $winOldBytes)" } else { "$winOldPath exists (size not measured)" }
        Add-Finding -Severity 'Medium' -Title 'The previous Windows installation is still left behind' `
            -Evidence $winOldEv `
            -Impact 'Windows.old is the copy of the previous installation left after an upgrade. It is only used to roll back, and Windows normally deletes it by itself after ten days.' `
            -Fix 'Settings > System > Storage > Temporary files, tick "Previous Windows installation(s)" and clean up. Note that rolling back is no longer possible afterwards.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'No Windows.old - the previous installation has been cleaned up'
    }

    # component store

    if ($Fast) {
        Add-Skip -Message 'Component store (WinSxS): skipped because -Fast is set - the analysis takes several minutes.'
    } elseif (-not $script:Ctx.IsAdmin) {
        Add-Skip -Message 'Component store (WinSxS): dism /AnalyzeComponentStore requires administrator.'
    } else {
        try {
            $dismRaw = (& dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                Add-Skip -Message "Component store (WinSxS): dism exited with code $LASTEXITCODE."
            } else {
                # Size is kept as the raw text DISM printed, so no number parsing can
                # go wrong on a machine with a different decimal separator.
                $sizeText = ''
                $sizeMatch = [regex]::Match($dismRaw, 'Actual Size of Component Store\s*:\s*([^\r\n]+)')
                if ($sizeMatch.Success) {
                    $sizeText = $sizeMatch.Groups[1].Value.Trim()
                } else {
                    # Localised output: the size lines come in a fixed order, and the
                    # second one is always the actual store size.
                    $allSizes = [regex]::Matches($dismRaw, ':\s*([\d][\d.,]*\s*(?:KB|MB|GB|TB))\s*$',
                        [Text.RegularExpressions.RegexOptions]::Multiline)
                    if ($allSizes.Count -ge 2) { $sizeText = $allSizes[1].Groups[1].Value.Trim() }
                    elseif ($allSizes.Count -eq 1) { $sizeText = $allSizes[0].Groups[1].Value.Trim() }
                }

                $pkgMatch = [regex]::Match($dismRaw, 'Reclaimable Packages\s*:\s*(\d+)')
                if (-not $pkgMatch.Success) {
                    # The only line that is a label followed by a bare integer.
                    $pkgMatch = [regex]::Match($dismRaw, '^[^:\r\n]*:\s*(\d+)\s*$',
                        [Text.RegularExpressions.RegexOptions]::Multiline)
                }

                if (-not $sizeText -and -not $pkgMatch.Success) {
                    Add-Skip -Message 'Component store (WinSxS): could not parse the output from dism.'
                } else {
                    $storeEv = if ($sizeText) { "WinSxS is $sizeText" } else { 'WinSxS size not read out' }
                    if ($pkgMatch.Success -and [int]$pkgMatch.Groups[1].Value -gt 0) {
                        Add-Finding -Severity 'Low' -Title 'The component store has superseded packages that can be cleaned up' `
                            -Evidence "$storeEv, $($pkgMatch.Groups[1].Value) package(s) can be reclaimed" `
                            -Impact 'WinSxS holds on to old versions of updated components. The space frees itself up over time, but a cleanup is faster.' `
                            -Fix 'Run "dism /Online /Cleanup-Image /StartComponentCleanup" in an administrator PowerShell. After that you cannot uninstall the updates in question.' `
                            -Confidence 'Certain'
                    } else {
                        Add-Ok -Message "The component store is tidy - $storeEv, no packages to reclaim"
                    }
                }
            }
        } catch {
            Add-Skip -Message 'Component store (WinSxS): dism.exe could not be run.'
        }
    }

    # space hogs

    if ($Fast) {
        Add-Skip -Message 'Recycle Bin and temporary folders: skipped because -Fast is set (measuring folders can take several seconds).'
    } else {
        # Recycle bin, summed across every lettered fixed volume. Files belonging to
        # other users are simply unreadable without admin and drop out silently.
        $binTotal = 0
        $binParts = @()
        foreach ($v in $volumes) {
            $binPath = $v.Letter + ':\$Recycle.Bin'
            $binBytes = & $measureTree -TreePath $binPath
            if ($null -ne $binBytes -and $binBytes -gt 0) {
                $binTotal += $binBytes
                # A few stray bytes of bookkeeping exist on every volume; listing
                # them as "0 KB" only adds noise to the breakdown.
                if ($binBytes -ge 1MB) { $binParts += "$($v.Letter): $(Format-Size -Bytes $binBytes)" }
            }
        }
        if ($volumes.Count -eq 0) {
            Add-Skip -Message 'Recycle Bin: no volumes to measure because the volume list could not be retrieved.'
        } elseif ($binTotal -gt 10GB) {
            Add-Finding -Severity 'Low' -Title 'The Recycle Bin is holding on to a lot of space' `
                -Evidence "$(Format-Size -Bytes $binTotal) in total ($($binParts -join ', '))" `
                -Impact 'Deleted files keep their space until the Recycle Bin is emptied. On a full disk this is often the easiest space to free up.' `
                -Fix 'Right-click the Recycle Bin and choose Empty Recycle Bin, or set up automatic emptying under Settings > System > Storage > Storage Sense.' `
                -Confidence 'Certain'
        } elseif ($binTotal -gt 0) {
            Add-Ok -Message "The Recycle Bin is at a reasonable level - $(Format-Size -Bytes $binTotal)"
        } else {
            Add-Ok -Message 'The Recycle Bin is empty'
        }

        # Each temp location, with the threshold that actually matters for it.
        $tempTargets = @(
            [PSCustomObject]@{ Path = $env:TEMP; Name = 'The user temp folder'; Limit = 5GB; Fix = 'Settings > System > Storage > Temporary files, or run cleanmgr.exe.' }
            [PSCustomObject]@{ Path = (Join-Path -Path $env:windir -ChildPath 'Temp'); Name = 'The Windows temp folder'; Limit = 5GB; Fix = 'Settings > System > Storage > Temporary files.' }
            [PSCustomObject]@{ Path = (Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution\Download'); Name = 'The Windows Update download folder'; Limit = 10GB; Fix = 'The contents are just cached update packages. Settings > System > Storage > Temporary files clears it out safely.' }
        )
        foreach ($t in $tempTargets) {
            $bytes = & $measureTree -TreePath $t.Path
            if ($null -eq $bytes) {
                Add-Skip -Message "$($t.Name): the folder does not exist or could not be measured ($($t.Path))."
            } elseif ($bytes -gt $t.Limit) {
                Add-Finding -Severity 'Low' -Title "$($t.Name) is large" `
                    -Evidence "$($t.Path) is $(Format-Size -Bytes $bytes)" `
                    -Impact 'Temporary files are supposed to clean themselves up. When the folder gets large, something has failed to clean up after itself.' `
                    -Fix $t.Fix -Confidence 'Certain'
            } else {
                Add-Ok -Message "$($t.Name) is $(Format-Size -Bytes $bytes)"
            }
        }
    }

    # NTFS dirty bit. When a volume is marked dirty, Windows has already decided the file
    # system needs repair and has queued chkdsk for the next boot. Nothing in the interface
    # says so, and the machine keeps running on the volume in the meantime.
    if (Get-Command -Name fsutil -CommandType Application -ErrorAction SilentlyContinue) {
        $dirtyVolumes = @()
        $dirtyAssessed = @()
        $dirtyUnreadable = @()

        # BootExecute needs no elevation and covers every volume at once: Windows writes
        # "autocheck autochk /r \??\C:" here when a repair is queued, against the normal
        # "autocheck autochk *". Checking it first means an unelevated run still catches
        # the case that matters most.
        $bootExecuteText = ''
        $bootExecute = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'BootExecute'
        if ($bootExecute) { $bootExecuteText = (@($bootExecute) -join ' ') }
        # IndexOf, not a regex assembled from the drive letter - no pattern is built from
        # data anywhere in this block.
        $autochkHasSwitch = ($bootExecuteText.IndexOf('autochk /', [StringComparison]::OrdinalIgnoreCase) -ge 0)

        foreach ($volumeLetter in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceID)) {
            if ($autochkHasSwitch -and $bootExecuteText.IndexOf($volumeLetter, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $dirtyAssessed += $volumeLetter
                $dirtyVolumes += "$volumeLetter (BootExecute is '$bootExecuteText' - a repair pass is queued for the next boot)"
                continue
            }

            # fsutil is the second opinion and it needs administrator - but only for the
            # system volume. A data volume answers to an ordinary user, which is exactly
            # how the previous version went wrong: D: answering "not dirty" set a single
            # "checked" flag, and the check then reported "no fixed volume is marked dirty"
            # while C: had been skipped without a word. Coverage is now tracked per volume.
            $dirtyRaw = & fsutil dirty query $volumeLetter 2>&1 | Out-String
            $fsutilExit = $LASTEXITCODE
            # Both answers name the volume; "Error 5: Access is denied." does not. Requiring
            # the volume name stops an error message being read as a clean bill of health.
            $answersAboutVolume = ($dirtyRaw.IndexOf($volumeLetter, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            if ($fsutilExit -ne 0 -or -not $answersAboutVolume) {
                $dirtyUnreadable += $volumeLetter
                continue
            }
            $dirtyAssessed += $volumeLetter
            # Only the clean answer carries a negation, in every language.
            if ($dirtyRaw -notmatch '(?i)\bnot\b') {
                $dirtyVolumes += "$volumeLetter (fsutil reports the volume dirty)"
            }
        }

        if ($dirtyVolumes.Count -gt 0) {
            Add-Finding -Severity 'High' -Title 'A volume is marked dirty and has a repair pass queued' `
                -Evidence ($dirtyVolumes -join '; ') `
                -Impact 'Windows has found a file system inconsistency and scheduled chkdsk for the next restart. Until that runs the volume keeps being written to in the state that caused it, and the usual cause is either a failing drive or a hard power loss.' `
                -Fix 'Back up first, then restart so the queued check can run. Inspect the result afterwards in Event Viewer > Windows Logs > Application, source Chkdsk / Wininit. If it comes back repeatedly, treat the drive as suspect.' `
                -Confidence 'Likely'
        } elseif ($dirtyAssessed.Count -eq 0) {
            Add-Skip -Message ("The NTFS dirty bit was not checked on any volume - fsutil needs administrator rights for the system volume, and BootExecute shows no queued repair. Not read: {0}." -f (($dirtyUnreadable -join ', ')))
        } elseif ($dirtyUnreadable.Count -gt 0) {
            Add-Skip -Message ("No queued repair on {0}, but {1} could not be read without administrator rights - so the dirty bit is only partly assessed." -f (($dirtyAssessed -join ', ')), (($dirtyUnreadable -join ', ')))
        } else {
            Add-Ok -Message ("No repair is queued and none of the fixed volumes is marked dirty ({0})." -f (($dirtyAssessed -join ', ')))
        }
    }

    # Windows Recovery Environment. It is what Reset this PC, Startup Repair and the
    # BitLocker recovery flow all boot into. A machine whose WinRE is missing or disabled
    # has no recovery path short of external media - and nothing warns about it.
    if (Get-Command -Name reagentc -CommandType Application -ErrorAction SilentlyContinue) {
        try {
            $reagentRaw = & reagentc /info 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                Add-Skip -Message 'Windows Recovery Environment status was not read - reagentc requires administrator rights.'
            } else {
                # The status word is translated; the WinRE location line is a path and is not.
                # An enabled WinRE always has a location, a disabled one has an empty one.
                $winreLocated = ($reagentRaw -match '(?im)^\s*[^:\r\n]*:\s*\\\\\?\\GLOBALROOT\S+')
                if ($winreLocated) {
                    Add-Ok -Message 'The Windows Recovery Environment is present and enabled, so Startup Repair and Reset this PC can run.'
                } else {
                    Add-Finding -Severity 'Medium' -Title 'The Windows Recovery Environment is not available' `
                        -Evidence 'reagentc /info reports no WinRE location, which means it is disabled or its image is missing.' `
                        -Impact 'Startup Repair, Reset this PC, System Restore from boot and the BitLocker recovery screen all live in WinRE. Without it, a machine that will not boot can only be recovered from external installation media.' `
                        -Fix 'Check with: reagentc /info. Turn it back on as administrator with: reagentc /enable. If that fails the winre.wim image is missing and has to be restored from installation media.' `
                        -Confidence 'Likely'
                }
            }
        } catch {
            Add-Skip -Message 'Windows Recovery Environment status could not be read.'
        }
    }

    # Raw SMART attributes. Get-StorageReliabilityCounter is empty on a great many consumer
    # SATA drives, which leaves the wear and reallocated-sector figures unread. The
    # MSStorageDriver classes expose the raw attribute table where the driver supports it,
    # and simply are not there where it does not - so this degrades to a skip rather than
    # a wrong answer.
    if ($Fast) {
        Add-Skip -Message 'Raw SMART attributes: skipped because -Fast is set.'
    } elseif (-not $ctx.IsAdmin) {
        Add-Skip -Message 'Raw SMART attributes were not read - the MSStorageDriver WMI classes require administrator rights.'
    } else {
        try {
            $smartStatus = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
            if ($smartStatus.Count -eq 0) {
                Add-Skip -Message 'Raw SMART attributes: no drive on this machine exposes the MSStorageDriver failure-prediction interface (normal for NVMe and for many USB bridges).'
            } else {
                $predicted = @($smartStatus | Where-Object { $_.PredictFailure })
                if ($predicted.Count -gt 0) {
                    Add-Finding -Severity 'Critical' -Title 'A drive is predicting its own failure' `
                        -Evidence (@($predicted | ForEach-Object { "$($_.InstanceName) reports PredictFailure = True, reason code $($_.Reason)" }) -join '; ') `
                        -Impact 'The drive firmware itself says it expects to fail. This is the strongest warning a disk gives, and it usually arrives days to weeks before the failure.' `
                        -Fix 'Back up now, before anything else. Then replace the drive. Confirm with the vendor tool or: Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus' `
                        -Confidence 'Certain'
                } else {
                    Add-Ok -Message ("None of the {0} drive(s) exposing SMART failure prediction is predicting a failure." -f $smartStatus.Count)
                }
            }
        } catch {
            Add-Skip -Message 'Raw SMART attributes: the MSStorageDriver WMI classes are not available on this machine.'
        }
    }
}

# Category "Performance", ordered by how much each finding actually costs the user:
# startup items, Windows' own boot timings, memory pressure, then background load.
function Test-PerformanceHealth {
    [CmdletBinding()]
    param()

    # local helpers as script blocks, so that PSScriptAnalyzer's verb rules
    # for functions do not apply to internal logic

    # Registry values can come back as DWORD, REG_SZ or something else entirely depending
    # on who wrote them. Without a safe conversion an [int] cast throws.
    $asInt = {
        param($Value)
        if ($null -eq $Value) { return $null }
        $parsed = 0
        if ([int]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
        return $null
    }

    # Windows stores event data as <Data Name="X">value</Data>. We look values up
    # by name, not position, because field order varies between Windows versions.
    $readEventData = {
        param($EventRecord)
        $map = @{}
        try {
            $xml = [xml]$EventRecord.ToXml()
            foreach ($node in $xml.Event.EventData.Data) {
                $attr = $node.Attributes['Name']
                if ($attr) { $map[$attr.Value] = [string]$node.InnerText }
            }
        } catch {
            # Unexpected content in the event - we return whatever we managed to parse.
            Write-Verbose -Message $_.Exception.Message
        }
        return $map
    }

    # Pulls the actual program file out of a Run value. Returns $null for values
    # without a full path (typically "rundll32.exe ..."), which resolve via PATH and would
    # therefore produce false "file is missing" hits.
    $resolveRunTarget = {
        param([string]$CommandLine)
        if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
        $raw = $CommandLine.Trim()
        $target = $null
        if ($raw.StartsWith('"')) {
            $end = $raw.IndexOf('"', 1)
            if ($end -gt 1) { $target = $raw.Substring(1, $end - 1) }
        }
        if (-not $target) {
            if ($raw -match '(?i)^(.+?\.(?:exe|com|bat|cmd|scr|pif))(?:\s|$)') {
                $target = $Matches[1]
            } else {
                $space = $raw.IndexOf(' ')
                if ($space -gt 0) { $target = $raw.Substring(0, $space) } else { $target = $raw }
            }
        }
        try { $target = [Environment]::ExpandEnvironmentVariables($target) } catch {
            # Invalid %VAR% syntax in the value - use the text as it is.
            Write-Verbose -Message $_.Exception.Message
        }
        $target = $target.Trim()
        if ($target -notmatch '^[A-Za-z]:\\') { return $null }
        return $target
    }

    # 1. Startup items

    # Task Manager does not disable a startup item by deleting the value, but by
    # setting bit 0 in the first byte here. Without this we count disabled items as
    # active and overstate the problem badly. The flags are kept separate per hive, because
    # the same name often exists under both HKLM and HKCU without being in the same state.
    $disabledStartup = @{ HKLM = @{}; HKCU = @{} }
    $approvedPaths = @(
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' },
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' },
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
    )
    foreach ($approved in $approvedPaths) {
        try {
            $approvedKey = Get-Item -LiteralPath $approved.Path -ErrorAction Stop
            foreach ($valueName in $approvedKey.GetValueNames()) {
                $flag = $approvedKey.GetValue($valueName)
                if ($flag -is [byte[]] -and $flag.Length -gt 0 -and (($flag[0] -band 1) -eq 1)) {
                    $disabledStartup[$approved.Hive][$valueName] = $true
                }
            }
        } catch {
            # The keys are only created once something is actually disabled - absence is normal.
            Write-Verbose -Message $_.Exception.Message
        }
    }

    $startupEntries = @()
    $runKeys = @(
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKLM Run' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKLM RunOnce' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKLM Run (32-bit)' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKLM RunOnce (32-bit)' },
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKCU Run' },
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKCU RunOnce' }
    )
    foreach ($runKey in $runKeys) {
        try {
            $key = Get-Item -LiteralPath $runKey.Path -ErrorAction Stop
            foreach ($valueName in $key.GetValueNames()) {
                if ([string]::IsNullOrWhiteSpace($valueName)) { continue }
                $startupEntries += [PSCustomObject]@{
                    Name       = $valueName
                    Command    = [string]$key.GetValue($valueName)
                    Source     = $runKey.Label
                    IsRegistry = $true
                    Enabled    = (-not $disabledStartup[$runKey.Hive].ContainsKey($valueName))
                }
            }
        } catch {
            # WOW6432Node does not exist on 32-bit Windows, and RunOnce is usually missing entirely.
            Write-Verbose -Message $_.Exception.Message
        }
    }

    $startupFolders = @(
        @{ Hive = 'HKCU'; Path = [Environment]::GetFolderPath('Startup'); Label = 'Startup folder (this user)' },
        @{ Hive = 'HKLM'; Path = [Environment]::GetFolderPath('CommonStartup'); Label = 'Startup folder (all users)' }
    )
    foreach ($folder in $startupFolders) {
        if ([string]::IsNullOrWhiteSpace($folder.Path)) { continue }
        try {
            $files = @(Get-ChildItem -LiteralPath $folder.Path -File -ErrorAction Stop |
                Where-Object { $_.Name -ne 'desktop.ini' })
            foreach ($file in $files) {
                $startupEntries += [PSCustomObject]@{
                    Name       = $file.Name
                    Command    = $file.FullName
                    Source     = $folder.Label
                    IsRegistry = $false
                    Enabled    = (-not $disabledStartup[$folder.Hive].ContainsKey($file.Name))
                }
            }
        } catch {
            # The folder can be missing on new profiles or point at an unreachable network path.
            Write-Verbose -Message $_.Exception.Message
        }
    }

    $activeStartup = @($startupEntries | Where-Object { $_.Enabled })
    $disabledCount = @($startupEntries | Where-Object { -not $_.Enabled }).Count

    if ($startupEntries.Count -eq 0) {
        Add-Skip -Message 'Found no startup items at all - the Run keys and the startup folders are empty or unreadable.'
    } else {
        $startupNames = @($activeStartup | ForEach-Object { $_.Name })
        $shownNames = $startupNames
        if ($startupNames.Count -gt 12) { $shownNames = @($startupNames | Select-Object -First 12) }
        $nameList = $shownNames -join ', '
        if ($startupNames.Count -gt 12) { $nameList = $nameList + (' (+{0} more)' -f ($startupNames.Count - 12)) }
        $startupEvidence = '{0} active startup items, {1} disabled. Active: {2}' -f $activeStartup.Count, $disabledCount, $nameList

        if ($activeStartup.Count -gt 20) {
            Add-Finding -Severity 'High' -Title 'Very many programs start automatically with Windows' `
                -Evidence $startupEvidence `
                -Impact 'Every item uses CPU, disk and memory right after sign-in. With more than 20 the desktop stays sluggish for several minutes every time you sign in.' `
                -Fix 'Ctrl+Shift+Esc > Startup apps. Turn off everything that does not have to run from sign-in - most programs start just fine when you open them yourself.' `
                -Confidence 'Likely'
        } elseif ($activeStartup.Count -gt 10) {
            Add-Finding -Severity 'Medium' -Title 'Many programs start automatically with Windows' `
                -Evidence $startupEvidence `
                -Impact 'Stretches the time from sign-in until the machine is actually usable, and keeps background processes alive for the rest of the session.' `
                -Fix 'Ctrl+Shift+Esc > Startup apps. Sort by "Startup impact" and turn off the high-impact entries you do not need right away.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message ('Startup is tidy: {0} active items ({1} disabled).' -f $activeStartup.Count, $disabledCount)
        }

        $brokenStartup = @()
        foreach ($entry in $activeStartup) {
            if (-not $entry.IsRegistry) { continue }
            $target = & $resolveRunTarget $entry.Command
            if (-not $target) { continue }
            if (-not (Test-Path -LiteralPath $target -ErrorAction SilentlyContinue)) {
                $brokenStartup += ('{0} -> {1}' -f $entry.Name, $target)
            }
        }
        if ($brokenStartup.Count -gt 0) {
            $brokenShown = $brokenStartup
            if ($brokenStartup.Count -gt 6) { $brokenShown = @($brokenStartup | Select-Object -First 6) }
            Add-Finding -Severity 'Low' -Title 'Startup entries point at files that do not exist' `
                -Evidence (('{0} entry/entries: ' -f $brokenStartup.Count) + ($brokenShown -join ' | ')) `
                -Impact 'Windows tries to start these at every sign-in and fails. It costs a little time, fills the logs with noise, and is typically leftovers from uninstalled programs.' `
                -Fix 'Delete the values in question under HKCU\Software\Microsoft\Windows\CurrentVersion\Run (and the equivalent under HKLM) in regedit, after you have confirmed that the program really is gone.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message 'All startup entries with a full file path point at files that exist.'
        }
    }

    # 2. Windows' own boot measurements

    # The log has to be confirmed present before an empty search result is interpreted. Otherwise a
    # machine without this channel would be declared healthy for something we never got to check.
    $diagLog = 'Microsoft-Windows-Diagnostics-Performance/Operational'
    $diagLogInfo = $null
    if (-not $Fast) {
        try {
            $diagLogInfo = Get-WinEvent -ListLog $diagLog -ErrorAction Stop
        } catch {
            # The channel does not exist - common on Server editions and in some virtual machines.
            Write-Verbose -Message $_.Exception.Message
        }
    }
    $diagLogUsable = ($null -ne $diagLogInfo -and $diagLogInfo.IsEnabled -and $diagLogInfo.RecordCount -gt 0)

    if ($Fast) {
        Add-Skip -Message 'Boot measurements from the event log were skipped because -Fast is set.'
    } elseif (-not $diagLogUsable) {
        # Without admin this channel is unreadable, and Get-WinEvent -ListLog then returns
        # nothing - which looks identical to the log being absent. Naming the wrong cause
        # sends the reader looking for a missing log that is actually there and populated.
        if (-not $script:Ctx.IsAdmin) {
            Add-Skip -Message ('The log {0} needs administrator rights to read, so the boot measurements Windows records itself were not assessed.' -f $diagLog)
        } else {
            Add-Skip -Message ('The log {0} is missing, disabled or empty, so the boot measurements Windows records itself could not be read (common in virtual machines and right after installation).' -f $diagLog)
        }
    } else {
        $bootEvents = @()
        try {
            $bootEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $diagLog; Id = 100 } -MaxEvents 10 -ErrorAction Stop)
        } catch {
            # The log exists, but does not contain any boot measurements yet.
            Write-Verbose -Message $_.Exception.Message
        }

        if ($bootEvents.Count -eq 0) {
            Add-Skip -Message ('Found no event ID 100 (boot time) in {0} yet - the log only fills up after a few restarts.' -f $diagLog)
        } else {
            $mainPathTimes = @()
            $latestData = $null
            foreach ($bootEvent in $bootEvents) {
                $data = & $readEventData $bootEvent
                if ($null -eq $latestData) { $latestData = $data }
                $bootMs = 0
                if ($data.ContainsKey('MainPathBootTime') -and [int]::TryParse($data['MainPathBootTime'], [ref]$bootMs) -and $bootMs -gt 0) {
                    $mainPathTimes += $bootMs
                }
            }

            if ($mainPathTimes.Count -eq 0) {
                Add-Skip -Message 'The boot events were missing the MainPathBootTime field, so boot time could not be calculated.'
            } else {
                # Median, not average: a single slow boot after Windows Update
                # is normal and should not trigger a finding.
                $sortedTimes = @($mainPathTimes | Sort-Object)
                $medianMs = $sortedTimes[[int][math]::Floor($sortedTimes.Count / 2)]
                $latestMs = $mainPathTimes[0]
                $totalMs = 0
                $startupAppCount = ''
                if ($null -ne $latestData) {
                    if ($latestData.ContainsKey('BootTime')) { [void][int]::TryParse($latestData['BootTime'], [ref]$totalMs) }
                    if ($latestData.ContainsKey('BootNumStartupApps')) { $startupAppCount = $latestData['BootNumStartupApps'] }
                }
                $bootEvidence = 'Median main path boot time over {0} measurements: {1} s (last boot: {2} s).' -f $mainPathTimes.Count, [math]::Round($medianMs / 1000, 1), [math]::Round($latestMs / 1000, 1)
                if ($totalMs -gt 0) {
                    $bootEvidence = $bootEvidence + (' Until the system went idle: {0} s.' -f [math]::Round($totalMs / 1000, 1))
                }
                if ($startupAppCount) {
                    $bootEvidence = $bootEvidence + (' Windows counted {0} startup apps at the last boot.' -f $startupAppCount)
                }

                if ($medianMs -ge 100000) {
                    Add-Finding -Severity 'High' -Title 'Boot takes considerably longer than it should' `
                        -Evidence $bootEvidence `
                        -Impact 'More than a minute and a half before the desktop is ready. On a machine with an SSD 10-30 s is normal, so something here - a driver, a service or a startup app - is slowing things down.' `
                        -Fix 'Event Viewer > Applications and Services Logs > Microsoft > Windows > Diagnostics-Performance > Operational: event ID 101 and 103 name the program or service that is delaying boot.' `
                        -Confidence 'Likely'
                } elseif ($medianMs -ge 60000) {
                    Add-Finding -Severity 'Medium' -Title 'Boot is slower than normal' `
                        -Evidence $bootEvidence `
                        -Impact 'Windows itself counts anything over 60 seconds as a slow boot. Noticeable waiting every time the machine is turned on.' `
                        -Fix 'Cut the number of startup apps in Task Manager > Startup apps, and look at event ID 101/103 in the Diagnostics-Performance log to find the worst offender.' `
                        -Confidence 'Likely'
                } else {
                    Add-Ok -Message ('Boot time is normal: median {0} s over {1} measurements.' -f [math]::Round($medianMs / 1000, 1), $mainPathTimes.Count)
                }

                if ($null -ne $latestData -and $latestData.ContainsKey('BootIsDegradation') -and $latestData['BootIsDegradation'] -eq 'true') {
                    Add-Finding -Severity 'Low' -Title 'Windows has recorded that boot has become slower' `
                        -Evidence ('Event 100 from {0} has BootIsDegradation=true.' -f $bootEvents[0].TimeCreated) `
                        -Impact 'Something installed or changed recently has made boot measurably slower than it was.' `
                        -Fix 'Compare with event ID 101/103 in the same log to see which program or service was added.' `
                        -Confidence 'Likely'
                }
            }
        }

        $delayEvents = @()
        try {
            $delayEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $diagLog; Id = 101, 103; StartTime = (Get-Date).AddDays(-60) } -MaxEvents 200 -ErrorAction Stop)
        } catch {
            # Windows only logs these when something actually delays boot - absence is a good sign.
            Write-Verbose -Message $_.Exception.Message
        }

        if ($delayEvents.Count -eq 0) {
            Add-Ok -Message 'Windows has not recorded any apps or services delaying boot in the last 60 days.'
        } else {
            # Worst measurement per component, but we also count how many times it was
            # measured: one slow boot is chance, ten in a row is a pattern.
            $delayWorst = @{}
            $delayCount = @{}
            foreach ($delayEvent in $delayEvents) {
                $data = & $readEventData $delayEvent
                $label = $data['FriendlyName']
                if ([string]::IsNullOrWhiteSpace($label)) { $label = $data['Name'] }
                if ([string]::IsNullOrWhiteSpace($label)) { continue }
                $delayMs = 0
                if (-not ($data.ContainsKey('TotalTime') -and [int]::TryParse($data['TotalTime'], [ref]$delayMs))) { continue }
                if ($delayMs -le 0) { continue }
                if ((-not $delayWorst.ContainsKey($label)) -or $delayWorst[$label] -lt $delayMs) { $delayWorst[$label] = $delayMs }
                if ($delayCount.ContainsKey($label)) { $delayCount[$label] = $delayCount[$label] + 1 } else { $delayCount[$label] = 1 }
            }

            if ($delayWorst.Count -eq 0) {
                Add-Skip -Message 'Event 101/103 were present, but without usable time values.'
            } else {
                $ranked = @($delayWorst.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5)
                $worstMs = $ranked[0].Value
                $delayList = ($ranked | ForEach-Object {
                        $times = $delayCount[$_.Key]
                        $timesText = 'times'
                        if ($times -eq 1) { $timesText = 'time' }
                        '{0}: {1} s (measured {2} {3})' -f $_.Key, [math]::Round($_.Value / 1000, 1), $times, $timesText
                    }) -join ', '
                $delayEvidence = 'Worst measured delay per component (event 101/103, last 60 days): {0}' -f $delayList

                if ($worstMs -ge 20000) {
                    Add-Finding -Severity 'Medium' -Title 'An app or service is delaying boot badly' `
                        -Evidence $delayEvidence `
                        -Impact 'Windows has measured that the component holds up sign-in for more than 20 seconds. This is the most concrete cause of slow boot Windows can point at.' `
                        -Fix 'Turn off the worst offender in Task Manager > Startup apps, or uninstall it. If it is a service, consider start type Manual in services.msc.' `
                        -Confidence 'Likely'
                } elseif ($worstMs -ge 8000) {
                    Add-Finding -Severity 'Low' -Title 'Some components take noticeable time during boot' `
                        -Evidence $delayEvidence `
                        -Impact 'A few extra seconds before the desktop responds. Not serious, but this is where the time goes.' `
                        -Fix 'Consider turning off the slowest ones in Task Manager > Startup apps if you do not need them immediately after sign-in.' `
                        -Confidence 'Likely'
                } else {
                    Add-Finding -Severity 'Info' -Title 'Components Windows has measured during boot' `
                        -Evidence $delayEvidence `
                        -Impact 'All of them are under 8 seconds, which is within normal. No action needed.' `
                        -Confidence 'Certain'
                }
            }
        }
    }

    # 3. Memory pressure

    $totalRamBytes = 0
    if ($script:Ctx.OS -and $script:Ctx.OS.TotalVisibleMemorySize) {
        $totalRamBytes = [double]$script:Ctx.OS.TotalVisibleMemorySize * 1KB
    } elseif ($script:Ctx.TotalRamGB) {
        $totalRamBytes = [double]$script:Ctx.TotalRamGB * 1GB
    }

    $perfMem = $null
    try {
        $perfMem = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory -ErrorAction Stop | Select-Object -First 1
    } catch {
        # The performance counters can be broken or disabled on the machine.
        Write-Verbose -Message $_.Exception.Message
    }

    if ($null -eq $perfMem) {
        Add-Skip -Message 'The memory performance counters (Win32_PerfRawData_PerfOS_Memory) were not available, so free RAM and commit charge could not be measured.'
    } else {
        $availableBytes = [double]$perfMem.AvailableBytes
        if ($totalRamBytes -gt 0 -and $availableBytes -gt 0) {
            $availablePct = [math]::Round(($availableBytes / $totalRamBytes) * 100, 1)
            $memEvidence = '{0} free of {1} total ({2} %), measured now.' -f (Format-Size -Bytes $availableBytes), (Format-Size -Bytes $totalRamBytes), $availablePct
            if ($availablePct -lt 8) {
                Add-Finding -Severity 'High' -Title 'The machine has very little free memory' `
                    -Evidence $memEvidence `
                    -Impact 'Under 8 % free means Windows has to page actively to disk. That gives stuttering, slow window switching and apps that freeze briefly.' `
                    -Fix 'Close the biggest memory hogs (see the finding about memory use per process), or add RAM. Ctrl+Shift+Esc > Performance > Memory shows the trend.' `
                    -Confidence 'Likely'
            } elseif ($availablePct -lt 15) {
                Add-Finding -Severity 'Medium' -Title 'Little free memory right now' `
                    -Evidence $memEvidence `
                    -Impact 'Not much headroom. Open one more large thing and Windows starts paging and the machine feels slow.' `
                    -Fix 'Close apps you are not using, and check in Ctrl+Shift+Esc > Performance > Memory whether this is a steady level or a random spike.' `
                    -Confidence 'Uncertain'
            } else {
                Add-Ok -Message ('Free memory is fine: {0} ({1} %) of {2}.' -f (Format-Size -Bytes $availableBytes), $availablePct, (Format-Size -Bytes $totalRamBytes))
            }
        } else {
            Add-Skip -Message 'Could not calculate the share of free memory because total or available memory was reported as zero.'
        }

        $commitBytes = [double]$perfMem.CommittedBytes
        $commitLimit = [double]$perfMem.CommitLimit
        if ($commitLimit -gt 0 -and $commitBytes -gt 0) {
            $commitPct = [math]::Round(($commitBytes / $commitLimit) * 100, 1)
            $commitEvidence = 'Commit charge {0} of {1} ({2} %).' -f (Format-Size -Bytes $commitBytes), (Format-Size -Bytes $commitLimit), $commitPct
            if ($commitPct -ge 92) {
                Add-Finding -Severity 'High' -Title 'Commit charge is approaching the ceiling' `
                    -Evidence $commitEvidence `
                    -Impact 'Once the commit limit is reached, Windows refuses to give apps more memory. Then come the "your system is out of memory" dialogs and apps that quit without warning.' `
                    -Fix 'Close memory-heavy apps, and let Windows manage the paging file: System Properties > Advanced > Performance > Settings > Advanced > Virtual memory.' `
                    -Confidence 'Likely'
            } elseif ($commitPct -ge 82) {
                Add-Finding -Severity 'Medium' -Title 'High commit charge' `
                    -Evidence $commitEvidence `
                    -Impact 'The machine is using most of its total memory budget (RAM plus paging file). Little room left for heavy work.' `
                    -Fix 'Check that the paging file is system managed under System Properties > Advanced > Performance > Settings > Advanced > Virtual memory, and close apps you are not using.' `
                    -Confidence 'Likely'
            } else {
                Add-Ok -Message ('Commit charge is within range: {0} % of the limit.' -f $commitPct)
            }
        } else {
            Add-Skip -Message 'Commit charge could not be read (CommittedBytes or CommitLimit was zero).'
        }
    }

    # $null means the query failed, an empty list means the paging file really
    # is turned off. The two must not be confused - only the second is a finding.
    $pageFiles = $null
    try {
        $pageFiles = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)
    } catch {
        $pageFiles = $null
        Write-Verbose -Message $_.Exception.Message
    }

    if ($null -eq $pageFiles) {
        Add-Skip -Message 'Win32_PageFileUsage could not be queried, so the paging file was not assessed.'
    } elseif ($pageFiles.Count -eq 0) {
        $autoManaged = 'unknown'
        if ($script:Ctx.ComputerSystem) { $autoManaged = [string]$script:Ctx.ComputerSystem.AutomaticManagedPagefile }
        Add-Finding -Severity 'Low' -Title 'No paging file is in use' `
            -Evidence ('Win32_PageFileUsage returned zero instances. AutomaticManagedPagefile={0}.' -f $autoManaged) `
            -Impact 'Without a paging file the commit limit is set equal to physical RAM. Heavy apps can fail with out-of-memory even though Task Manager shows free RAM, and complete memory dumps on a blue screen are never written.' `
            -Fix 'System Properties > Advanced > Performance > Settings > Advanced > Virtual memory: tick "Automatically manage paging file size for all drives".' `
            -Confidence 'Uncertain'
    } else {
        $pageFlagged = $false
        foreach ($pageFile in $pageFiles) {
            $allocatedMb = [double]$pageFile.AllocatedBaseSize
            $peakMb = [double]$pageFile.PeakUsage
            if ($allocatedMb -le 0) { continue }
            $peakPct = [math]::Round(($peakMb / $allocatedMb) * 100, 1)
            $pageEvidence = '{0}: peak usage {1} MB of {2} MB allocated ({3} %), in use now {4} MB.' -f $pageFile.Name, $peakMb, $allocatedMb, $peakPct, $pageFile.CurrentUsage
            if ($peakPct -ge 85) {
                $pageFlagged = $true
                Add-Finding -Severity 'Medium' -Title 'The paging file has been close to full' `
                    -Evidence $pageEvidence `
                    -Impact 'The peak usage shows the machine has been under real memory pressure since the last boot. If the paging file fills up, apps stop.' `
                    -Fix 'Let Windows manage the size (System Properties > Advanced > Performance > Settings > Advanced > Virtual memory), or add RAM if this keeps happening.' `
                    -Confidence 'Likely'
            } elseif ($peakPct -ge 60) {
                $pageFlagged = $true
                Add-Finding -Severity 'Low' -Title 'The paging file has been well used' `
                    -Evidence $pageEvidence `
                    -Impact 'The machine has had periods of memory pressure since boot. Not critical, but it explains any stuttering under heavy use.' `
                    -Fix 'No action needed now. Keep an eye on Ctrl+Shift+Esc > Performance > Memory when the machine feels slow.' `
                    -Confidence 'Uncertain'
            }
        }
        if (-not $pageFlagged) {
            Add-Ok -Message ('The paging file has not been under pressure ({0} file(s) checked).' -f $pageFiles.Count)
        }
    }

    $topProcesses = @()
    try {
        $topProcesses = @(Get-Process -ErrorAction SilentlyContinue |
            Group-Object -Property ProcessName |
            ForEach-Object {
                [PSCustomObject]@{
                    Name  = $_.Name
                    Count = $_.Count
                    Bytes = ($_.Group | Measure-Object -Property WorkingSet64 -Sum).Sum
                }
            } |
            Sort-Object -Property Bytes -Descending |
            Select-Object -First 5)
    } catch {
        # The process list can be partially denied under low privileges.
        Write-Verbose -Message $_.Exception.Message
    }

    if ($topProcesses.Count -eq 0) {
        Add-Skip -Message 'The process list could not be read, so the biggest memory hogs were not reported.'
    } else {
        $procList = ($topProcesses | ForEach-Object {
                if ($_.Count -gt 1) { '{0} ({1} processes): {2}' -f $_.Name, $_.Count, (Format-Size -Bytes $_.Bytes) }
                else { '{0}: {1}' -f $_.Name, (Format-Size -Bytes $_.Bytes) }
            }) -join ', '
        Add-Finding -Severity 'Info' -Title 'The processes using the most memory right now' `
            -Evidence $procList `
            -Impact 'Snapshot, summed per program name. Useful for seeing what is eating memory when the machine feels slow.' `
            -Confidence 'Certain'
    }

    # 4. Performance settings

    $visualFx = & $asInt (Get-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting')
    $minAnimate = Get-RegValue -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate'
    $visualFxText = 'not set (Windows decides)'
    if ($null -ne $visualFx) {
        switch ($visualFx) {
            0 { $visualFxText = '0 = let Windows choose' }
            1 { $visualFxText = '1 = best appearance' }
            2 { $visualFxText = '2 = best performance' }
            3 { $visualFxText = '3 = custom' }
            default { $visualFxText = ('{0} = unknown value' -f $visualFx) }
        }
    }
    $animText = 'not set'
    if ($null -ne $minAnimate) {
        if ([string]$minAnimate -eq '1') { $animText = 'window animations on' } else { $animText = 'window animations off' }
    }
    Add-Finding -Severity 'Info' -Title 'Visual effects' `
        -Evidence ('VisualFXSetting: {0}. MinAnimate: {1}.' -f $visualFxText, $animText) `
        -Impact 'On modern hardware the animations cost little real performance, but they make the interface feel slower because every action has a built-in delay.' `
        -Fix 'Want a snappier interface: search for "Adjust the appearance and performance of Windows" and pick "Adjust for best performance".' `
        -Confidence 'Certain'

    $sysMain = Get-ServiceState -Name 'SysMain'
    $prefetchValue = & $asInt (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher')
    if (-not $sysMain) {
        Add-Skip -Message 'The SysMain service does not exist on this machine, so SysMain and prefetch were not assessed.'
    } else {
        $sysMainStart = 'unknown'
        try { $sysMainStart = [string]$sysMain.StartType } catch {
            # StartType does not exist in every .NET version - we fall back on status alone.
            Write-Verbose -Message $_.Exception.Message
        }
        $sysMainStatus = [string]$sysMain.Status
        $prefetchText = 'not set'
        if ($null -ne $prefetchValue) { $prefetchText = [string]$prefetchValue }
        $sysMainEvidence = 'SysMain: status {0}, start type {1}. EnablePrefetcher: {2}.' -f $sysMainStatus, $sysMainStart, $prefetchText
        $prefetchOn = ($null -ne $prefetchValue -and $prefetchValue -gt 0)
        $sysMainOff = ($sysMainStart -eq 'Disabled' -or $sysMainStatus -eq 'Stopped')

        if ($sysMainOff -and $prefetchOn) {
            Add-Finding -Severity 'Low' -Title 'SysMain and the prefetch setting are out of sync' `
                -Evidence $sysMainEvidence `
                -Impact 'EnablePrefetcher is on, but the service that uses the prefetch data is not running. Windows then writes prefetch files nobody reads. Typically a half-finished cleanup after a tuning guide.' `
                -Fix 'Pick one or the other: set SysMain to Automatic in services.msc, or set EnablePrefetcher to 0 under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters.' `
                -Confidence 'Likely'
        } elseif ((-not $sysMainOff) -and $null -ne $prefetchValue -and $prefetchValue -eq 0) {
            Add-Finding -Severity 'Low' -Title 'SysMain is running, but prefetch is turned off' `
                -Evidence $sysMainEvidence `
                -Impact 'The service is running without anything to work on. You pay for the background service without getting faster program starts back.' `
                -Fix 'Set EnablePrefetcher to 3 under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters, or set SysMain to Disabled in services.msc.' `
                -Confidence 'Likely'
        } elseif ($sysMainOff) {
            Add-Finding -Severity 'Info' -Title 'SysMain is turned off' `
                -Evidence $sysMainEvidence `
                -Impact 'Consistent setup. On an SSD SysMain matters little, so this is a valid choice - program starts may be marginally slower the first time.' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message ('SysMain and prefetch are in sync: the service is {0}, EnablePrefetcher is {1}.' -f $sysMainStatus.ToLower(), $prefetchText)
        }
    }

    $videoControllers = $null
    try {
        $videoControllers = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop)
    } catch {
        $videoControllers = $null
        Write-Verbose -Message $_.Exception.Message
    }
    # Name matching, not vendor ID: AMD uses the same VEN ID on integrated and dedicated graphics.
    $dedicatedGpu = @()
    if ($null -ne $videoControllers) {
        $dedicatedGpu = @($videoControllers | Where-Object {
                $_.Name -match '(?i)(GeForce|RTX|GTX|Quadro|Tesla|Radeon (RX|R9|R7|Pro|VII)|FirePro|Arc (A|B)\d)'
            })
    }
    if ($null -eq $videoControllers) {
        Add-Skip -Message 'Win32_VideoController could not be queried, so GPU scheduling was not assessed.'
    } elseif ($dedicatedGpu.Count -eq 0) {
        Add-Skip -Message 'Found no dedicated graphics card, so hardware-accelerated GPU scheduling was not assessed (the setting only has an effect with driver support).'
    } else {
        $hwSchMode = & $asInt (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode')
        $gpuNames = ($dedicatedGpu | ForEach-Object { $_.Name }) -join ', '
        if ($null -eq $hwSchMode) {
            Add-Finding -Severity 'Info' -Title 'GPU scheduling follows the driver default' `
                -Evidence ('HwSchMode is not set under HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers. Dedicated GPU: {0}.' -f $gpuNames) `
                -Impact 'Windows uses the driver default. Nothing is wrong, but the setting has not been chosen deliberately.' `
                -Confidence 'Certain'
        } elseif ($hwSchMode -eq 2) {
            Add-Ok -Message ('Hardware-accelerated GPU scheduling is on (HwSchMode=2) with {0}.' -f $gpuNames)
        } else {
            Add-Finding -Severity 'Info' -Title 'Hardware-accelerated GPU scheduling is off' `
                -Evidence ('HwSchMode={0}. Dedicated GPU: {1}.' -f $hwSchMode, $gpuNames) `
                -Impact 'Can give slightly higher input latency in games on hardware that supports the feature. The effect varies between drivers and is rarely dramatic.' `
                -Fix 'Settings > System > Display > Graphics > Change default graphics settings > Hardware-accelerated GPU scheduling. Requires a restart.' `
                -Confidence 'Uncertain'
        }
    }

    $gameDvr = & $asInt (Get-RegValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled')
    $appCapture = & $asInt (Get-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled')
    $gameMode = & $asInt (Get-RegValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled')
    if ($null -eq $gameDvr -and $null -eq $appCapture) {
        Add-Skip -Message 'Found no Game DVR settings in the registry for this user.'
    } else {
        $gameDvrText = 'not set'
        if ($null -ne $gameDvr) { $gameDvrText = [string]$gameDvr }
        $appCaptureText = 'not set'
        if ($null -ne $appCapture) { $appCaptureText = [string]$appCapture }
        $gameModeText = 'not set'
        if ($null -ne $gameMode) { $gameModeText = [string]$gameMode }
        $gameEvidence = 'GameDVR_Enabled={0}, AppCaptureEnabled={1}, AutoGameModeEnabled={2}.' -f $gameDvrText, $appCaptureText, $gameModeText
        $dvrOn = (($null -ne $gameDvr -and $gameDvr -eq 1) -or ($null -ne $appCapture -and $appCapture -eq 1))
        if ($dvrOn) {
            Add-Finding -Severity 'Low' -Title 'Game DVR (background recording) is enabled' `
                -Evidence $gameEvidence `
                -Impact 'Background recording keeps a video encoder running while you play and typically costs a few percent of the frame rate. Most noticeable on machines that are already close to the edge.' `
                -Fix 'Settings > Gaming > Captures: turn off "Record what happened". If you do not use Game Bar at all, the whole feature can be turned off in the same place.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message ('Game DVR background recording is not enabled. {0}' -f $gameEvidence)
        }
    }

    # 5. Processor power policy

    $powerOutput = @()
    try {
        $powerOutput = @(& powercfg.exe /query SCHEME_CURRENT SUB_PROCESSOR 2>$null)
    } catch {
        # powercfg is missing or denied in heavily locked-down environments.
        Write-Verbose -Message $_.Exception.Message
    }

    if ($powerOutput.Count -eq 0) {
        Add-Skip -Message 'powercfg /query SCHEME_CURRENT SUB_PROCESSOR produced no output, so the processor power settings were not read.'
    } else {
        # All the labels in the powercfg output are translated into the display language, but
        # the GUID aliases and the GUIDs themselves are not. So we anchor on those, and
        # take the last two hex values in each block: powercfg always writes
        # "Minimum/Maximum Possible Setting" first and then the AC index before the DC index.
        $procSettings = @{}
        $currentAlias = $null
        $hexValues = @()
        $schemeName = ''
        foreach ($line in $powerOutput) {
            $text = [string]$line
            # The first GUID line is the power plan itself, with the display name in parentheses.
            if (-not $schemeName -and $text -match '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-.*\(([^)]+)\)\s*$') { $schemeName = $Matches[1] }
            if ($text -match '(?i)\b(PROCTHROTTLEMIN|PROCTHROTTLEMAX)\s*$') {
                if ($currentAlias -and $hexValues.Count -ge 2) { $procSettings[$currentAlias] = @($hexValues | Select-Object -Last 2) }
                $currentAlias = $Matches[1].ToUpperInvariant()
                $hexValues = @()
                continue
            }
            # A new GUID means the next settings block starts, so the previous one is closed.
            if ($currentAlias -and $text -match '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-') {
                if ($hexValues.Count -ge 2) { $procSettings[$currentAlias] = @($hexValues | Select-Object -Last 2) }
                $currentAlias = $null
                $hexValues = @()
                continue
            }
            if ($currentAlias -and $text -match '0x([0-9a-fA-F]{8})') {
                $hexValues += [Convert]::ToInt32($Matches[1], 16)
            }
        }
        if ($currentAlias -and $hexValues.Count -ge 2) { $procSettings[$currentAlias] = @($hexValues | Select-Object -Last 2) }

        $maxAc = -1
        $maxDc = -1
        if ($procSettings.ContainsKey('PROCTHROTTLEMAX')) {
            $maxAc = $procSettings['PROCTHROTTLEMAX'][0]
            $maxDc = $procSettings['PROCTHROTTLEMAX'][1]
        }
        if ($maxAc -lt 1 -or $maxAc -gt 100) {
            Add-Skip -Message 'Found no usable value for maximum processor state in the powercfg output, so the processor power settings were not assessed.'
        } else {
            $minAc = $null
            $minDc = $null
            if ($procSettings.ContainsKey('PROCTHROTTLEMIN')) {
                $minAc = $procSettings['PROCTHROTTLEMIN'][0]
                $minDc = $procSettings['PROCTHROTTLEMIN'][1]
            }
            $schemeText = 'the active power plan'
            if ($schemeName) { $schemeText = ('the power plan "{0}"' -f $schemeName) }
            $procEvidence = 'In {0}: maximum processor state {1} % on AC power' -f $schemeText, $maxAc
            if ($null -ne $minAc) { $procEvidence = $procEvidence + (', minimum {0} %' -f $minAc) }
            if ($script:Ctx.HasBattery -and $maxDc -ge 0) {
                $procEvidence = $procEvidence + ('. On battery: maximum {0} %' -f $maxDc)
                if ($null -ne $minDc) { $procEvidence = $procEvidence + (', minimum {0} %' -f $minDc) }
            }
            $procEvidence = $procEvidence + '.'

            if ($maxAc -le 70) {
                Add-Finding -Severity 'High' -Title 'The processor is heavily limited on AC power' `
                    -Evidence $procEvidence `
                    -Impact ('Maximum processor state is {0} %. The machine never gets to use its full clock speed, no matter how heavy the work is. You notice it in everything.' -f $maxAc) `
                    -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > Processor power management > Maximum processor state: set Plugged in to 100 %.' `
                    -Confidence 'Certain'
            } elseif ($maxAc -lt 100) {
                Add-Finding -Severity 'Medium' -Title 'Maximum processor state is below 100 % on AC power' `
                    -Evidence $procEvidence `
                    -Impact ('The processor is only allowed to use {0} % of its frequency range. Often set deliberately to keep fans and heat down, but it costs performance in heavy work.' -f $maxAc) `
                    -Fix 'Control Panel > Power Options > Change advanced power settings > Processor power management > Maximum processor state: set Plugged in to 100 %.' `
                    -Confidence 'Certain'
            } else {
                Add-Ok -Message 'The processor is allowed to use its full frequency on AC power (maximum processor state 100 %).'
            }

            if ($null -ne $minAc -and $minAc -ge 100) {
                Add-Finding -Severity 'Low' -Title 'Minimum processor state is locked at 100 %' `
                    -Evidence $procEvidence `
                    -Impact 'The processor never clocks down, not even at idle. That means higher power draw, more heat and more fan noise without making the machine any faster under load.' `
                    -Fix 'Control Panel > Power Options > Change advanced power settings > Processor power management > Minimum processor state: set Plugged in to 5 %.' `
                    -Confidence 'Likely'
            }

            if ($script:Ctx.HasBattery -and $maxDc -gt 0 -and $maxDc -le 50) {
                Add-Finding -Severity 'Low' -Title 'The processor is heavily limited on battery' `
                    -Evidence $procEvidence `
                    -Impact ('Maximum processor state on battery is {0} %. That gives longer battery life, but the machine feels clearly slower when it is not plugged in.' -f $maxDc) `
                    -Fix 'Control Panel > Power Options > Change advanced power settings > Processor power management > Maximum processor state > On battery.' `
                    -Confidence 'Likely'
            }
        }
    }

    # 6. Background load: scheduled tasks and automatic services

    if ($Fast) {
        Add-Skip -Message 'The scheduled task review was skipped because -Fast is set.'
    } else {
        $thirdPartyTasks = @()
        $taskReadFailed = $false
        try {
            $thirdPartyTasks = @(Get-ScheduledTask -ErrorAction Stop |
                Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -eq 'Ready' })
        } catch {
            # The ScheduledTasks module is missing in some stripped-down installations.
            $taskReadFailed = $true
            Write-Verbose -Message $_.Exception.Message
        }

        if ($taskReadFailed) {
            Add-Skip -Message 'Get-ScheduledTask was not available, so third-party scheduled tasks were not counted.'
        } elseif ($thirdPartyTasks.Count -eq 0) {
            Add-Ok -Message 'No active third-party scheduled tasks outside \Microsoft\.'
        } else {
            # Only tasks that repeat more often than hourly produce measurable background load.
            # There is no reason to complain about daily update checks.
            $frequentTasks = @()
            foreach ($task in $thirdPartyTasks) {
                foreach ($trigger in @($task.Triggers)) {
                    if (-not $trigger.Repetition) { continue }
                    $interval = [string]$trigger.Repetition.Interval
                    if ([string]::IsNullOrWhiteSpace($interval)) { continue }
                    try {
                        $span = [System.Xml.XmlConvert]::ToTimeSpan($interval)
                        if ($span.TotalMinutes -gt 0 -and $span.TotalMinutes -le 60) {
                            $frequentTasks += ('{0} (every {1} min)' -f $task.TaskName, [math]::Round($span.TotalMinutes))
                        }
                    } catch {
                        # Durations with a month or year component cannot be converted, and are not frequent anyway.
                        Write-Verbose -Message $_.Exception.Message
                    }
                }
            }
            $frequentTasks = @($frequentTasks | Select-Object -Unique)

            $taskEvidence = '{0} active tasks outside \Microsoft\, of which {1} repeat at least once an hour.' -f $thirdPartyTasks.Count, $frequentTasks.Count
            if ($frequentTasks.Count -gt 0) {
                $frequentShown = $frequentTasks
                if ($frequentTasks.Count -gt 6) { $frequentShown = @($frequentTasks | Select-Object -First 6) }
                $taskEvidence = $taskEvidence + (' Frequent: {0}.' -f ($frequentShown -join ', '))
            }

            if ($thirdPartyTasks.Count -gt 40 -or $frequentTasks.Count -ge 6) {
                Add-Finding -Severity 'Medium' -Title 'Many third-party scheduled tasks' `
                    -Evidence $taskEvidence `
                    -Impact 'Every task wakes a process, usually to check for updates. Many frequent tasks give steady background activity on disk and CPU, and on a laptop you notice it in battery life.' `
                    -Fix 'Open Task Scheduler (taskschd.msc) and go through the tasks in the root folder and the vendor folders. Disable update tasks for software you update manually.' `
                    -Confidence 'Likely'
            } elseif ($thirdPartyTasks.Count -gt 20) {
                Add-Finding -Severity 'Low' -Title 'Quite a few third-party scheduled tasks' `
                    -Evidence $taskEvidence `
                    -Impact 'Normal for a machine with a lot of installed software, but this is where steady background activity comes from.' `
                    -Fix 'Task Scheduler (taskschd.msc) if you want to clean up. No rush.' `
                    -Confidence 'Likely'
            } else {
                # Get-ScheduledTask only returns tasks the caller may read, so an unelevated
                # run sees a subset - here 14 of 24. Reporting that count as a clean bill of
                # health without saying it is partial overstates what was actually checked.
                $taskScope = if ($script:Ctx.IsAdmin) { '' } else { ' (counted without administrator rights, so tasks owned by other users or by SYSTEM are not included)' }
                Add-Ok -Message ('Third-party scheduled tasks are within range: {0}{1}' -f $taskEvidence, $taskScope)
            }
        }
    }

    $autoServices = @()
    try {
        $autoServices = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' })
    } catch {
        # Win32_Service can be denied under heavily restricted privileges.
        Write-Verbose -Message $_.Exception.Message
    }

    if ($autoServices.Count -eq 0) {
        Add-Skip -Message 'The service list (Win32_Service) could not be read, so automatic third-party services were not counted.'
    } else {
        # Crude but fast indicator: a service with its executable outside %SystemRoot%
        # almost always comes from software the user installed themselves.
        $nonWindowsServices = @($autoServices | Where-Object {
                $_.PathName -and ($_.PathName -notmatch '(?i)^"?[A-Za-z]:\\Windows\\')
            })
        $serviceNames = @($nonWindowsServices | ForEach-Object { $_.Name })
        $serviceShown = $serviceNames
        if ($serviceNames.Count -gt 10) { $serviceShown = @($serviceNames | Select-Object -First 10) }
        $serviceEvidence = '{0} of {1} services with start type Automatic have their executable outside {2}: {3}' -f $nonWindowsServices.Count, $autoServices.Count, $env:SystemRoot, ($serviceShown -join ', ')
        if ($serviceNames.Count -gt 10) { $serviceEvidence = $serviceEvidence + (' (+{0} more)' -f ($serviceNames.Count - 10)) }

        if ($nonWindowsServices.Count -gt 25) {
            Add-Finding -Severity 'Medium' -Title 'Many third-party services start automatically' `
                -Evidence $serviceEvidence `
                -Impact 'The services start before you sign in and run all the time. More than 25 of them give noticeable background load on memory and boot time.' `
                -Fix 'Go through services.msc and set start type to Manual for services belonging to software you rarely use. Leave services you do not recognize alone.' `
                -Confidence 'Uncertain'
        } elseif ($nonWindowsServices.Count -gt 15) {
            Add-Finding -Severity 'Low' -Title 'Quite a few third-party services start automatically' `
                -Evidence $serviceEvidence `
                -Impact 'Common on a machine with a lot of installed software. Every service costs a little memory and a little boot time.' `
                -Fix 'services.msc if you want to set some to Manual. No rush, and leave services you do not recognize alone.' `
                -Confidence 'Uncertain'
        } else {
            Add-Ok -Message ('The number of automatic third-party services is moderate: {0} of {1} automatic services.' -f $nonWindowsServices.Count, $autoServices.Count)
        }
    }
}

<#
    Test-PowerHealth - category "Power": power plan, battery and thermals.

    Design notes:
    * Half of these checks only apply to portable machines, so everything battery
      related is gated on $script:Ctx.HasBattery and degrades to Add-Skip elsewhere.
    * Plan settings are read from root\cimv2\power (Win32_PowerSettingDataIndex)
      instead of parsing "powercfg /query" output: WMI returns plain integers that are
      identical on every locale, while powercfg's labels are translated by Windows.
    * SettingIndexValue is a UInt32 and can hold 4294967295. Casting that to [int]
      throws and would abort the whole read, hence [int64] plus a "not set" guard.
    * Registry values are compared as strings so a surprising value type can never
      raise a cast exception in a tool that promises not to throw.
    * Every external call is read-only (powercfg /getactivescheme, /waketimers,
      /lastwake, /devicequery). powercfg /batteryreport is deliberately never invoked
      because it writes a file to disk.
#>
function Test-PowerHealth {
    [CmdletBinding()]
    param()

    $ctx = $script:Ctx
    if (-not $ctx) { $ctx = @{} }

    # Read through Get-Variable so the function still works under Set-StrictMode
    # if the caller happens not to define -Fast at all.
    $fastMode = [bool](Get-Variable -Name 'Fast' -ValueOnly -ErrorAction SilentlyContinue)

    # helpers

    # Read-only powercfg wrapper. Returns trimmed non-empty lines, or $null when
    # powercfg is missing or refuses (rights, policy, trimmed-down images).
    $invokePowercfg = {
        param([string[]]$Arguments)
        try {
            $raw = & powercfg.exe @Arguments 2>&1
            if ($LASTEXITCODE -ne 0) { return $null }
            $lines = @()
            foreach ($item in $raw) {
                $text = ([string]$item).Trim()
                if ($text.Length -gt 0) { $lines += $text }
            }
            return ,$lines
        } catch {
            # powercfg.exe absent or blocked - treat exactly like "no data"
            return $null
        }
    }

    # Keeps external output short enough to stay readable on an evidence line.
    $limitText = {
        param([string]$Text, [int]$Max)
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        if ($Text.Length -le $Max) { return $Text }
        return ($Text.Substring(0, $Max) + '...')
    }

    # active power plan

    $activeGuid = $null
    $activeName = $null
    try {
        $plans = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerPlan -ErrorAction Stop |
            Where-Object { $_.IsActive })
        if ($plans.Count -gt 0) {
            $activeName = $plans[0].ElementName
            if ($plans[0].InstanceID -match '\{([0-9A-Fa-f-]{36})\}') { $activeGuid = $Matches[1].ToLower() }
        }
    } catch {
        # root\cimv2\power is missing on some VM and Server Core images - fall back to powercfg
        $activeGuid = $null
    }
    if (-not $activeGuid) {
        $schemeLines = & $invokePowercfg @('/getactivescheme')
        if ($schemeLines -and $schemeLines.Count -gt 0) {
            $schemeText = $schemeLines -join ' '
            if ($schemeText -match '([0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})') { $activeGuid = $Matches[1].ToLower() }
            if ($schemeText -match '\(([^)]+)\)\s*$') { $activeName = $Matches[1] }
        }
    }

    # The four GUIDs Windows ships with; anything else is an OEM or user-made plan.
    $knownPlans = @{
        '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
        '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
        'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'
        'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Ultimate Performance'
    }

    if ($activeGuid) {
        if (-not $activeName) { $activeName = 'unknown name' }
        $planEvidence = "Active plan: $activeName ({$activeGuid})"
        $isPerfPlan = ($activeGuid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -or $activeGuid -eq 'e9a42b02-d5df-448d-aa00-03f14749eb61')
        if ($ctx.HasBattery -and $isPerfPlan) {
            Add-Finding -Severity Medium -Title 'Performance plan is active on a machine with a battery' -Evidence $planEvidence -Impact 'High performance and Ultimate Performance turn off most of the power saving: shorter battery life, a hotter chassis and more fan noise even when the machine is idle.' -Fix 'Settings > System > Power & battery > Power mode = Balanced. Alternatively: powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e' -Confidence Certain
        } elseif ((-not $ctx.HasBattery) -and $activeGuid -eq 'a1841308-3541-4fab-bc81-f71556f20b4a') {
            Add-Finding -Severity Low -Title 'Power saver plan is active on a machine without a battery' -Evidence $planEvidence -Impact 'Power saver holds back the processor and the display without any gain on a machine that is always plugged into the wall.' -Fix 'Settings > System > Power > Power mode = Balanced. Alternatively: powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e' -Confidence Certain
        } elseif (-not $knownPlans.ContainsKey($activeGuid)) {
            Add-Finding -Severity Info -Title 'A custom or OEM-supplied power plan is active' -Evidence $planEvidence -Impact 'The plan is none of the four Windows default plans, so timeouts, processor limits and wake rules can differ from what Windows itself would have picked.' -Fix 'See the whole contents with the read-only call: powercfg /query. Switch to Balanced under Settings > System > Power if you want to.' -Confidence Likely
        } else {
            Add-Ok -Message "The power plan matches the machine type ($activeName)."
        }
    } else {
        Add-Skip -Message 'The active power plan could not be read - neither root\cimv2\power nor powercfg answered.'
    }

    # setting values for the active plan

    $settings = @{}
    if ($activeGuid) {
        try {
            $rows = Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerSettingDataIndex -ErrorAction Stop
            foreach ($row in $rows) {
                if ($row.InstanceID -match '\{([0-9A-Fa-f-]{36})\}\\(AC|DC)\\\{([0-9A-Fa-f-]{36})\}') {
                    if ($Matches[1].ToLower() -eq $activeGuid -and $null -ne $row.SettingIndexValue) {
                        $settings[($Matches[2] + '|' + $Matches[3].ToLower())] = [int64]$row.SettingIndexValue
                    }
                }
            }
        } catch {
            # Class is absent on some images - leave the table empty and skip the checks below
            $settings = @{}
        }
    }
    # 0xFFFFFFFF means "not configured" for these settings and must not be read as a number.
    $getSetting = {
        param([string]$Mode, [string]$SettingGuid)
        $key = $Mode + '|' + $SettingGuid
        if (-not $settings.ContainsKey($key)) { return $null }
        $value = $settings[$key]
        if ($value -ge 4294967295) { return $null }
        return $value
    }
    if ($settings.Count -eq 0) {
        Add-Skip -Message 'Detailed power settings (timeouts, processor limit, USB, battery) could not be read - Win32_PowerSettingDataIndex returned no rows for the active plan.'
    }

    $gVideo   = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
    $gSleep   = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
    $gProcMax = 'bc5038f7-23e0-4960-96da-33abaf5935ec'
    $gUsbSusp = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
    $gWakeTmr = 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
    $gLid     = '5ca83367-6e45-459f-a27b-476b1d01c936'
    $gCritAct = '637ea02f-bbcb-4015-8e2c-a1c7b9c0b546'
    $gCritLvl = '9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469'
    $gEsBatt  = 'e69653ca-cf7f-4f05-aa73-cb833fa90ad4'

    # fast startup

    $powerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
    $hiberBoot = Get-RegValue -Path $powerKey -Name 'HiberbootEnabled'
    $hiberOn = Get-RegValue -Path $powerKey -Name 'HibernateEnabled'
    # Fast startup is a hibernation feature, so it cannot be in play when hibernation is off.
    $hibernationActive = -not ($null -ne $hiberOn -and "$hiberOn" -eq '0')

    if (-not $hibernationActive) {
        Add-Ok -Message 'Fast startup is out of the picture because hibernation is off (HibernateEnabled = 0) - "Shut down" gives a real cold start.'
    } elseif ($null -eq $hiberBoot -or "$hiberBoot" -eq '1') {
        $hbEvidence = 'HiberbootEnabled = 1'
        $hbConfidence = 'Certain'
        if ($null -eq $hiberBoot) {
            $hbEvidence = "HiberbootEnabled does not exist under $powerKey, and Windows treats a missing value as on"
            $hbConfidence = 'Likely'
        }
        Add-Finding -Severity Low -Title 'Fast startup is enabled' -Evidence $hbEvidence -Impact 'With fast startup, "Shut down" is no longer a real shutdown: the kernel session is hibernated to hiberfil.sys. The NTFS volumes are therefore left marked as in use, so Linux in a dual-boot refuses to mount them writable, and faults that need a real cold start (drivers, firmware, kernel state) survive "Shut down". Only "Restart" gives a full restart.' -Fix 'Control Panel > Power Options > Choose what the power buttons do > Change settings that are currently unavailable > clear "Turn on fast startup".' -Confidence $hbConfidence
    } else {
        Add-Ok -Message 'Fast startup is turned off (HiberbootEnabled = 0) - "Shut down" gives a real cold start.'
    }

    # hibernation + hiberfil

    if (-not $hibernationActive) {
        if ($ctx.HasBattery) {
            Add-Finding -Severity Low -Title 'Hibernation is turned off on a machine with a battery' -Evidence 'HibernateEnabled = 0' -Impact 'Without hibernation, Windows cannot save the session to disk when the battery reaches critical level. The action then becomes sleep or shutdown, and unsaved work can be lost.' -Fix 'Run as administrator: powercfg /hibernate on' -Confidence Likely
        } else {
            Add-Ok -Message 'Hibernation is off on a machine without a battery - it frees disk space and has no practical downside.'
        }
    } else {
        $sysDrive = $ctx.SystemDrive
        if (-not $sysDrive) { $sysDrive = 'C:' }
        $hiberFile = $null
        try {
            $hiberFile = Get-Item -LiteralPath (Join-Path -Path $sysDrive -ChildPath 'hiberfil.sys') -Force -ErrorAction Stop
        } catch {
            # File may sit on another volume or be unreadable without rights
            $hiberFile = $null
        }
        if ($hiberFile) {
            $hiberSize = Format-Size -Bytes ([double]$hiberFile.Length)
            $hiberType = Get-RegValue -Path $powerKey -Name 'HiberFileType'
            $typeText = 'full (the whole session can be hibernated)'
            if ("$hiberType" -eq '1') { $typeText = 'reduced (fast startup only, real hibernation is not possible)' }
            Add-Finding -Severity Info -Title 'The hibernation file takes up disk space' -Evidence "$($hiberFile.FullName) = $hiberSize, HiberFileType = $typeText" -Impact 'The hibernation file is sized after the amount of RAM and cannot be shrunk without weakening hibernation.' -Fix 'If you need the space and never use hibernation: powercfg /hibernate off (as administrator). Note that this also turns off fast startup.' -Confidence Certain
        } else {
            Add-Ok -Message 'Hibernation is enabled (HibernateEnabled is not 0).'
        }
    }

    # modern standby (S0) note

    $csEnabled = Get-RegValue -Path $powerKey -Name 'CsEnabled'
    if ("$csEnabled" -eq '1') {
        Add-Finding -Severity Info -Title 'The machine uses modern standby (S0)' -Evidence 'CsEnabled = 1' -Impact 'In S0 the machine keeps running lightweight work while it looks switched off. It can therefore drain the battery in a bag and be woken by network traffic, unlike classic S3 sleep.' -Fix 'See what is keeping the machine awake with the read-only call: powercfg /requests. For the full analysis use powercfg /sleepstudy, but it writes a report file and has to be run manually.' -Confidence Certain
    }

    # wake timers

    $wakeAc = & $getSetting 'AC' $gWakeTmr
    $wakeDc = & $getSetting 'DC' $gWakeTmr
    $timerLines = & $invokePowercfg @('/waketimers')
    if ($null -eq $timerLines) {
        Add-Skip -Message 'powercfg /waketimers returned no data - the call normally requires administrator rights.'
    } else {
        # The prose is localised, but a real timer always names an exe or a device path
        $activeTimers = @($timerLines | Where-Object { $_ -match '\.exe|\\Device\\' })
        if ($activeTimers.Count -gt 0) {
            $timerEvidence = & $limitText ($activeTimers -join ' | ') 220
            Add-Finding -Severity Medium -Title 'Active wake timers can start the machine on their own' -Evidence "$($activeTimers.Count) active wake timer(s): $timerEvidence" -Impact 'A scheduled task has asked to be allowed to wake the machine from sleep. The machine then starts up on its own, often at night, and tends to stay awake afterwards.' -Fix 'Find the task in Task Scheduler and clear "Wake the computer to run this task" under Conditions. Alternatively: Control Panel > Power Options > Change plan settings > Change advanced power settings > Sleep > Allow wake timers = Disable.' -Confidence Likely
        } else {
            $wakeText = 'no active wake timers'
            if ($null -ne $wakeAc -or $null -ne $wakeDc) { $wakeText = "$wakeText (the setting is AC = $wakeAc, DC = $wakeDc)" }
            Add-Ok -Message "powercfg /waketimers: $wakeText."
        }
    }
    if ($ctx.HasBattery -and $null -ne $wakeDc -and $wakeDc -eq 1) {
        Add-Finding -Severity Low -Title 'Wake timers are allowed while the machine runs on battery' -Evidence 'Allow wake timers, DC = 1 (Windows uses 0 or 2 on battery in the default plans)' -Impact 'A scheduled task can wake the machine while it sits in a bag on battery, and then it ends up both hot and empty.' -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > Sleep > Allow wake timers > On battery = Disable.' -Confidence Likely
    }

    # devices armed to wake

    if ($fastMode) {
        Add-Skip -Message 'Skipped powercfg /devicequery wake_armed because -Fast is set.'
    } else {
        $armed = & $invokePowercfg @('/devicequery', 'wake_armed')
        if ($null -eq $armed) {
            Add-Skip -Message 'powercfg /devicequery wake_armed returned no data on this machine.'
        } else {
            # When nothing is armed, powercfg prints a single sentinel word - NONE on
            # English Windows, translated elsewhere. Device friendly names always
            # contain a space, so dropping one-word lines detects the sentinel in any
            # language instead of matching a hard-coded list of translations.
            $armedDevices = @($armed | Where-Object { $_ -match '\S\s+\S' })
            if ($armedDevices.Count -eq 0) {
                Add-Ok -Message 'No devices are allowed to wake the machine from sleep.'
            } else {
                # Keyboards and mice are armed by default and are harmless; a NIC is the one that wakes a machine at night
                $netDevices = @($armedDevices | Where-Object { $_ -match 'NIC|Ethernet|Wi-?Fi|Wireless|Network|LAN|802\.11' })
                if ($netDevices.Count -gt 0) {
                    Add-Finding -Severity Low -Title 'The network adapter is allowed to wake the machine' -Evidence ("$($netDevices.Count) of $($armedDevices.Count) armed devices are network adapters: " + (& $limitText ($netDevices -join '; ') 180)) -Impact 'A network adapter that is wake armed can wake the machine on a magic packet or on a pattern match in the traffic. With the wrong driver setting, ordinary broadcast traffic keeps the machine awake - the typical symptom is a PC that is on in the morning without anyone touching it.' -Fix 'Device Manager > the network adapter > Properties > Power Management: keep only "Only allow a magic packet to wake the computer", or clear "Allow this device to wake the computer". Check afterwards with: powercfg /devicequery wake_armed' -Confidence Likely
                } else {
                    Add-Ok -Message "$($armedDevices.Count) device(s) can wake the machine, but none of them are network adapters (typically keyboard and mouse)."
                }
            }
        }
    }

    # last wake cause

    $lastWake = & $invokePowercfg @('/lastwake')
    if ($null -eq $lastWake -or $lastWake.Count -eq 0) {
        Add-Skip -Message 'powercfg /lastwake returned no data - the call normally requires administrator rights.'
    } elseif ($lastWake.Count -le 1) {
        # Only the count line came back, so nothing has woken the machine since boot
        Add-Ok -Message "No recorded wake source since the last boot ($($lastWake -join ' '))."
    } else {
        Add-Finding -Severity Info -Title 'The last wake source was recorded by the firmware' -Evidence (& $limitText ($lastWake -join ' | ') 220) -Impact 'Shows what last took the machine out of sleep. If the source is a device or a task you do not recognize, it usually explains why the machine starts on its own.' -Fix 'Cross-check against the read-only calls powercfg /devicequery wake_armed and powercfg /waketimers.' -Confidence Certain
    }

    # USB selective suspend

    $usbAc = & $getSetting 'AC' $gUsbSusp
    $usbDc = & $getSetting 'DC' $gUsbSusp
    if ($null -eq $usbAc -and $null -eq $usbDc) {
        Add-Skip -Message 'The USB selective suspend setting could not be read for the active power plan.'
    } elseif (($null -ne $usbAc -and $usbAc -eq 0) -or ($null -ne $usbDc -and $usbDc -eq 0)) {
        $usbSeverity = 'Info'
        if ($ctx.HasBattery) { $usbSeverity = 'Low' }
        Add-Finding -Severity $usbSeverity -Title 'USB selective suspend is turned off' -Evidence "USB selective suspend setting: AC = $usbAc, DC = $usbDc (0 = disabled, 1 = enabled)" -Impact 'The USB controllers are kept awake at all times. On a machine with a battery that is a measurable loss of runtime, and some USB devices can also keep the machine from going to sleep.' -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > USB settings > USB selective suspend setting = Enabled. If it was turned off on purpose to stabilize a USB device, it can stay as it is.' -Confidence Likely
    } else {
        Add-Ok -Message "USB selective suspend is enabled (AC = $usbAc, DC = $usbDc)."
    }

    # processor maximum state

    $procAc = & $getSetting 'AC' $gProcMax
    $procDc = & $getSetting 'DC' $gProcMax
    if ($null -eq $procAc) {
        Add-Skip -Message 'The maximum processor state could not be read for the active power plan.'
    } elseif ($procAc -lt 100) {
        $procImpact = 'Windows keeps the processor below full frequency even when the machine is plugged into the wall. This is one of the most common reasons a machine feels slow while nothing else looks wrong.'
        if ($procAc -eq 99) { $procImpact = 'The value 99 % is the known way to turn off turbo. It lowers temperature and power draw but costs top speed - make sure it is intentional.' }
        Add-Finding -Severity Medium -Title 'The maximum processor state is limited on AC power' -Evidence "Maximum processor state, AC = $procAc % (the default is 100 %)" -Impact $procImpact -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > Processor power management > Maximum processor state > Plugged in = 100 %.' -Confidence Certain
    } else {
        Add-Ok -Message "The processor has full maximum state on AC power (AC = $procAc %)."
    }
    if ($ctx.HasBattery -and $null -ne $procDc) {
        if ($procDc -lt 50) {
            Add-Finding -Severity Low -Title 'The processor is heavily throttled on battery' -Evidence "Maximum processor state, DC = $procDc %" -Impact 'Below 50 % makes the machine noticeably slow as soon as the charger is unplugged, even for light tasks.' -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > Processor power management > Maximum processor state > On battery.' -Confidence Certain
        } else {
            Add-Ok -Message "The maximum processor state on battery is $procDc %."
        }
    }

    # battery section

    if ($ctx.BatteryQueryFailed) {
        Add-Finding -Severity Low -Title 'The battery could not be queried' `
            -Evidence 'Get-CimInstance Win32_Battery failed, so it is not known whether this machine has a battery.' `
            -Impact 'Every battery check (wear, charge cycles, runtime, on-battery limits) was skipped. On a laptop that hides real battery wear behind a query failure. A failing Win32_Battery query is also a symptom in itself - it usually means the WMI repository or the ACPI battery driver is broken.' `
            -Fix 'Check that the battery appears in Device Manager under Batteries, and verify WMI with: Get-CimInstance Win32_Battery. If WMI is broken more widely, "winmgmt /verifyrepository" reports on it.' `
            -Confidence Certain
    } elseif (-not $ctx.HasBattery) {
        Add-Skip -Message 'The battery checks (wear, charge cycles, runtime, battery settings) were skipped - the machine has no battery.'
    } else {
        $designCap = $null
        $fullCap = $null
        $capSource = $null
        $battery = $null
        if ($ctx.Battery) { $battery = @($ctx.Battery)[0] }
        if ($battery) {
            if ($battery.DesignCapacity -and [double]$battery.DesignCapacity -gt 0) { $designCap = [double]$battery.DesignCapacity }
            if ($battery.FullChargeCapacity -and [double]$battery.FullChargeCapacity -gt 0) { $fullCap = [double]$battery.FullChargeCapacity }
            if ($designCap -and $fullCap) { $capSource = 'Win32_Battery' }
        }
        # Most OEMs leave the Win32_Battery capacity fields empty; the real numbers live in root\WMI
        if (-not $capSource) {
            try {
                $staticData = @(Get-CimInstance -Namespace 'root\WMI' -ClassName BatteryStaticData -ErrorAction Stop)
                if ($staticData.Count -gt 0 -and $staticData[0].DesignedCapacity -gt 0) { $designCap = [double]$staticData[0].DesignedCapacity }
            } catch {
                # BatteryStaticData is an optional ACPI class and is missing on many machines
                $designCap = $null
            }
            try {
                $fullData = @(Get-CimInstance -Namespace 'root\WMI' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)
                if ($fullData.Count -gt 0 -and $fullData[0].FullChargedCapacity -gt 0) { $fullCap = [double]$fullData[0].FullChargedCapacity }
            } catch {
                # Same story - the firmware vendor decides whether this class exists
                $fullCap = $null
            }
            if ($designCap -and $fullCap) { $capSource = 'root\WMI: BatteryStaticData + BatteryFullChargedCapacity' }
        }

        $reportHint = 'You get the full wear report with powercfg /batteryreport /output %USERPROFILE%\battery-report.html - it writes a file to disk, so this tool does not run it for you.'
        if ($capSource -and $designCap -gt 0) {
            $healthPct = [math]::Round(($fullCap / $designCap) * 100, 1)
            $wearPct = [math]::Round(100 - $healthPct, 1)
            $capEvidence = "Design capacity $([math]::Round($designCap, 0)) mWh against full charge capacity $([math]::Round($fullCap, 0)) mWh = $healthPct % left ($wearPct % wear), source: $capSource"
            if ($healthPct -lt 60) {
                Add-Finding -Severity High -Title 'The battery is heavily worn' -Evidence $capEvidence -Impact 'Below 60 % of design capacity means less than half the original runtime. Cells this worn also drop steeply in voltage under load, so the machine can switch itself off without warning even though the percentage reading says there is charge left.' -Fix "Plan a battery replacement. $reportHint" -Confidence Certain
            } elseif ($healthPct -lt 80) {
                Add-Finding -Severity Medium -Title 'The battery has noticeable wear' -Evidence $capEvidence -Impact 'Below 80 % of design capacity gives clearly shorter runtime than the machine was sold with, and the wear tends to accelerate from here.' -Fix "Avoid leaving the machine at 100 % charge around the clock, and use the manufacturer's charge threshold if it has one. $reportHint" -Confidence Certain
            } else {
                Add-Ok -Message "The battery has $healthPct % of its design capacity left ($wearPct % wear)."
            }
        } else {
            Add-Skip -Message "Battery wear could not be calculated - neither Win32_Battery nor root\WMI reported both design and full charge capacity. $reportHint"
        }

        try {
            $cycles = @(Get-CimInstance -Namespace 'root\WMI' -ClassName BatteryCycleCount -ErrorAction Stop)
            if ($cycles.Count -gt 0 -and $null -ne $cycles[0].CycleCount -and [int64]$cycles[0].CycleCount -gt 0) {
                Add-Finding -Severity Info -Title 'The charge cycle count was read from the firmware' -Evidence "CycleCount = $($cycles[0].CycleCount)" -Impact 'Most lithium batteries are rated for 300-1000 full cycles before they drop below 80 % of design capacity.' -Fix 'No action. The number is useful together with the wear percentage when you judge whether the battery should be replaced.' -Confidence Likely
            } else {
                Add-Skip -Message 'Charge cycles are not reported by the firmware on this machine (BatteryCycleCount is empty or 0).'
            }
        } catch {
            # BatteryCycleCount is optional and simply does not exist on many laptops
            Add-Skip -Message 'Charge cycles could not be read - the WMI class BatteryCycleCount does not exist on this machine.'
        }

        if ($battery) {
            $charge = $battery.EstimatedChargeRemaining
            $status = $battery.BatteryStatus
            $onBattery = ("$status" -eq '1')
            $runTime = $battery.EstimatedRunTime
            $runText = 'unknown'
            # 71582788 minutes is the ACPI "unlimited / running on AC" sentinel, not an error
            if ($null -ne $runTime -and [int64]$runTime -gt 0 -and [int64]$runTime -lt 71582788) {
                $runText = "$([math]::Round([int64]$runTime / 60.0, 1)) hours"
            }
            if ($onBattery) {
                Add-Finding -Severity Info -Title 'The machine is running on battery right now' -Evidence "Charge level $charge %, BatteryStatus = 1 (discharging), estimated remaining runtime: $runText" -Impact 'Measurements of performance, frequency and temperature taken now are affected by the power saving that applies on battery.' -Fix 'No action. Run the report on AC power if you want to compare performance numbers.' -Confidence Certain
            } else {
                Add-Ok -Message "The machine is running on AC power (BatteryStatus = $status), charge level $charge %."
            }
        } else {
            Add-Skip -Message 'The charge level could not be read - Win32_Battery returned no instance even though the machine is supposed to have a battery.'
        }

        $videoDc = & $getSetting 'DC' $gVideo
        if ($null -eq $videoDc) {
            Add-Skip -Message 'The display timeout on battery could not be read from the active power plan.'
        } elseif ($videoDc -eq 0) {
            Add-Finding -Severity Low -Title 'The display never turns off on battery' -Evidence 'Turn off display after, DC = 0 (never)' -Impact 'The display is the single biggest consumer on a laptop. The never setting drains the battery every time the machine is left unused.' -Fix 'Settings > System > Power & battery > Screen and sleep > On battery power, turn off my screen after = 5 minutes.' -Confidence Certain
        } elseif ($videoDc -gt 1800) {
            Add-Finding -Severity Info -Title 'The display stays on a long time before it turns off on battery' -Evidence "Turn off display after, DC = $([math]::Round($videoDc / 60.0, 0)) minutes" -Impact 'More than 30 minutes wastes battery when the machine is left unused.' -Fix 'Settings > System > Power & battery > Screen and sleep > On battery power, turn off my screen after.' -Confidence Likely
        } else {
            Add-Ok -Message "The display turns off after $([math]::Round($videoDc / 60.0, 0)) minutes on battery."
        }

        $sleepDc = & $getSetting 'DC' $gSleep
        if ($null -ne $sleepDc -and $sleepDc -eq 0) {
            Add-Finding -Severity Medium -Title 'The machine never goes to sleep on battery' -Evidence 'Sleep after, DC = 0 (never)' -Impact 'A laptop that never sleeps keeps running in the bag. The result is a flat battery and a hot machine in a closed space with no airflow.' -Fix 'Settings > System > Power & battery > Screen and sleep > On battery power, put my device to sleep after = 15 minutes.' -Confidence Certain
        } elseif ($null -ne $sleepDc) {
            Add-Ok -Message "The machine goes to sleep after $([math]::Round($sleepDc / 60.0, 0)) minutes on battery."
        }

        $critAct = & $getSetting 'DC' $gCritAct
        $critLvl = & $getSetting 'DC' $gCritLvl
        if ($null -ne $critAct) {
            # String keys so an unexpected value can never blow up an [int] cast
            $actNames = @{ '0' = 'do nothing'; '1' = 'sleep'; '2' = 'hibernate'; '3' = 'shut down' }
            $actText = 'unknown action'
            if ($actNames.ContainsKey("$critAct")) { $actText = $actNames["$critAct"] }
            if ($critAct -eq 0) {
                Add-Finding -Severity High -Title 'No action at critical battery level' -Evidence "Critical battery action, DC = 0 ($actText), critical level = $critLvl %" -Impact 'The machine runs until the power is gone and switches off hard. Unsaved work is lost, and a hard shutdown in the middle of a write can damage the file system.' -Fix 'Control Panel > Power Options > Change plan settings > Change advanced power settings > Battery > Critical battery action = Hibernate.' -Confidence Certain
            } else {
                Add-Ok -Message "At critical battery level ($critLvl %) the machine will: $actText."
            }
        }

        $esBatt = & $getSetting 'DC' $gEsBatt
        if ($null -eq $esBatt) {
            Add-Skip -Message 'The battery saver threshold could not be read from the active power plan.'
        } elseif ($esBatt -eq 0) {
            Add-Finding -Severity Low -Title 'Battery saver never turns on automatically' -Evidence 'Battery saver threshold, DC = 0 % (off)' -Impact 'Windows does not hold back background activity, syncing and brightness when the battery gets low, so the last few percent last a shorter time than they could have.' -Fix 'Settings > System > Power & battery > Battery saver > Turn battery saver on automatically at = 20 %.' -Confidence Likely
        } else {
            Add-Ok -Message "Battery saver turns on automatically at $esBatt % battery."
        }

        if ($ctx.IsLaptop) {
            $lidDc = & $getSetting 'DC' $gLid
            if ($null -ne $lidDc -and $lidDc -eq 0) {
                Add-Finding -Severity Low -Title 'Nothing happens when the lid is closed on battery' -Evidence 'Lid close action, DC = 0 (do nothing)' -Impact 'The machine keeps running with the lid shut. It gets hot in the bag, the fans get no air, and the battery drains.' -Fix 'Control Panel > Power Options > Choose what closing the lid does > On battery = Sleep.' -Confidence Certain
            } elseif ($null -ne $lidDc) {
                Add-Ok -Message "Closing the lid on battery triggers action $lidDc (1 = sleep, 2 = hibernate, 3 = shut down)."
            }
        }
    }

    # thermal zones

    $thermalRead = $false
    $rawZones = @()
    try {
        $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        $hottest = $null
        foreach ($zone in $zones) {
            if ($null -eq $zone.CurrentTemperature) { continue }
            $celsius = [math]::Round(([double]$zone.CurrentTemperature / 10.0) - 273.15, 1)
            $rawZones += "$($zone.InstanceName) = $celsius C"
            # Plenty of firmwares expose placeholder zones with impossible values - those must not produce findings
            if ($celsius -ge 20 -and $celsius -le 130) {
                if ($null -eq $hottest -or $celsius -gt $hottest) { $hottest = $celsius }
            }
        }
        if ($null -ne $hottest) {
            $thermalRead = $true
            $zoneEvidence = ($rawZones -join '; ')
            if ($hottest -gt 90) {
                Add-Finding -Severity High -Title 'A thermal zone reports a very high temperature' -Evidence "Hottest zone: $hottest C (all zones: $zoneEvidence)" -Impact 'Above 90 C the machine throttles itself to survive, and sustained heat shortens the life of the battery, the fans and the solder joints.' -Fix 'Check for dust in the fans and air intakes, that the machine is not standing on a soft surface blocking the ventilation, and which process is causing the load in Task Manager.' -Confidence Likely
            } elseif ($hottest -gt 80) {
                Add-Finding -Severity Medium -Title 'A thermal zone reports a high temperature' -Evidence "Hottest zone: $hottest C (all zones: $zoneEvidence)" -Impact 'Sustained above 80 C means more fan noise and lower turbo. If the machine is close to idle right now, the number is higher than it should be.' -Fix 'Clean the air intakes and fans, and find which process is causing the load in Task Manager > Performance.' -Confidence Likely
            } else {
                Add-Ok -Message "A thermal zone reports $hottest C - within the normal range."
            }
        }
    } catch {
        # MSAcpi_ThermalZoneTemperature needs admin rights and is absent on many machines and VMs
        $thermalRead = $false
    }
    if (-not $thermalRead) {
        $why = 'the WMI class MSAcpi_ThermalZoneTemperature did not answer on this machine'
        if (-not $ctx.IsAdmin) { $why = 'the class requires administrator rights, and the tool is running without them' }
        if ($rawZones.Count -gt 0) { $why = "the zones report implausible values ($($rawZones -join '; ')), typically firmware placeholders" }
        Add-Skip -Message "Temperature could not be read: $why. Use the manufacturer's tool or the BIOS to see actual temperatures."
    }

    # cpu throttling

    try {
        $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
        if ($cpus.Count -gt 0) {
            $cpu = $cpus[0]
            $maxMhz = [int64]$cpu.MaxClockSpeed
            $curMhz = [int64]$cpu.CurrentClockSpeed
            $load = $cpu.LoadPercentage
            if ($maxMhz -gt 0 -and $curMhz -gt 0) {
                $ratio = [math]::Round(($curMhz / [double]$maxMhz) * 100, 0)
                # A low clock on its own means nothing (idle), so high load must be present at the same time
                if ($ratio -lt 60 -and $null -ne $load -and [int64]$load -ge 50) {
                    Add-Finding -Severity Low -Title 'The processor runs well below base frequency at the same time as high load' -Evidence "CurrentClockSpeed $curMhz MHz of MaxClockSpeed $maxMhz MHz ($ratio %) at $load % load" -Impact 'A low frequency under high load can mean thermal throttling, a power limit in the firmware or a power plan holding it back. A single snapshot from WMI is a weak signal and can just as well be down to random timing.' -Fix 'Measure over time with Performance Monitor (perfmon, the "% of Maximum Frequency" counter) or a tool from the manufacturer, and check Maximum processor state in Power Options.' -Confidence Uncertain
                } else {
                    Add-Ok -Message "Processor frequency $curMhz MHz against base frequency $maxMhz MHz - no sign of throttling in the snapshot."
                }
            } else {
                Add-Skip -Message 'The processor frequency could not be compared - Win32_Processor did not report both the current and the maximum clock speed.'
            }
        }
    } catch {
        # Win32_Processor is rarely missing, but some VMs answer with empty fields
        Add-Skip -Message 'The processor clock speed could not be read from Win32_Processor.'
    }

    # Sustained throttling, as Windows itself measured it. The clock-speed snapshot above
    # is one instant; Kernel-Processor-Power event 37 is the kernel saying the processor
    # was held below its nominal speed by something other than the OS - firmware, thermals
    # or a power limit. On a machine whose ACPI thermal zones report placeholder values,
    # this is the only trustworthy throttling signal available.
    if ($Fast) {
        Add-Skip -Message 'Throttling history: skipped because -Fast is set.'
    } else {
        $throttleEvents = @()
        try {
            $throttleEvents = @(Get-WinEvent -FilterHashtable @{
                    LogName      = 'System'
                    ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
                    Id           = 37
                    StartTime    = (Get-Date).AddDays(-30)
                } -MaxEvents 200 -ErrorAction Stop)
        } catch {
            # No event 37 in the window is the normal, healthy case, and Get-WinEvent
            # throws rather than returning nothing.
            Write-Verbose -Message ("No Kernel-Processor-Power event 37 in the window: {0}" -f $_.Exception.Message)
        }
        if ($throttleEvents.Count -eq 0) {
            Add-Ok -Message 'No firmware or thermal throttling recorded by the kernel in the last 30 days (event 37).'
        } else {
            $throttleSeverity = if ($throttleEvents.Count -ge 50) { 'Medium' } else { 'Low' }
            Add-Finding -Severity $throttleSeverity -Title 'The processor has been throttled below its nominal speed' `
                -Evidence ("{0} Kernel-Processor-Power event(s) with ID 37 in the last 30 days. Most recent: {1}" -f $throttleEvents.Count, (($throttleEvents | Select-Object -First 3 | ForEach-Object { $_.TimeCreated }) -join ', ')) `
                -Impact 'Windows recorded that the processor was held below its nominal frequency by something outside the operating system: temperature, a firmware power limit, or an undersized power supply. It shows up as the machine feeling fast at first and then slowing under sustained load.' `
                -Fix 'Check cooling first - dust in the heatsink and dried-out thermal paste are the usual causes. Then look at the UEFI power and thermal limits (PPT, TDC, EDC on AMD; PL1/PL2 on Intel), and confirm the power plan is not the cause with: powercfg /qh SCHEME_CURRENT SUB_PROCESSOR' `
                -Confidence 'Likely'
        }
    }

    # Physical memory: the modules themselves, and whether the built-in diagnostic has
    # ever been run and what it said. Nothing else in the script looks at RAM hardware,
    # and a failing module presents as random crashes that look like software faults.
    try {
        $memoryModules = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop)
        if ($memoryModules.Count -gt 0) {
            $moduleText = (@($memoryModules | ForEach-Object {
                        $sizeGb = [math]::Round(([double]$_.Capacity) / 1GB, 0)
                        $speed = if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed }
                        "$($_.DeviceLocator) $sizeGb GB @ $speed MT/s $($_.Manufacturer)".Trim()
                    }) -join '; ')
            $mixedSpeeds = @($memoryModules | ForEach-Object { $_.Speed } | Sort-Object -Unique)
            if ($mixedSpeeds.Count -gt 1) {
                Add-Finding -Severity 'Low' -Title 'The memory modules are not all the same speed' `
                    -Evidence $moduleText `
                    -Impact 'Mixed modules run at the speed of the slowest one, and mismatched kits are a common cause of instability that looks like random application crashes.' `
                    -Fix 'Use a matched kit if you can. If the machine is unstable, test with one module at a time.' `
                    -Confidence 'Likely'
            } else {
                Add-Finding -Severity 'Info' -Title 'Installed memory modules' `
                    -Evidence $moduleText `
                    -Impact 'Useful when diagnosing instability, and for knowing which slots are occupied before an upgrade.' `
                    -Confidence 'Certain'
            }
        }
    } catch {
        Add-Skip -Message 'Win32_PhysicalMemory could not be read, so the memory modules were not inventoried.'
    }

    if (-not $Fast) {
        $memDiag = @()
        try {
            $memDiag = @(Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'
                    Id = 1101, 1201
                } -MaxEvents 5 -ErrorAction Stop)
        } catch {
            Write-Verbose -Message ("No memory diagnostic results found: {0}" -f $_.Exception.Message)
        }
        if ($memDiag.Count -eq 0) {
            Add-Skip -Message 'The Windows memory diagnostic has never been run on this machine, so there is no RAM test result to report. Run mdsched.exe if the machine is unstable.'
        } else {
            $latest = $memDiag[0]
            $resultText = (([string]$latest.Message) -replace '\s+', ' ').Trim()
            if ($resultText.Length -gt 200) { $resultText = $resultText.Substring(0, 200) }
            # Event 1201 is the detailed result; hardware problems are reported there.
            if ([int]$latest.Id -eq 1201 -or $resultText -match '(?i)error|problem|fail') {
                Add-Finding -Severity 'High' -Title 'The Windows memory diagnostic reported a problem' `
                    -Evidence ("Event {0} on {1}: {2}" -f $latest.Id, $latest.TimeCreated, $resultText) `
                    -Impact 'A memory module that fails a test causes crashes, file corruption and blue screens that look like unrelated software faults.' `
                    -Fix 'Test one module at a time to find the faulty one, and replace it. MemTest86 from a USB stick tests more thoroughly than the built-in tool.' `
                    -Confidence 'Likely'
            } else {
                Add-Ok -Message ("The Windows memory diagnostic last ran {0} and found no errors." -f $latest.TimeCreated)
            }
        }
    }
}

<#
  Network - what the machine exposes to the net it is standing on, and what it
  trusts coming back.

  No netsh parsing anywhere. Its output is translated, so on a Norwegian Windows
  every string match would silently fail and the check would report "all clear".
  Where a value only exists as localised text - Wi-Fi encryption, the WinHTTP
  proxy - it is read from the WLAN profile XML and from the raw registry blob
  instead, both of which are language-neutral. Firewall rules are matched on
  Name, never DisplayName, for the same reason.

  Everything is read-only: Get-*, Test-Path and registry lookups. Every block is
  wrapped, because the Net* modules, the SMB cmdlets and the WLAN profiles are
  all absent on Server Core, in slim VM images, or without elevation.
#>
function Test-NetworkHealth {
    [CmdletBinding()]
    param()

    # Used to tell "points at my own network" from "points out on the internet",
    # for both DNS servers and hosts-file entries.
    $isLocalAddress = {
        param([string]$Address)
        if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
        return ($Address -match '^(0\.0\.0\.0$|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fd|fc)')
    }

    # Loopback and tunnel pseudo-adapters show up as physical on machines with
    # Npcap, VPN clients or hypervisors installed, and would skew every count.
    $virtualPattern = 'Loopback|Virtual|VMware|Hyper-V|VirtualBox|TAP|Tunnel|Bluetooth|WAN Miniport'

    # adapters
    $physical = @()
    try {
        $physical = @(Get-NetAdapter -Physical -ErrorAction Stop)
    } catch {
        # The NetAdapter module is missing on some SKUs - handled by Add-Skip below.
        $physical = @()
    }

    $netProfiles = @()
    try {
        $netProfiles = @(Get-NetConnectionProfile -ErrorAction Stop)
    } catch {
        # Absent when the Network List Service is not running, e.g. on Server Core.
        $netProfiles = @()
    }

    # Wi-Fi is identified by NdisPhysicalMedium 9 and by the digits in the
    # MediaType string - neither is translated.
    $wifiAdapters = @($physical | Where-Object {
            $_.NdisPhysicalMedium -eq 9 -or "$($_.MediaType)" -match '802\.11'
        })
    $wifiIndexes = @($wifiAdapters | ForEach-Object { $_.ifIndex })

    if ($physical.Count -eq 0) {
        Add-Skip -Message 'Found no physical network adapters (Get-NetAdapter is unavailable, or the machine only has virtual adapters) - skipping the link speed check.'
    } else {
        $upAdapters = @($physical | Where-Object {
                $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback'
            })
        if ($upAdapters.Count -eq 0) {
            Add-Skip -Message 'No physical network adapters are connected right now - skipping the link speed check.'
        } else {
            $adapterLines = @()
            foreach ($nic in $upAdapters) {
                $tag = ''
                $prof = $netProfiles | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex } | Select-Object -First 1
                if ($null -ne $prof) { $tag = " [$($prof.NetworkCategory): $($prof.Name)]" }
                $adapterLines += ('{0} ({1}) - {2}{3}' -f $nic.Name, $nic.InterfaceDescription, $nic.LinkSpeed, $tag)
            }
            Add-Finding -Severity 'Info' -Title 'Active network adapters and network profiles' `
                -Evidence ($adapterLines -join '; ') `
                -Impact 'Overview of which adapters are in use, what speed they actually run at, and which category Windows has assigned to the network they are on.' `
                -Confidence 'Certain'
        }

        # A wired card that negotiates below what it can do is almost always the
        # cable or the switch port, not the driver - so the fix is physical.
        $wired = @($physical | Where-Object {
                $_.Status -eq 'Up' -and "$($_.MediaType)" -eq '802.3' -and
                $_.InterfaceDescription -notmatch $virtualPattern
            })
        if ($script:Ctx.IsVM) {
            Add-Skip -Message 'Virtual machine - the link speed of a virtual network adapter says nothing about the cable or the switch port.'
        } elseif ($wired.Count -eq 0) {
            Add-Skip -Message 'No connected wired network adapters - skipping the comparison of link speed against rated adapter capacity.'
        } else {
            $underRun = @()
            foreach ($nic in $wired) {
                $desc = "$($nic.InterfaceDescription) $($nic.Name)"
                # Rated speed is only available from the model name. Order matters:
                # "2.5GbE" also contains "GbE", so the wider patterns come last.
                $ratedMbps = 0
                if ($desc -match '10\s*-?\s*(G|Gb|Gbit|GbE|Gigabit)\b') { $ratedMbps = 10000 }
                elseif ($desc -match '2\.5\s*-?\s*(G|Gb|Gbit|GbE|Gigabit)') { $ratedMbps = 2500 }
                elseif ($desc -match '5\s*-?\s*(G|Gb|Gbit|GbE|Gigabit)\b') { $ratedMbps = 5000 }
                elseif ($desc -match 'FE Family|Fast Ethernet|10/100') { $ratedMbps = 100 }
                elseif ($desc -match '(GbE|Gigabit|1000BASE)') { $ratedMbps = 1000 }

                $actualMbps = 0
                if ($null -ne $nic.Speed -and $nic.Speed -gt 0) {
                    $actualMbps = [int][math]::Round(([double]$nic.Speed) / 1000000)
                }
                if ($actualMbps -le 0) { continue }

                if ($ratedMbps -gt 0 -and $actualMbps -lt $ratedMbps) {
                    $underRun += ('{0}: {1} Mb/s of {2} Mb/s ({3})' -f $nic.Name, $actualMbps, $ratedMbps, $nic.InterfaceDescription)
                } elseif ($ratedMbps -eq 0 -and $actualMbps -le 100) {
                    $underRun += ('{0}: {1} Mb/s, rated capacity unknown ({2})' -f $nic.Name, $actualMbps, $nic.InterfaceDescription)
                }
            }
            if ($underRun.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Title 'Wired network adapter is running below its capacity' `
                    -Evidence ($underRun -join '; ') `
                    -Impact 'The adapter has negotiated down to a lower speed than it supports. The most common cause is a damaged or too old cable (Cat5 cannot do 2.5 Gb/s), a switch port that is only 1 Gb, or a bad contact in the plug.' `
                    -Fix 'Switch to a Cat5e/Cat6 cable and move the cable to another port on the router or the switch. Check again with: Get-NetAdapter | Select-Object Name,LinkSpeed' `
                    -Confidence 'Likely'
            } else {
                Add-Ok -Message "All connected wired network adapters run at the expected speed ($($wired.Count) checked)."
            }
        }
    }

    # Wi-Fi
    # The WLAN profiles are XML on disk and contain <authentication>open</authentication>.
    # That is the only source for the encryption type that is not translated.
    $connectedWifi = @($netProfiles | Where-Object { $wifiIndexes -contains $_.InterfaceIndex })
    if ($physical.Count -eq 0) {
        Add-Skip -Message 'Could not list the network adapters - do not know whether the machine has Wi-Fi, and the encryption has not been checked.'
    } elseif ($wifiAdapters.Count -eq 0) {
        Add-Skip -Message 'The machine has no wireless network adapter - skipping the Wi-Fi encryption check.'
    } elseif ($connectedWifi.Count -eq 0) {
        Add-Skip -Message 'A wireless adapter is present, but it is not connected to any network - skipping the Wi-Fi encryption check.'
    } else {
        $connectedSsids = @($connectedWifi | ForEach-Object { "$($_.Name)" })
        $openSsids = @()
        $verifiedSsids = @()
        $wlanProfilesRead = $false
        try {
            $wlanRoot = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Wlansvc\Profiles\Interfaces'
            $xmlFiles = @(Get-ChildItem -Path $wlanRoot -Recurse -Filter '*.xml' -ErrorAction Stop)
            $wlanProfilesRead = ($xmlFiles.Count -gt 0)
            foreach ($file in $xmlFiles) {
                try {
                    $doc = [xml](Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop)
                    $ssid = "$($doc.WLANProfile.SSIDConfig.SSID.name)"
                    if ($connectedSsids -notcontains $ssid) { continue }
                    $auth = "$($doc.WLANProfile.MSM.security.authEncryption.authentication)"
                    $enc = "$($doc.WLANProfile.MSM.security.authEncryption.encryption)"
                    # Only count the SSID as checked once its security block was
                    # actually parsed - an unmatched profile is not a clean bill.
                    if ($auth -ne '' -or $enc -ne '') { $verifiedSsids += $ssid }
                    if ($auth -eq 'open' -and $enc -eq 'none') { $openSsids += $ssid }
                } catch {
                    # One unreadable or malformed profile must not stop the rest.
                    continue
                }
            }
        } catch {
            # The directory is ACL'd to SYSTEM and Administrators - handled below.
            $wlanProfilesRead = $false
        }
        $unverifiedSsids = @($connectedSsids | Where-Object { $verifiedSsids -notcontains $_ })

        if (-not $wlanProfilesRead) {
            Add-Skip -Message 'Could not read the WLAN profiles under %ProgramData%\Microsoft\Wlansvc (requires administrator) - do not know whether the wireless network is encrypted.'
        } elseif ($openSsids.Count -gt 0) {
            $alsoPrivate = @($connectedWifi | Where-Object {
                    $openSsids -contains $_.Name -and "$($_.NetworkCategory)" -eq 'Private'
                })
            $extra = ''
            if ($alsoPrivate.Count -gt 0) {
                $extra = ' The network is also set to Private, so file and printer sharing and network discovery are open to everyone on the same network.'
            }
            Add-Finding -Severity 'High' -Title 'Connected to a wireless network with no encryption' `
                -Evidence ('SSID {0}: authentication=open, encryption=none in the WLAN profile' -f ($openSsids -join ', ')) `
                -Impact ('All traffic that is not encrypted on its own can be read and modified by anyone within radio range.' + $extra) `
                -Fix 'Disconnect from the network, or use a VPN for as long as you are on it. Settings > Network & internet > Wi-Fi > Manage known networks to remove the profile.' `
                -Confidence 'Certain'
        } elseif ($unverifiedSsids.Count -gt 0) {
            Add-Skip -Message "Found no WLAN profile for the network it is connected to ($($unverifiedSsids -join ', ')) - the encryption has not been checked."
        } else {
            Add-Ok -Message "The wireless network is encrypted ($($verifiedSsids -join ', '))."
        }
    }

    # firewall
    $fwProfiles = @()
    try {
        $fwProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    } catch {
        # The Windows firewall can be replaced by a third-party product entirely.
        $fwProfiles = @()
    }

    $activeCategories = @($netProfiles | ForEach-Object { "$($_.NetworkCategory)" })
    if ($fwProfiles.Count -eq 0) {
        Add-Skip -Message 'Could not read the firewall profiles (Get-NetFirewallProfile did not respond) - cannot confirm that the firewall is on.'
    } else {
        $offProfiles = @($fwProfiles | Where-Object { -not $_.Enabled })
        if ($offProfiles.Count -eq $fwProfiles.Count) {
            Add-Finding -Severity 'Critical' -Title 'The Windows firewall is turned off for every profile' `
                -Evidence (($fwProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ') `
                -Impact 'Nothing is filtering inbound traffic. Every single listening service on the machine is directly reachable from the network it is on.' `
                -Fix 'Windows Security > Firewall & network protection - turn the firewall on for all three profiles. If a third-party product turned it off, check that the product is actually running.' `
                -Confidence 'Certain'
        } elseif ($offProfiles.Count -gt 0) {
            # Only certain if the machine is standing on a network of that category
            # right now; otherwise it is a hole that opens later.
            $offNames = @($offProfiles | ForEach-Object { "$($_.Name)" })
            $conf = 'Likely'
            if (@($activeCategories | Where-Object { $offNames -contains $_ }).Count -gt 0) { $conf = 'Certain' }
            Add-Finding -Severity 'High' -Title 'The firewall is turned off for one or more profiles' `
                -Evidence ('Turned off: {0}. Active network categories right now: {1}' -f ($offNames -join ', '), (($activeCategories | Sort-Object -Unique) -join ', ')) `
                -Impact 'As soon as the machine is on a network in this category, inbound traffic is no longer filtered.' `
                -Fix 'Windows Security > Firewall & network protection - turn the firewall on for the profile that is off.' `
                -Confidence $conf
        } else {
            Add-Ok -Message 'The Windows firewall is active for all three profiles (Domain, Private, Public).'
        }

        $allowInbound = @($fwProfiles | Where-Object { "$($_.DefaultInboundAction)" -eq 'Allow' })
        if ($allowInbound.Count -gt 0) {
            Add-Finding -Severity 'High' -Title 'The firewall lets in everything that is not explicitly blocked' `
                -Evidence (($allowInbound | ForEach-Object { "$($_.Name): DefaultInboundAction=Allow" }) -join ', ') `
                -Impact 'The default rule is inverted. Every listening port is open to the network unless there is a separate block rule for each one.' `
                -Fix 'wf.msc > Windows Defender Firewall Properties > pick the profile > set Inbound connections to Block.' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message 'The default action for inbound traffic is Block on every firewall profile.'
        }
    }

    # inbound rules on Public
    $inboundAllow = @()
    try {
        $inboundAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    } catch {
        # Rule store can be unreadable when policy is being applied.
        $inboundAllow = @()
    }

    # Profile is a flag enum; "Any" covers Public without naming it.
    $publicRules = @($inboundAllow | Where-Object {
            $p = "$($_.Profile)"
            $p -eq 'Any' -or $p -match 'Public'
        })

    if ($inboundAllow.Count -eq 0) {
        Add-Skip -Message 'Got no results from Get-NetFirewallRule - skipping the review of inbound ALLOW rules.'
    } elseif ($Fast) {
        Add-Skip -Message "$($publicRules.Count) enabled inbound ALLOW rules apply to the Public profile, but the program paths were not looked up (-Fast is set)."
    } else {
        $userWritable = @()
        try {
            $ruleTitles = @{}
            foreach ($rule in $publicRules) { $ruleTitles[$rule.Name] = $rule.DisplayName }
            $appFilters = @($publicRules | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $hits = @($appFilters | Where-Object {
                    $prog = "$($_.Program)"
                    $prog -ne '' -and $prog -ne 'Any' -and
                    $prog -match '\\AppData\\|\\Users\\|\\ProgramData\\|\\Temp\\'
                })
            $userWritable = @($hits | Group-Object -Property Program | ForEach-Object {
                    $title = $ruleTitles[$_.Group[0].InstanceID]
                    if ([string]::IsNullOrWhiteSpace($title)) { $title = "$($_.Group[0].InstanceID)" }
                    '{0} ({1})' -f $_.Name, $title
                })
        } catch {
            # Application filters are not retrievable for every GPO-delivered rule.
            $userWritable = @()
        }

        if ($userWritable.Count -gt 0) {
            $shown = @($userWritable | Select-Object -First 6)
            $more = ''
            if ($userWritable.Count -gt 6) { $more = " (+$($userWritable.Count - 6) more)" }
            Add-Finding -Severity 'Medium' -Title 'Inbound firewall openings on Public point at programs in user-writable folders' `
                -Evidence (($shown -join '; ') + $more) `
                -Impact 'Files under AppData, Users and ProgramData can be replaced without administrator rights. If one of these programs is swapped out, the replacement inherits a ready-made opening in through the firewall - including when the machine is on an unknown network.' `
                -Fix 'wf.msc > Inbound Rules, sort by Program, and disable the rules for programs you do not need to reach from outside. Most of them were added automatically the first time the program asked for network access.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message "None of the $($publicRules.Count) enabled inbound ALLOW rules on the Public profile point at a program in a user-writable folder."
        }
    }

    # listening ports
    $listeners = @()
    # Tracked separately: a port list that could not be read is not the same as
    # a machine with no open ports, and must never be reported as healthy.
    $listenersRead = $false
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $listenersRead = $true
    } catch {
        # Get-NetTCPConnection is missing on very old builds.
        $listeners = @()
    }

    $exposed = @()
    if (-not $listenersRead -or $listeners.Count -eq 0) {
        Add-Skip -Message 'Could not read the listening TCP ports (Get-NetTCPConnection did not respond) - skipping the port overview.'
    } else {
        $procNames = @{}
        try {
            foreach ($proc in (Get-Process -ErrorAction Stop)) { $procNames[[int]$proc.Id] = $proc.ProcessName }
        } catch {
            # Without the process list the PID is shown instead of a name.
            $procNames = @{}
        }

        $exposed = @($listeners | Where-Object {
                $addr = "$($_.LocalAddress)"
                $addr -notmatch '^127\.' -and $addr -ne '::1'
            })

        $riskPorts = @{
            22   = 'SSH'
            135  = 'RPC endpoint mapper'
            139  = 'NetBIOS session'
            445  = 'SMB'
            3389 = 'RDP'
            5357 = 'WSD'
            5985 = 'WinRM HTTP'
            5986 = 'WinRM HTTPS'
        }

        $portRows = @()
        foreach ($group in ($exposed | Group-Object -Property LocalPort | Sort-Object -Property { [int]$_.Name })) {
            $port = [int]$group.Name
            $ownerPid = [int]$group.Group[0].OwningProcess
            $owner = $procNames[$ownerPid]
            if ([string]::IsNullOrWhiteSpace($owner)) { $owner = "PID $ownerPid" }
            $label = ''
            if ($riskPorts.ContainsKey($port)) { $label = " [$($riskPorts[$port])]" }
            $addresses = (($group.Group | ForEach-Object { "$($_.LocalAddress)" }) | Sort-Object -Unique) -join '/'
            $portRows += ('{0}{1} {2} ({3})' -f $port, $label, $owner, $addresses)
        }

        if ($portRows.Count -eq 0) {
            Add-Ok -Message 'No TCP ports are listening outside loopback - the machine does not accept inbound connections.'
        } else {
            $shown = @($portRows | Select-Object -First 15)
            $more = ''
            if ($portRows.Count -gt 15) { $more = " (+$($portRows.Count - 15) more)" }
            Add-Finding -Severity 'Info' -Title 'TCP ports listening outside loopback' `
                -Evidence (($shown -join '; ') + $more) `
                -Impact 'These ports are reachable from the network if the firewall lets them through. 135, 139, 445 and 5357 are Windows defaults when file and printer sharing is on; the ports above 49152 are RPC services Windows starts itself.' `
                -Confidence 'Certain'
        }
    }
    $listeningPorts = @($exposed | ForEach-Object { [int]$_.LocalPort })

    # RDP and WinRM
    $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcpPath = "$tsPath\WinStations\RDP-Tcp"
    $denyRdp = Get-RegValue -Path $tsPath -Name 'fDenyTSConnections'
    if ($null -eq $denyRdp) {
        Add-Skip -Message 'Did not find fDenyTSConnections in the registry - cannot determine whether Remote Desktop is on.'
    } elseif ([int]$denyRdp -eq 0) {
        $nla = Get-RegValue -Path $rdpTcpPath -Name 'UserAuthentication'
        $rdpPort = Get-RegValue -Path $rdpTcpPath -Name 'PortNumber'
        if ($null -eq $rdpPort) { $rdpPort = 3389 }
        $rdpOnPublic = @($publicRules | Where-Object { $_.Name -like 'RemoteDesktop-*' })

        if ($null -ne $nla -and [int]$nla -eq 0) {
            Add-Finding -Severity 'High' -Title 'Remote Desktop is on without Network Level Authentication (NLA)' `
                -Evidence "fDenyTSConnections=0, UserAuthentication=0, port $rdpPort" `
                -Impact 'Without NLA a full session is set up before the user has proven who they are. That hands out free password guessing attempts and exposes the sign-in screen itself to known bugs.' `
                -Fix 'Settings > System > Remote Desktop > turn on "Require devices to use Network Level Authentication to connect".' `
                -Confidence 'Certain'
        } elseif ($rdpOnPublic.Count -gt 0) {
            Add-Finding -Severity 'High' -Title 'Remote Desktop is open on the Public profile as well' `
                -Evidence ("fDenyTSConnections=0, port $rdpPort, enabled rules: " + (($rdpOnPublic | ForEach-Object { $_.Name }) -join ', ')) `
                -Impact 'RDP accepts connections also when the machine is on an unknown network. Exposed RDP is the most common way in for ransomware.' `
                -Fix 'Limit the rule to Private and Domain in wf.msc, or turn the feature off in Settings > System > Remote Desktop.' `
                -Confidence 'Certain'
        } else {
            $nlaText = 'unknown'
            if ($null -ne $nla) { $nlaText = "$nla" }
            Add-Finding -Severity 'Medium' -Title 'Remote Desktop is turned on' `
                -Evidence "fDenyTSConnections=0, port $rdpPort, UserAuthentication=$nlaText" `
                -Impact 'The machine accepts RDP sign-ins. With NLA on and the firewall limited to Private the risk is manageable, but the service is an attack surface that should not be left open without a reason.' `
                -Fix 'Settings > System > Remote Desktop - turn it off if you do not use it.' `
                -Confidence 'Certain'
        }
    } else {
        Add-Ok -Message 'Remote Desktop (RDP) is turned off (fDenyTSConnections=1).'
    }

    $winrmPorts = @($listeningPorts | Where-Object { $_ -eq 5985 -or $_ -eq 5986 } | Sort-Object -Unique)
    if (-not $listenersRead) {
        Add-Skip -Message 'The port list could not be read - do not know whether WinRM is listening on the network.'
    } elseif ($winrmPorts.Count -gt 0) {
        $winrmSvc = Get-ServiceState -Name 'WinRM'
        $startType = 'unknown'
        if ($null -ne $winrmSvc) { $startType = "$($winrmSvc.StartType)" }
        Add-Finding -Severity 'Medium' -Title 'WinRM is listening on the network' `
            -Evidence ("Port $($winrmPorts -join ', ') is listening outside loopback, the WinRM service has start type $startType.") `
            -Impact 'WinRM provides remote command execution. On a client machine it is rarely needed, and it is the standard route attackers use to move further into a network.' `
            -Fix 'If remote management is not in use, remove the listener with Disable-PSRemoting (requires administrator). If you need it, limit the WINRM-HTTP-In-TCP firewall rule to Private and Domain.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'WinRM is not listening on the network.'
    }

    # SMB
    $smbServer = $null
    $smbClient = $null
    try { $smbServer = Get-SmbServerConfiguration -ErrorAction Stop } catch {
        # Reading the SMB server config normally requires elevation.
        $smbServer = $null
    }
    try { $smbClient = Get-SmbClientConfiguration -ErrorAction Stop } catch {
        # Same; the registry lookups below cover the values that matter most.
        $smbClient = $null
    }

    $smb1Reasons = @()
    if ($null -ne $smbServer -and $smbServer.EnableSMB1Protocol -eq $true) {
        $smb1Reasons += 'Get-SmbServerConfiguration: EnableSMB1Protocol=True'
    }
    # Only an explicit 1 counts. A missing value is the normal, healthy state on
    # every build since 1709, where the component is not installed at all.
    $smb1Value = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    if ($null -ne $smb1Value -and [int]$smb1Value -eq 1) {
        $smb1Reasons += 'LanmanServer\Parameters\SMB1=1'
    }
    $smb1Driver = Get-ServiceState -Name 'mrxsmb10'
    if ($null -ne $smb1Driver -and "$($smb1Driver.StartType)" -ne 'Disabled') {
        $smb1Reasons += "The SMB1 client driver mrxsmb10 is installed with start type $($smb1Driver.StartType)"
    }

    if ($smb1Reasons.Count -gt 0) {
        Add-Finding -Severity 'High' -Title 'SMB1 is still enabled' `
            -Evidence ($smb1Reasons -join '; ') `
            -Impact 'SMB1 cannot protect traffic against tampering and has no modern authentication. It is the protocol WannaCry and NotPetya spread through, and Microsoft pulled it from Windows in 2017.' `
            -Fix 'Turn off "SMB 1.0/CIFS File Sharing Support" in Control Panel > Programs > Turn Windows features on or off, and restart the machine.' `
            -Confidence 'Certain'
    } elseif ($null -eq $smbServer -and $null -eq $smb1Driver) {
        Add-Skip -Message 'Could not read the SMB server configuration (requires administrator) and found no SMB1 driver - SMB1 status is not confirmed.'
    } else {
        Add-Ok -Message 'SMB1 is not enabled, and the SMB1 client driver is not in use.'
    }

    $guestPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth'
    $guestEvidence = ''
    if ($null -ne $smbClient -and $smbClient.EnableInsecureGuestLogons -eq $true) {
        $guestEvidence = 'Get-SmbClientConfiguration: EnableInsecureGuestLogons=True'
    }
    if ($null -ne $guestPolicy -and [int]$guestPolicy -eq 1) {
        $guestEvidence = 'LanmanWorkstation policy: AllowInsecureGuestAuth=1'
    }
    if ($guestEvidence -ne '') {
        Add-Finding -Severity 'Medium' -Title 'The SMB client accepts insecure guest logons' `
            -Evidence $guestEvidence `
            -Impact 'The machine connects to file servers without requiring the server to prove who it is. Anyone on the same network can then pose as the file server and hand out tampered files.' `
            -Fix 'Set AllowInsecureGuestAuth to 0 (DWORD) under HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation, or run Set-SmbClientConfiguration -EnableInsecureGuestLogons $false as administrator.' `
            -Confidence 'Certain'
    } elseif ($null -eq $smbClient -and $null -eq $guestPolicy) {
        Add-Skip -Message 'Could not read the SMB client configuration - cannot confirm that insecure guest logons are off.'
    } else {
        Add-Ok -Message 'The SMB client does not accept insecure guest logons.'
    }

    # Signing only matters when the machine actually serves files, so this is
    # gated on 445 being reachable rather than reported on every client.
    if (-not $listenersRead) {
        Add-Skip -Message 'The port list could not be read - do not know whether the SMB server is reachable from the network, so signing has not been assessed.'
    } elseif ($listeningPorts -contains 445) {
        if ($null -eq $smbServer) {
            Add-Skip -Message 'Port 445 is listening, but the SMB server configuration could not be read (requires administrator) - signing has not been checked.'
        } elseif ($smbServer.RequireSecuritySignature -ne $true) {
            Add-Finding -Severity 'Low' -Title 'The SMB server does not require signing' `
                -Evidence "Port 445 is listening outside loopback, RequireSecuritySignature=$($smbServer.RequireSecuritySignature), EncryptData=$($smbServer.EncryptData)" `
                -Impact 'Without required signing, traffic to shared folders can be altered in transit by someone who is already on the same network (SMB relay).' `
                -Fix 'Set-SmbServerConfiguration -RequireSecuritySignature $true as administrator. Note that very old clients will no longer be able to connect.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message 'The SMB server requires signing on all traffic.'
        }
    } else {
        Add-Ok -Message 'The SMB server is not listening outside loopback - the machine is not sharing files on the network.'
    }

    # NetBIOS, LLMNR and mDNS
    # Read NetBT's own registry, not Win32_NetworkAdapterConfiguration. That WMI class only
    # lists adapters with IPEnabled=True and leaves out the Hyper-V and WSL virtual switch
    # host adapters entirely - so a machine running WSL2 could be told "NetBIOS is disabled
    # on every active network adapter" while NetBIOS sat listening on port 139 on
    # vEthernet (Default Switch), which is exactly where NetbiosOptions is left at the
    # DHCP default. The NetBT interface keys cover every interface that has a binding.
    $nbtEnabled = @()
    $nbtChecked = $false
    $nbtRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    try {
        $nbtKeys = @(Get-ChildItem -LiteralPath $nbtRoot -ErrorAction Stop)
        if ($nbtKeys.Count -gt 0) {
            $nbtChecked = $true
            # Map interface GUID -> friendly name so the evidence names something recognisable.
            $adapterNames = @{}
            try {
                foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop)) {
                    if ($adapter.InterfaceGuid) { $adapterNames[[string]$adapter.InterfaceGuid] = $adapter.Name }
                }
            } catch {
                Write-Verbose -Message ("Get-NetAdapter unavailable, GUIDs will be shown instead: {0}" -f $_.Exception.Message)
            }
            # NetBT keeps an interface key long after the adapter is gone, so the registry is
            # full of GUIDs for hardware that was removed years ago. Those cannot broadcast
            # anything. Reporting them turned this finding into a wall of GUIDs on a machine
            # with a normal history, which buries the one adapter that actually mattered.
            $nbtStale = 0
            foreach ($nbtKey in $nbtKeys) {
                $option = Get-RegValue -Path $nbtKey.PSPath -Name 'NetbiosOptions'
                # 0 = follow DHCP (in practice on), 1 = on, 2 = off.
                if ($null -ne $option -and [int]$option -eq 2) { continue }
                $guid = $nbtKey.PSChildName -replace '^Tcpip_', ''
                if (-not $adapterNames.ContainsKey($guid)) {
                    # Only skip it when the adapter list was actually readable - otherwise
                    # every interface would look stale and the check would report nothing.
                    if ($adapterNames.Count -gt 0) { $nbtStale++; continue }
                }
                $label = if ($adapterNames.ContainsKey($guid)) { $adapterNames[$guid] } else { $guid }
                $value = if ($null -eq $option) { 'not set' } else { "$option" }
                $nbtEnabled += "$label (NetbiosOptions=$value)"
            }
        }
    } catch {
        # The key is absent on some minimal images.
        $nbtChecked = $false
    }

    if (-not $nbtChecked) {
        Add-Skip -Message ("Could not read {0} - skipping the NetBIOS over TCP/IP check." -f $nbtRoot)
    } elseif ($nbtEnabled.Count -gt 0) {
        $staleNote = if ($nbtStale -gt 0) { " ($nbtStale further NetBT entries belong to adapters that no longer exist and were ignored.)" } else { '' }
        Add-Finding -Severity 'Low' -Title 'NetBIOS over TCP/IP is not turned off' `
            -Evidence ((@($nbtEnabled | Select-Object -First 6) -join '; ') + $staleNote) `
            -Impact 'When a DNS lookup fails, the machine broadcasts the name it is after on the local network (NBT-NS). Anyone on the same network can answer "that is me" and get the machine to send its NTLM logon there - the basis for tools like Responder.' `
            -Fix 'Per adapter: Network Connections > Properties > Internet Protocol Version 4 > Advanced > WINS > "Disable NetBIOS over TCP/IP". Virtual switch adapters (Hyper-V, WSL) do not appear there - set NetbiosOptions to 2 directly under HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_<GUID>. Check afterwards with: Get-NetTCPConnection -LocalPort 139 -State Listen' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message ("NetBIOS over TCP/IP is disabled on all {0} interfaces registered with NetBT, including virtual switch adapters." -f $nbtKeys.Count)
    }

    $llmnr = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ($null -ne $llmnr -and [int]$llmnr -eq 0) {
        Add-Ok -Message 'LLMNR is turned off by policy (EnableMulticast=0).'
    } else {
        $llmnrEvidence = 'EnableMulticast is missing under HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if ($null -ne $llmnr) { $llmnrEvidence = "EnableMulticast=$llmnr" }
        Add-Finding -Severity 'Low' -Title 'LLMNR is not explicitly turned off' `
            -Evidence $llmnrEvidence `
            -Impact 'LLMNR is the same weakness as NBT-NS: names DNS fails to resolve are broadcast on the local network and can be answered by anyone. Microsoft has deprecated the protocol itself.' `
            -Fix 'Set EnableMulticast to 0 (DWORD) under HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient, or enable "Turn off multicast name resolution" in gpedit.msc.' `
            -Confidence 'Likely'
    }

    $mdns = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
    $mdnsState = 'on (EnableMDNS is missing, which is the default)'
    $mdnsOff = $false
    if ($null -ne $mdns) {
        if ([int]$mdns -eq 0) { $mdnsState = 'off (EnableMDNS=0)'; $mdnsOff = $true }
        else { $mdnsState = "on (EnableMDNS=$mdns)" }
    }
    $discoveryServices = @()
    foreach ($svcName in @('FDResPub', 'SSDPSRV', 'upnphost', 'lltdsvc')) {
        $svc = Get-ServiceState -Name $svcName
        if ($null -ne $svc -and "$($svc.Status)" -eq 'Running') { $discoveryServices += $svcName }
    }
    if ($mdnsOff -and $discoveryServices.Count -eq 0) {
        Add-Ok -Message 'Neither mDNS nor the WSD/SSDP services are broadcasting the machine name on the local network.'
    } else {
        # Only a real (if small) problem when the machine is standing on a network
        # it does not trust; on a home LAN this is how printers are found.
        $onPublic = @($netProfiles | Where-Object { "$($_.NetworkCategory)" -eq 'Public' })
        $sev = 'Info'
        if ($onPublic.Count -gt 0 -and $discoveryServices -contains 'FDResPub') { $sev = 'Low' }
        $svcText = 'none'
        if ($discoveryServices.Count -gt 0) { $svcText = ($discoveryServices -join ', ') }
        Add-Finding -Severity $sev -Title 'The machine announces itself on the local network' `
            -Evidence "mDNS: $mdnsState. Running discovery services: $svcText." `
            -Impact 'mDNS and WSD/SSDP broadcast machine name and services to everyone on the same network. That is needed to find printers and streaming devices, but it also hands a stranger on the network a free overview of the machine.' `
            -Fix 'Settings > Network & internet > Advanced network settings > Advanced sharing settings - turn off Network discovery for Public networks.' `
            -Confidence 'Likely'
    }

    # DNS and DoH
    $knownResolvers = @(
        '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
        '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15',
        '76.76.2.0', '76.76.10.0', '185.228.168.9', '185.228.169.9', '45.90.28.0', '45.90.30.0'
    )
    $dnsRows = @()
    $unknownResolvers = @()
    try {
        $activeIndexes = @($netProfiles | ForEach-Object { $_.InterfaceIndex })
        $dnsEntries = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
                $_.ServerAddresses.Count -gt 0 -and $activeIndexes -contains $_.InterfaceIndex
            })
        foreach ($entry in $dnsEntries) {
            $dnsRows += "$($entry.InterfaceAlias): $($entry.ServerAddresses -join ', ')"
            foreach ($server in $entry.ServerAddresses) {
                if (-not (& $isLocalAddress $server) -and $knownResolvers -notcontains $server) {
                    $unknownResolvers += "$server on $($entry.InterfaceAlias)"
                }
            }
        }
    } catch {
        # The DnsClient module is absent from some minimal installations.
        $dnsRows = @()
    }

    $dohInterfaces = @()
    try {
        $dohInterfaces = @(Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters' -Recurse -ErrorAction Stop |
                Where-Object { $_.PSChildName -eq 'DohInterfaceSettings' })
    } catch {
        # The key only exists once DoH has been configured on at least one adapter.
        $dohInterfaces = @()
    }

    if ($dnsRows.Count -eq 0) {
        Add-Skip -Message 'Found no DNS servers on the active network adapters - skipping the DNS check.'
    } else {
        $dohText = 'DNS-over-HTTPS is not configured on any adapter'
        if ($dohInterfaces.Count -gt 0) { $dohText = "DNS-over-HTTPS is configured on $($dohInterfaces.Count) adapter(s)" }
        Add-Finding -Severity 'Info' -Title 'DNS setup' `
            -Evidence (($dnsRows -join '; ') + ". $dohText.") `
            -Impact 'The DNS server sees every single domain name the machine looks up. Without DNS-over-HTTPS the lookups go out in clear text and can be both read and altered by anyone sitting between the machine and the server.' `
            -Fix 'To encrypt the lookups: Settings > Network & internet > pick the adapter > DNS server assignment > Edit > DNS encryption: Encrypted only.' `
            -Confidence 'Certain'
    }
    if ($unknownResolvers.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Title 'An unknown public DNS server is configured' `
            -Evidence ($unknownResolvers -join '; ') `
            -Impact 'The DNS server is neither your router nor one of the well-known public services. If something other than you set it, it can send you to the wrong site without anything looking wrong in the browser.' `
            -Fix 'If you do not recognize the address: Settings > Network & internet > pick the adapter > DNS server assignment > Automatic (DHCP).' `
            -Confidence 'Uncertain'
    }

    # hosts file
    # The location is configurable, and a moved DataBasePath is itself a trick.
    $hostsDir = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DataBasePath'
    if ([string]::IsNullOrWhiteSpace("$hostsDir")) {
        $hostsDir = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc'
    } else {
        $hostsDir = [Environment]::ExpandEnvironmentVariables("$hostsDir")
    }
    $hostsPath = Join-Path -Path $hostsDir -ChildPath 'hosts'

    $hostsEntries = @()
    $hostsRead = $false
    try {
        if (Test-Path -LiteralPath $hostsPath) {
            foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
                $trimmed = "$line".Trim()
                if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
                $parts = @($trimmed -split '\s+' | Where-Object { $_ -ne '' })
                if ($parts.Count -lt 2) { continue }
                foreach ($name in $parts[1..($parts.Count - 1)]) {
                    if ($name.StartsWith('#')) { break }
                    $hostsEntries += [pscustomobject]@{ Address = $parts[0]; Name = $name }
                }
            }
            $hostsRead = $true
        }
    } catch {
        # The file can be locked by a security product.
        $hostsRead = $false
    }

    if (-not $hostsRead) {
        Add-Skip -Message "Could not read the hosts file ($hostsPath) - skipping the check for name overrides."
    } else {
        # Docker Desktop writes its own block on every start; it is not a finding.
        $custom = @($hostsEntries | Where-Object {
                $_.Name -notmatch '^(localhost|::1)$' -and $_.Name -notmatch '\.docker\.internal$'
            })
        $securityDomains = 'windowsupdate|update\.microsoft|download\.microsoft|wustat\.windows|definitionupdates|wdcp(alt)?\.microsoft|smartscreen|avast|avg\.com|avira|bitdefender|eset\.com|kaspersky|mcafee|malwarebytes|norton(security)?\.com|symantec|sophos|trendmicro|virustotal|sysinternals|clamav|drweb|f-secure|comodo|emsisoft'
        $blockedSecurity = @($custom | Where-Object { $_.Name -match $securityDomains })
        $remoteRedirects = @($custom | Where-Object { -not (& $isLocalAddress $_.Address) })

        if ($blockedSecurity.Count -gt 0) {
            Add-Finding -Severity 'High' -Title 'The hosts file blocks update or security domains' `
                -Evidence ((@($blockedSecurity | Select-Object -First 8 | ForEach-Object { "$($_.Address) $($_.Name)" }) -join '; ') + " - in $hostsPath") `
                -Impact 'Putting antivirus and Windows Update domains in the hosts file is standard behavior for malware and for cracked software. The machine stops getting security and signature updates without saying a word.' `
                -Fix "Open $hostsPath in Notepad as administrator and remove the lines above. Then run a full scan with Windows Defender (Start-MpScan -ScanType FullScan)." `
                -Confidence 'Likely'
        }
        if ($remoteRedirects.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Title 'The hosts file sends domains to addresses outside the local network' `
                -Evidence (@($remoteRedirects | Select-Object -First 8 | ForEach-Object { "$($_.Address) $($_.Name)" }) -join '; ') `
                -Impact 'The entries override DNS and send the traffic to a specific server out on the internet. That is common in development setups, but it is also how traffic gets redirected quietly.' `
                -Fix "Open $hostsPath and remove the entries you did not put there yourself." `
                -Confidence 'Uncertain'
        }
        if ($blockedSecurity.Count -eq 0 -and $remoteRedirects.Count -eq 0) {
            if ($custom.Count -gt 0) {
                Add-Finding -Severity 'Info' -Title 'The hosts file has custom entries' `
                    -Evidence ("$($custom.Count) entry(ies), including: " + (@($custom | Select-Object -First 5 | ForEach-Object { "$($_.Address) $($_.Name)" }) -join '; ')) `
                    -Impact 'All of them point locally or at the local network - typically a local development server, a test entry or an ad blocking list.' `
                    -Fix "Look through $hostsPath if you do not recognize any of this." `
                    -Confidence 'Certain'
            } else {
                Add-Ok -Message 'The hosts file contains no name overrides beyond the default setup.'
            }
        }
    }

    # proxy
    # netsh winhttp show proxy is translated, so the raw blob is decoded instead:
    # 4 bytes version, 4 counter, 4 flags, then a length-prefixed ANSI proxy string.
    $winhttpProxy = ''
    $winhttpValuePresent = $false
    try {
        $blob = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name 'WinHttpSettings' -ErrorAction Stop).WinHttpSettings
        if ($null -ne $blob -and $blob.Length -ge 16) {
            $winhttpValuePresent = $true
            $length = [BitConverter]::ToInt32($blob, 12)
            if ($length -gt 0 -and ($length + 16) -le $blob.Length) {
                $winhttpProxy = [Text.Encoding]::ASCII.GetString($blob, 16, $length)
            }
        }
    } catch {
        # The value is absent on machines that never had a proxy - that is normal.
        $winhttpProxy = ''
    }

    $ieSettings = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $userProxyOn = Get-RegValue -Path $ieSettings -Name 'ProxyEnable'
    $userProxy = Get-RegValue -Path $ieSettings -Name 'ProxyServer'
    $userPac = Get-RegValue -Path $ieSettings -Name 'AutoConfigURL'

    $proxyParts = @()
    if (-not [string]::IsNullOrWhiteSpace($winhttpProxy)) { $proxyParts += "WinHTTP (system): $winhttpProxy" }
    if ($null -ne $userProxyOn -and [int]$userProxyOn -eq 1 -and -not [string]::IsNullOrWhiteSpace("$userProxy")) {
        $proxyParts += "User: $userProxy"
    }
    if (-not [string]::IsNullOrWhiteSpace("$userPac")) { $proxyParts += "PAC script: $userPac" }

    if ($proxyParts.Count -gt 0) {
        # In a domain a proxy is normal and set by IT. Outside one it is unexpected.
        $sev = 'High'
        $conf = 'Likely'
        if ($script:Ctx.DomainJoined) { $sev = 'Info'; $conf = 'Certain' }
        Add-Finding -Severity $sev -Title 'The machine sends web traffic through a proxy' `
            -Evidence ($proxyParts -join '; ') `
            -Impact 'All HTTP and HTTPS traffic goes through this host. If you did not set it up yourself, someone can read and alter your web traffic - the standard pattern for ad injection and for tools that intercept TLS.' `
            -Fix 'Settings > Network & internet > Proxy. Turn off both "Use setup script" and "Use a proxy server" if you do not recognize the address.' `
            -Confidence $conf
    } else {
        $okText = 'No proxy is configured, neither for the system (WinHTTP) nor for the user.'
        if (-not $winhttpValuePresent) {
            $okText = 'No proxy is configured for the user, and the WinHTTP setting has never been put to use (default).'
        }
        Add-Ok -Message $okText
    }

    # third-party NIC filters
    $thirdPartyFilters = @()
    $bindingsRead = $false
    try {
        $bindings = @(Get-NetAdapterBinding -ErrorAction Stop | Where-Object {
                $_.Enabled -and "$($_.ComponentID)" -notlike 'ms_*'
            })
        $bindingsRead = $true
        $thirdPartyFilters = @($bindings | Group-Object -Property ComponentID | ForEach-Object {
                '{0} [{1}] on {2} adapter(s)' -f $_.Group[0].DisplayName, $_.Name, $_.Count
            })
    } catch {
        # Requires the NetAdapter module, same as the adapter checks above.
        $thirdPartyFilters = @()
    }

    if (-not $bindingsRead) {
        Add-Skip -Message 'Get-NetAdapterBinding did not respond - the protocol bindings on the network adapters have not been reviewed.'
    } elseif ($thirdPartyFilters.Count -gt 0) {
        Add-Finding -Severity 'Info' -Title 'Third-party network filters are bound to the network adapters' `
            -Evidence ($thirdPartyFilters -join '; ') `
            -Impact 'These drivers see all traffic going through the adapter. That is normal for VPN clients, VirtualBox, Wireshark/Npcap and some security products, but a filter you do not recognize is worth a closer look.' `
            -Fix 'Network Connections (ncpa.cpl) > right-click the adapter > Properties shows the same list, where you can uncheck filters you do not use.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'No third-party network filters are bound to the network adapters.'
    }

    # Outbound BLOCK rules aimed at Windows' own binaries. Tweak and "telemetry blocker"
    # scripts add these freely, and the result is a machine that silently cannot update or
    # cannot reach Defender's cloud - with nothing in the interface saying so.
    try {
        $systemBinaryPattern = '(?i)\\(wuauclt|usoclient|MoUsoCoreWorker|MpCmdRun|MsMpEng|SecurityHealthService|svchost|smartscreen|wermgr|CompatTelRunner|DeviceCensus|sihclient)\.exe$'
        $outboundBlocks = @()
        # Get-NetFirewallRule throws "No matching MSFT_NetFirewallRule objects found" when
        # the filter matches nothing, rather than returning an empty set. A machine with no
        # outbound block rules at all is the healthy case, so it must not surface as an error.
        $blockRules = @(Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue)
        if ($blockRules.Count -gt 0) {
            $appFilters = @(Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $filterByRule = @{}
            foreach ($filter in $appFilters) {
                if ($filter.Program -and $filter.Program -ne 'Any') { $filterByRule[[string]$filter.InstanceID] = [string]$filter.Program }
            }
            foreach ($rule in $blockRules) {
                $program = $filterByRule[[string]$rule.InstanceID]
                if ($program -and $program -match $systemBinaryPattern) {
                    $outboundBlocks += "$($rule.DisplayName) -> $program"
                }
            }
        }
        if ($outboundBlocks.Count -gt 0) {
            Add-Finding -Severity 'High' -Title 'Outbound firewall rules block Windows own update or security binaries' `
                -Evidence (($outboundBlocks | Select-Object -First 6) -join '; ') `
                -Impact 'These rules stop Windows Update or Defender from reaching Microsoft. The machine keeps reporting itself as configured for automatic updates while no update or signature ever arrives, and nothing in Settings indicates why. This is the single most damaging thing the popular telemetry-blocking scripts do.' `
                -Fix 'wf.msc > Outbound Rules, sort by Action, and delete or disable the Block rules pointing at these programs. Then run Windows Update and check that it completes.' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message 'No outbound firewall rule blocks Windows update or security binaries.'
        }
    } catch {
        Add-Skip -Message ("Outbound firewall rules could not be examined: {0}" -f $_.Exception.Message)
    }

    # DNS over every address family. The IPv4-only view misses a machine whose IPv6
    # resolver points somewhere else entirely, and NRPT rules override both.
    try {
        # fec0:0:0:ffff::1 through ::3 are the site-local addresses Windows ships on every
        # interface as a fallback. They are not a configured resolver, and reporting them
        # would fire this finding on every machine in existence.
        $windowsDefaultV6Dns = @('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
        $v6Servers = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction Stop |
                Where-Object { $_.InterfaceAlias -notmatch '(?i)loopback' } |
                ForEach-Object {
                    $realServers = @($_.ServerAddresses | Where-Object { $windowsDefaultV6Dns -notcontains $_ })
                    if ($realServers.Count -gt 0) {
                        [PSCustomObject]@{ InterfaceAlias = $_.InterfaceAlias; ServerAddresses = $realServers }
                    }
                })
        if ($v6Servers.Count -gt 0) {
            $v6Text = (@($v6Servers | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" }) -join '; ')
            Add-Finding -Severity 'Info' -Title 'IPv6 DNS servers are configured' `
                -Evidence $v6Text `
                -Impact 'Windows prefers IPv6 when both are available, so these servers see the lookups even when the IPv4 setting points somewhere else. A machine hardened on IPv4 alone can still resolve everything through an IPv6 resolver nobody looked at.' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message 'No IPv6 DNS servers beyond the Windows defaults are configured, so name resolution follows the IPv4 setting.'
        }
    } catch {
        Add-Skip -Message 'IPv6 DNS servers could not be read.'
    }

    try {
        $nrpt = @(Get-DnsClientNrptRule -ErrorAction Stop)
        if ($nrpt.Count -gt 0) {
            $nrptText = (@($nrpt | Select-Object -First 4 | ForEach-Object { "$($_.Namespace -join ',') -> $($_.NameServers -join ',')" }) -join '; ')
            Add-Finding -Severity 'Medium' -Title 'Name Resolution Policy rules redirect specific domains' `
                -Evidence ("{0} NRPT rule(s): {1}" -f $nrpt.Count, $nrptText) `
                -Impact 'NRPT overrides the normal DNS setting for the namespaces it names, and it is applied before anything else. It is how a VPN does split DNS legitimately - and also a quiet way to send just the domains that matter to a different resolver.' `
                -Fix 'Inspect them with: Get-DnsClientNrptRule. Rules from a VPN client disappear when the tunnel is down; anything that survives that is worth explaining.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message 'No Name Resolution Policy rules redirect DNS for specific domains.'
        }
    } catch {
        Add-Skip -Message 'Name Resolution Policy rules could not be read.'
    }

    # File shares. Inferring "not sharing" from port 445 was wrong in both directions:
    # the port is open on almost every Windows machine, and a share can exist behind it.
    try {
        # The built-in administrative shares, which every Windows machine publishes and which
        # are not a finding: the per-drive C$/D$ ones, plus the fixed-name ADMIN$, IPC$ and
        # print$. The old filter only matched a single letter before the $, so ADMIN$ was
        # reported as a published share on every machine that had it.
        $builtinShares = @('ADMIN$', 'IPC$', 'PRINT$', 'FAX$')
        $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object {
                $_.Name -notmatch '^\w\$$' -and $builtinShares -notcontains $_.Name.ToUpperInvariant()
            })
        if ($shares.Count -eq 0) {
            Add-Ok -Message 'No file shares beyond the built-in administrative ones are published from this machine.'
        } else {
            $shareText = (@($shares | Select-Object -First 6 | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join '; ')
            # Everyone-readable is the case worth separating out.
            $openShares = @()
            foreach ($share in $shares) {
                try {
                    $access = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop |
                            Where-Object { $_.AccountName -match '(?i)^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)$' -and [string]$_.AccessControlType -eq 'Allow' })
                    if ($access.Count -gt 0) { $openShares += "$($share.Name) ($(($access | ForEach-Object { $_.AccountName }) -join ', '))" }
                } catch {
                    Write-Verbose -Message ("Share permissions for {0} could not be read: {1}" -f $share.Name, $_.Exception.Message)
                }
            }
            if ($openShares.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Title 'File shares are readable by everyone on the network' `
                    -Evidence ("{0} share(s): {1}. Broadly permitted: {2}" -f $shares.Count, $shareText, ($openShares -join '; ')) `
                    -Impact 'Anyone who can reach port 445 on this machine can list and read these folders. On a home network that includes every device on the Wi-Fi, and on a public network it includes strangers.' `
                    -Fix 'Remove the share, or tighten it: Get-SmbShareAccess -Name <share>, then Revoke-SmbShareAccess for Everyone and grant only the accounts that need it.' `
                    -Confidence 'Certain'
            } else {
                Add-Finding -Severity 'Info' -Title 'File shares are published from this machine' `
                    -Evidence ("{0} share(s): {1}" -f $shares.Count, $shareText) `
                    -Impact 'Shares are reachable by anything that can talk to port 445. None of them grants access to Everyone, so this is informational.' `
                    -Confidence 'Certain'
            }
        }
    } catch {
        Add-Skip -Message ("SMB shares could not be enumerated: {0}" -f $_.Exception.Message)
    }

    # Port proxies forward a local port somewhere else at the kernel level, and they appear
    # in no firewall list. They are how an unexplained listening port turns out to be a
    # bridge to another host entirely.
    if (Get-Command -Name netsh -CommandType Application -ErrorAction SilentlyContinue) {
        try {
            $portproxyRaw = & netsh interface portproxy show all 2>&1 | Out-String
            # Match address/port quadruples, which is language-independent - the table
            # headings are translated but the rows are addresses and numbers.
            $portproxyRows = @([regex]::Matches($portproxyRaw, '(?m)^\s*(\S+)\s+(\d{1,5})\s+(\S+)\s+(\d{1,5})\s*$') |
                    ForEach-Object { "$($_.Groups[1].Value):$($_.Groups[2].Value) -> $($_.Groups[3].Value):$($_.Groups[4].Value)" })
            if ($portproxyRows.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Title 'Ports on this machine are forwarded to another address' `
                    -Evidence (($portproxyRows | Select-Object -First 6) -join '; ') `
                    -Impact 'A port proxy accepts a connection here and forwards it somewhere else, in the kernel, below the firewall. It shows up in no rule list, and it explains listening ports that otherwise have no owning program. WSL sets these up legitimately; so does anyone wanting a quiet pivot into a network.' `
                    -Fix 'List them with: netsh interface portproxy show all - and remove one with: netsh interface portproxy delete v4tov4 listenport=<port>' `
                    -Confidence 'Likely'
            } else {
                Add-Ok -Message 'No port proxies forward traffic from this machine to another address.'
            }
        } catch {
            Add-Skip -Message 'netsh interface portproxy could not be read.'
        }
    }

    # Saved wireless profiles. The connected network is checked elsewhere; these are the
    # ones the machine will join on its own the moment it hears the name.
    if (Get-Command -Name netsh -CommandType Application -ErrorAction SilentlyContinue) {
        try {
            $wlanProfilesRaw = & netsh wlan show profiles 2>&1 | Out-String
            # Profile names appear after a colon; the label around it is translated.
            $wlanNames = @([regex]::Matches($wlanProfilesRaw, '(?m)^\s*\S[^:\r\n]*:\s*(\S.*?)\s*$') |
                    ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^\s*$' } | Select-Object -Unique)
            $weakProfiles = @()
            foreach ($wlanName in $wlanNames) {
                $detail = & netsh wlan show profile name="$wlanName" key=clear 2>&1 | Out-String
                # Authentication and cipher values are protocol names, not translated.
                if ($detail -match '(?i)\b(WEP|TKIP)\b') { $weakProfiles += "$wlanName (WEP or TKIP)" }
                elseif ($detail -match '(?i)\bOpen\b' -and $detail -notmatch '(?i)\b(WPA|OWE)') { $weakProfiles += "$wlanName (open, no encryption)" }
            }
            if ($weakProfiles.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Title 'Saved wireless networks use no encryption or a broken one' `
                    -Evidence (($weakProfiles | Select-Object -First 6) -join '; ') `
                    -Impact 'The machine reconnects to a saved network automatically whenever it hears the name. An open or WEP profile means anyone can stand up an access point with that name and have this machine join it, and then read or alter the traffic. Old hotel and airport profiles are the usual culprits.' `
                    -Fix 'Settings > Network & internet > Wi-Fi > Manage known networks - forget the ones you do not need. From PowerShell: netsh wlan delete profile name="<name>"' `
                    -Confidence 'Likely'
            } elseif ($wlanNames.Count -gt 0) {
                Add-Ok -Message ("All {0} saved wireless profile(s) use modern encryption - none is open, WEP or TKIP." -f $wlanNames.Count)
            }
        } catch {
            Add-Skip -Message 'Saved wireless profiles could not be read.'
        }
    }
}

# Category "Security" - the category most prone to false alarms, so two rules apply
# throughout: a missing value means "Windows default" and is not flagged, only an
# explicitly weakened one is; and every probe is isolated, because SecurityCenter2,
# the Defender module, BitLocker and DeviceGuard are all absent on some SKUs.
function Test-SecurityHealth {
    [CmdletBinding()]
    param()

    # local helpers

    # Why: SecurityCenter2 packs vendor, real-time status and signature status into three bytes in
    # a single integer. Without decoding we cannot tell "installed" from "actually active".
    $decodeAvState = {
        param([object]$RawState)

        $decoded = [pscustomobject]@{ RealTime = $false; UpToDate = $true; Known = $false }
        try {
            $hex = '{0:x6}' -f [uint32]$RawState
            if ($hex.Length -gt 6) { $hex = $hex.Substring($hex.Length - 6) }
            $rtByte = [Convert]::ToInt32($hex.Substring(2, 2), 16)
            $sigByte = [Convert]::ToInt32($hex.Substring(4, 2), 16)
            $decoded.RealTime = ($rtByte -eq 16 -or $rtByte -eq 17)
            $decoded.UpToDate = ($sigByte -eq 0)
            $decoded.Known = $true
        } catch {
            Write-Verbose -Message "Could not decode productState: $($_.Exception.Message)"
        }
        return $decoded
    }

    # Why: a Defender exclusion in a folder the user can write to is a real hole - malware only
    # needs to copy itself there. Exclusions under Program Files already require admin and are
    # therefore far less interesting.
    $isUserWritablePath = {
        param([string]$CandidatePath)

        if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
        $lowered = $CandidatePath.ToLowerInvariant()
        $userWritablePatterns = @(
            '*\users\*', '*\appdata\*', '*\temp*', '*\downloads*', '*\programdata\*',
            '*\public\*', '*\windows\tasks*', '*%userprofile%*', '*%appdata%*',
            '*%localappdata%*', '*%temp%*', '*%programdata%*', '*\perflogs*'
        )
        foreach ($pattern in $userWritablePatterns) {
            if ($lowered -like $pattern) { return $true }
        }
        # A bare drive root or a plain wildcard covers everything, including the user folders.
        if ($lowered -match '^[a-z]:\\?$' -or $lowered -eq '*' -or $lowered -match '^[a-z]:\\\*') { return $true }
        return $false
    }

    $ctx = $script:Ctx

    # 1. Registered AV products

    $avProducts = @()
    $activeAvNames = @()
    $staleAvNames = @()

    if ($ctx.IsServer) {
        Add-Skip -Message 'Windows Security Center (root\SecurityCenter2) does not exist on Server editions - skipping the overview of registered antivirus products.'
    } else {
        # A failed query and a genuinely empty Security Center are not the same thing, and
        # the difference matters: 0 entries means no antivirus, while a broken WMI namespace
        # means we do not know. Without this flag the catch below reports "could not read"
        # and the count check then fires a Critical "no antivirus is registered" on top of
        # it - a false alarm about the most important protection on the machine.
        $avQueryFailed = $false
        try {
            $avProducts = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        } catch {
            $avQueryFailed = $true
            Add-Skip -Message "Could not read registered antivirus products from Security Center: $($_.Exception.Message)"
        }

        foreach ($product in $avProducts) {
            $state = & $decodeAvState -RawState $product.productState
            if (-not $state.Known) { continue }
            if ($state.RealTime) { $activeAvNames += [string]$product.displayName }
            if (-not $state.UpToDate) { $staleAvNames += [string]$product.displayName }
        }

        if ($avQueryFailed) {
            # Already reported as a skip above. Saying nothing more is correct here -
            # the Defender checks below read their own source and still apply.
        } elseif ($avProducts.Count -eq 0) {
            Add-Finding -Severity Critical -Title 'No antivirus product is registered in Windows Security Center' `
                -Evidence 'root\SecurityCenter2 -> AntiVirusProduct returned 0 entries' `
                -Impact 'The machine has no known real-time protection against malware.' `
                -Fix 'Open Windows Security -> Virus & threat protection and check that Microsoft Defender or another AV is active.' `
                -Confidence Likely
        } elseif ($activeAvNames.Count -eq 0) {
            Add-Finding -Severity Critical -Title 'Antivirus is installed, but none has real-time protection on' `
                -Evidence ("Registered: {0}. None of them report active real-time status (productState)." -f (($avProducts | ForEach-Object { $_.displayName }) -join ', ')) `
                -Impact 'Files are not scanned when written or executed - malware can establish itself freely.' `
                -Fix 'Turn on real-time protection in Windows Security -> Virus & threat protection -> Virus & threat protection settings.' `
                -Confidence Likely
        } else {
            Add-Ok -Message ("Active real-time protection from: {0}." -f ($activeAvNames -join ', '))
        }

        if ($activeAvNames.Count -gt 1) {
            Add-Finding -Severity Medium -Title 'Several antivirus products are running real-time protection at the same time' `
                -Evidence ("Active at the same time: {0}" -f ($activeAvNames -join ', ')) `
                -Impact 'Two real-time engines scanning the same files costs performance and they can block each other from updating.' `
                -Fix 'Uninstall the antivirus product you do not use via Settings -> Apps -> Installed apps.' `
                -Confidence Likely
        }

        if ($staleAvNames.Count -gt 0) {
            Add-Finding -Severity Medium -Title 'Antivirus product reports out-of-date signatures' `
                -Evidence ("Security Center reports out-of-date definition status for: {0}" -f ($staleAvNames -join ', ')) `
                -Impact 'New threats are not detected until the signatures are updated.' `
                -Fix 'Run an update from inside the antivirus product itself, or Windows Security -> Virus & threat protection -> Check for updates.' `
                -Confidence Likely
        }
    }

    # 2. Defender status

    $mpStatus = $null
    $mpPref = $null
    $defenderNormalMode = $false

    if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        } catch {
            Add-Skip -Message "Get-MpComputerStatus failed - Defender details could not be read: $($_.Exception.Message)"
        }
    } else {
        Add-Skip -Message 'The Defender module (Get-MpComputerStatus) does not exist on this machine - skipping Defender details.'
    }

    if ($mpStatus) {
        $runningMode = [string]$mpStatus.AMRunningMode
        $defenderNormalMode = ($runningMode -eq 'Normal')

        if ($runningMode -like '*Passive*' -or $runningMode -eq 'EDR Block Mode') {
            if ($activeAvNames.Count -gt 0) {
                Add-Ok -Message ("Microsoft Defender is in {0} because another antivirus has the real-time role - that is expected." -f $runningMode)
            } else {
                Add-Finding -Severity High -Title 'Microsoft Defender is in passive mode without another antivirus having taken over' `
                    -Evidence ("AMRunningMode = {0}, but no third-party AV reports active real-time protection" -f $runningMode) `
                    -Impact 'Defender does not scan in real time, and no other engine does either.' `
                    -Fix 'Uninstall leftovers from a previous antivirus, or turn Defender on in Windows Security -> Virus & threat protection.' `
                    -Confidence Likely
            }
        } elseif ($runningMode -eq 'Not running') {
            if ($activeAvNames.Count -gt 0) {
                Add-Ok -Message 'Microsoft Defender is not running because another antivirus product has taken over.'
            } else {
                Add-Finding -Severity Critical -Title 'Microsoft Defender is not running, and no other antivirus engine is active' `
                    -Evidence 'AMRunningMode = Not running' `
                    -Impact 'The machine is left with no real-time protection against malware at all.' `
                    -Fix 'Open Windows Security -> Virus & threat protection and enable protection.' `
                    -Confidence Certain
            }
        }

        if ($defenderNormalMode) {
            if (-not $mpStatus.RealTimeProtectionEnabled) {
                Add-Finding -Severity Critical -Title 'Defender real-time protection is turned off' `
                    -Evidence 'Get-MpComputerStatus -> RealTimeProtectionEnabled = False (AMRunningMode = Normal)' `
                    -Impact 'Files are not scanned when written or executed. This is the single most important protection on the machine.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Settings -> turn on Real-time protection.' `
                    -Confidence Certain
            } else {
                Add-Ok -Message 'Defender real-time protection is active.'
            }


            if (-not $mpStatus.BehaviorMonitorEnabled) {
                Add-Finding -Severity High -Title 'Defender behavior monitoring is turned off' `
                    -Evidence 'Get-MpComputerStatus -> BehaviorMonitorEnabled = False' `
                    -Impact 'Malware that has no signature but behaves maliciously is not stopped.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Settings -> turn on Real-time protection (enables behavior monitoring).' `
                    -Confidence Certain
            } else {
                Add-Ok -Message 'Defender behavior monitoring is active.'
            }
        }

        # Signature age: 0-1 day is normal, more than 3 days means the updates have stalled.
        $sigAge = $null
        if ($null -ne $mpStatus.AntivirusSignatureAge) { $sigAge = [int]$mpStatus.AntivirusSignatureAge }
        if ($null -ne $sigAge -and $sigAge -lt 10000) {
            $sigDate = ''
            if ($mpStatus.AntivirusSignatureLastUpdated) { $sigDate = ' (last updated {0})' -f ([datetime]$mpStatus.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd HH:mm') }
            if ($sigAge -gt 7) {
                Add-Finding -Severity High -Title 'Defender virus signatures are more than a week old' `
                    -Evidence ("AntivirusSignatureAge = {0} days{1}" -f $sigAge, $sigDate) `
                    -Impact 'Malware discovered in the last week is not recognized.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Protection updates -> Check for updates.' `
                    -Confidence Certain
            } elseif ($sigAge -gt 3) {
                Add-Finding -Severity Medium -Title 'Defender virus signatures are a few days old' `
                    -Evidence ("AntivirusSignatureAge = {0} days{1}" -f $sigAge, $sigDate) `
                    -Impact 'Signatures normally update several times a day - a backlog suggests updating has stopped.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Protection updates -> Check for updates.' `
                    -Confidence Certain
            } else {
                Add-Ok -Message ("Defender virus signatures are {0} days old{1}." -f $sigAge, $sigDate)
            }
        }

        if (-not $mpStatus.IsTamperProtected) {
            Add-Finding -Severity Medium -Title 'Tamper Protection is off' `
                -Evidence 'Get-MpComputerStatus -> IsTamperProtected = False' `
                -Impact 'Malware can turn off Defender settings directly through the registry with nothing to stop it.' `
                -Fix 'Windows Security -> Virus & threat protection -> Settings -> turn on Tamper Protection.' `
                -Confidence Certain
        } else {
            Add-Ok -Message 'Tamper Protection is on - Defender settings cannot be changed by malware.'
        }

        # Last scan: Defender runs maintenance scans on its own, so a long gap is
        # hygiene and not an acute risk.
        $lastScan = $null
        foreach ($scanTime in @($mpStatus.QuickScanEndTime, $mpStatus.FullScanEndTime)) {
            if ($scanTime -and (-not $lastScan -or [datetime]$scanTime -gt $lastScan)) { $lastScan = [datetime]$scanTime }
        }
        if ($null -eq $lastScan) {
            Add-Finding -Severity Low -Title 'Defender has no recorded completed scan' `
                -Evidence 'QuickScanEndTime and FullScanEndTime are both empty' `
                -Impact 'The machine has probably never been searched for malware that was already there.' `
                -Fix 'Windows Security -> Virus & threat protection -> Scan options -> Full scan.' `
                -Confidence Likely
        } else {
            $scanDays = [int]((Get-Date) - $lastScan).TotalDays
            if ($scanDays -gt 30) {
                Add-Finding -Severity Low -Title 'It is a long time since Defender completed a scan' `
                    -Evidence ("Last completed scan: {0} ({1} days ago)" -f $lastScan.ToString('yyyy-MM-dd HH:mm'), $scanDays) `
                    -Impact 'Real-time protection catches new files, but not necessarily anything that was on the disk before it was turned on.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Scan options -> Full scan.' `
                    -Confidence Certain
            } else {
                Add-Ok -Message ("Defender last completed a scan {0} ({1} days ago)." -f $lastScan.ToString('yyyy-MM-dd'), $scanDays)
            }
        }
    }

    # 3. Defender preferences and cloud protection

    if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
        } catch {
            Add-Skip -Message "Get-MpPreference failed - Defender settings and exclusions could not be read: $($_.Exception.Message)"
        }
    }

    if ($mpPref) {
        # RealTimeProtectionEnabled stays True while the individual scanning engines are
        # switched off one by one, so the real-time check above can report a green tick on
        # a machine where scripts, archives or downloaded files are not scanned at all.
        # These are what "debloat" and "performance tweak" scripts turn off, and this is
        # the state most easily mistaken for a protected machine. Only evaluated when
        # Defender is the active antivirus - in passive mode the engines are meant to be off.
        if ($defenderNormalMode) {
            $engineSwitches = @(
                @{ Name = 'DisableScriptScanning';         Means = 'scripts (JS, VBS, PowerShell) are not scanned' }
                @{ Name = 'DisableIOAVProtection';         Means = 'browser downloads and mail attachments are not scanned' }
                @{ Name = 'DisableArchiveScanning';        Means = 'archives (zip, rar, 7z) are not scanned' }
                @{ Name = 'DisableBlockAtFirstSeen';       Means = 'the cloud verdict on brand-new files is never requested' }
                @{ Name = 'DisableRemovableDriveScanning'; Means = 'USB sticks and external drives are not scanned' }
                @{ Name = 'DisableEmailScanning';          Means = 'mail files are not scanned' }
                @{ Name = 'DisableScanningNetworkFiles';   Means = 'files on network shares are not scanned' }
            )
            $enginesOff = @()
            foreach ($switch in $engineSwitches) {
                if ($true -eq $mpPref.($switch.Name)) { $enginesOff += "$($switch.Name) = True ($($switch.Means))" }
            }
            if ($enginesOff.Count -gt 0) {
                Add-Finding -Severity High -Title 'Parts of Defender are switched off even though real-time protection reads as on' `
                    -Evidence ("Get-MpPreference -> {0}" -f ($enginesOff -join '; ')) `
                    -Impact 'Windows Security shows green and real-time protection reports as enabled, but these scanning engines are not running. Anything arriving by the route they cover is never inspected.' `
                    -Fix ("Turn them back on in an elevated PowerShell, one per switch, for example: Set-MpPreference -{0} " -f (($enginesOff[0] -split ' ')[0]) + '$false') `
                    -Confidence Certain
            } else {
                Add-Ok -Message 'All Defender scanning engines are on (scripts, downloads, archives, removable drives, network files, mail, first-seen cloud blocking).'
            }
        }

        $mapsValue = [int]$mpPref.MAPSReporting
        if ($mapsValue -eq 0) {
            Add-Finding -Severity Medium -Title 'Defender cloud-delivered protection is turned off' `
                -Evidence 'Get-MpPreference -> MAPSReporting = 0 (Disabled)' `
                -Impact 'Defender loses lookups against the Microsoft cloud, which is what stops brand new threats before a signature exists.' `
                -Fix 'Windows Security -> Virus & threat protection -> Settings -> turn on Cloud-delivered protection.' `
                -Confidence Certain
        } else {
            Add-Ok -Message ("Cloud-delivered protection is on (MAPSReporting = {0})." -f $mapsValue)
        }

        if ([int]$mpPref.SubmitSamplesConsent -eq 2) {
            Add-Finding -Severity Low -Title 'Automatic sample submission to Microsoft is turned off' `
                -Evidence 'Get-MpPreference -> SubmitSamplesConsent = 2 (Never send)' `
                -Impact 'Suspicious files are not analyzed in the cloud, so cloud protection gives weaker answers on unknown files.' `
                -Fix 'Windows Security -> Virus & threat protection -> Settings -> Automatic sample submission.' `
                -Confidence Certain
        }

        $puaValue = [int]$mpPref.PUAProtection
        if ($puaValue -eq 0) {
            Add-Finding -Severity Low -Title 'Potentially unwanted app (PUA) protection is off' `
                -Evidence 'Get-MpPreference -> PUAProtection = 0' `
                -Impact 'Browser hijackers, fake "PC optimizers" and adware are not blocked.' `
                -Fix 'Windows Security -> App & browser control -> Reputation-based protection settings -> Potentially unwanted app blocking.' `
                -Confidence Certain
        } else {
            Add-Ok -Message ("PUA protection is active (PUAProtection = {0})." -f $puaValue)
        }

        $netProt = [int]$mpPref.EnableNetworkProtection
        if ($netProt -eq 0) {
            Add-Finding -Severity Medium -Title 'Network Protection is off' `
                -Evidence 'Get-MpPreference -> EnableNetworkProtection = 0' `
                -Impact 'Outbound connections to known phishing and malware domains are not blocked, whatever browser is used.' `
                -Fix "Turn it on in Windows Security, or with the command: Set-MpPreference -EnableNetworkProtection Enabled" `
                -Confidence Certain
        } elseif ($netProt -eq 2) {
            Add-Finding -Severity Low -Title 'Network Protection is in audit mode and blocks nothing' `
                -Evidence 'Get-MpPreference -> EnableNetworkProtection = 2 (AuditMode)' `
                -Impact 'Malicious domains are logged, but the connection is let through.' `
                -Fix "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Confidence Certain
        } else {
            Add-Ok -Message 'Network Protection blocks malicious domains.'
        }

        if ([int]$mpPref.EnableControlledFolderAccess -eq 0) {
            Add-Finding -Severity Low -Title 'Controlled folder access (ransomware protection) is off' `
                -Evidence 'Get-MpPreference -> EnableControlledFolderAccess = 0' `
                -Impact 'Unknown programs can write freely in Documents, Pictures and other user folders - which is exactly what ransomware does.' `
                -Fix 'Windows Security -> Virus & threat protection -> Ransomware protection -> Controlled folder access. Note that it may require you to allow your own programs.' `
                -Confidence Likely
        } else {
            Add-Ok -Message 'Controlled folder access is active against ransomware.'
        }

        # Defender exclusions. Without admin, Get-MpPreference returns the literal string
        # "N/A: Must be an administrator to view exclusions" in these fields, which would
        # otherwise be reported as a real exclusion.
        $exclusionsReadable = -not (
            "$($mpPref.ExclusionPath)$($mpPref.ExclusionProcess)$($mpPref.ExclusionExtension)" -match 'Must be an administrator'
        )

        $pathExclusions = @()
        $procExclusions = @()
        $extExclusions = @()
        if ($exclusionsReadable) {
            $pathExclusions = @($mpPref.ExclusionPath | Where-Object { $_ })
            $procExclusions = @($mpPref.ExclusionProcess | Where-Object { $_ })
            $extExclusions = @($mpPref.ExclusionExtension | Where-Object { $_ })
        } else {
            Add-Skip -Message 'Defender exclusions: Get-MpPreference only shows them to an administrator, so folders, processes and file types were not assessed.'
        }

        $riskyPaths = @()
        foreach ($exclusion in $pathExclusions) {
            if (& $isUserWritablePath -CandidatePath ([string]$exclusion)) { $riskyPaths += [string]$exclusion }
        }

        if ($riskyPaths.Count -gt 0) {
            Add-Finding -Severity High -Title 'Defender has exclusions for folders the user can write to' `
                -Evidence ("Excluded from scanning: {0}" -f ($riskyPaths -join '; ')) `
                -Impact 'Anything placed in these folders is never scanned. Malware only needs to copy itself there to become invisible to Defender.' `
                -Fix 'Review the list in Windows Security -> Virus & threat protection -> Settings -> Exclusions, and remove the ones you do not recognize.' `
                -Confidence Certain
        }

        $otherPaths = @($pathExclusions | Where-Object { $riskyPaths -notcontains [string]$_ })
        if ($otherPaths.Count -gt 0) {
            Add-Finding -Severity Low -Title 'Defender has folder exclusions outside user-writable areas' `
                -Evidence ("Excluded from scanning: {0}" -f ($otherPaths -join '; ')) `
                -Impact 'These exclusions require administrator rights to write to, but they are still blind spots in scanning.' `
                -Fix 'Check that each exclusion is still needed: Windows Security -> Virus & threat protection -> Settings -> Exclusions.' `
                -Confidence Likely
        }

        if ($procExclusions.Count -gt 0) {
            Add-Finding -Severity Medium -Title 'Defender has process exclusions' `
                -Evidence ("Process exclusions: {0}" -f ($procExclusions -join '; ')) `
                -Impact 'Anything these processes open or write is not scanned - a process exclusion is often broader than people think.' `
                -Fix 'Windows Security -> Virus & threat protection -> Settings -> Exclusions -> remove processes that are no longer needed.' `
                -Confidence Certain
        }

        if ($extExclusions.Count -gt 0) {
            $dangerousExt = @($extExclusions | Where-Object { ([string]$_).TrimStart('.').ToLowerInvariant() -in @('exe', 'dll', 'ps1', 'bat', 'cmd', 'scr', 'js', 'vbs', 'msi', 'hta', 'sys') })
            if ($dangerousExt.Count -gt 0) {
                Add-Finding -Severity High -Title 'Defender has exclusions for executable file types' `
                    -Evidence ("File types excluded from scanning: {0}" -f ($dangerousExt -join ', ')) `
                    -Impact 'Malware with that extension is not scanned no matter where on the disk it sits.' `
                    -Fix 'Remove the file type exclusions in Windows Security -> Virus & threat protection -> Settings -> Exclusions.' `
                    -Confidence Certain
            } else {
                Add-Finding -Severity Low -Title 'Defender has exclusions for some file types' `
                    -Evidence ("File types excluded from scanning: {0}" -f ($extExclusions -join ', ')) `
                    -Impact 'Files with these extensions are not scanned, wherever they sit.' `
                    -Fix 'Windows Security -> Virus & threat protection -> Settings -> Exclusions.' `
                    -Confidence Likely
            }
        }

        if ($exclusionsReadable -and $pathExclusions.Count -eq 0 -and $procExclusions.Count -eq 0 -and $extExclusions.Count -eq 0) {
            Add-Ok -Message 'Defender has no exclusions for folders, processes or file types - the whole disk is scanned.'
        }

        # ASR rules

        $asrNames = @{
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email and webmail'
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office from creating child processes'
        }

        $asrIds = @($mpPref.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
        $asrActions = @($mpPref.AttackSurfaceReductionRules_Actions)
        $asrState = @{}
        for ($i = 0; $i -lt $asrIds.Count; $i++) {
            $action = 0
            if ($i -lt $asrActions.Count -and $null -ne $asrActions[$i]) { $action = [int]$asrActions[$i] }
            $asrState[([string]$asrIds[$i]).ToLowerInvariant()] = $action
        }

        $blockedCount = @($asrState.Values | Where-Object { $_ -eq 1 }).Count
        $auditCount = @($asrState.Values | Where-Object { $_ -eq 2 -or $_ -eq 6 }).Count

        $missingKeyRules = @()
        foreach ($ruleId in $asrNames.Keys) {
            if (-not $asrState.ContainsKey($ruleId) -or $asrState[$ruleId] -ne 1) { $missingKeyRules += $asrNames[$ruleId] }
        }

        if ($asrIds.Count -eq 0) {
            Add-Finding -Severity Medium -Title 'No ASR (Attack Surface Reduction) rules are configured' `
                -Evidence 'Get-MpPreference -> AttackSurfaceReductionRules_Ids is empty' `
                -Impact 'The most common attack paths - Office macros starting processes, scripts running downloaded files, password theft from LSASS - are not blocked.' `
                -Fix "Enable the most important rules, for example: Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled" `
                -Confidence Likely
        } elseif ($missingKeyRules.Count -gt 0) {
            Add-Finding -Severity Medium -Title 'Key ASR rules are not in block mode' `
                -Evidence ("{0} of {1} configured rules block, {2} are in audit/warn. Not blocking: {3}" -f $blockedCount, $asrIds.Count, $auditCount, ($missingKeyRules -join '; ')) `
                -Impact 'The rules that are missing cover the most used attack paths against an ordinary PC.' `
                -Fix "Set them to Enabled with Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Enabled" `
                -Confidence Likely
        } else {
            Add-Ok -Message ("ASR: {0} of {1} rules block, including all the most valuable ones (LSASS, vulnerable drivers, email attachments, Office child processes)." -f $blockedCount, $asrIds.Count)
        }
    }

    # 4. VBS, HVCI and Credential Guard

    $deviceGuard = $null
    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    } catch {
        Add-Skip -Message "Win32_DeviceGuard does not exist on this machine - skipping VBS/HVCI/Credential Guard: $($_.Exception.Message)"
    }

    if ($deviceGuard) {
        $vbsStatus = [int]$deviceGuard.VirtualizationBasedSecurityStatus
        $running = @()
        foreach ($service in @($deviceGuard.SecurityServicesRunning)) { $running += [int]$service }
        $available = @()
        foreach ($property in @($deviceGuard.AvailableSecurityProperties)) { $available += [int]$property }

        if ($vbsStatus -ne 2) {
            if ($ctx.IsVM) {
                Add-Skip -Message 'Virtualization-based security (VBS) is not running - expected in a virtual machine without nested virtualization.'
            } elseif ($available -contains 1) {
                Add-Finding -Severity Medium -Title 'Virtualization-based security (VBS) is off even though the hardware supports it' `
                    -Evidence ("VirtualizationBasedSecurityStatus = {0} (0=off, 1=configured but not running, 2=running). AvailableSecurityProperties includes hypervisor support." -f $vbsStatus) `
                    -Impact 'Without VBS the foundation for Memory integrity (HVCI) and Credential Guard is missing - kernel drivers and passwords in memory are less protected.' `
                    -Fix 'Windows Security -> Device security -> Core isolation -> Memory integrity. Requires virtualization (SVM/VT-x) to be on in UEFI.' `
                    -Confidence Likely
            } else {
                Add-Skip -Message ("VBS is not running and the hardware does not report hypervisor support (VirtualizationBasedSecurityStatus = {0})." -f $vbsStatus)
            }
        } else {
            if ($running -contains 2) {
                Add-Ok -Message 'Memory integrity (HVCI) is running and verifies kernel drivers in the hypervisor.'
            } else {
                Add-Finding -Severity Medium -Title 'Memory integrity (HVCI) is not running even though VBS is' `
                    -Evidence ("VBS status = 2 (running), but SecurityServicesRunning = [{0}] does not contain 2 (HVCI)" -f ($running -join ', ')) `
                    -Impact 'Vulnerable or signed-but-malicious kernel drivers can be loaded and give an attacker full control of the machine.' `
                    -Fix 'Windows Security -> Device security -> Core isolation -> turn on Memory integrity. Blocked by old, incompatible drivers.' `
                    -Confidence Likely
            }

            if ($running -contains 1) {
                Add-Ok -Message 'Credential Guard is running and isolates credentials from the LSASS process.'
            } elseif ($ctx.DomainJoined) {
                Add-Finding -Severity Medium -Title 'Credential Guard is not running on a domain-joined machine' `
                    -Evidence ("SecurityServicesRunning = [{0}] does not contain 1 (Credential Guard)" -f ($running -join ', ')) `
                    -Impact 'Domain credentials and NTLM hashes sit available in LSASS and can be pulled out on a local compromise.' `
                    -Fix 'Enable it through Group Policy: Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn On Virtualization Based Security.' `
                    -Confidence Likely
            } else {
                Add-Finding -Severity Info -Title 'Credential Guard is not enabled' `
                    -Evidence ("SecurityServicesRunning = [{0}]" -f ($running -join ', ')) `
                    -Impact 'Credential Guard is primarily relevant for domain-joined and Entra-joined machines, and is off by default outside the Enterprise editions.' `
                    -Confidence Certain
            }
        }
    }

    # 5. Secure Boot and TPM

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($secureBoot) {
            Add-Ok -Message 'Secure Boot is enabled in firmware.'
        } else {
            Add-Finding -Severity Medium -Title 'Secure Boot is turned off' `
                -Evidence 'Confirm-SecureBootUEFI returned False' `
                -Impact 'Unsigned boot code and bootkits can load before Windows starts, that is before antivirus runs at all.' `
                -Fix 'Turn on Secure Boot in the UEFI setup. Requires the disk to use GPT/UEFI boot.' `
                -Confidence Certain
        }
    } catch {
        Add-Skip -Message "Secure Boot status could not be read (typically older BIOS/CSM boot or missing rights): $($_.Exception.Message)"
    }

    $tpmPresent = $null
    $tpmUsable = $null    # present is not the same as usable - see the finding below
    $tpmEvidence = ''
    if (Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            # Without admin, Get-Tpm returns an object with empty fields instead of failing.
            # [bool]$null becomes $false, which would otherwise be read as "no TPM".
            $tpm = Get-Tpm -ErrorAction Stop
            if ($null -ne $tpm.TpmPresent) {
                $tpmPresent = [bool]$tpm.TpmPresent
                $tpmEvidence = 'Get-Tpm -> TpmPresent = {0}, TpmReady = {1}, TpmEnabled = {2}' -f $tpm.TpmPresent, $tpm.TpmReady, $tpm.TpmEnabled
                # TpmReady is the field that decides whether Windows can actually use it.
                # Only judge it when the value came back - unelevated it is empty, and
                # treating empty as "not ready" would invent a finding.
                if ($null -ne $tpm.TpmReady) { $tpmUsable = [bool]$tpm.TpmReady }
                elseif ($null -ne $tpm.TpmEnabled) { $tpmUsable = [bool]$tpm.TpmEnabled }
            }
        } catch {
            Write-Verbose -Message "Get-Tpm failed, trying WMI: $($_.Exception.Message)"
        }
    }
    if ($null -eq $tpmPresent) {
        try {
            $tpmWmi = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
            if ($tpmWmi) {
                $tpmPresent = $true
                $tpmEvidence = 'Win32_Tpm -> IsEnabled = {0}, IsActivated = {1}, SpecVersion = {2}' -f $tpmWmi.IsEnabled_InitialValue, $tpmWmi.IsActivated_InitialValue, $tpmWmi.SpecVersion
                if ($null -ne $tpmWmi.IsEnabled_InitialValue -and $null -ne $tpmWmi.IsActivated_InitialValue) {
                    $tpmUsable = ([bool]$tpmWmi.IsEnabled_InitialValue -and [bool]$tpmWmi.IsActivated_InitialValue)
                }
            }
        } catch {
            Write-Verbose -Message "Win32_Tpm unavailable: $($_.Exception.Message)"
        }
    }

    if ($null -eq $tpmPresent) {
        Add-Skip -Message 'TPM status could not be read (usually requires administrator rights, and a TPM is often missing in virtual machines).'
    } elseif ($tpmPresent -and $false -eq $tpmUsable) {
        # A chip that is present but not ready is the common failure, not a missing one.
        # A firmware update that resets the fTPM leaves exactly this state, and the machine
        # then asks for a BitLocker recovery key and refuses the Hello PIN - while a check
        # that only looks at TpmPresent happily reports the TPM as available.
        Add-Finding -Severity High -Title 'A TPM is present, but Windows cannot use it' `
            -Evidence $tpmEvidence `
            -Impact 'Anything with a hardware root stops working: BitLocker cannot unlock automatically and falls back to the recovery key, the Windows Hello PIN is rejected, and Credential Guard loses its anchor. The usual cause is a UEFI or fTPM firmware update that reset the chip, or fTPM/PTT switched off in the UEFI setup.' `
            -Fix 'Open tpm.msc to see the state. If it says the TPM is not ready, check that fTPM (AMD) or PTT (Intel) is enabled in the UEFI setup. Save your BitLocker recovery key BEFORE clearing a TPM - clearing it makes every key sealed to that chip unrecoverable.' `
            -Confidence Likely
    } elseif ($tpmPresent) {
        Add-Ok -Message ("A TPM is present and available. {0}" -f $tpmEvidence)
    } elseif ($ctx.IsVM) {
        Add-Skip -Message 'No TPM found - expected in a virtual machine without a virtual TPM.'
    } else {
        Add-Finding -Severity Medium -Title 'No TPM is available' `
            -Evidence $tpmEvidence `
            -Impact 'Without a TPM, BitLocker cannot unlock automatically, Windows Hello cannot store keys securely, and Credential Guard gets no hardware root.' `
            -Fix 'Check that fTPM/PTT is enabled in the UEFI setup.' `
            -Confidence Likely
    }

    # 6. Disk encryption

    $encryptedVolumes = @()
    $volumeSource = ''
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $encryptedVolumes = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        Mount     = [string]$_.MountPoint
                        Protected = ([string]$_.ProtectionStatus -eq 'On')
                        State     = [string]$_.VolumeStatus
                    }
                })
            $volumeSource = 'Get-BitLockerVolume'
        } catch {
            Write-Verbose -Message "Get-BitLockerVolume failed: $($_.Exception.Message)"
        }
    }
    if ($encryptedVolumes.Count -eq 0) {
        try {
            $conversionNames = @{ 0 = 'Not encrypted'; 1 = 'Fully encrypted'; 2 = 'Encryption in progress'; 3 = 'Decryption in progress'; 4 = 'Encryption paused'; 5 = 'Decryption paused' }
            $encryptedVolumes = @(Get-CimInstance -Namespace 'root\cimv2\security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop | ForEach-Object {
                    $conversion = [int]$_.ConversionStatus
                    $stateText = 'Unknown'
                    if ($conversionNames.ContainsKey($conversion)) { $stateText = $conversionNames[$conversion] }
                    [pscustomobject]@{
                        Mount     = [string]$_.DriveLetter
                        Protected = ([int]$_.ProtectionStatus -eq 1)
                        State     = $stateText
                    }
                })
            $volumeSource = 'Win32_EncryptableVolume'
        } catch {
            Write-Verbose -Message "Win32_EncryptableVolume unavailable: $($_.Exception.Message)"
        }
    }

    if ($encryptedVolumes.Count -eq 0) {
        if (-not $ctx.IsAdmin) {
            Add-Skip -Message 'Encryption status requires administrator rights - run the tool as administrator to include BitLocker.'
        } else {
            Add-Skip -Message 'Found no encryptable volumes to report (the BitLocker module and Win32_EncryptableVolume are both unavailable, typical on Home editions without device encryption).'
        }
    } else {
        $systemDriveLetter = [string]$ctx.SystemDrive
        $systemVolume = $encryptedVolumes | Where-Object { $_.Mount -and $systemDriveLetter -and $_.Mount.TrimEnd('\') -eq $systemDriveLetter.TrimEnd('\') } | Select-Object -First 1
        if (-not $systemVolume) { $systemVolume = $encryptedVolumes | Select-Object -First 1 }

        if ($systemVolume -and -not $systemVolume.Protected) {
            $severity = 'Medium'
            $impactText = 'Everything on the system disk can be read by pulling the disk out or booting the machine from a USB stick.'
            if ($ctx.IsLaptop) {
                $severity = 'High'
                $impactText = 'This is a laptop. If it is lost or stolen, all the content can be read by moving the disk to another PC.'
            }
            Add-Finding -Severity $severity -Title 'The system disk is not encrypted' `
                -Evidence ("System volume {0}: protection off, status '{1}' (source: {2})" -f $systemVolume.Mount, $systemVolume.State, $volumeSource) `
                -Impact $impactText `
                -Fix 'Settings -> Privacy & security -> Device encryption, or Control Panel -> BitLocker Drive Encryption. Remember to keep the recovery key.' `
                -Confidence Certain
        } elseif ($systemVolume) {
            Add-Ok -Message ("The system disk {0} is encrypted and protected ({1})." -f $systemVolume.Mount, $systemVolume.State)
        }

        $unprotectedData = @($encryptedVolumes | Where-Object { -not $_.Protected -and $systemVolume -and $_.Mount -ne $systemVolume.Mount })
        if ($unprotectedData.Count -gt 0) {
            Add-Finding -Severity Low -Title 'Data volumes without encryption' `
                -Evidence ("Unencrypted volumes: {0}" -f (($unprotectedData | ForEach-Object { $_.Mount }) -join ', ')) `
                -Impact 'Data on these volumes can be read directly if the disk goes astray.' `
                -Fix 'Control Panel -> BitLocker Drive Encryption -> Turn on BitLocker for the volume in question.' `
                -Confidence Certain
        }
    }

    # 7. LSA protection and credentials

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $runAsPpl = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
    if ($null -ne $runAsPpl -and [int]$runAsPpl -ge 1) {
        Add-Ok -Message ("LSA protection (RunAsPPL = {0}) stops other processes from reading LSASS memory." -f $runAsPpl)
    } else {
        Add-Finding -Severity Low -Title 'LSA protection (RunAsPPL) is not set' `
            -Evidence ("{0}\RunAsPPL = {1}" -f $lsaPath, $(if ($null -eq $runAsPpl) { 'missing' } else { $runAsPpl })) `
            -Impact 'Without PPL protection, a program with administrator rights can read passwords and tokens straight out of the LSASS process.' `
            -Fix 'Windows Security -> Device security -> Core isolation -> Local Security Authority protection (requires a restart).' `
            -Confidence Likely
    }

    $wdigest = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    if ($null -ne $wdigest -and [int]$wdigest -eq 1) {
        Add-Finding -Severity High -Title 'WDigest stores passwords in clear text in memory' `
            -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1' `
            -Impact 'Your password sits readable in LSASS memory. This is a classic setting attackers set themselves in order to harvest passwords.' `
            -Fix 'Remove the UseLogonCredential value (or set it to 0) and restart the machine. Find out why it was set.' `
            -Confidence Certain
    } else {
        Add-Ok -Message 'WDigest does not store passwords in clear text (UseLogonCredential is not enabled).'
    }

    # 8. UAC

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enableLua = Get-RegValue -Path $policyPath -Name 'EnableLUA'
    $consentAdmin = Get-RegValue -Path $policyPath -Name 'ConsentPromptBehaviorAdmin'
    $secureDesktop = Get-RegValue -Path $policyPath -Name 'PromptOnSecureDesktop'
    $tokenFilter = Get-RegValue -Path $policyPath -Name 'LocalAccountTokenFilterPolicy'

    if ($null -ne $enableLua -and [int]$enableLua -eq 0) {
        Add-Finding -Severity Critical -Title 'User Account Control (UAC) is turned off completely' `
            -Evidence ("{0}\EnableLUA = 0" -f $policyPath) `
            -Impact 'Everything you start runs with full administrator rights without asking. One wrong click is enough to compromise the machine, and many Windows protections stop working.' `
            -Fix 'Control Panel -> User Accounts -> Change User Account Control settings -> move the slider up from the bottom. Requires a restart.' `
            -Confidence Certain
    } else {
        Add-Ok -Message 'User Account Control (UAC) is enabled.'

        if ($null -ne $consentAdmin -and [int]$consentAdmin -eq 0) {
            Add-Finding -Severity High -Title 'UAC elevates without prompting' `
                -Evidence ("{0}\ConsentPromptBehaviorAdmin = 0 (elevate without prompting)" -f $policyPath) `
                -Impact 'Programs get administrator rights without you seeing a single dialog - UAC is technically on, but stops nothing.' `
                -Fix 'Control Panel -> User Accounts -> Change User Account Control settings -> choose at least "Notify me only when apps try to make changes to my computer".' `
                -Confidence Certain
        }

        if ($null -ne $secureDesktop -and [int]$secureDesktop -eq 0) {
            Add-Finding -Severity Medium -Title 'The UAC prompt is not shown on the secure desktop' `
                -Evidence ("{0}\PromptOnSecureDesktop = 0" -f $policyPath) `
                -Impact 'An ordinary program can draw a fake UAC dialog over the real one and trick you into approving something other than what you think.' `
                -Fix 'Put the UAC slider back to the default level in Control Panel -> User Accounts.' `
                -Confidence Certain
        }
    }

    if ($null -ne $tokenFilter -and [int]$tokenFilter -eq 1) {
        Add-Finding -Severity Medium -Title 'UAC filtering for network logons is turned off' `
            -Evidence ("{0}\LocalAccountTokenFilterPolicy = 1" -f $policyPath) `
            -Impact 'Local administrator accounts get a full privilege token over the network. This is exactly what makes "pass-the-hash" between PCs possible.' `
            -Fix 'Remove the LocalAccountTokenFilterPolicy value if it was not set deliberately for remote administration.' `
            -Confidence Likely
    }

    # 9. Local accounts

    $localAccounts = @()
    try {
        $localAccounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    } catch {
        Add-Skip -Message "Could not read local user accounts from Win32_UserAccount: $($_.Exception.Message)"
    }

    if ($localAccounts.Count -gt 0) {
        $enabledAccounts = @($localAccounts | Where-Object { -not $_.Disabled })

        $noPassword = @($enabledAccounts | Where-Object { $_.PasswordRequired -eq $false })
        if ($noPassword.Count -gt 0) {
            Add-Finding -Severity High -Title 'Enabled local accounts do not require a password' `
                -Evidence ("Accounts with PasswordRequired = False: {0}" -f (($noPassword | ForEach-Object { $_.Name }) -join ', ')) `
                -Impact 'The account can be used without a password. If it also has administrator rights, the whole machine is open to anyone with physical access.' `
                -Fix 'Settings -> Accounts -> Sign-in options -> set a password, or disable the account if it is not in use.' `
                -Confidence Likely
        } else {
            Add-Ok -Message ("All {0} enabled local accounts require a password." -f $enabledAccounts.Count)
        }

        $builtinAdmin = $localAccounts | Where-Object { ([string]$_.SID) -like '*-500' } | Select-Object -First 1
        if ($builtinAdmin -and -not $builtinAdmin.Disabled) {
            Add-Finding -Severity Medium -Title 'The built-in Administrator account is enabled' `
                -Evidence ("Account '{0}' (SID {1}) is enabled" -f $builtinAdmin.Name, $builtinAdmin.SID) `
                -Impact 'The account is exempt from UAC filtering, has a well-known SID and is often used to regain access after a break-in.' `
                -Fix 'Use your normal account day to day and disable the built-in one: Computer Management -> Local Users and Groups -> Users -> Administrator -> Account is disabled.' `
                -Confidence Certain
        } elseif ($builtinAdmin) {
            Add-Ok -Message 'The built-in Administrator account is disabled.'
        }

        $guestAccount = $localAccounts | Where-Object { ([string]$_.SID) -like '*-501' } | Select-Object -First 1
        if ($guestAccount -and -not $guestAccount.Disabled) {
            Add-Finding -Severity High -Title 'The Guest account is enabled' `
                -Evidence ("Account '{0}' (SID {1}) is enabled" -f $guestAccount.Name, $guestAccount.SID) `
                -Impact 'The Guest account allows sign-in without a password and is used for anonymous access to shared folders.' `
                -Fix 'Computer Management -> Local Users and Groups -> Users -> Guest -> tick "Account is disabled".' `
                -Confidence Certain
        } elseif ($guestAccount) {
            Add-Ok -Message 'The Guest account is disabled.'
        }
    }

    # The Administrators group: the name is localized, so we look it up from the fixed SID.
    $adminMembers = @()
    try {
        $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
    } catch {
        Write-Verbose -Message "Get-LocalGroupMember failed, trying ADSI: $($_.Exception.Message)"
        try {
            $adminSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
            $adminGroupName = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
            $shortName = $adminGroupName.Split('\')[-1]
            $adsiGroup = [ADSI]("WinNT://./$shortName,group")
            foreach ($member in @($adsiGroup.PSBase.Invoke('Members'))) {
                $adminMembers += [string]$member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
            }
        } catch {
            Add-Skip -Message "The members of the local Administrators group could not be listed: $($_.Exception.Message)"
        }
    }

    if ($adminMembers.Count -gt 0) {
        Add-Finding -Severity Info -Title 'Members of the local Administrators group' `
            -Evidence ("{0} member(s): {1}" -f $adminMembers.Count, ($adminMembers -join ', ')) `
            -Impact 'All of these can install software and change system settings. If you do not recognize an entry, it should be looked into.' `
            -Confidence Certain
    }

    # Account lockout slows down password guessing. 'net accounts' is localized, so we read
    # the values by position (the order is the same in every language) and not by label.
    try {
        $netAccountLines = @(& "$env:SystemRoot\System32\net.exe" accounts 2>$null | Where-Object { $_ -match ':' })
        if ($netAccountLines.Count -ge 6) {
            $lockoutRaw = ($netAccountLines[5] -replace '^[^:]*:\s*', '').Trim()
            if ($lockoutRaw -match '^\d+$' -and [int]$lockoutRaw -gt 0) {
                Add-Ok -Message ("Account lockout is active: the account locks after {0} failed sign-in attempts." -f $lockoutRaw)
            } elseif ($ctx.DomainJoined) {
                Add-Skip -Message 'The account lockout policy is set by the domain on this machine - the local value is not decisive.'
            } else {
                Add-Finding -Severity Medium -Title 'No account lockout on wrong passwords' `
                    -Evidence ("net accounts -> lockout threshold = '{0}'" -f $lockoutRaw) `
                    -Impact 'A program can try passwords forever, locally or over the network, without the account locking.' `
                    -Fix 'Local Security Policy (secpol.msc) -> Account Policies -> Account Lockout Policy -> set the threshold to for example 10.' `
                    -Confidence Likely
            }
        } else {
            Add-Skip -Message 'The account lockout policy could not be parsed from the net accounts output.'
        }
    } catch {
        Add-Skip -Message "Could not read the account policy with net accounts: $($_.Exception.Message)"
    }

    # 10. Remote access

    $rdpDenied = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($null -ne $rdpDenied -and [int]$rdpDenied -eq 0) {
        $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
        if ($null -ne $nla -and [int]$nla -eq 0) {
            Add-Finding -Severity High -Title 'RDP is enabled without requiring Network Level Authentication (NLA)' `
                -Evidence 'fDenyTSConnections = 0 and RDP-Tcp\UserAuthentication = 0' `
                -Impact 'Anyone who reaches port 3389 gets the sign-in screen before presenting valid credentials. That opens up both password guessing and pre-authentication vulnerabilities.' `
                -Fix 'Settings -> System -> Remote Desktop -> turn on "Require computers to use Network Level Authentication to connect".' `
                -Confidence Certain
        } else {
            Add-Finding -Severity Low -Title 'Remote Desktop (RDP) is enabled' `
                -Evidence 'fDenyTSConnections = 0, UserAuthentication (NLA) = 1' `
                -Impact 'NLA is on, so the setup is sound, but RDP is still a listening service and should be off if you do not use it.' `
                -Fix 'Settings -> System -> Remote Desktop -> turn it off if you do not need it.' `
                -Confidence Certain
        }
    } else {
        Add-Ok -Message 'Remote Desktop (RDP) is turned off.'
    }

    $remoteRegistry = Get-ServiceState -Name 'RemoteRegistry'
    if ($remoteRegistry -and [string]$remoteRegistry.Status -eq 'Running') {
        Add-Finding -Severity Medium -Title 'The Remote Registry service (RemoteRegistry) is running' `
            -Evidence ("RemoteRegistry: Status = {0}, StartType = {1}" -f $remoteRegistry.Status, $remoteRegistry.StartType) `
            -Impact 'The registry can be read and changed over the network. The service is heavily used for reconnaissance during attacks and is almost never needed on a client machine.' `
            -Fix 'Services (services.msc) -> Remote Registry -> stop the service and set the startup type to Disabled.' `
            -Confidence Certain
    } else {
        Add-Ok -Message 'Remote Registry (RemoteRegistry) is not running.'
    }

    $winrm = Get-ServiceState -Name 'WinRM'
    if ($winrm -and [string]$winrm.Status -eq 'Running') {
        $allowUnencrypted = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic'
        $allowBasic = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic'
        if (($null -ne $allowUnencrypted -and [int]$allowUnencrypted -eq 1) -or ($null -ne $allowBasic -and [int]$allowBasic -eq 1)) {
            Add-Finding -Severity High -Title 'WinRM allows unencrypted traffic or Basic authentication' `
                -Evidence ("WinRM is running. AllowUnencryptedTraffic = {0}, AllowBasic = {1}" -f $allowUnencrypted, $allowBasic) `
                -Impact 'Usernames and passwords can be picked straight out of the network traffic during remote administration.' `
                -Fix 'Group Policy -> Windows Components -> Windows Remote Management -> WinRM Service -> disable "Allow unencrypted traffic" and "Allow Basic authentication".' `
                -Confidence Certain
        } else {
            Add-Finding -Severity Low -Title 'WinRM (remote administration over PowerShell) is running' `
                -Evidence ("WinRM: Status = {0}, StartType = {1}" -f $winrm.Status, $winrm.StartType) `
                -Impact 'The service listens for remote commands. The configuration looks sound, but the surface should be off if you do not manage the machine remotely.' `
                -Fix 'Run Get-Service WinRM to see the status, and disable the service if you do not use PowerShell remoting.' `
                -Confidence Certain
        }
    } else {
        Add-Ok -Message 'WinRM (PowerShell remoting) is not running.'
    }

    $sshd = Get-ServiceState -Name 'sshd'
    if ($sshd -and [string]$sshd.Status -eq 'Running') {
        Add-Finding -Severity Low -Title 'The OpenSSH server (sshd) is running' `
            -Evidence ("sshd: Status = {0}, StartType = {1}" -f $sshd.Status, $sshd.StartType) `
            -Impact 'The machine accepts SSH logins. If password authentication is allowed, it will be guessed at from the internet as soon as the port is open externally.' `
            -Fix 'Check C:\ProgramData\ssh\sshd_config for PasswordAuthentication, or stop the service if you do not use SSH.' `
            -Confidence Certain
    }

    $spooler = Get-ServiceState -Name 'Spooler'
    $pointAndPrintPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $noWarnElevate = Get-RegValue -Path $pointAndPrintPath -Name 'NoWarningNoElevationOnInstall'
    $restrictDrivers = Get-RegValue -Path $pointAndPrintPath -Name 'RestrictDriverInstallationToAdministrators'
    if ($spooler -and [string]$spooler.Status -eq 'Running') {
        if (($null -ne $noWarnElevate -and [int]$noWarnElevate -eq 1) -or ($null -ne $restrictDrivers -and [int]$restrictDrivers -eq 0)) {
            Add-Finding -Severity High -Title 'The print spooler allows driver installation without administrator rights' `
                -Evidence ("Spooler is running. NoWarningNoElevationOnInstall = {0}, RestrictDriverInstallationToAdministrators = {1}" -f $noWarnElevate, $restrictDrivers) `
                -Impact 'This is exactly the setup PrintNightmare exploits: an ordinary user can get code running as SYSTEM by "installing a printer".' `
                -Fix 'Remove NoWarningNoElevationOnInstall and set RestrictDriverInstallationToAdministrators to 1 under HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint.' `
                -Confidence Certain
        } else {
            Add-Ok -Message 'The print spooler is running, but driver installation is still restricted to administrators.'
        }
    } else {
        Add-Ok -Message 'The print spooler (Spooler) is not running - the PrintNightmare surface is gone.'
    }

    # 11. The PowerShell 2.0 engine

    # Why: DISM (Get-WindowsOptionalFeature) is slow and fails on machines with a damaged
    # component store, so we read the engine's own registry key instead.
    $ps2Install = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1' -Name 'Install'
    $ps2EngineVersion = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellVersion'
    if ($null -ne $ps2Install -and [int]$ps2Install -eq 1 -and $null -ne $ps2EngineVersion) {
        Add-Finding -Severity Medium -Title 'The PowerShell 2.0 engine is still installed' `
            -Evidence ("HKLM:\SOFTWARE\Microsoft\PowerShell\1 -> Install = 1, PowerShellEngine\PowerShellVersion = {0}" -f $ps2EngineVersion) `
            -Impact 'An attack can start "powershell -version 2" and thereby bypass script block logging, AMSI and transcription, which only exist in newer versions.' `
            -Fix 'Turn off the "Windows PowerShell 2.0" feature in Control Panel -> Programs -> Turn Windows features on or off.' `
            -Confidence Likely
    } else {
        Add-Ok -Message 'The PowerShell 2.0 engine is not installed - downgrade attacks against script logging are not possible.'
    }

    # 12. SMB signing and NTLM level

    $lmLevel = Get-RegValue -Path $lsaPath -Name 'LmCompatibilityLevel'
    if ($null -eq $lmLevel) {
        Add-Ok -Message 'The NTLM level is at the Windows default (LmCompatibilityLevel is not overridden) - only NTLMv2 is sent.'
    } elseif ([int]$lmLevel -lt 3) {
        Add-Finding -Severity High -Title 'The NTLM level allows the old, weak LM/NTLMv1 protocols' `
            -Evidence ("{0}\LmCompatibilityLevel = {1} (3 or higher is required for NTLMv2 only)" -f $lsaPath, $lmLevel) `
            -Impact 'LM and NTLMv1 responses can be cracked back to the password in minutes, and make relay attacks against the machine far easier.' `
            -Fix 'Local Security Policy (secpol.msc) -> Security Options -> "Network security: LAN Manager authentication level" -> "Send NTLMv2 response only".' `
            -Confidence Certain
    } else {
        Add-Ok -Message ("The NTLM level is set to {0} - only NTLMv2 is sent." -f $lmLevel)
    }

    $smbServerSigning = $null
    $smbClientSigning = $null
    $smb1Enabled = $null
    try {
        $smbServerConfig = Get-SmbServerConfiguration -ErrorAction Stop
        $smbServerSigning = [bool]$smbServerConfig.RequireSecuritySignature
        $smb1Enabled = [bool]$smbServerConfig.EnableSMB1Protocol
    } catch {
        Write-Verbose -Message "Get-SmbServerConfiguration unavailable, falling back to the registry: $($_.Exception.Message)"
        $regServerSigning = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature'
        if ($null -ne $regServerSigning) { $smbServerSigning = ([int]$regServerSigning -eq 1) }
    }
    try {
        $smbClientConfig = Get-SmbClientConfiguration -ErrorAction Stop
        $smbClientSigning = [bool]$smbClientConfig.RequireSecuritySignature
    } catch {
        Write-Verbose -Message "Get-SmbClientConfiguration unavailable: $($_.Exception.Message)"
    }

    if ($null -eq $smbServerSigning -and $null -eq $smbClientSigning) {
        Add-Skip -Message 'The SMB configuration could not be read (the SmbShare module is missing) - skipping SMB signing.'
    } else {
        if ($smbServerSigning -eq $false) {
            Add-Finding -Severity Medium -Title 'The SMB server does not require signing' `
                -Evidence 'Get-SmbServerConfiguration -> RequireSecuritySignature = False' `
                -Impact 'An attacker on the same network can sit in the middle and relay the SMB session (NTLM relay) against the machine.' `
                -Fix "Set-SmbServerConfiguration -RequireSecuritySignature `$true (run as administrator)" `
                -Confidence Likely
        } elseif ($smbServerSigning -eq $true) {
            Add-Ok -Message 'The SMB server requires signing - NTLM relay against the machine is blocked.'
        }

        if ($smbClientSigning -eq $false) {
            Add-Finding -Severity Low -Title 'The SMB client does not require signing' `
                -Evidence 'Get-SmbClientConfiguration -> RequireSecuritySignature = False' `
                -Impact 'The machine can be tricked into connecting to a fake file server that relays your sign-in somewhere else.' `
                -Fix "Set-SmbClientConfiguration -RequireSecuritySignature `$true (run as administrator)" `
                -Confidence Likely
        } elseif ($smbClientSigning -eq $true) {
            Add-Ok -Message 'The SMB client requires signing.'
        }

        if ($smb1Enabled -eq $true) {
            Add-Finding -Severity High -Title 'SMBv1 is still enabled on the server side' `
                -Evidence 'Get-SmbServerConfiguration -> EnableSMB1Protocol = True' `
                -Impact 'SMBv1 is the protocol WannaCry and NotPetya spread over, and it has no modern protection against tampering.' `
                -Fix 'Control Panel -> Turn Windows features on or off -> remove "SMB 1.0/CIFS File Sharing Support".' `
                -Confidence Certain
        } elseif ($smb1Enabled -eq $false) {
            Add-Ok -Message 'SMBv1 is disabled.'
        }
    }

    $insecureGuest = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth'
    if ($null -ne $insecureGuest -and [int]$insecureGuest -eq 1) {
        Add-Finding -Severity Medium -Title 'The SMB client allows insecure guest logons' `
            -Evidence 'LanmanWorkstation\Parameters\AllowInsecureGuestAuth = 1' `
            -Impact 'The machine connects to shared folders without authentication and without signing - a fake server on the network can serve tampered files.' `
            -Fix 'Remove the AllowInsecureGuestAuth value, or set it to 0.' `
            -Confidence Certain
    }

    # 13. Exploit protection at system level

    if (Get-Command -Name Get-ProcessMitigation -ErrorAction SilentlyContinue) {
        try {
            $mitigation = Get-ProcessMitigation -System -ErrorAction Stop
            # Why: NOTSET means "system default", which is ON for DEP/ASLR/CFG. Only an explicit OFF
            # is an actual deviation - if we flag NOTSET, the tool screams on every single healthy PC.
            $disabledMitigations = @()
            if ([string]$mitigation.Dep.Enable -eq 'OFF') { $disabledMitigations += 'DEP (data execution prevention)' }
            if ([string]$mitigation.Aslr.BottomUp -eq 'OFF') { $disabledMitigations += 'ASLR (address space layout randomization)' }
            if ([string]$mitigation.CFG.Enable -eq 'OFF') { $disabledMitigations += 'CFG (control flow guard)' }
            if ([string]$mitigation.SEHOP.Enable -eq 'OFF') { $disabledMitigations += 'SEHOP (exception chain validation)' }

            if ($disabledMitigations.Count -gt 0) {
                Add-Finding -Severity High -Title 'Exploit protection is explicitly turned off at system level' `
                    -Evidence ("Get-ProcessMitigation -System reports OFF for: {0}" -f ($disabledMitigations -join ', ')) `
                    -Impact 'These mechanisms are what make memory bugs hard to exploit. With them off, old vulnerabilities become exploitable again.' `
                    -Fix 'Windows Security -> App & browser control -> Exploit protection -> System settings -> set them back to "Use default".' `
                    -Confidence Certain
            } else {
                Add-Ok -Message 'Exploit protection (DEP, ASLR, CFG, SEHOP) is at system default or enabled.'
            }
        } catch {
            Add-Skip -Message "Get-ProcessMitigation -System could not be read (often requires administrator rights): $($_.Exception.Message)"
        }
    } else {
        Add-Skip -Message 'Get-ProcessMitigation does not exist in this Windows build - skipping exploit protection.'
    }

    # 14. Root certificates

    if ($Fast) {
        Add-Skip -Message 'The root certificate review is skipped in fast mode.'
    } else {
        try {
            $rootCerts = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)
            # Why: nearly every large CA shows up with the organization name in the subject. Anything
            # outside this list is usually legitimate (AV products, corporate proxies, developer tools),
            # hence Likely and not a higher severity.
            $knownCaTokens = @(
                'Microsoft', 'DigiCert', 'VeriSign', 'Symantec', 'Baltimore', 'GlobalSign', 'Entrust',
                'Sectigo', 'COMODO', 'USERTrust', 'AddTrust', 'GoDaddy', 'Go Daddy', 'Starfield',
                'Amazon', 'Thawte', 'GeoTrust', 'IdenTrust', 'DST Root', 'ISRG', "Let's Encrypt",
                'Certum', 'Buypass', 'QuoVadis', 'SwissSign', 'T-Systems', 'TeliaSonera', 'Telia',
                'Actalis', 'D-TRUST', 'SSL.com', 'AffirmTrust', 'SecureTrust', 'XRamp', 'NetLock',
                'Security Communication', 'Trustwave', 'Certigna', 'HARICA', 'Hellenic', 'TWCA',
                'Chambers', 'Camerfirma', 'ePKI', 'Autoridad', 'Izenpe', 'Microsec', 'OISTE',
                'WISeKey', 'Staat der Nederlanden', 'SZAFIR', 'Hongkong', 'SecureSign', 'Trustis',
                'Atos', 'emSign', 'vTrus', 'UCA', 'CFCA', 'GDCA', 'ANF', 'NAVER', 'Root Agency',
                'DoD ', 'Federal Common Policy', 'Certainly', 'BJCA', 'TrustAsia', 'Google Trust',
                'GTS Root', 'GTS CA', 'Cybertrust', 'AC RAIZ', 'Firmaprofesional', 'e-Szigno',
                'TUBITAK', 'Deutsche Telekom', 'LuxTrust', 'Disig', 'ACCV', 'Halcom', 'A-Trust',
                'Certipost', 'DigitalSign', 'E-Tugra', 'TrustCor', 'GlobalTrust', 'Apple Root',
                'Sertifika', 'Root CA'
            )

            $unknownRoots = @()
            $expiringRoots = @()
            $now = Get-Date
            foreach ($cert in $rootCerts) {
                $subject = [string]$cert.Subject
                $isKnown = $false
                foreach ($token in $knownCaTokens) {
                    if ($subject -like ('*' + $token + '*')) { $isKnown = $true; break }
                }
                if (-not $isKnown) { $unknownRoots += $subject }
                if ($cert.NotAfter -gt $now -and $cert.NotAfter -lt $now.AddDays(60)) {
                    $expiringRoots += ('{0} (expires {1})' -f $subject, $cert.NotAfter.ToString('yyyy-MM-dd'))
                }
            }

            if ($unknownRoots.Count -gt 0) {
                $shown = @($unknownRoots | Select-Object -First 6)
                $suffix = ''
                if ($unknownRoots.Count -gt $shown.Count) { $suffix = (' (+{0} more)' -f ($unknownRoots.Count - $shown.Count)) }
                Add-Finding -Severity Medium -Title 'Root certificates that do not belong to known public certificate authorities' `
                    -Evidence ("{0} of {1} root certificates were not recognized: {2}{3}" -f $unknownRoots.Count, $rootCerts.Count, ($shown -join '; '), $suffix) `
                    -Impact 'A root certificate in this store can sign valid certificates for any website at all. If one is put there by malware or an insecure proxy, HTTPS traffic can be intercepted. Antivirus products, corporate proxies and developer tools do however also put entirely legitimate certificates here.' `
                    -Fix 'Open certlm.msc -> Trusted Root Certification Authorities -> Certificates and check that every entry belongs to software you installed yourself.' `
                    -Confidence Likely
            } else {
                Add-Ok -Message ("All {0} root certificates in the machine store belong to known public certificate authorities." -f $rootCerts.Count)
            }

            if ($expiringRoots.Count -gt 0) {
                Add-Finding -Severity Low -Title 'Root certificates expire soon' `
                    -Evidence (($expiringRoots | Select-Object -First 5) -join '; ') `
                    -Impact 'When a root certificate expires, websites and programs that depend on it can suddenly start giving certificate errors.' `
                    -Fix 'Run Windows Update - Microsoft refreshes the root certificate list automatically through it.' `
                    -Confidence Likely
            }
        } catch {
            Add-Skip -Message "The root certificate store could not be read: $($_.Exception.Message)"
        }
    }

    # 15. SmartScreen and Mark-of-the-Web
    # SmartScreen is the reputation check on a file the moment it is run, and Mark-of-the-Web
    # is what tells Windows the file came from the internet in the first place. Both are
    # standard targets in "debloat" and "privacy" guides, and turning either off is silent -
    # nothing in the interface indicates that downloads are no longer being checked.

    $smartScreenPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'
    $smartScreenUser = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled'
    $smartScreenLevel = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel'

    # Policy wins when set. 0 is off; the user-facing value is the string Off/Warn/RequireAdmin.
    $smartScreenOff = $false
    $smartScreenEvidence = ''
    if ($null -ne $smartScreenPolicy) {
        $smartScreenOff = ([int]$smartScreenPolicy -eq 0)
        $smartScreenEvidence = "Policy EnableSmartScreen = $smartScreenPolicy" +
            $(if ($null -ne $smartScreenLevel) { ", ShellSmartScreenLevel = $smartScreenLevel" } else { '' })
    } elseif ($null -ne $smartScreenUser) {
        $smartScreenOff = ([string]$smartScreenUser -match '^(?i)off$')
        $smartScreenEvidence = "Explorer SmartScreenEnabled = $smartScreenUser (no policy set)"
    } else {
        $smartScreenEvidence = 'Neither EnableSmartScreen (policy) nor SmartScreenEnabled (Explorer) is set - the Windows default applies, which is on.'
    }

    if ($smartScreenOff) {
        Add-Finding -Severity Medium -Title 'SmartScreen is turned off' `
            -Evidence $smartScreenEvidence `
            -Impact 'Programs downloaded from the internet run without a reputation check. SmartScreen is what stops the newly built installer that no antivirus has a signature for yet, and it is the layer that catches the first hours of a campaign.' `
            -Fix 'Windows Security > App & browser control > Reputation-based protection settings > turn on "Check apps and files". If a policy is setting it, the value is EnableSmartScreen under HKLM:\SOFTWARE\Policies\Microsoft\Windows\System.' `
            -Confidence Certain
    } else {
        Add-Ok -Message ("SmartScreen reputation checking is not disabled. {0}" -f $smartScreenEvidence)
    }

    # Attachment Manager: SaveZoneInformation = 1 stops Windows writing the Zone.Identifier
    # stream, so downloaded files lose Mark-of-the-Web entirely. Nothing downstream can then
    # tell that a file came from the internet - not SmartScreen, not Office Protected View,
    # not the ASR rules that key on it. HKCU is where the guides put it.
    $attachmentPaths = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    )
    $motwOff = @()
    $scanOff = @()
    foreach ($attachmentPath in $attachmentPaths) {
        if ([int](Get-RegValue -Path $attachmentPath -Name 'SaveZoneInformation') -eq 1) { $motwOff += $attachmentPath }
        if ([int](Get-RegValue -Path $attachmentPath -Name 'ScanWithAntiVirus') -eq 1) { $scanOff += $attachmentPath }
    }

    if ($motwOff.Count -gt 0) {
        Add-Finding -Severity High -Title 'Windows is not marking downloaded files as coming from the internet' `
            -Evidence ("SaveZoneInformation = 1 under: {0}" -f ($motwOff -join '; ')) `
            -Impact 'Mark-of-the-Web is never written. Every protection that depends on knowing a file came from the internet stops working at once: SmartScreen has nothing to check, Office opens macro documents without Protected View, and the ASR rules that block content from email and the web no longer match. This one setting quietly removes several layers.' `
            -Fix 'Delete the SaveZoneInformation value under the listed key(s), or set it to 2. Then confirm on a fresh download with: Get-Item <file> -Stream Zone.Identifier' `
            -Confidence Certain
    }
    # Its own check, not an elseif: a machine with both values set would otherwise have the
    # second one hidden by the first, and they disable different things.
    if ($scanOff.Count -gt 0) {
        Add-Finding -Severity Medium -Title 'Attachments are not scanned when opened' `
            -Evidence ("ScanWithAntiVirus = 1 under: {0} (1 = no scan, 3 = scan)" -f ($scanOff -join '; ')) `
            -Impact 'Files saved from mail and the browser are not handed to the antivirus when they are opened.' `
            -Fix 'Set ScanWithAntiVirus to 3. Do not just delete the value - unconfigured behaves the same as 1 here, so deleting it leaves attachments unscanned. Via policy: User Configuration > Administrative Templates > Windows Components > Attachment Manager > "Notify antivirus programs when opening attachments" > Enabled.' `
            -Confidence Certain
    }
    if ($motwOff.Count -eq 0 -and $scanOff.Count -eq 0) {
        Add-Ok -Message 'Downloaded files keep their Mark-of-the-Web, so SmartScreen, Protected View and the ASR rules can all act on it.'
    }

    # 16. AutoPlay/AutoRun

    $explorerPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $noDriveTypeAutoRun = Get-RegValue -Path $explorerPolicy -Name 'NoDriveTypeAutoRun'
    if ($null -ne $noDriveTypeAutoRun -and [int]$noDriveTypeAutoRun -eq 255) {
        Add-Ok -Message 'AutoRun is turned off for all drive types (NoDriveTypeAutoRun = 255).'
    } else {
        Add-Finding -Severity Low -Title 'AutoRun is not turned off for all drive types' `
            -Evidence ("{0}\NoDriveTypeAutoRun = {1} (255 turns everything off)" -f $explorerPolicy, $(if ($null -eq $noDriveTypeAutoRun) { 'missing' } else { $noDriveTypeAutoRun })) `
            -Impact 'Windows blocks autorun.inf on USB sticks by default, but AutoPlay can still offer to open content automatically from unknown media.' `
            -Fix 'Settings -> Bluetooth & devices -> AutoPlay -> turn it off, or set NoDriveTypeAutoRun to 255 through Group Policy.' `
            -Confidence Likely
    }

    # 17. Automatic sign-in and Hello

    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $autoLogon = Get-RegValue -Path $winlogonPath -Name 'AutoAdminLogon'
    if ($null -ne $autoLogon -and [string]$autoLogon -eq '1') {
        $storedPassword = Get-RegValue -Path $winlogonPath -Name 'DefaultPassword'
        if (-not [string]::IsNullOrEmpty([string]$storedPassword)) {
            Add-Finding -Severity Critical -Title 'Automatic sign-in with the password stored in clear text in the registry' `
                -Evidence ("{0}\AutoAdminLogon = 1 and DefaultPassword contains a value ({1} characters)" -f $winlogonPath, ([string]$storedPassword).Length) `
                -Impact 'The password can be read by any local user or any program, and the machine signs itself in without anyone typing anything.' `
                -Fix 'Remove the AutoAdminLogon and DefaultPassword values under HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, and change the password.' `
                -Confidence Certain
        } else {
            Add-Finding -Severity High -Title 'Automatic sign-in is enabled' `
                -Evidence ("{0}\AutoAdminLogon = 1" -f $winlogonPath) `
                -Impact 'The machine signs in to the desktop without anyone typing a password. Anyone with physical access therefore gets full access.' `
                -Fix 'Run netplwiz and tick "Users must enter a user name and password to use this computer".' `
                -Confidence Certain
        }
    } else {
        Add-Ok -Message 'Automatic sign-in without a password (AutoAdminLogon) is not enabled.'
    }

    $passwordless = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Name 'DevicePasswordLessBuildVersion'
    if ($null -ne $passwordless -and [int]$passwordless -ge 2) {
        Add-Finding -Severity Info -Title 'Passwordless sign-in (Windows Hello) is turned on for the device' `
            -Evidence ("DevicePasswordLessBuildVersion = {0}" -f $passwordless) `
            -Impact 'Sign-in happens with a PIN, face or fingerprint tied to this machine instead of the account password. That is the recommended setup - just remember that the account password still applies on other devices.' `
            -Confidence Certain
    }

    # 18. Persistence mechanisms
    #
    # Everything above asks whether the machine is configured safely. This asks a different
    # question: is something already here that arranged to keep running? These are the
    # registry locations that hand code execution to whatever is written in them, and that
    # almost nothing legitimate touches on a personal machine. That last part is what makes
    # them worth checking at all - the Run keys and the scheduled task list are far more
    # popular with attackers, but they are so full of legitimate entries that reporting
    # them produces a list nobody reads. These are quiet by default, so a hit means something.

    # Image File Execution Options: a Debugger value under a program name makes Windows run
    # THAT instead, every time the named program starts. The classic accessibility hijack
    # (sethc.exe, utilman.exe) works this way, and it survives reboots and password changes.
    # Microsoft ships a handful of legitimate ones, so they are excluded by name.
    # Both registry views: a hijack aimed at a 32-bit program lives under WOW6432Node, and
    # checking only the 64-bit view would miss it entirely.
    $ifeoRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )
    $ifeoExpected = @('AcroRd32.exe', 'Acrobat.exe', 'msedge.exe', 'YourPhone.exe')
    $ifeoHits = @()
    $silentExitHits = @()
    foreach ($ifeoRoot in $ifeoRoots) {
        try {
            foreach ($sub in @(Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction Stop)) {
                $dbg = Get-RegValue -Path $sub.PSPath -Name 'Debugger'
                if (-not [string]::IsNullOrWhiteSpace([string]$dbg) -and $ifeoExpected -notcontains $sub.PSChildName) {
                    $view = if ($ifeoRoot -match 'WOW6432Node') { ' [32-bit view]' } else { '' }
                    $ifeoHits += "$($sub.PSChildName)$view -> $dbg"
                }
            }
        } catch [System.Management.Automation.ItemNotFoundException] {
            # The key genuinely does not exist. That is clean, not unknown.
            Write-Verbose -Message ("{0} does not exist" -f $ifeoRoot)
        } catch {
            # Anything else means the check did not run. Saying nothing would let an
            # unreadable key read as a pass.
            Add-Skip -Message ("Image File Execution Options could not be enumerated under {0}: {1}" -f $ifeoRoot, $_.Exception.Message)
        }
    }

    # SilentProcessExit is the same idea with a different trigger: MonitorProcess runs when
    # the named process exits. It is how a payload gets restarted after being killed.
    $silentExitRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    try {
        foreach ($sub in @(Get-ChildItem -LiteralPath $silentExitRoot -ErrorAction Stop)) {
            $monitor = Get-RegValue -Path $sub.PSPath -Name 'MonitorProcess'
            if (-not [string]::IsNullOrWhiteSpace([string]$monitor)) {
                $silentExitHits += "$($sub.PSChildName) -> $monitor"
            }
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Verbose -Message 'SilentProcessExit does not exist - nothing is registered'
    } catch {
        Add-Skip -Message ("SilentProcessExit could not be enumerated: {0}" -f $_.Exception.Message)
    }

    if ($ifeoHits.Count -gt 0) {
        Add-Finding -Severity High -Title 'A program has been redirected through Image File Execution Options' `
            -Evidence (($ifeoHits | Select-Object -First 5) -join '; ') `
            -Impact 'A Debugger value here means Windows starts the listed program INSTEAD of the one that was asked for, every single time, with that program rights. Debuggers and a few installers use this legitimately, but it is also a long-standing way to hijack a system binary and survive both reboots and a password change.' `
            -Fix ("Check each entry under {0} and under the 32-bit view at {1}. If you did not set it up - and it is not a debugger you installed - delete the Debugger value in that subkey." -f $ifeoRoots[0], $ifeoRoots[1]) `
            -Confidence Likely
    } else {
        Add-Ok -Message 'No program is redirected through Image File Execution Options (no Debugger values outside the ones Windows and Adobe set).'
    }
    if ($silentExitHits.Count -gt 0) {
        Add-Finding -Severity High -Title 'A program is set to launch something else when it exits' `
            -Evidence (($silentExitHits | Select-Object -First 5) -join '; ') `
            -Impact 'MonitorProcess under SilentProcessExit runs when the named process ends. Almost nothing uses this legitimately, and it is a known way to have a payload restart itself as soon as it is killed.' `
            -Fix ("Check the entries under {0} and remove what you did not put there. To confirm whether one is actually armed, the matching subkey needs ReportingMode set and GlobalFlag 0x200 under Image File Execution Options - without both, the value is configured but dormant." -f $silentExitRoot) `
            -Confidence Likely
    } else {
        Add-Ok -Message 'Nothing is registered to launch a second program when a process exits (SilentProcessExit).'
    }

    # Winlogon Userinit and Shell run at every interactive sign-in. Both have exactly one
    # correct value on a normal machine; anything appended after a comma also runs.
    # Compare against the resolved system path rather than pattern-matching the filename.
    # A pattern that only pins "...\userinit.exe" accepts C:\Temp\evil\userinit.exe, which
    # is precisely the substitution this check exists to catch. String -ne is
    # case-insensitive in PowerShell, which is what is wanted for a path.
    # HKCU is checked too: Windows honours a per-user Shell, and a hijack that only needs
    # the current user does not have to touch HKLM at all.
    $expectedUserinit = Join-Path $env:SystemRoot 'system32\userinit.exe'
    $logonHits = @()
    foreach ($hive in @(
            @{ Path = $winlogonPath; Label = 'HKLM' }
            @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Label = 'HKCU' }
        )) {
        $userinit = ([string](Get-RegValue -Path $hive.Path -Name 'Userinit')).Trim()
        $shell = ([string](Get-RegValue -Path $hive.Path -Name 'Shell')).Trim()
        # One trailing comma is the Windows default and carries no extra program.
        if ($userinit -and ($userinit.TrimEnd(',').Trim() -ne $expectedUserinit)) {
            $logonHits += "$($hive.Label) Userinit = $userinit"
        }
        if ($shell -and $shell -ne 'explorer.exe') {
            $logonHits += "$($hive.Label) Shell = $shell"
        }
    }

    # AppInit_DLLs loads the listed DLLs into most processes that use user32.dll. Empty on a
    # normal machine, and ignored entirely when Secure Boot is on - which is worth saying,
    # because otherwise the finding overstates what a leftover value actually does.
    # Both registry views, each paired with the LoadAppInit_DLLs from its own view - the
    # switch is per-view, so reading one view's list against the other's switch would report
    # the wrong state.
    $windowsKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $secureBootOn = $null
    try { $secureBootOn = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBootOn = $null }
    $appInitArmed = $false
    foreach ($appInitKey in @($windowsKey, 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $appInit = [string](Get-RegValue -Path $appInitKey -Name 'AppInit_DLLs')
        if ([string]::IsNullOrWhiteSpace($appInit)) { continue }
        $appInitEnabled = Get-RegValue -Path $appInitKey -Name 'LoadAppInit_DLLs'
        $view = if ($appInitKey -match 'WOW6432Node') { '32-bit view' } else { '64-bit view' }
        if ([int]$appInitEnabled -ne 1) {
            $appInitNote = 'LoadAppInit_DLLs is not 1, so it is not loading'
        } elseif ($true -eq $secureBootOn) {
            # Secure Boot disables the mechanism outright, whatever the values say.
            $appInitNote = 'LoadAppInit_DLLs = 1, but Secure Boot is on, so Windows ignores it'
        } else {
            $appInitNote = 'LoadAppInit_DLLs = 1 and Secure Boot is not on, so it is active'
            $appInitArmed = $true
        }
        $logonHits += "AppInit_DLLs [$view] = $appInit ($appInitNote)"
    }

    if ($logonHits.Count -gt 0) {
        # A dormant AppInit_DLLs leftover is not the same as a live Userinit substitution.
        # Only claim High when something in the list can actually run.
        $logonUnloadable = @($logonHits | Where-Object { $_ -notmatch '^AppInit_DLLs' })
        $logonSeverity = if ($logonUnloadable.Count -gt 0 -or $appInitArmed) { 'High' } else { 'Low' }
        Add-Finding -Severity $logonSeverity -Title 'A sign-in or process-startup hook has a non-default value' `
            -Evidence ($logonHits -join '; ') `
            -Impact 'Userinit and Shell run at every interactive sign-in, and AppInit_DLLs is loaded into nearly every process that draws a window. The default values are userinit.exe, explorer.exe and empty. Anything else here runs automatically, as you, without appearing in Task Manager startup or in msconfig. Note that Secure Boot disables AppInit_DLLs regardless of the value.' `
            -Fix ("Compare against the defaults: Userinit should be C:\\Windows\\system32\\userinit.exe, - Shell should be explorer.exe - AppInit_DLLs should be empty. They live under {0} and {1}." -f $winlogonPath, $windowsKey) `
            -Confidence Likely
    } else {
        # Only what this branch actually verified. The IFEO and SilentProcessExit results
        # have their own OK lines above - folding them in here meant the report could print
        # "nothing is redirected through Image File Execution Options" in the same run as a
        # High finding saying a program had been redirected through exactly that.
        Add-Ok -Message 'The sign-in hooks are at their defaults (Userinit, Shell and AppInit_DLLs, in both HKLM and HKCU).'
    }

    # LSA extension points. Anything listed here is loaded by lsass.exe, the process that
    # holds credentials - so a DLL here reads them by definition. The defaults are stable
    # across Windows versions, which makes an unexpected entry meaningful.
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaExpected = @{
        'Notification Packages'   = @('scecli', 'rassfm')
        'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', '""')
        'Authentication Packages' = @('msv1_0')
    }
    $lsaHits = @()
    foreach ($lsaName in $lsaExpected.Keys) {
        $lsaValue = @(Get-RegValue -Path $lsaKey -Name $lsaName)
        foreach ($entry in $lsaValue) {
            $trimmed = ([string]$entry).Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($lsaExpected[$lsaName] -notcontains $trimmed.ToLower()) { $lsaHits += "$lsaName -> $trimmed" }
        }
    }
    if ($lsaHits.Count -gt 0) {
        Add-Finding -Severity High -Title 'An unexpected package is registered with LSA' `
            -Evidence ($lsaHits -join '; ') `
            -Impact 'Everything listed under these values is loaded into lsass.exe, the process that holds credentials in memory. A DLL loaded there can read every password and hash that passes through sign-in. Some smart-card middleware and enterprise agents register here legitimately, but on a personal machine the list should hold nothing but the Windows defaults.' `
            -Fix ("Identify the DLL behind each unexpected name - they load from System32. If it does not belong to software you installed deliberately, treat the machine as compromised rather than deleting the value: LSA packages are loaded before you get a desktop. The values are under {0}." -f $lsaKey) `
            -Confidence Uncertain
    } else {
        Add-Ok -Message 'Only the standard Windows packages are registered with LSA (nothing extra is loaded into lsass.exe).'
    }

    # WMI permanent event subscriptions: a filter (the trigger), a consumer (what runs) and
    # a binding between them, stored in the CIM repository rather than in the registry or on
    # disk. It is fileless persistence that survives reboots and that nothing in Task Manager
    # or msconfig will ever show. Requires admin to read root\subscription.
    if (-not $ctx.IsAdmin) {
        Add-Skip -Message 'WMI event subscriptions were not checked - reading root\subscription requires administrator rights.'
    } else {
        try {
            # Match on class AND name, not name alone. Name is a key on each derived class
            # rather than on the abstract base, so an ActiveScriptEventConsumer may call
            # itself "SCM Event Log Consumer" and is then a different object entirely from
            # the NTEventLogEventConsumer that Windows ships - which cannot execute anything.
            # Allowlisting by name alone would wave that straight through.
            $wmiShipped = @(
                @{ Class = 'NTEventLogEventConsumer'; Name = 'SCM Event Log Consumer' }
            )
            $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop |
                    Where-Object {
                        $consumerClass = $_.CimClass.CimClassName
                        $consumerName = $_.Name
                        -not (@($wmiShipped | Where-Object { $_.Class -eq $consumerClass -and $_.Name -eq $consumerName }).Count)
                    })
            $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)

            if ($consumers.Count -eq 0) {
                Add-Ok -Message ("No WMI event consumers beyond the ones Windows ships ({0} binding(s) present)." -f $bindings.Count)
            } else {
                $consumerDetail = @($consumers | Select-Object -First 5 | ForEach-Object {
                        $what = $_.CommandLineTemplate
                        if (-not $what) { $what = $_.ScriptText }
                        if (-not $what) { $what = $_.CreatorSID }
                        $shown = ([string]$what -replace '\s+', ' ').Trim()
                        if ($shown.Length -gt 120) { $shown = $shown.Substring(0, 120) + '...' }
                        "$($_.Name) [$($_.CimClass.CimClassName)] $shown"
                    })
                Add-Finding -Severity High -Title 'A WMI event subscription is registered on this machine' `
                    -Evidence (($consumerDetail -join '; ') + " - $($bindings.Count) filter-to-consumer binding(s) in total") `
                    -Impact 'A WMI subscription runs code when a condition it defines is met - a time of day, a process starting, a user signing in. It lives in the CIM repository rather than on disk, survives reboots, and appears in no startup list, so it is a favourite for persistence that ordinary cleanup misses. Some management and monitoring software does use it legitimately.' `
                    -Fix 'Inspect them: Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding, then look up the matching __EventFilter and __EventConsumer. If you do not recognise one and no management software explains it, treat it as a real finding.' `
                    -Confidence Uncertain
            }
        } catch {
            Add-Skip -Message ("WMI event subscriptions could not be read: {0}" -f $_.Exception.Message)
        }
    }

    # 19. Defender detection history
    # Whether Defender is configured correctly is one question; whether it has actually
    # caught something, and whether that something was dealt with, is a different one.
    # A threat still sitting at Detected or Failed means the file is where it was.
    if (-not (Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
        Add-Skip -Message 'Defender detection history was not read - Get-MpThreatDetection is not available on this machine.'
    } else {
        try {
            $detections = @(Get-MpThreatDetection -ErrorAction Stop)
            if ($detections.Count -eq 0) {
                Add-Ok -Message 'Defender has no recorded threat detections on this machine.'
            } else {
                # ThreatStatusID: 2 = Quarantined, 3 = Removed, 6 = Cleaned are resolved.
                # 1 = Detected and 4 = Cleaned-failed / still present are not.
                $unresolved = @($detections | Where-Object { @(2, 3, 6) -notcontains [int]$_.ThreatStatusID })
                $recent = @($detections | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3 |
                        ForEach-Object { "$($_.InitialDetectionTime) status $($_.ThreatStatusID)" })
                if ($unresolved.Count -gt 0) {
                    Add-Finding -Severity High -Title 'Defender has detections that were never resolved' `
                        -Evidence ("{0} of {1} detection(s) are not quarantined, removed or cleaned. Most recent: {2}" -f $unresolved.Count, $detections.Count, ($recent -join '; ')) `
                        -Impact 'Defender found something and did not finish dealing with it. The file is most likely still where it was found, and a detection that keeps coming back usually means the source has not been removed.' `
                        -Fix 'Open Windows Security > Virus & threat protection > Protection history and act on each item. From PowerShell: Get-MpThreatDetection | Select-Object InitialDetectionTime,ThreatStatusID,Resources' `
                        -Confidence Likely
                } else {
                    Add-Finding -Severity Info -Title 'Defender has resolved detections in its history' `
                        -Evidence ("{0} detection(s), all quarantined, removed or cleaned. Most recent: {1}" -f $detections.Count, ($recent -join '; ')) `
                        -Impact 'Nothing outstanding. Worth knowing about, because a history full of the same detection points at a source that keeps reintroducing it.' `
                        -Confidence Certain
                }
            }
        } catch {
            Add-Skip -Message ("Defender detection history could not be read: {0}" -f $_.Exception.Message)
        }
    }

    # 20. BitLocker key protectors
    # An encrypted volume with no recovery password is a volume you can lose permanently:
    # a firmware update that resets the TPM leaves nothing to unlock it with.
    if (-not $ctx.IsAdmin) {
        Add-Skip -Message 'BitLocker key protectors were not enumerated - it requires administrator rights.'
    } elseif (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Add-Skip -Message 'BitLocker key protectors were not enumerated - Get-BitLockerVolume is not available on this edition.'
    } else {
        try {
            $protectedVolumes = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { [string]$_.ProtectionStatus -eq 'On' })
            if ($protectedVolumes.Count -eq 0) {
                Add-Skip -Message 'No BitLocker-protected volumes on this machine, so key protectors were not assessed.'
            } else {
                $withoutRecovery = @()
                foreach ($volume in $protectedVolumes) {
                    $types = @($volume.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
                    if ($types -notcontains 'RecoveryPassword') {
                        $withoutRecovery += "$($volume.MountPoint) has only: $(($types | Sort-Object -Unique) -join ', ')"
                    }
                }
                if ($withoutRecovery.Count -gt 0) {
                    Add-Finding -Severity High -Title 'An encrypted volume has no recovery password' `
                        -Evidence ($withoutRecovery -join '; ') `
                        -Impact 'Without a recovery password there is exactly one way in. A UEFI or fTPM firmware update that resets the TPM, a motherboard replacement, or a Secure Boot change then leaves the data unreadable with no way back - this is the most common cause of permanent BitLocker data loss.' `
                        -Fix 'Add one as administrator: manage-bde -protectors -add <drive> -RecoveryPassword, then save it: manage-bde -protectors -get <drive>. Back it up to your Microsoft account or print it - not to the encrypted disk itself.' `
                        -Confidence Certain
                } else {
                    Add-Ok -Message ("All {0} BitLocker-protected volume(s) have a recovery password protector." -f $protectedVolumes.Count)
                }
            }
        } catch {
            Add-Skip -Message ("BitLocker key protectors could not be read: {0}" -f $_.Exception.Message)
        }
    }

    # 21. VBS and HVCI: configured versus actually running
    # SecurityServicesConfigured says what was asked for, SecurityServicesRunning says what
    # the hypervisor actually started. When they disagree something is blocking it, and the
    # machine has the protection turned on in the interface while not having it at all.
    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        # Both properties report 0 to mean "none", as a single-element array rather than an
        # empty one. Left in, that 0 counts as a configured service that is also running, so
        # a machine with nothing enabled got told "every configured protection is running (0)"
        # - a healthy line about a list that does not exist.
        $configured = @($deviceGuard.SecurityServicesConfigured | Where-Object { [int]$_ -ne 0 })
        $running = @($deviceGuard.SecurityServicesRunning | Where-Object { [int]$_ -ne 0 })
        $serviceNames = @{ 1 = 'Credential Guard'; 2 = 'Memory integrity (HVCI)'; 3 = 'System Guard'; 4 = 'SMM firmware measurement'; 5 = 'Kernel-mode hardware-enforced stack protection' }
        $notRunning = @($configured | Where-Object { $running -notcontains $_ })
        if ($configured.Count -eq 0) {
            # Nothing requested. Whether that is a problem is the Credential Guard and HVCI
            # checks' job, not this one - this only compares intent against reality.
            Add-Skip -Message 'No virtualization-based protection is configured, so there was nothing to compare against what is running.'
        } elseif ($notRunning.Count -gt 0) {
            $notRunningText = (@($notRunning | ForEach-Object { if ($serviceNames.ContainsKey([int]$_)) { $serviceNames[[int]$_] } else { "service $_" } }) -join ', ')
            Add-Finding -Severity Medium -Title 'A virtualization-based protection is configured but not running' `
                -Evidence ("SecurityServicesConfigured = [{0}], SecurityServicesRunning = [{1}]. Not running: {2}. VirtualizationBasedSecurityStatus = {3}." -f ($configured -join ', '), ($running -join ', '), $notRunningText, $deviceGuard.VirtualizationBasedSecurityStatus) `
                -Impact 'The setting is on in Windows Security, but the hypervisor never started the service. The usual cause is an incompatible kernel driver - often from an old VPN client, an anti-cheat, or a virtualization product - which leaves the machine with the protection switched on and absent at the same time.' `
                -Fix 'Find the blocking driver: the System log, source Microsoft-Windows-DeviceGuard, records why. Windows Security > Device security > Core isolation details also names incompatible drivers. Update or remove that driver and restart.' `
                -Confidence Certain
        } else {
            $runningText = (@($configured | ForEach-Object { if ($serviceNames.ContainsKey([int]$_)) { $serviceNames[[int]$_] } else { "service $_" } }) -join ', ')
            Add-Ok -Message ("Every virtualization-based protection that is configured is actually running: {0}." -f $runningText)
        }
    } catch {
        Add-Skip -Message 'Win32_DeviceGuard could not be read, so configured-versus-running VBS state was not compared.'
    }

    # 22. Boot configuration flags
    # These are the switches that turn off the protections everything else here assumes.
    # testsigning lets unsigned kernel drivers load; nointegritychecks removes the check
    # entirely; a kernel debugger lets another machine read and write this one's memory.
    # They are read from the BCD store through WMI so no external tool is needed.
    # Read the mounted BCD hive rather than parsing bcdedit output: the element names are
    # numeric codes and the values are raw bytes, so nothing here depends on the display
    # language. bcdedit prints "Yes"/"No", which is translated. The WMI BcdStore provider
    # was the other candidate and it refuses to open the system store even elevated.
    $bcdFlags = @()
    $bcdRead = $false
    try {
        $bcdObjects = @(Get-ChildItem -LiteralPath 'HKLM:\BCD00000000\Objects' -ErrorAction Stop)
        $bcdRead = ($bcdObjects.Count -gt 0)
        # BcdLibraryBoolean_* element codes. 12000004 is the entry description.
        $bootChecks = @{
            '16000049' = @{ Name = 'testsigning'; Means = 'unsigned kernel drivers are allowed to load' }
            '16000048' = @{ Name = 'nointegritychecks'; Means = 'driver signature enforcement is switched off entirely' }
            '16000010' = @{ Name = 'kernel debugging'; Means = 'another machine can read and write this one memory over the debug transport' }
        }
        foreach ($bcdObject in $bcdObjects) {
            foreach ($code in $bootChecks.Keys) {
                $elementKey = Join-Path $bcdObject.PSPath "Elements\$code"
                if (-not (Test-Path -LiteralPath $elementKey)) { continue }
                $element = (Get-ItemProperty -LiteralPath $elementKey -ErrorAction SilentlyContinue).Element
                # Boolean elements are a single byte: 01 = on.
                $isOn = ($element -is [byte[]] -and $element.Length -ge 1 -and $element[0] -eq 1)
                if (-not $isOn) { continue }
                $descriptionKey = Join-Path $bcdObject.PSPath 'Elements\12000004'
                $entryName = [string](Get-ItemProperty -LiteralPath $descriptionKey -ErrorAction SilentlyContinue).Element
                if ([string]::IsNullOrWhiteSpace($entryName)) { $entryName = $bcdObject.PSChildName }
                $bcdFlags += "$($bootChecks[$code].Name) is on for '$entryName' - $($bootChecks[$code].Means)"
            }
        }
        if (-not $bcdRead) {
            Add-Skip -Message 'The BCD hive holds no boot objects, so boot configuration flags were not assessed.'
        } elseif ($bcdFlags.Count -gt 0) {
            Add-Finding -Severity High -Title 'The boot configuration disables a kernel protection' `
                -Evidence ($bcdFlags -join '; ') `
                -Impact 'These flags are meant for driver development. Left on, they undo driver signature enforcement - the thing that stops a vulnerable or malicious kernel driver from loading, which is the route the whole vulnerable-driver blocklist exists to block. Some anti-cheat and DRM systems also refuse to run.' `
                -Fix 'As administrator: bcdedit /set testsigning off, bcdedit /set nointegritychecks off, bcdedit /debug off - then restart. Check with: bcdedit /enum {current}' `
                -Confidence Certain
        } else {
            Add-Ok -Message ("None of the {0} boot entries has a kernel protection switched off (testsigning, nointegritychecks and kernel debugging are all off)." -f $bcdObjects.Count)
        }
    } catch {
        Add-Skip -Message 'The BCD hive (HKLM:\BCD00000000) could not be read, so boot configuration flags were not assessed - it requires administrator rights.'
    }

    # 23. Certificates that exist only in the per-user store
    # Cert:\CurrentUser\Root returns the machine store merged in, so comparing counts there
    # says nothing. The registry is where a purely per-user root actually lives, and that is
    # the interesting case: it needs no administrator rights to install.
    try {
        $userOnlyRootKey = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'
        $machineRootKey = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'
        $userThumbprints = @(Get-ChildItem -LiteralPath $userOnlyRootKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
        $machineThumbprints = @(Get-ChildItem -LiteralPath $machineRootKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
        $userOnly = @($userThumbprints | Where-Object { $machineThumbprints -notcontains $_ })
        if ($userOnly.Count -eq 0) {
            Add-Ok -Message 'No root certificates exist only in the per-user store - nothing was installed as trusted without administrator rights.'
        } else {
            $userOnlyNames = @($userOnly | ForEach-Object {
                    $cert = Get-Item -LiteralPath ("Cert:\CurrentUser\Root\{0}" -f $_) -ErrorAction SilentlyContinue
                    if ($cert) { $cert.Subject } else { $_ }
                } | Select-Object -First 5)
            Add-Finding -Severity Medium -Title 'Root certificates are trusted for this user only' `
                -Evidence ("{0} certificate(s) exist in HKCU but not in the machine store: {1}" -f $userOnly.Count, ($userOnlyNames -join '; ')) `
                -Impact 'A root certificate in the per-user store is trusted by every browser and program running as you, and installing one needs no administrator rights at all. That makes it the easy way to set up HTTPS interception, and it is invisible to any check that only looks at the machine store.' `
                -Fix 'Open certmgr.msc (not certlm.msc) > Trusted Root Certification Authorities > Certificates and confirm you recognise each one. Development tools like mkcert and Fiddler put legitimate certificates here.' `
                -Confidence Likely
        }
    } catch {
        Add-Skip -Message 'The per-user root certificate store could not be read.'
    }

    # 24. Secure Boot revocation list (dbx)
    # An empty or tiny dbx means the firmware never received the revocations that block
    # the known-vulnerable bootloaders, so Secure Boot is on but not stopping much.
    if ($null -ne $secureBootOn -and $true -eq $secureBootOn) {
        try {
            $dbx = Get-SecureBootUEFI -Name dbx -ErrorAction Stop
            $dbxBytes = @($dbx.Bytes).Count
            # A current dbx on Windows 11 is tens of kilobytes. Anything under a few KB
            # means the machine never got the revocation updates.
            if ($dbxBytes -lt 4096) {
                Add-Finding -Severity Medium -Title 'The Secure Boot revocation list looks out of date' `
                    -Evidence ("The UEFI dbx variable is {0} bytes. A current revocation list on Windows 11 is tens of kilobytes." -f ('{0:N0}' -f $dbxBytes)) `
                    -Impact 'Secure Boot is on, but the firmware has not received the list of revoked bootloaders. The signed-but-vulnerable bootloaders behind BlackLotus and similar bootkits are then still accepted, which is most of what Secure Boot is supposed to stop.' `
                    -Fix 'Install all Windows updates - Microsoft ships dbx updates through Windows Update. Some boards also need a UEFI firmware update from the vendor. Check the size afterwards with: (Get-SecureBootUEFI -Name dbx).Bytes.Count' `
                    -Confidence Likely
            } else {
                Add-Ok -Message ("The Secure Boot revocation list (dbx) is {0:N0} bytes, so the firmware has received revocation updates." -f $dbxBytes)
            }
        } catch {
            Add-Skip -Message 'The Secure Boot dbx variable could not be read (it needs administrator rights and a UEFI machine).'
        }
    }

    # 25. Delegated: PrivescCheck
    # Privilege-escalation surface - weak service ACLs, unquoted service paths, writable
    # entries in %PATH%, DLL hijack candidates. This script deliberately does not
    # reimplement any of that: itm4n maintains it, it is a large body of careful work, and
    # copying the checks out of it would be taking the work without the credit. So it is
    # invoked, if the caller has it, and the result is attributed.
    if ($PrivescCheckPath) {
        Write-Host '    running PrivescCheck (this takes a while)...' -ForegroundColor DarkGray
        # -Audit adds the configuration checks, -Silent suppresses its own banner, and CSV
        # is the one stable, parseable output it offers. -Report makes it write a file,
        # which is the only disk write anywhere in this script - so it goes to a uniquely
        # named temporary path and is deleted again in the finally block below. The header
        # and the README both say so rather than leaving the reader to discover it.
        $privescPrefix = Join-Path ([IO.Path]::GetTempPath()) ("privesc-{0}" -f [guid]::NewGuid().ToString('N'))
        $privescCsv = "$privescPrefix.csv"
        try {
            $privescExpression = ". '$($PrivescCheckPath -replace "'", "''")'; Invoke-PrivescCheck -Audit -Silent -Format CSV -Report '$($privescPrefix -replace "'", "''")'"
            $privescRun = Invoke-ExternalAudit -ScriptPath $PrivescCheckPath -Expression $privescExpression -TimeoutSeconds 600
            if (-not $privescRun.Ok) {
                Add-Skip -Message ("PrivescCheck was not run: {0}" -f $privescRun.Reason)
            }
            elseif (-not (Test-Path -LiteralPath $privescCsv)) {
                Add-Skip -Message 'PrivescCheck ran but wrote no CSV report, so its findings could not be read.'
            }
            else {
                $privescRows = @(Import-Csv -LiteralPath $privescCsv -ErrorAction Stop)
                # Its severity column is High/Medium/Low/Info; map onto ours and keep only
                # what it actually flagged rather than every check it ran.
                $privescHits = @($privescRows | Where-Object { $_.Severity -and $_.Severity -notmatch '(?i)^(none|info)$' })
                if ($privescHits.Count -eq 0) {
                    Add-Ok -Message ("PrivescCheck found no privilege-escalation issues ({0} checks run). Attribution: itm4n/PrivescCheck, BSD-3-Clause." -f $privescRows.Count)
                } else {
                    foreach ($severityName in 'High', 'Medium', 'Low') {
                        $group = @($privescHits | Where-Object { $_.Severity -match "(?i)^$severityName$" })
                        if ($group.Count -eq 0) { continue }
                        $titles = (@($group | Select-Object -First 6 | ForEach-Object { $_.Description }) -join '; ')
                        Add-Finding -Severity $severityName -Title ("PrivescCheck reports {0} {1}-severity privilege-escalation finding(s)" -f $group.Count, $severityName.ToLower()) `
                            -Evidence $titles `
                            -Impact 'These come from PrivescCheck (itm4n, BSD-3-Clause), not from this script. They cover the local privilege-escalation surface: service and file permissions, unquoted paths, and writable locations that a standard user could abuse to become administrator.' `
                            -Fix 'Run PrivescCheck directly for the full detail on each item. It skips many of its checks when run elevated, so run it - and this script - as an ordinary user for its complete output.' `
                            -Confidence Likely
                    }
                }
            }
        } catch {
            Add-Skip -Message ("PrivescCheck output could not be parsed: {0}" -f $_.Exception.Message)
        } finally {
            # Leave nothing behind: the report file existing is the only way this script
            # ever touches the disk, and it must not outlive the run that caused it.
            # -LiteralPath on the directory with -Filter on the leaf, not -Path with a
            # wildcard: TEMP sits under the user profile, and a username containing [ or ]
            # would make -Path treat it as a character class, silently match nothing, and
            # leave the report behind. Same trap as the registry read earlier in this file.
            $privescDir = Split-Path -Path $privescPrefix -Parent
            $privescLeaf = Split-Path -Path $privescPrefix -Leaf
            foreach ($leftover in @(Get-ChildItem -LiteralPath $privescDir -Filter "$privescLeaf.*" -File -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $leftover.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 26. LSA protection: does lsass actually run protected?
    # RunAsPPL in the registry is what was asked for. Wininit event 12 is what happened at
    # boot. They differ when the setting was added but the machine has not restarted, or
    # when firmware locked the setting out.
    if ($ctx.IsAdmin) {
        $runAsPplValue = Get-RegValue -Path $lsaKey -Name 'RunAsPPL'
        if ($null -ne $runAsPplValue -and [int]$runAsPplValue -ge 1) {
            $lsassProtected = $null
            try {
                $wininitEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12 } -MaxEvents 5 -ErrorAction Stop)
                if ($wininitEvents.Count -gt 0) { $lsassProtected = $true }
            } catch {
                Write-Verbose -Message ("No Wininit event 12 found: {0}" -f $_.Exception.Message)
            }
            if ($true -eq $lsassProtected) {
                Add-Ok -Message 'LSA protection is not just configured - Wininit event 12 confirms LSASS actually started as a protected process.'
            } else {
                Add-Finding -Severity Medium -Title 'LSA protection is configured, but nothing confirms it took effect' `
                    -Evidence ("RunAsPPL = {0} under {1}, but no Wininit event 12 (LSASS started as a protected process) was found in the System log." -f $runAsPplValue, $lsaKey) `
                    -Impact 'The registry value is what was asked for; the event is what happened. They differ when the machine has not restarted since the value was set, or when firmware or a driver stopped LSASS from starting protected - and then credential theft against LSASS is not blocked even though the setting says it is.' `
                    -Fix 'Restart the machine if the setting is new. Afterwards confirm with: Get-WinEvent -FilterHashtable @{LogName=''System''; ProviderName=''Microsoft-Windows-Wininit''; Id=12}' `
                    -Confidence Likely
            }
        }
    }
}

<#
  Privacy - what still leaves the machine. Privacy is preference, not fault, so
  almost everything here is Info or Low; Medium is reserved for the cases where
  data actually goes to a third party without the user likely knowing.

  The telemetry nuance most tools get wrong: AllowTelemetry=0 ("Security") is
  only honoured on Enterprise/Education/LTSC. On Home and Pro the OS silently
  clamps 0 up to 1 (Required), so a 0 there is not the guarantee it looks like.
#>
function Test-PrivacyHealth {
    [CmdletBinding()]
    param()

    $cdmPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    $consentRoot = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'

    # telemetry level

    # Both hives are read because gpedit writes Policies\DataCollection while
    # several "debloat" scripts only write the CurrentVersion one; disagreement
    # between them is itself worth reporting.
    $telPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry'
    $telCv = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry'

    $edition = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID'
    if (-not $edition) { $edition = 'unknown' }
    # Only these editions actually honour level 0; everything else floors at 1.
    $honoursZero = ($edition -match 'Enterprise|Education|IoTEnterprise|ServerRdsh|LTSC|LTSB')

    $telNames = @{ 0 = 'Security (0)'; 1 = 'Required (1)'; 2 = 'Enhanced (2)'; 3 = 'Optional (3)' }

    $effective = $telPolicy
    if ($null -eq $effective) { $effective = $telCv }

    if ($null -eq $effective) {
        Add-Finding -Severity 'Info' -Title 'Telemetry level is not set by policy' `
            -Evidence "AllowTelemetry does not exist under Policies\DataCollection or CurrentVersion\Policies\DataCollection. Edition: $edition." `
            -Impact 'Windows uses the default level from setup, typically Optional (3) on machines where the user clicked through the first-run setup. That sends things like browsing history metadata and app usage to Microsoft.' `
            -Fix 'Settings > Privacy & security > Diagnostics & feedback > turn off "Send optional diagnostic data".' `
            -Confidence 'Likely'
    } else {
        $lvl = 0
        try { $lvl = [int]$effective } catch { $lvl = -1 }
        $label = $telNames[$lvl]
        if (-not $label) { $label = "unknown value ($effective)" }

        if ($lvl -eq 0 -and -not $honoursZero) {
            # The headline nuance: a 0 on Pro/Home is cosmetic.
            Add-Finding -Severity 'Info' -Title 'Telemetry level 0 is not honoured on this Windows edition' `
                -Evidence "AllowTelemetry = 0, but the edition is $edition. Level 0 (Security) is only respected on Enterprise, Education, IoT Enterprise and LTSC/LTSB." `
                -Impact 'Windows clamps the value up to 1 (Required) in practice. The machine still sends basic device, driver and crash data to Microsoft. Level 1 is still the lowest you can actually reach on Pro and Home.' `
                -Fix 'No action needed if 1 is acceptable - that is the floor on this edition. If telemetry really has to go to 0, that requires Enterprise/Education/LTSC.' `
                -Confidence 'Certain'
        } elseif ($lvl -eq 0) {
            Add-Ok -Message "Telemetry set to level 0 (Security), and edition $edition actually honours it"
        } elseif ($lvl -eq 1) {
            Add-Ok -Message "Telemetry set to level 1 (Required) - the lowest level possible on $edition"
        } elseif ($lvl -ge 2) {
            Add-Finding -Severity 'Low' -Title 'Enhanced telemetry is turned on' `
                -Evidence "AllowTelemetry = $lvl ($label) on edition $edition." `
                -Impact 'Levels 2 and 3 send usage patterns, app activity and extended diagnostic data to Microsoft, not just what is needed to keep the machine secure and up to date.' `
                -Fix 'Settings > Privacy & security > Diagnostics & feedback > turn off "Send optional diagnostic data".' `
                -Confidence 'Certain'
        }

        if ($null -ne $telPolicy -and $null -ne $telCv -and $telPolicy -ne $telCv) {
            Add-Finding -Severity 'Low' -Title 'The two telemetry keys disagree' `
                -Evidence "Policies\DataCollection\AllowTelemetry = $telPolicy, but CurrentVersion\Policies\DataCollection\AllowTelemetry = $telCv." `
                -Impact 'The policy key normally wins, but a disagreement usually means a cleanup script set one and Windows or a policy set the other. The value can flip back at the next policy refresh.' `
                -Fix 'Set both to the same value, or manage it in one place via gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds.' `
                -Confidence 'Likely'
        }
    }

    # telemetry services

    foreach ($svcPair in @(
            @{ Name = 'DiagTrack'; Label = 'DiagTrack (Connected User Experiences and Telemetry)' },
            @{ Name = 'dmwappushservice'; Label = 'dmwappushservice (WAP Push message routing)' })) {

        $svc = Get-ServiceState -Name $svcPair.Name
        if (-not $svc) {
            Add-Skip -Message "$($svcPair.Label) does not exist on this installation"
            continue
        }
        if ($svc.Status -eq 'Running') {
            Add-Finding -Severity 'Info' -Title "$($svcPair.Name) is running and sending diagnostic data" `
                -Evidence "The $($svcPair.Name) service has status $($svc.Status), start type $($svc.StartType)." `
                -Impact 'This is the channel the telemetry actually goes out through. It is on by default in Windows, so this is normal - but it is the service that makes the level setting above have any effect at all.' `
                -Fix 'Lower the telemetry level in Settings instead of stopping the service; Windows starts it again on updates.' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message "$($svcPair.Name) is not running (status $($svc.Status), start type $($svc.StartType))"
        }
    }

    # advertising ID

    $adId = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled'
    if ($null -eq $adId -or $adId -eq 1) {
        $adEvidence = if ($null -eq $adId) { 'AdvertisingInfo\Enabled is not set (Windows treats that as on).' } else { 'AdvertisingInfo\Enabled = 1.' }
        Add-Finding -Severity 'Low' -Title 'Advertising ID is active' `
            -Evidence $adEvidence `
            -Impact 'Apps get a stable ID they can use to link what you do across different apps, and advertising is tailored accordingly.' `
            -Fix 'Settings > Privacy & security > General > turn off "Let apps show me personalized ads by using my advertising ID".' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'Advertising ID is turned off (AdvertisingInfo\Enabled = 0)'
    }

    # activity history

    $sysPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $publish = Get-RegValue -Path $sysPolicy -Name 'PublishUserActivities'
    $upload = Get-RegValue -Path $sysPolicy -Name 'UploadUserActivities'

    if ($upload -eq 1) {
        # Publishing stays local; uploading is the part that leaves the machine.
        Add-Finding -Severity 'Medium' -Title 'Activity history is uploaded to the Microsoft account' `
            -Evidence "UploadUserActivities = 1 under $sysPolicy." `
            -Impact 'Which apps and documents you open is synced to the cloud and becomes available on other devices you are signed in to. This is the part of the timeline that actually leaves the machine.' `
            -Fix 'Settings > Privacy & security > Activity history > clear the checkbox that sends activity to Microsoft.' `
            -Confidence 'Certain'
    } elseif ($upload -eq 0) {
        Add-Ok -Message 'Activity history upload is blocked by policy (UploadUserActivities = 0)'
    }

    if ($publish -eq 0) {
        Add-Ok -Message 'Activity history collection is off (PublishUserActivities = 0)'
    } elseif ($null -eq $publish -and $null -eq $upload) {
        Add-Finding -Severity 'Info' -Title 'Activity history is not managed by policy' `
            -Evidence "Neither PublishUserActivities nor UploadUserActivities exists under $sysPolicy." `
            -Impact 'Windows uses the default, which collects local activity history. Uploading to the cloud also requires the user to have ticked that box, so the data does not necessarily leave the machine.' `
            -Fix 'Settings > Privacy & security > Activity history if you want to turn off local storage as well.' `
            -Confidence 'Likely'
    }

    # tailored content and suggestions

    # SubscribedContent-* are numbered per surface (lock screen, Start, Settings,
    # tips). Counting them is more useful than naming each opaque number.
    $suggestOn = New-Object System.Collections.ArrayList
    foreach ($n in 'SilentInstalledAppsEnabled', 'SystemPaneSuggestionsEnabled', 'SoftLandingEnabled', 'RotatingLockScreenOverlayEnabled', 'PreInstalledAppsEnabled', 'OemPreInstalledAppsEnabled') {
        $v = Get-RegValue -Path $cdmPath -Name $n
        if ($v -eq 1) { $null = $suggestOn.Add($n) }
    }

    $subOn = 0
    $subTotal = 0
    try {
        $cdm = Get-ItemProperty -Path $cdmPath -ErrorAction Stop
        foreach ($prop in $cdm.PSObject.Properties) {
            if ($prop.Name -like 'SubscribedContent*Enabled') {
                $subTotal++
                if ($prop.Value -eq 1) { $subOn++ }
            }
        }
    } catch {
        # ContentDeliveryManager is absent on stripped or freshly imaged profiles.
        $subTotal = -1
    }

    if ($subTotal -lt 0) {
        Add-Skip -Message 'The ContentDeliveryManager key does not exist - suggestions and tailored content could not be read'
    } elseif ($suggestOn.Count -gt 0 -or $subOn -gt 0) {
        Add-Finding -Severity 'Low' -Title 'Tailored content and app suggestions are active' `
            -Evidence "$subOn of $subTotal SubscribedContent flags are on$(if ($suggestOn.Count) { ", and these are 1: $($suggestOn -join ', ')" } else { '' })." `
            -Impact 'The Start menu, the lock screen and Settings show suggestions picked from your usage, and SilentInstalledAppsEnabled lets Windows install sponsored apps without asking.' `
            -Fix 'Settings > Privacy & security > General, and Settings > Personalization > Start > turn off suggestions and tips.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message "App suggestions and tailored content are turned off ($subTotal SubscribedContent flags are 0)"
    }

    $consumer = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures'
    if ($consumer -eq 1) {
        Add-Ok -Message 'Consumer features (automatic install of sponsored apps) are blocked by policy'
    } else {
        Add-Finding -Severity 'Low' -Title 'Consumer features are not blocked' `
            -Evidence "DisableWindowsConsumerFeatures under HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent is $(if ($null -eq $consumer) { 'not set' } else { $consumer })." `
            -Impact 'Windows can download and pin sponsored apps and games in the Start menu after an update or on a new user profile. It requires contact with the Microsoft content service.' `
            -Fix 'Pro/Enterprise only: gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Cloud Content > "Turn off Microsoft consumer experiences".' `
            -Confidence 'Likely'
    }

    # app permissions per capability

    $caps = @(
        @{ Key = 'microphone'; Label = 'Microphone' },
        @{ Key = 'webcam'; Label = 'Camera' },
        @{ Key = 'location'; Label = 'Location' },
        @{ Key = 'contacts'; Label = 'Contacts' },
        @{ Key = 'appointments'; Label = 'Calendar' },
        @{ Key = 'email'; Label = 'Email' },
        @{ Key = 'phoneCallHistory'; Label = 'Call history' },
        @{ Key = 'chat'; Label = 'Messaging' },
        @{ Key = 'broadFileSystemAccess'; Label = 'Full file system access' },
        @{ Key = 'userNotificationListener'; Label = 'Notification access' }
    )

    if (-not (Test-Path -Path $consentRoot -ErrorAction SilentlyContinue)) {
        Add-Skip -Message 'CapabilityAccessManager\ConsentStore does not exist - app permissions could not be read'
    } else {
        $allowedCaps = New-Object System.Collections.ArrayList
        $sensitiveGrants = New-Object System.Collections.ArrayList

        foreach ($cap in $caps) {
            $capPath = Join-Path $consentRoot $cap.Key
            $global = Get-RegValue -Path $capPath -Name 'Value'
            if (-not $global) {
                # Capability never surfaced on this SKU or never touched by any app.
                continue
            }

            # Count only apps explicitly granted; 'Prompt' and unset are not access.
            $granted = 0
            try {
                foreach ($child in (Get-ChildItem -Path $capPath -ErrorAction Stop)) {
                    if ($child.PSChildName -eq 'NonPackaged') {
                        foreach ($np in (Get-ChildItem -Path $child.PSPath -ErrorAction SilentlyContinue)) {
                            if ((Get-RegValue -Path $np.PSPath -Name 'Value') -eq 'Allow') { $granted++ }
                        }
                    } elseif ((Get-RegValue -Path $child.PSPath -Name 'Value') -eq 'Allow') {
                        $granted++
                    }
                }
            } catch {
                # No per-app subkeys under this capability - global value still counts.
                $granted = 0
            }

            if ($global -eq 'Allow') {
                $null = $allowedCaps.Add("$($cap.Label): $granted app(s)")
                if ($granted -gt 0 -and @('microphone', 'webcam', 'broadFileSystemAccess', 'userNotificationListener') -contains $cap.Key) {
                    $null = $sensitiveGrants.Add("$($cap.Label) ($granted)")
                }
            }
        }

        if ($allowedCaps.Count -eq 0) {
            Add-Ok -Message 'None of the sensitive app permissions are set to Allow globally'
        } else {
            Add-Finding -Severity 'Info' -Title 'App permissions set to Allow' `
                -Evidence ($allowedCaps -join '; ') `
                -Impact 'The number is apps that were explicitly granted Allow, not apps that can merely ask. If the category is set to Allow globally, new apps can request access without the toggle being touched.' `
                -Fix 'Settings > Privacy & security > App permissions - go through the categories and turn off the ones you do not use.' `
                -Confidence 'Certain'
        }

        if ($sensitiveGrants.Count -gt 0) {
            Add-Finding -Severity 'Low' -Title 'Apps have been granted access to microphone, camera, files or notifications' `
                -Evidence ('Categories with active grants: ' + ($sensitiveGrants -join ', ') + '.') `
                -Impact 'Full file system access and notification reading are the two that surprise people most - they give an app a view of all your documents and of the contents of every notification, including one-time codes.' `
                -Fix 'Settings > Privacy & security > Microphone / Camera / File system / Notifications - remove apps you do not recognise.' `
                -Confidence 'Certain'
        }
    }

    # location services

    $locPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation'
    $locConsent = Get-RegValue -Path (Join-Path $consentRoot 'location') -Name 'Value'
    $lfsvc = Get-ServiceState -Name 'lfsvc'

    if ($locPolicy -eq 1) {
        Add-Ok -Message 'Location services are turned off by policy (DisableLocation = 1)'
    } elseif ($locConsent -eq 'Deny') {
        Add-Ok -Message 'Location services are set to Deny for this user'
    } elseif ($locConsent -eq 'Allow') {
        $lfState = if ($lfsvc) { "$($lfsvc.Status)" } else { 'service does not exist' }
        Add-Finding -Severity 'Info' -Title 'Location services are on' `
            -Evidence "ConsentStore\location\Value = Allow, geolocation service lfsvc: $lfState." `
            -Impact 'Windows can work out your position from the wifi networks around you and share it with apps. On a desktop machine this is rarely useful.' `
            -Fix 'Settings > Privacy & security > Location > turn off "Location services".' `
            -Confidence 'Certain'
    } else {
        Add-Skip -Message 'Location services: found no readable state in ConsentStore or policy'
    }

    # search and Cortana

    $bing = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled'
    $noBox = Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions'
    $noWeb = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch'
    $cloudSearch = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch'

    $webSearchOff = ($bing -eq 0 -or $noBox -eq 1 -or $noWeb -eq 1)
    if ($webSearchOff) {
        $bits = New-Object System.Collections.ArrayList
        if ($bing -eq 0) { $null = $bits.Add('BingSearchEnabled=0') }
        if ($noBox -eq 1) { $null = $bits.Add('DisableSearchBoxSuggestions=1') }
        if ($noWeb -eq 1) { $null = $bits.Add('DisableWebSearch=1') }
        Add-Ok -Message "Web search in Start is turned off ($($bits -join ', '))"
    } else {
        Add-Finding -Severity 'Medium' -Title 'Everything you type in the Start menu is sent to Bing' `
            -Evidence "BingSearchEnabled = $(if ($null -eq $bing) { 'not set' } else { $bing }), DisableSearchBoxSuggestions = $(if ($null -eq $noBox) { 'not set' } else { $noBox }), DisableWebSearch = $(if ($null -eq $noWeb) { 'not set' } else { $noWeb })." `
            -Impact 'The search box forwards your keystrokes to the Microsoft search service as you type - including when you are only looking for a local file or a program. This is the place most people leak from without knowing.' `
            -Fix 'Set HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled to 0, or on Pro: gpedit.msc > User Configuration > Administrative Templates > Windows Components > File Explorer > "Turn off display of recent search entries in the File Explorer search box".' `
            -Confidence 'Certain'
    }

    if ($cloudSearch -eq 0) {
        Add-Ok -Message 'Cloud search against Microsoft account content is turned off (AllowCloudSearch = 0)'
    }

    $cortanaPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana'
    if ($script:Ctx.IsWin11) {
        # Cortana was unbundled from Windows 11, so the policy is moot there
        # regardless of whether a leftover value is still in the registry.
        Add-Skip -Message 'Cortana: no longer part of Windows 11, the check is not relevant'
    } elseif ($cortanaPolicy -eq 0) {
        Add-Ok -Message 'Cortana is blocked by policy (AllowCortana = 0)'
    } elseif ($cortanaPolicy -eq 1) {
        Add-Finding -Severity 'Info' -Title 'Cortana is allowed' `
            -Evidence 'AllowCortana = 1 under HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search.' `
            -Impact 'Cortana processes voice and search requests in the Microsoft cloud. It is little used on Windows 10 today, but it is still enabled.' `
            -Fix 'gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Search > "Allow Cortana" = Disabled.' `
            -Confidence 'Likely'
    } else {
        Add-Skip -Message 'Cortana: the AllowCortana policy is not set, so the state depends on what the user chose and could not be read reliably'
    }

    # Copilot and Recall (Windows 11 only)

    if (-not $script:Ctx.IsWin11) {
        Add-Skip -Message 'Copilot and Recall: do not exist on Windows 10, skipped'
    } else {
        $copilotOff = ((Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot') -eq 1) -or
                      ((Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot') -eq 1)
        if ($copilotOff) {
            Add-Ok -Message 'Windows Copilot is turned off by policy (TurnOffWindowsCopilot = 1)'
        } else {
            Add-Finding -Severity 'Info' -Title 'Windows Copilot is not disabled' `
                -Evidence 'TurnOffWindowsCopilot is not set to 1 in either HKLM or HKCU under Policies\Microsoft\Windows\WindowsCopilot.' `
                -Impact 'Copilot sends what you ask it to the Microsoft cloud service. That only happens once you use it, so this is worth knowing rather than a hole.' `
                -Fix 'Settings > Personalization > Taskbar > turn off Copilot, or uninstall the app from Settings > Apps.' `
                -Confidence 'Likely'
        }

        $recallPolicyOff = ((Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'AllowRecallEnablement') -eq 0) -or
                           ((Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'TurnOffSavingSnapshots') -eq 1)

        # Recall only exists on Copilot+ hardware; absence is the normal case.
        # The DISM query costs several seconds, so policy alone settles -Fast runs.
        $recallState = $null
        if (-not ($Fast -or $recallPolicyOff)) {
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction Stop
                if ($feature) { $recallState = $feature.State.ToString() }
            } catch {
                # DISM feature query needs elevation and the feature is absent on most SKUs.
                $recallState = $null
            }
        }

        if ($null -eq $recallState) {
            if ($recallPolicyOff) {
                Add-Ok -Message 'Recall is blocked by policy (WindowsAI), regardless of whether the feature is present'
            } else {
                Add-Skip -Message 'Recall: the feature was not found on this machine (requires a Copilot+ PC, or reading it requires administrator)'
            }
        } elseif ($recallState -match 'Enabled') {
            Add-Finding -Severity 'Medium' -Title 'Recall is installed and enabled' `
                -Evidence "Get-WindowsOptionalFeature -FeatureName Recall gives State = $recallState." `
                -Impact 'Recall takes screenshots of everything you do at regular intervals and indexes the content locally. Even though the analysis is local, your entire screen history ends up sitting in a searchable database on disk.' `
                -Fix 'Settings > Privacy & security > Recall & snapshots > turn off "Save snapshots".' `
                -Confidence 'Certain'
        } else {
            Add-Ok -Message "Recall is not enabled (state: $recallState)"
        }
    }

    # error reporting

    $werPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled'
    $werLocal = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled'
    if ($werPolicy -eq 1 -or $werLocal -eq 1) {
        Add-Ok -Message 'Windows Error Reporting is turned off (Windows Error Reporting\Disabled = 1)'
    } else {
        Add-Finding -Severity 'Info' -Title 'Windows Error Reporting sends crash data' `
            -Evidence "Disabled is $(if ($null -eq $werLocal) { 'not set' } else { $werLocal }) locally and $(if ($null -eq $werPolicy) { 'not set' } else { $werPolicy }) in policy - the default is on." `
            -Impact 'When a program crashes a report is sent to Microsoft. The report can contain memory dumps from the program, so in principle whatever you were working on at the time.' `
            -Fix 'gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows Error Reporting > "Disable Windows Error Reporting". Note that this also removes the value of crash analysis for yourself.' `
            -Confidence 'Certain'
    }

    # account type and settings sync

    $acctChecked = $false
    try {
        $me = Get-LocalUser -Name $env:USERNAME -ErrorAction Stop
        $acctChecked = $true
        if ($me.PrincipalSource -eq 'MicrosoftAccount') {
            Add-Finding -Severity 'Info' -Title 'You are signed in with a Microsoft account' `
                -Evidence "Get-LocalUser $($me.Name) gives PrincipalSource = MicrosoftAccount." `
                -Impact 'The sign-in, and with it an identifiable link between the machine and you, goes through Microsoft. That is a real difference from a local account - but it is also what gives you BitLocker key backup and account recovery.' `
                -Fix 'If you want to switch: Settings > Accounts > Your info > "Sign in with a local account instead". Save the BitLocker recovery key first.' `
                -Confidence 'Certain'
        } elseif ($me.PrincipalSource -eq 'Local') {
            Add-Ok -Message "The sign-in account $($me.Name) is a local account, not a Microsoft account"
        } else {
            Add-Ok -Message "The sign-in account $($me.Name) has PrincipalSource $($me.PrincipalSource)"
        }
    } catch {
        # Get-LocalUser is absent on some minimal images and fails for domain accounts.
        $acctChecked = $false
    }
    if (-not $acctChecked) {
        Add-Skip -Message "Account type: Get-LocalUser could not look up $env:USERNAME (common on domain-joined or Entra-joined machines)"
    }

    $syncPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync'
    $syncUser = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync' -Name 'SyncPolicy'
    if ($syncPolicy -ge 2 -or $syncUser -eq 5) {
        Add-Ok -Message 'Settings sync to the Microsoft account is turned off'
    } elseif ($null -ne $syncUser -or $null -ne $syncPolicy) {
        Add-Finding -Severity 'Low' -Title 'Settings are synced to the Microsoft account' `
            -Evidence "SettingSync\SyncPolicy = $(if ($null -eq $syncUser) { 'not set' } else { $syncUser }), DisableSettingSync policy = $(if ($null -eq $syncPolicy) { 'not set' } else { $syncPolicy })." `
            -Impact 'Themes, passwords, browser settings and language choices are uploaded to your Microsoft account so they follow you between devices.' `
            -Fix 'Settings > Accounts > Windows backup > turn off "Remember my preferences".' `
            -Confidence 'Likely'
    } else {
        Add-Skip -Message 'Settings sync: found no SettingSync key (typical on machines with a local account only)'
    }

    # delivery optimization

    $doPolicy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode'
    $doLocal = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode'
    $doMode = $doPolicy
    if ($null -eq $doMode) { $doMode = $doLocal }

    if ($doMode -eq 3) {
        # Mode 3 is the only one that peers with strangers over the open internet.
        Add-Finding -Severity 'Medium' -Title 'Delivery Optimization shares downloads with unknown machines' `
            -Evidence 'DODownloadMode = 3 (HTTP combined with peering across the internet).' `
            -Impact 'The machine both fetches and sends update chunks to arbitrary other Windows machines on the internet. It uses your upload capacity and exposes the machine to unknown peers.' `
            -Fix 'Settings > Windows Update > Advanced options > Delivery Optimization > pick "Devices on my local network" or turn sharing off entirely.' `
            -Confidence 'Certain'
    } elseif ($doMode -eq 1 -or $doMode -eq 2) {
        Add-Ok -Message "Delivery Optimization only shares on the local network (DODownloadMode = $doMode)"
    } elseif ($doMode -eq 0 -or $doMode -eq 99 -or $doMode -eq 100) {
        Add-Ok -Message "Delivery Optimization only fetches from Microsoft, no sharing (DODownloadMode = $doMode)"
    } else {
        Add-Finding -Severity 'Info' -Title 'Delivery Optimization is on the default setting' `
            -Evidence 'DODownloadMode exists neither in policy nor under CurrentVersion\DeliveryOptimization\Config.' `
            -Impact 'The default on Windows 10/11 is mode 1, that is sharing only with machines on your own network. That is rarely a problem, but the value is not set explicitly.' `
            -Fix 'Settings > Windows Update > Advanced options > Delivery Optimization if you want to confirm or change the choice.' `
            -Confidence 'Likely'
    }

    # CEIP and feedback scheduled tasks

    if ($Fast) {
        Add-Skip -Message 'CEIP and feedback tasks: skipped in -Fast mode'
    } else {
        $ceipNames = 'Consolidator', 'UsbCeip', 'KernelCeipTask', 'Microsoft Compatibility Appraiser',
        'ProgramDataUpdater', 'DmClient', 'DmClientOnScenarioDownload'
        $tasksFound = $false
        $ceipReady = New-Object System.Collections.ArrayList
        $ceipOff = 0
        try {
            $allTasks = Get-ScheduledTask -ErrorAction Stop
            $tasksFound = $true
            foreach ($t in $allTasks) {
                $match = $false
                foreach ($n in $ceipNames) { if ($t.TaskName -like "$n*") { $match = $true } }
                if (-not $match) { continue }
                if ($t.State -eq 'Disabled') { $ceipOff++ } else { $null = $ceipReady.Add($t.TaskName) }
            }
        } catch {
            # ScheduledTasks module is missing on some minimal or older images.
            $tasksFound = $false
        }

        if (-not $tasksFound) {
            Add-Skip -Message 'CEIP and feedback tasks: Get-ScheduledTask is not available on this machine'
        } elseif ($ceipReady.Count -eq 0 -and $ceipOff -eq 0) {
            Add-Skip -Message 'CEIP and feedback tasks: none of the known tasks exist on this installation'
        } elseif ($ceipReady.Count -eq 0) {
            Add-Ok -Message "All $ceipOff CEIP and feedback tasks in Task Scheduler are disabled"
        } else {
            Add-Finding -Severity 'Info' -Title 'CEIP and feedback tasks are active' `
                -Evidence "$($ceipReady.Count) of $($ceipReady.Count + $ceipOff) tasks are ready to run: $($ceipReady -join ', ')." `
                -Impact 'These tasks collect compatibility and usage data and upload it on their own schedule, independent of the telemetry level in Settings. The Appraiser task is the one that builds the inventory of installed software.' `
                -Fix 'Task Scheduler > Microsoft > Windows > Customer Experience Improvement Program and \Application Experience - disable the tasks there. Requires administrator.' `
                -Confidence 'Certain'
        }
    }

    # cloud clipboard and phone link

    $clipCloudPolicy = Get-RegValue -Path $sysPolicy -Name 'AllowCrossDeviceClipboard'
    $clipUpload = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Clipboard' -Name 'CloudClipboardAutomaticUpload'

    if ($clipCloudPolicy -eq 0) {
        Add-Ok -Message 'Cloud clipboard is blocked by policy (AllowCrossDeviceClipboard = 0)'
    } elseif ($clipUpload -eq 1) {
        Add-Finding -Severity 'Medium' -Title 'Everything you copy is uploaded to the cloud' `
            -Evidence 'Clipboard\CloudClipboardAutomaticUpload = 1.' `
            -Impact 'Every single copy, including passwords you paste from a password manager, is automatically synced to your Microsoft account and to other devices.' `
            -Fix 'Settings > System > Clipboard > turn off "Sync across your devices".' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'Automatic upload of the clipboard to the cloud is not enabled'
    }

    $mmx = Get-RegValue -Path $sysPolicy -Name 'EnableMmx'
    if ($mmx -eq 0) {
        Add-Ok -Message 'Phone integration (Phone Link) is blocked by policy (EnableMmx = 0)'
    } else {
        # PowerShell 7 reaches Appx through the WinPS compatibility shim, which
        # warns on import - silence it so the check stays quiet on both hosts.
        # A failed query is not the same as an absent app, so track it separately.
        $phoneApp = $null
        $appxUsable = $true
        try {
            $phoneApp = Get-AppxPackage -Name 'Microsoft.YourPhone' -ErrorAction Stop -WarningAction SilentlyContinue
        } catch {
            $appxUsable = $false
        }
        if (-not $appxUsable) {
            Add-Skip -Message 'Phone Link: the Appx module could not be queried, so it is unknown whether the app is installed'
        } elseif ($phoneApp) {
            Add-Finding -Severity 'Info' -Title 'Phone Link is installed' `
                -Evidence "The Appx package Microsoft.YourPhone version $($phoneApp.Version) is installed, and EnableMmx is $(if ($null -eq $mmx) { 'not set' } else { $mmx })." `
                -Impact 'If the app is paired with a phone, messages, notifications, photos and call history go through the Microsoft service. If it is not paired, it sends nothing.' `
                -Fix 'Settings > Bluetooth & devices > Phone Link if you want to unlink, or uninstall the app from Settings > Apps.' `
                -Confidence 'Likely'
        } else {
            Add-Ok -Message 'Phone Link is not installed'
        }
    }
}

# Category "Updates": can the machine update itself at all, and is it doing so?
# The order is deliberate - first whether the update engine is alive (services, policy),
# then whether it actually delivers (last install, failed attempts), and finally the
# surrounding edge (support window, Store, winget). A machine with wuauserv disabled
# never has anything to show in its history, so the engine must be judged first.
function Test-UpdateHealth {
    [CmdletBinding()]
    param()

    $wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $nowUtc = [datetime]::UtcNow

    # Defender signatures are installed several times a day. Include them and
    # every machine looks freshly updated even if the last cumulative update is a year old.
    $definitionPattern = 'Security Intelligence|Antivirus|Antimalware|Defender|KB2267602|KB2310138'

    # The WU engine
    # Services first: if wuauserv is disabled, everything else in this category is noise.
    $serviceSpec = @(
        @{ Name = 'wuauserv'; Label = 'Windows Update'; Sev = 'Critical'
            Impact = 'The machine cannot download or install updates at all - it stays at the security level it has today, forever.'
        },
        @{ Name = 'UsoSvc'; Label = 'Update Orchestrator'; Sev = 'High'
            Impact = 'Nothing schedules scans or installs, so updates only arrive if you start them by hand.'
        },
        @{ Name = 'BITS'; Label = 'Background Intelligent Transfer Service (BITS)'; Sev = 'High'
            Impact = 'Update downloads have no transport and fail.'
        },
        @{ Name = 'DoSvc'; Label = 'Delivery Optimization'; Sev = 'Low'
            Impact = 'Downloads fall back to fetching directly - slower, but updates still get through.'
        }
    )

    $disabledServices = @()
    $checkedServices = 0
    foreach ($spec in $serviceSpec) {
        $svc = Get-ServiceState -Name $spec.Name
        if ($null -eq $svc) {
            Add-Skip -Message "The $($spec.Name) service does not exist on this Windows edition."
            continue
        }
        $checkedServices++
        # Manual is normal for wuauserv and DoSvc on Windows 10/11 - they are
        # trigger-started. Only Disabled is a real finding.
        if ($svc.StartType -eq 'Disabled') {
            $disabledServices += $spec.Name
            Add-Finding -Severity $spec.Sev `
                -Title "$($spec.Label) is disabled" `
                -Evidence "The $($spec.Name) service has start type Disabled (status: $($svc.Status))." `
                -Impact $spec.Impact `
                -Fix "Check in Services (services.msc) that $($spec.Name) is set to Manual or Automatic. This is often set by an 'optimization' tool." `
                -Confidence 'Certain'
        }
    }
    # Only report OK when something was actually examined - a check that could not run is not a pass.
    if ($checkedServices -gt 0 -and $disabledServices.Count -eq 0) {
        Add-Ok -Message "The Windows Update services are not disabled ($checkedServices of 4 checked)."
    }

    # policies
    $noAuto = Get-RegValue -Path $auPolicy -Name 'NoAutoUpdate'
    if ($noAuto -eq 1) {
        Add-Finding -Severity 'High' -Title 'Automatic updating is turned off by policy' `
            -Evidence "NoAutoUpdate = 1 in $auPolicy" `
            -Impact 'Windows does not scan for updates on its own. The machine sits on old security fixes until someone checks manually.' `
            -Fix 'Remove the NoAutoUpdate value, or set "Configure Automatic Updates" to Not Configured in gpedit.msc under Computer Configuration > Administrative Templates > Windows Components > Windows Update.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'No policy turning off automatic updating (NoAutoUpdate).'
    }

    # WSUS on a machine without a domain usually means updates never arrive:
    # the server does not exist on the network the machine is on.
    $wuServer = Get-RegValue -Path $wuPolicy -Name 'WUServer'
    $useWuServer = Get-RegValue -Path $auPolicy -Name 'UseWUServer'
    if ($wuServer) {
        if (-not $script:Ctx.DomainJoined) {
            Add-Finding -Severity 'High' -Title 'The machine points at a WSUS server but is not in a domain' `
                -Evidence "WUServer = $wuServer (UseWUServer = $useWuServer), PartOfDomain = False" `
                -Impact 'Windows asks an update server that is probably not reachable, and then gets nothing from Microsoft either.' `
                -Fix "Delete WUServer and WUStatusServer under $wuPolicy and UseWUServer under $auPolicy, so the machine goes straight to Windows Update." `
                -Confidence 'Likely'
        } else {
            Add-Finding -Severity 'Info' -Title 'Updates are controlled by a WSUS server' `
                -Evidence "WUServer = $wuServer on a domain-joined machine." `
                -Impact 'Which updates the machine gets is decided centrally, not by Windows Update directly.' `
                -Fix 'No action if this is how your employer set it up.' `
                -Confidence 'Certain'
        }
    }

    # Deferral: quality updates carry the security fixes, so there even a few
    # weeks is worth mentioning. Feature updates can safely be deferred a long time.
    $deferQuality = Get-RegValue -Path $wuPolicy -Name 'DeferQualityUpdatesPeriodInDays'
    if ($deferQuality -and $deferQuality -ge 7) {
        $sev = if ($deferQuality -ge 21) { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Title 'Security updates are deferred by policy' `
            -Evidence "DeferQualityUpdatesPeriodInDays = $deferQuality days." `
            -Impact "The machine waits $deferQuality days after a security fix is published before installing it. The vulnerabilities are publicly known in the meantime." `
            -Fix "Set DeferQualityUpdatesPeriodInDays to 0 under $wuPolicy, or remove the value." `
            -Confidence 'Certain'
    }

    $deferFeature = Get-RegValue -Path $wuPolicy -Name 'DeferFeatureUpdatesPeriodInDays'
    if ($deferFeature -and $deferFeature -ge 180) {
        Add-Finding -Severity 'Low' -Title 'Feature updates are deferred for a very long time' `
            -Evidence "DeferFeatureUpdatesPeriodInDays = $deferFeature days." `
            -Impact 'The machine stays on an older Windows version and reaches end of support faster than it otherwise would.' `
            -Fix "Reduce or remove DeferFeatureUpdatesPeriodInDays under $wuPolicy." `
            -Confidence 'Certain'
    }

    # A pause is meant to last up to 35 days. A start date far in the past means the pause
    # is long expired, which is harmless - but it is also the state a forgotten pause leaves
    # behind, so report it rather than dropping it silently.
    foreach ($pauseName in 'PauseQualityUpdatesStartTime', 'PauseFeatureUpdatesStartTime') {
        $pauseRaw = Get-RegValue -Path $wuPolicy -Name $pauseName
        if (-not $pauseRaw) { continue }
        # -as gives $null instead of throwing when the value is not a date.
        $pauseDate = ([string]$pauseRaw) -as [datetime]
        if ($null -ne $pauseDate) {
            $pauseDays = [math]::Round(($nowUtc - $pauseDate).TotalDays)
            if ($pauseDays -le 40) {
                Add-Finding -Severity 'Medium' -Title 'Windows Update is paused' `
                    -Evidence "$pauseName = $pauseRaw (set $pauseDays days ago)." `
                    -Impact 'No updates are installed for as long as the pause lasts.' `
                    -Fix 'Settings > Windows Update > Resume updates.' `
                    -Confidence 'Certain'
            } else {
                Add-Finding -Severity 'Low' -Title 'A long-expired Windows Update pause is still recorded' `
                    -Evidence "$pauseName = $pauseRaw (set $pauseDays days ago, well past the 35-day maximum)." `
                    -Impact 'The pause itself has expired, so updates are flowing again. The leftover value is worth knowing about because it shows updates were deliberately held back at some point, and the same key can be set again without anyone noticing.' `
                    -Fix 'Nothing needs fixing if updates are arriving. Confirm under Settings > Windows Update that it does not say "Paused".' `
                    -Confidence 'Likely'
            }
        }
    }

    # The Settings app does not write to the policy key above - it writes here. This is
    # how updates are paused on an ordinary personal machine ("Pause for 5 weeks"), and
    # reading only the policy hive misses every one of those.
    $wuUx = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    foreach ($expiryName in 'PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime') {
        $expiryRaw = Get-RegValue -Path $wuUx -Name $expiryName
        if (-not $expiryRaw) { continue }
        $expiryDate = ([string]$expiryRaw) -as [datetime]
        if ($null -eq $expiryDate) { continue }
        $daysRemaining = [math]::Round(($expiryDate.ToUniversalTime() - $nowUtc).TotalDays)
        if ($daysRemaining -gt 0) {
            Add-Finding -Severity 'High' -Title 'Windows Update is paused from Settings' `
                -Evidence "$expiryName = $expiryRaw under $wuUx - the pause runs for another $daysRemaining day(s)." `
                -Impact 'No security updates are installed until that date. This is the most common reason a personal machine quietly stops patching: someone paused updates to get past a reboot and never resumed.' `
                -Fix 'Settings > Windows Update > Resume updates.' `
                -Confidence 'Certain'
            break   # the three values describe one pause; report it once
        }
    }

    $targetRelease = Get-RegValue -Path $wuPolicy -Name 'TargetReleaseVersionInfo'
    if ($targetRelease) {
        Add-Finding -Severity 'Info' -Title 'The Windows version is pinned by policy' `
            -Evidence "TargetReleaseVersionInfo = $targetRelease (the machine runs $($script:Ctx.DisplayVersion))." `
            -Impact 'The machine will not be upgraded past this version, and stops getting updates when that version goes out of support.' `
            -Fix "Remove TargetReleaseVersionInfo under $wuPolicy when you want to follow the latest version again." `
            -Confidence 'Certain'
    }

    # history
    # The COM object is a read-only client against the local Windows Update agent.
    $searcher = $null
    $history = @()
    try {
        $searcher = (New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateSearcher()
        $totalHistory = $searcher.GetTotalHistoryCount()
        if ($totalHistory -gt 0) {
            $history = @($searcher.QueryHistory(0, [Math]::Min($totalHistory, 200)))
        }
    } catch {
        # The WU agent can be turned off, broken or blocked by policy.
        Add-Skip -Message "The Windows Update agent (COM) did not respond: $($_.Exception.Message)"
    }

    # last updated
    $lastHotfix = $null
    try {
        $lastHotfix = Get-HotFix -ErrorAction Stop |
            Where-Object { $null -ne $_.InstalledOn } |
            Sort-Object -Property InstalledOn -Descending |
            Select-Object -First 1
    } catch {
        # Get-HotFix fails on some machines where the WMI provider is damaged.
        $lastHotfix = $null
    }

    # Requiring a KB number keeps drivers out. A machine that gets new Realtek drivers
    # every week, but no cumulative update in six months, should not look healthy.
    $lastRealInstall = $history |
        Where-Object {
            $_.Operation -eq 1 -and $_.ResultCode -eq 2 -and
            $_.Title -match 'KB\d{6,}' -and $_.Title -notmatch $definitionPattern
        } |
        Sort-Object -Property Date -Descending |
        Select-Object -First 1

    $daysCandidates = @()
    $evidenceParts = @()
    if ($lastHotfix) {
        $hotfixDays = [math]::Round(((Get-Date) - $lastHotfix.InstalledOn).TotalDays)
        $daysCandidates += $hotfixDays
        $evidenceParts += "$($lastHotfix.HotFixID) installed $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd')) ($hotfixDays days ago)"
    }
    if ($lastRealInstall) {
        $historyDays = [math]::Round(($nowUtc - $lastRealInstall.Date).TotalDays)
        $daysCandidates += $historyDays
        $evidenceParts += "last KB update in the history $($lastRealInstall.Date.ToString('yyyy-MM-dd')) ($historyDays days ago)"
    }

    if ($daysCandidates.Count -eq 0) {
        Add-Skip -Message 'Found no install date - neither Get-HotFix nor the update history returned anything.'
    } else {
        # Both sources are incomplete on their own: Get-HotFix only sees CBS packages,
        # the history is wiped when WU is repaired. The most recent hit is the most honest answer.
        $daysSince = ($daysCandidates | Sort-Object)[0]
        $evidence = $evidenceParts -join '; '
        if ($daysSince -gt 60) {
            Add-Finding -Severity 'High' -Title 'The machine has not had updates in a long time' `
                -Evidence "$evidence." `
                -Impact 'Security holes Microsoft has already closed are still open on this machine.' `
                -Fix 'Settings > Windows Update > Check for updates, and watch for anything failing along the way.' `
                -Confidence 'Likely'
        } elseif ($daysSince -gt 40) {
            Add-Finding -Severity 'Low' -Title 'It has been a while since the last update' `
                -Evidence "$evidence." `
                -Impact 'A little over one normal update cycle (Microsoft ships updates every month).' `
                -Fix 'Settings > Windows Update > Check for updates.' `
                -Confidence 'Likely'
        } else {
            $when = if ($daysSince -le 0) { 'today' } elseif ($daysSince -eq 1) { 'yesterday' } else { "$daysSince days ago" }
            Add-Ok -Message "Updates are installed regularly - the last one $when."
        }
    }

    # failed attempts
    if ($history.Count -gt 0) {
        # Only the last 90 days: a failure from last year is fixed or irrelevant by now.
        $recentFailures = $history | Where-Object {
            $_.ResultCode -eq 4 -and ($nowUtc - $_.Date).TotalDays -le 90
        }
        if ($recentFailures.Count -gt 0) {
            $grouped = $recentFailures | Group-Object -Property Title | Sort-Object -Property Count -Descending
            $worst = $grouped[0]
            $hr = '0x{0:X8}' -f $worst.Group[0].HResult
            $detail = ($grouped | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count)x)" }) -join '; '
            # A single failure is often transient. Repetition means the machine
            # is stuck in a loop it never gets out of on its own.
            if ($worst.Count -ge 3) {
                Add-Finding -Severity 'High' -Title 'One update fails over and over' `
                    -Evidence "$($worst.Name) has failed $($worst.Count) times in the last 90 days, last error code $hr." `
                    -Impact 'The machine tries the same update again and again without getting anywhere, and what is in it never gets installed.' `
                    -Fix "Look up error code $hr, and run the 'Windows Update' troubleshooter in Settings > System > Troubleshoot > Other troubleshooters." `
                    -Confidence 'Certain'
            } elseif ($worst.Count -eq 2) {
                Add-Finding -Severity 'Medium' -Title 'One update has failed several times' `
                    -Evidence "$detail. Last error code $hr." `
                    -Impact 'The update has not gone in, and the attempts look like they are repeating.' `
                    -Fix "Look up error code $hr and run the Windows Update troubleshooter in Settings > System > Troubleshoot." `
                    -Confidence 'Certain'
            } else {
                Add-Finding -Severity 'Low' -Title 'One-off failed updates in the history' `
                    -Evidence "$($recentFailures.Count) failed attempts in the last 90 days: $detail. Last error code $hr." `
                    -Impact 'Often transient - typically drivers that get pulled, or the network dropping mid-download. Worth a look if the same one keeps coming back.' `
                    -Fix 'Settings > Windows Update > Update history, and see whether the attempt succeeded later.' `
                    -Confidence 'Likely'
            }
        } else {
            Add-Ok -Message 'No failed updates in the history for the last 90 days.'
        }
    }

    # pending updates
    if ($Fast) {
        Add-Skip -Message 'Scan for pending updates skipped (-Fast) - it needs the network and takes time.'
    } elseif ($null -eq $searcher) {
        Add-Skip -Message 'Could not scan for pending updates - the Windows Update agent did not respond.'
    } else {
        try {
            $pending = @(($searcher.Search('IsInstalled=0')).Updates)
            if ($pending.Count -eq 0) {
                Add-Ok -Message 'No pending updates - the machine is current against Windows Update.'
            } else {
                # Type 2 = driver. MsrcSeverity is only set on security bulletins,
                # and is therefore language-independent - unlike the category names.
                $drivers = @($pending | Where-Object { $_.Type -eq 2 })
                $security = @($pending | Where-Object { $_.Type -ne 2 -and $_.MsrcSeverity })
                $other = @($pending | Where-Object { $_.Type -ne 2 -and -not $_.MsrcSeverity })

                if ($security.Count -gt 0) {
                    $worstSev = if ($security | Where-Object { $_.MsrcSeverity -eq 'Critical' }) { 'Critical' } else { ($security[0].MsrcSeverity) }
                    $titles = ($security | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; '
                    Add-Finding -Severity 'Medium' -Title 'Security updates are waiting to be installed' `
                        -Evidence "$($security.Count) pending security update(s), worst MSRC rating $worstSev. For example: $titles" `
                        -Impact 'The holes these close stay open until the updates are installed and the machine has been restarted.' `
                        -Fix 'Settings > Windows Update > Download & install.' `
                        -Confidence 'Certain'
                } else {
                    Add-Ok -Message 'No pending security updates.'
                }

                if ($other.Count -gt 0) {
                    Add-Finding -Severity 'Info' -Title 'Other updates are pending' `
                        -Evidence "$($other.Count) pending update(s) with no security rating, for example: $(($other | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; ')" `
                        -Impact 'Ordinary bug fixes and improvements. No hurry.' `
                        -Fix 'Settings > Windows Update whenever it suits you.' `
                        -Confidence 'Certain'
                }
                if ($drivers.Count -gt 0) {
                    Add-Finding -Severity 'Info' -Title 'Driver updates are available through Windows Update' `
                        -Evidence "$($drivers.Count) pending driver(s): $(($drivers | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; ')" `
                        -Impact 'Drivers from Windows Update are often older than the ones from the vendor. Only install them if you have a problem they solve.' `
                        -Fix 'Settings > Windows Update > Advanced options > Optional updates.' `
                        -Confidence 'Certain'
                }
            }
        } catch {
            # Without a network, or when WU is policy-controlled, the scan itself fails.
            Add-Skip -Message "Scan for pending updates failed: $($_.Exception.Message)"
        }
    }

    # pending restart
    # Only the two most reliable keys. PendingFileRenameOperations and
    # WindowsUpdate\Services\Pending are set on completely healthy machines
    # and give false alarms.
    $rebootKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    $rebootHits = @($rebootKeys | Where-Object { Test-Path -Path $_ -ErrorAction SilentlyContinue })
    if ($rebootHits.Count -gt 0) {
        $uptime = $script:Ctx.UptimeHours
        $hitNames = ($rebootHits | ForEach-Object { $_.Split('\')[-1] }) -join ', '
        # Uptime decides the severity: if the machine has been up a long time after the
        # flag was set, the user has actively put off the restart and the update is half done.
        if ($uptime -gt 168) {
            Add-Finding -Severity 'High' -Title 'A restart after an update has been put off for over a week' `
                -Evidence "The registry key $hitNames exists, and the machine has been up for $uptime hours." `
                -Impact 'The update is half installed. The security fix does not take effect until the restart is done, and new updates can end up queued behind this one.' `
                -Fix 'Restart the machine (Start > Power > Restart - not just Shut down, fast startup skips part of the job).' `
                -Confidence 'Certain'
        } elseif ($uptime -gt 48) {
            Add-Finding -Severity 'Medium' -Title 'The machine is waiting for a restart after an update' `
                -Evidence "The registry key $hitNames exists, and the machine has been up for $uptime hours." `
                -Impact 'The update does not finish until the next restart.' `
                -Fix 'Restart the machine when you get the chance.' `
                -Confidence 'Certain'
        } else {
            Add-Finding -Severity 'Info' -Title 'A restart is pending after a recent update' `
                -Evidence "The registry key $hitNames exists, uptime $uptime hours." `
                -Impact 'Completely normal right after an update has been installed.' `
                -Fix 'Restart whenever it suits you.' `
                -Confidence 'Certain'
        }
    } else {
        Add-Ok -Message 'No pending restart after an update.'
    }

    # Support period: assessed once, in the system check, against a single edition-aware
    # lifecycle table. A second copy here reported the same build twice with different
    # severities whenever the two tables drifted apart.
    # Builds older than the oldest table entry never reach that check, so catch them here.
    if (-not $script:Ctx.IsServer -and $script:Ctx.Build -gt 0 -and $script:Ctx.Build -lt 19041) {
        Add-Finding -Severity 'High' -Title 'The Windows version is older than anything still in support' `
            -Evidence "Build $($script:Ctx.Build) ($($script:Ctx.Caption) $($script:Ctx.DisplayVersion))." `
            -Impact 'This version does not get security updates any more.' `
            -Fix 'Upgrade Windows. Confirm the status at learn.microsoft.com/lifecycle.' `
            -Confidence 'Likely'
    }

    # Store
    # Store apps update themselves unless policy says otherwise.
    # 2 = off, 4 = on. The value is missing on the vast majority of machines, and that is normal.
    $storeAuto = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'AutoDownload'
    if ($storeAuto -eq 2) {
        Add-Finding -Severity 'Medium' -Title 'Automatic updating of Store apps is turned off' `
            -Evidence 'AutoDownload = 2 in HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' `
            -Impact 'Apps like browser components, Terminal and Photos stay on old versions with known bugs.' `
            -Fix 'Remove the AutoDownload value, or set it to 4. In the app: Microsoft Store > profile picture > Settings > App updates.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'Store apps are allowed to update themselves.'
    }

    # drivers
    $excludeDrivers = Get-RegValue -Path $wuPolicy -Name 'ExcludeWUDriversInQualityUpdate'
    $searchOrder = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -Name 'SearchOrderConfig'
    if ($excludeDrivers -eq 1) {
        Add-Finding -Severity 'Low' -Title 'Driver updates through Windows Update are blocked' `
            -Evidence "ExcludeWUDriversInQualityUpdate = 1 in $wuPolicy" `
            -Impact 'Hardware does not get updated drivers automatically. Often set deliberately to keep WU from overwriting a working driver - in that case this is just worth knowing.' `
            -Fix "Remove ExcludeWUDriversInQualityUpdate under $wuPolicy if you want drivers from Windows Update again." `
            -Confidence 'Certain'
    } elseif ($searchOrder -eq 0) {
        Add-Finding -Severity 'Low' -Title 'Windows does not search for drivers automatically' `
            -Evidence 'SearchOrderConfig = 0 in HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' `
            -Impact 'New hardware does not get drivers by itself, and you have to fetch them manually from the vendor.' `
            -Fix 'Set SearchOrderConfig to 1, or use Advanced system settings > Hardware > Device installation settings.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'Driver updates through Windows Update are not blocked.'
    }

    # winget
    $wingetCmd = Get-Command -Name 'winget' -CommandType Application -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Add-Skip -Message 'winget is not installed - third-party programs were not assessed.'
    } elseif ($Fast) {
        Add-Skip -Message 'winget count skipped (-Fast) - it needs the network and takes time.'
    } else {
        try {
            # Listing only. --disable-interactivity keeps it from waiting for a keypress.
            # No --accept-source-agreements: accepting an agreement is a state change written
            # to the user's winget settings, and this tool promises to change nothing. On a
            # machine where the agreements have not been accepted yet, winget exits non-zero
            # and the check reports a skip instead.
            $wingetRaw = & winget upgrade --disable-interactivity 2>&1 | Out-String
            $wingetExit = $LASTEXITCODE
            if ($wingetExit -ne 0) {
                $firstLine = @($wingetRaw -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 1
                Add-Skip -Message "winget upgrade exited with code $wingetExit - package list not assessed. $firstLine"
                return
            }
            $lines = @($wingetRaw -split "`r?`n")

            # The output is a table: a header, a line of dashes, then one line
            # per package. We count the rows instead of reading the summary line, since
            # that one is translated into the system language.
            $sepIndex = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i].Trim() -match '^-{5,}$') { $sepIndex = $i; break }
            }
            $upgradable = 0
            if ($sepIndex -ge 0) {
                $counting = $false
                for ($i = $sepIndex + 1; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i].Trim()
                    if (-not $line) {
                        # Blank line after the rows: the rest is a summary, or an
                        # extra table of packages that have to be upgraded explicitly.
                        if ($counting) { break } else { continue }
                    }
                    if ($line -match '\s{2,}\S') { $upgradable++; $counting = $true }
                    elseif ($counting) { break }
                }
            }

            if ($upgradable -eq 0) {
                Add-Ok -Message 'winget reports no programs with an upgrade available.'
            } elseif ($upgradable -ge 15) {
                Add-Finding -Severity 'Medium' -Title 'Many installed programs are out of date' `
                    -Evidence "winget upgrade lists $upgradable packages with a newer version available." `
                    -Impact 'Third-party programs are a common way in - especially browsers, PDF readers and media players that do not update themselves.' `
                    -Fix 'See the list with "winget upgrade", and upgrade what you want with "winget upgrade --all".' `
                    -Confidence 'Likely'
            } else {
                Add-Finding -Severity 'Low' -Title 'Some programs have newer versions available' `
                    -Evidence "winget upgrade lists $upgradable package(s) with a newer version available." `
                    -Impact 'Normal lag. Worth doing when it suits you, especially for programs that handle files from the internet.' `
                    -Fix 'Run "winget upgrade" to see the list.' `
                    -Confidence 'Likely'
            }
        } catch {
            # winget fails without a network, and when the source agreements have not been accepted.
            Add-Skip -Message "winget could not be run: $($_.Exception.Message)"
        }
    }
}

<#
    Test-LoggingHealth - the "Logging" category.

    Answers one question: when something happens on this machine, is there anything
    left to investigate with? Log size in bytes says nothing on its own, so this
    measures the real backward reach of each log (the span between its oldest and
    newest event), what the audit policy actually records, whether process and
    PowerShell events carry usable detail, and whether Sysmon is dropping events.

    Everything here is read-only: Get-WinEvent -ListLog, event reads, registry reads,
    Get-MpPreference and "auditpol /get", which only reports the policy in effect.
#>
function Test-LoggingHealth {
    [CmdletBinding()]
    param()

    # A missing class, key or SKU must degrade into Add-Skip, never a terminating error.
    $ErrorActionPreference = 'SilentlyContinue'

    # Explicit, the way the other category functions do it. A bare $ctx does resolve to the
    # same object - $script:Ctx defines a script-scoped variable named "ctx", and PowerShell
    # variable names are case-insensitive - but relying on that reads like a bug to anyone
    # auditing this file, so bind it locally instead of leaving it to the scope chain.
    $ctx = $script:Ctx

    function Get-PolicyFlag {
        param([string]$Path, [string]$Name)
        $value = Get-RegValue -Path $Path -Name $Name
        if ($null -eq $value) { return $null }
        try { return [int]$value } catch { return $null }  # a REG_SZ where a DWORD belongs is unreadable, not "off"
    }

    function Format-Flag {
        param($Value)
        if ($null -eq $Value) { return 'not set' }
        return [string]$Value
    }

    function Measure-LogRetention {
        # The only honest measure of retention: how far apart the first and last
        # surviving event are. Configured size cannot predict this on an unknown machine.
        param([string]$LogName)
        $span = [pscustomobject]@{ Days = $null; Oldest = $null; Newest = $null }
        try {
            $newest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
            $oldest = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop
            if ($newest -and $oldest -and $newest.TimeCreated -and $oldest.TimeCreated) {
                $span.Newest = $newest.TimeCreated
                $span.Oldest = $oldest.TimeCreated
                $span.Days = [math]::Round(($newest.TimeCreated - $oldest.TimeCreated).TotalDays, 1)
            }
        } catch {
            # Empty log, no read access, or a channel that refuses -Oldest: Days stays null.
            Write-Verbose -Message ("Could not read the oldest/newest event in {0}: {1}" -f $LogName, $_.Exception.Message)
        }
        return $span
    }

    function Get-AuditState {
        # auditpol prints localised text. Recognise only the wordings we know and fall
        # back to "Unknown" rather than guessing - a wrong guess here is a false alarm.
        param([string]$Setting)
        if ([string]::IsNullOrWhiteSpace($Setting)) { return 'Unknown' }
        $text = $Setting.Trim()
        if ($text -match '(?i)success|failure|vellykk|mislykk|erfolg|fehler|fehlschl|r.ussite|.chec|correcto|.xito|riuscit|geslaagd|mislukt') { return 'On' }
        if ($text -match '(?i)^(no\s|none\b|keine\b|aucun\b|sin\b|nessun\b|geen\b|brak\b)') { return 'Off' }
        return 'Unknown'
    }

    # core event log reach
    # Windows ships 20 MB System/Application/Security logs. On a busy machine that is
    # sometimes only a few days, and nobody notices until they need last month's events.
    $coreLogs = @(
        [pscustomobject]@{ Name = 'Security';           Label = 'Security log';           NeedsAdmin = $true }
        [pscustomobject]@{ Name = 'System';             Label = 'System log';             NeedsAdmin = $false }
        [pscustomobject]@{ Name = 'Application';        Label = 'Application log';        NeedsAdmin = $false }
        [pscustomobject]@{ Name = 'Windows PowerShell'; Label = 'Windows PowerShell log'; NeedsAdmin = $false }
    )

    foreach ($core in $coreLogs) {
        $info = Get-WinEvent -ListLog $core.Name -ErrorAction SilentlyContinue
        if (-not $info) {
            # A lookup that fails means "unavailable", not "does not exist" - Security
            # requires admin and would otherwise be reported as missing.
            if ($core.NeedsAdmin -and -not $ctx.IsAdmin) {
                Add-Skip -Message ("{0} ({1}) requires administrator rights to read, and was not measured." -f $core.Label, $core.Name)
            } else {
                Add-Skip -Message ("{0} ({1}) could not be read and was not measured." -f $core.Label, $core.Name)
            }
            continue
        }

        if (-not $info.IsEnabled) {
            Add-Finding -Severity High -Title ("{0} is disabled" -f $core.Label) `
                -Evidence ("Get-WinEvent -ListLog '{0}' returns IsEnabled = False. Configured cap is {1}, and the log holds {2} events." -f $core.Name, (Format-Size -Bytes ([double]$info.MaximumSizeInBytes)), ('{0:N0}' -f $info.RecordCount)) `
                -Impact 'Nothing is written to this log any more. Events that happen from now on do not exist afterwards, no matter how long you look for them.' `
                -Fix "eventvwr.msc > find the log > right-click > Properties > tick 'Enable logging'. Requires administrator." `
                -Confidence Certain
            continue
        }

        $maxBytes = [double]$info.MaximumSizeInBytes
        $fileBytes = [double]$info.FileSize
        $fixText = ("eventvwr.msc > right-click the log > Properties > set 'Maximum log size (KB)' to at least 262144 KB (256 MB). Requires administrator. The current value is {0}." -f (Format-Size -Bytes $maxBytes))

        # A log shrunk below the Windows default is a separate signal from a full log:
        # it means someone or some policy set it, and it will roll over no matter what.
        if ($maxBytes -gt 0 -and $maxBytes -lt 5MB) {
            Add-Finding -Severity Medium -Title ("{0} has an unusually small cap" -f $core.Label) `
                -Evidence ("MaximumSizeInBytes = {0} ({1}). The Windows default for this log is 20 MB." -f $info.MaximumSizeInBytes, (Format-Size -Bytes $maxBytes)) `
                -Impact 'The log rolls over in a short time no matter how little happens. The value was set manually or by a policy, it is not the Windows default.' `
                -Fix $fixText -Confidence Certain
        }

        $fillPct = 0
        if ($maxBytes -gt 0) { $fillPct = [math]::Round(100 * $fileBytes / $maxBytes, 0) }
        # Only a log that has actually filled up is losing history. A young log on a fresh
        # installation has a short span for a harmless reason and must not be flagged.
        $hasWrapped = (([string]$info.LogMode -eq 'Circular') -and $fillPct -ge 90 -and $info.RecordCount -gt 200)

        if ($core.NeedsAdmin -and -not $script:Ctx.IsAdmin) {
            Add-Skip -Message ("Actual retention for {0} could not be measured - reading the Security log requires administrator. Configured cap is {1}." -f $core.Label, (Format-Size -Bytes $maxBytes))
            continue
        }

        if (-not $hasWrapped) {
            # A log that is nearly empty has either never filled up or was cleared, and
            # those are opposite situations. Saying "no history has been overwritten yet"
            # about a log someone wiped yesterday is the one place this script would
            # assert the reverse of the truth about a security condition, so measure the
            # span before making that claim.
            $freshSpan = Measure-LogRetention -LogName $core.Name
            if ($null -ne $freshSpan.Days -and $freshSpan.Days -lt 2 -and $info.RecordCount -gt 0) {
                Add-Finding -Severity Medium -Title ("{0} holds less than two days of events without being full" -f $core.Label) `
                    -Evidence ("Oldest event {0}, newest {1}: the log covers {2:N1} days, but the file is only {3} of {4} ({5} %) with {6} events - so it has not rolled over." -f $freshSpan.Oldest, $freshSpan.Newest, $freshSpan.Days, (Format-Size -Bytes $fileBytes), (Format-Size -Bytes $maxBytes), $fillPct, ('{0:N0}' -f $info.RecordCount)) `
                    -Impact 'A log this short that is nowhere near its size limit did not lose history by rolling over. Either the machine was installed or reset very recently, or the log was cleared - which is one of the first things done to cover tracks after an intrusion.' `
                    -Fix ("If you did not clear it yourself, look for the clear event: Get-WinEvent -FilterHashtable @{{LogName='System'; Id=104}} -MaxEvents 20 for any log, and Id 1102 in the Security log for that one. Both record who did it and when." -f $null) `
                    -Confidence Likely
            } else {
                Add-Ok -Message ("{0} has not filled up ({1} of {2} used, {3} events) - no history has been overwritten yet." -f $core.Label, (Format-Size -Bytes $fileBytes), (Format-Size -Bytes $maxBytes), ('{0:N0}' -f $info.RecordCount))
            }
            continue
        }

        $span = Measure-LogRetention -LogName $core.Name
        if ($null -eq $span.Days) {
            Add-Skip -Message ("{0} is {1:N0} % full, but the oldest and newest events could not be read, so the actual retention is unknown." -f $core.Label, $fillPct)
            continue
        }

        $evidence = ("Oldest event {0}, newest {1}: the log covers {2:N1} days. The file is {3} of a maximum {4} ({5:N0} %) with {6} events, mode {7}." -f `
                $span.Oldest, $span.Newest, $span.Days, (Format-Size -Bytes $fileBytes), (Format-Size -Bytes $maxBytes), $fillPct, ('{0:N0}' -f $info.RecordCount), $info.LogMode)

        if ($span.Days -lt 3) {
            Add-Finding -Severity High -Title ("{0} only reaches {1:N1} days back" -f $core.Label, $span.Days) `
                -Evidence $evidence `
                -Impact ("Anything older than {0:N1} days has already been overwritten. If you notice something a week later, there are no traces left to investigate." -f $span.Days) `
                -Fix $fixText -Confidence Certain
        } elseif ($span.Days -lt 7) {
            Add-Finding -Severity Medium -Title ("{0} only reaches {1:N1} days back" -f $core.Label, $span.Days) `
                -Evidence $evidence `
                -Impact 'An incident discovered after a week cannot be reconstructed. Logons, service starts and errors from last week are gone.' `
                -Fix $fixText -Confidence Certain
        } else {
            Add-Ok -Message ("{0} covers {1:N1} days back ({2} events in {3})." -f $core.Label, $span.Days, ('{0:N0}' -f $info.RecordCount), (Format-Size -Bytes $maxBytes))
        }
    }

    # detection channels on/off
    $channels = @(
        [pscustomobject]@{ Name = 'Microsoft-Windows-CodeIntegrity/Operational'; Label = 'Code Integrity'; DefaultOn = $true }
        [pscustomobject]@{ Name = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Label = 'Windows Firewall'; DefaultOn = $true }
        [pscustomobject]@{ Name = 'Microsoft-Windows-PowerShell/Operational'; Label = 'PowerShell Operational'; DefaultOn = $true }
        [pscustomobject]@{ Name = 'Microsoft-Windows-AppLocker/EXE and DLL'; Label = 'AppLocker (EXE and DLL)'; DefaultOn = $true }
        [pscustomobject]@{ Name = 'Microsoft-Windows-AppLocker/MSI and Script'; Label = 'AppLocker (MSI and Script)'; DefaultOn = $true }
        [pscustomobject]@{ Name = 'Microsoft-Windows-TaskScheduler/Operational'; Label = 'Task Scheduler'; DefaultOn = $false }
    )

    $offByDefault = @()
    $turnedOff = @()
    $enabledNames = @()
    $channelsMissing = 0
    foreach ($channel in $channels) {
        $chInfo = Get-WinEvent -ListLog $channel.Name -ErrorAction SilentlyContinue
        if (-not $chInfo) { $channelsMissing++; continue }
        if ($chInfo.IsEnabled) {
            $enabledNames += $channel.Label
            continue
        }
        $entry = ("{0} ({1})" -f $channel.Label, $channel.Name)
        if ($channel.DefaultOn) { $turnedOff += $entry } else { $offByDefault += $entry }
    }

    if ($turnedOff.Count -gt 0) {
        Add-Finding -Severity Medium -Title ("{0} detection channel(s) that are normally on have been turned off" -f $turnedOff.Count) `
            -Evidence ("Get-WinEvent -ListLog returns IsEnabled = False for: {0}." -f ($turnedOff -join '; ')) `
            -Impact 'These channels show blocked drivers, firewall changes and PowerShell activity. While they are off the events never occur at all, and they cannot be recovered afterwards.' `
            -Fix "eventvwr.msc > Applications and Services Logs > find the channel > Properties > tick 'Enable logging'. Requires administrator." `
            -Confidence Certain
    }
    if ($offByDefault.Count -gt 0) {
        Add-Finding -Severity Low -Title 'The Task Scheduler event log is not turned on' `
            -Evidence ("IsEnabled = False for: {0}. This is the Windows default, not something anyone has changed." -f ($offByDefault -join '; ')) `
            -Impact 'Without this channel you cannot see when a scheduled task was created, changed or run. Scheduled tasks are a common way for malware to survive a reboot.' `
            -Fix "eventvwr.msc > Applications and Services Logs > Microsoft > Windows > TaskScheduler > Operational > Properties > 'Enable logging'." `
            -Confidence Likely
    }
    if ($enabledNames.Count -gt 0) {
        Add-Ok -Message ("{0} detection channels are enabled: {1}." -f $enabledNames.Count, ($enabledNames -join ', '))
    }
    if ($channelsMissing -gt 0) {
        Add-Skip -Message ("{0} detection channel(s) do not exist on this Windows edition and were skipped." -f $channelsMissing)
    }

    # audit policy
    # Reading the effective policy needs SeSecurityPrivilege, i.e. an elevated session.
    $auditStates = @{}
    $auditReadable = $false
    if (-not $script:Ctx.IsAdmin) {
        Add-Skip -Message 'The audit policy (auditpol /get) could not be read because it requires administrator. Run the tool elevated to include this check.'
    } else {
        try {
            $auditRaw = auditpol.exe /get /category:* /r 2>$null
            foreach ($line in @($auditRaw)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                # Fixed column order: machine, target, subcategory, GUID, inclusion, exclusion.
                # Anchoring on the GUID column instead of the CSV header keeps this working on
                # localised Windows, where auditpol translates the header row as well.
                $parts = ([string]$line).Split(',')
                if ($parts.Count -lt 5) { continue }
                $guid = $parts[3].Trim()
                if ($guid -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') { continue }
                $auditStates[$guid.ToUpperInvariant()] = Get-AuditState -Setting $parts[4]
            }
            $auditReadable = ($auditStates.Count -gt 0)
        } catch {
            # auditpol.exe absent or refused (trimmed image, locked-down SKU): stays unreadable.
            Write-Verbose -Message ("auditpol could not be run: {0}" -f $_.Exception.Message)
        }
        if (-not $auditReadable) {
            Add-Skip -Message 'auditpol /get returned no readable rows, so the audit policy could not be assessed on this machine.'
        }
    }

    $processCreationGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    $keyAudit = @(
        [pscustomobject]@{ Guid = $processCreationGuid; Label = 'Process Creation'; Event = '4688'; Severity = 'Medium'; Why = 'Without this there is no authoritative record of which programs have actually run on the machine.' }
        [pscustomobject]@{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Label = 'Logon'; Event = '4624/4625'; Severity = 'High'; Why = 'Neither successful nor failed logons are recorded. Password guessing and account abuse become invisible.' }
        [pscustomobject]@{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Label = 'Account Lockout'; Event = '4740'; Severity = 'Medium'; Why = 'Account lockouts are not logged, and you lose the clearest sign of an ongoing password attack.' }
        [pscustomobject]@{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Label = 'Security System Extension'; Event = '4697'; Severity = 'Low'; Why = 'New services and drivers being installed produce no event. This is a common way for malware to get a foothold.' }
        [pscustomobject]@{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Label = 'Security Group Management'; Event = '4732'; Severity = 'Medium'; Why = 'You cannot see when an account is added to the Administrators group.' }
        [pscustomobject]@{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Label = 'Audit Policy Change'; Event = '4719'; Severity = 'High'; Why = 'An attacker can turn off the rest of the logging without leaving a trace anywhere.' }
    )

    $processCreationState = $null
    if ($auditReadable) {
        $unknownCount = @($auditStates.Values | Where-Object { $_ -eq 'Unknown' }).Count
        if ($unknownCount -gt ($auditStates.Count / 2)) {
            Add-Skip -Message ("The audit policy was read ({0} subcategories), but auditpol answers in a language the tool does not parse. No assessment was made, to avoid false alarms." -f $auditStates.Count)
        } else {
            $processCreationState = $auditStates[$processCreationGuid]
            $onCount = @($auditStates.Values | Where-Object { $_ -eq 'On' }).Count
            if ($onCount -eq 0) {
                Add-Finding -Severity High -Title 'The audit policy logs nothing' `
                    -Evidence ("All {0} subcategories from 'auditpol /get /category:*' are set to no auditing." -f $auditStates.Count) `
                    -Impact 'The Security log is not filled with anything at all. A completely empty audit policy is unusual and can itself be a trace of someone cleaning up.' `
                    -Fix "secpol.msc > Local Policies > Advanced Audit Policy Configuration, or use a recognised baseline. Check the result with: auditpol /get /category:*" `
                    -Confidence Certain
            } else {
                Add-Ok -Message ("The audit policy is readable, and {0} of {1} subcategories log something." -f $onCount, $auditStates.Count)
            }

            # Not everything should be on - full auditing produces a log storm that shortens
            # retention further. Only the subcategories that carry real investigative weight.
            foreach ($sub in $keyAudit) {
                if ($auditStates[$sub.Guid] -ne 'Off') { continue }
                $extraFix = ''
                if ($sub.Guid -eq $processCreationGuid) {
                    $extraFix = " Turn on 'Include command line in process creation events' at the same time, otherwise 4688 is close to worthless."
                }
                Add-Finding -Severity $sub.Severity -Title ("Auditing of {0} ({1}) is turned off" -f $sub.Label, $sub.Event) `
                    -Evidence ("auditpol reports no auditing for the subcategory {0}, GUID {1}." -f $sub.Label, $sub.Guid) `
                    -Impact $sub.Why `
                    -Fix ("secpol.msc > Local Policies > Advanced Audit Policy Configuration > '{0}' > tick Success (and Failure where it makes sense). Check afterwards with: auditpol /get /subcategory:{1}{2}" -f $sub.Label, $sub.Guid, $extraFix) `
                    -Confidence Certain
            }
            $keyOn = @($keyAudit | Where-Object { $auditStates[$_.Guid] -eq 'On' }).Count
            if ($keyOn -gt 0) {
                Add-Ok -Message ("{0} of {1} important audit subcategories are logging, among them the ones covering logon, account lockout and changes to the policy itself." -f $keyOn, $keyAudit.Count)
            }
        }
    }

    # command line in process events
    $cmdLinePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdLineFlag = Get-PolicyFlag -Path $cmdLinePath -Name 'ProcessCreationIncludeCmdLine_Enabled'
    if ($cmdLineFlag -eq 1) {
        Add-Ok -Message 'Process events (4688) contain the full command line - ProcessCreationIncludeCmdLine_Enabled = 1.'
    } elseif ($processCreationState -eq 'On') {
        # Only a finding when 4688 is actually being written; otherwise it is noise on noise.
        Add-Finding -Severity High -Title 'Process events are logged without the command line' `
            -Evidence ("Auditing of Process Creation is on, but ProcessCreationIncludeCmdLine_Enabled under {0} is {1}." -f $cmdLinePath, (Format-Flag -Value $cmdLineFlag)) `
            -Impact 'You get to know that powershell.exe or cmd.exe started, but not what they ran. It is almost always the arguments that reveal what actually happened.' `
            -Fix "gpedit.msc > Computer Configuration > Administrative Templates > System > Audit Process Creation > 'Include command line in process creation events' = Enabled." `
            -Confidence Certain
    } elseif ($processCreationState -eq 'Off') {
        Add-Skip -Message 'Command line in 4688 is not turned on, but Process Creation auditing is off anyway. Fix the auditing first, then this setting becomes relevant.'
    } else {
        Add-Skip -Message ("ProcessCreationIncludeCmdLine_Enabled is {0}, but without a readable audit policy it is unknown whether 4688 is written at all." -f (Format-Flag -Value $cmdLineFlag))
    }

    # PowerShell logging
    $psWinRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $psCoreRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore'
    $winScriptBlock = Get-PolicyFlag -Path ($psWinRoot + '\ScriptBlockLogging') -Name 'EnableScriptBlockLogging'
    $winModule = Get-PolicyFlag -Path ($psWinRoot + '\ModuleLogging') -Name 'EnableModuleLogging'
    $winTranscript = Get-PolicyFlag -Path ($psWinRoot + '\Transcription') -Name 'EnableTranscripting'
    $coreScriptBlock = Get-PolicyFlag -Path ($psCoreRoot + '\ScriptBlockLogging') -Name 'EnableScriptBlockLogging'
    $coreModule = Get-PolicyFlag -Path ($psCoreRoot + '\ModuleLogging') -Name 'EnableModuleLogging'
    $coreTranscript = Get-PolicyFlag -Path ($psCoreRoot + '\Transcription') -Name 'EnableTranscripting'

    $psEvidence = ("The Windows PowerShell key: ScriptBlockLogging={0}, ModuleLogging={1}, Transcription={2}. The PowerShellCore key: ScriptBlockLogging={3}, ModuleLogging={4}, Transcription={5}." -f `
        (Format-Flag -Value $winScriptBlock), (Format-Flag -Value $winModule), (Format-Flag -Value $winTranscript),
        (Format-Flag -Value $coreScriptBlock), (Format-Flag -Value $coreModule), (Format-Flag -Value $coreTranscript))

    if ($winScriptBlock -eq 1) {
        Add-Ok -Message 'Script Block Logging is enabled for Windows PowerShell, so decoded script blocks end up in event 4104.'
    } else {
        Add-Finding -Severity Medium -Title 'Script Block Logging is not enabled' `
            -Evidence $psEvidence `
            -Impact 'Obfuscated PowerShell commands are not logged in decoded form. Event 4104 is often the only place you can see what an attack actually did.' `
            -Fix ("gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > 'Turn on PowerShell Script Block Logging' = Enabled. Equivalent to {0}\ScriptBlockLogging\EnableScriptBlockLogging = 1 (DWORD)." -f $psWinRoot) `
            -Confidence Likely
    }

    if ($winModule -eq 1) {
        Add-Ok -Message 'Module Logging is enabled for Windows PowerShell (event 4103).'
    }
    if ($winTranscript -eq 1 -or $coreTranscript -eq 1) {
        Add-Ok -Message 'PowerShell transcription is enabled, so whole sessions are written to text files.'
    }

    # PS7 reads its policy from the PowerShellCore hive only. Enabling logging under the
    # Windows key and stopping there leaves pwsh.exe entirely unlogged - a very common trap,
    # and a silent one, because every report still shows script block logging as "on".
    $pwshPath = $null
    $pwshCmd = Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($pwshCmd) { $pwshPath = @($pwshCmd)[0].Source }
    if (-not $pwshPath) {
        foreach ($candidate in @("$env:ProgramFiles\PowerShell\7\pwsh.exe", "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe")) {
            if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { $pwshPath = $candidate; break }
        }
    }

    if (-not $pwshPath) {
        Add-Skip -Message 'PowerShell 7 (pwsh.exe) is not installed, so a separate logging policy under PowerShellCore is not relevant here.'
    } elseif ($coreScriptBlock -eq 1) {
        Add-Ok -Message ("PowerShell 7 is installed and is covered by its own script block logging under {0}." -f $psCoreRoot)
    } elseif ($winScriptBlock -eq 1) {
        Add-Finding -Severity High -Title 'PowerShell 7 is not logged, even though Windows PowerShell is' `
            -Evidence ("{0} is installed. {1}\ScriptBlockLogging\EnableScriptBlockLogging = 1, while the corresponding value under {2} is not set." -f $pwshPath, $psWinRoot, $psCoreRoot) `
            -Impact 'PowerShell 7 only reads the PowerShellCore key. Everything run through pwsh.exe is unlogged, while tools and reports show script block logging as enabled. It is a hole you believe is closed.' `
            -Fix ("Set {0}\ScriptBlockLogging\EnableScriptBlockLogging = 1 (DWORD), or use gpedit.msc > Administrative Templates > PowerShell Core > 'Turn on PowerShell Script Block Logging'." -f $psCoreRoot) `
            -Confidence Certain
    } else {
        Add-Skip -Message ("PowerShell 7 is installed ({0}), but neither the Windows key nor the PowerShellCore key has script block logging. Covered by the finding above." -f $pwshPath)
    }

    # Sysmon
    $sysmonService = $null
    foreach ($name in @('Sysmon64', 'Sysmon')) {
        $candidateSvc = Get-ServiceState -Name $name
        if ($candidateSvc) { $sysmonService = $candidateSvc; break }
    }
    $sysmonDriver = $null
    try {
        $sysmonDriver = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name LIKE 'Sysmon%'" -ErrorAction Stop)[0]
    } catch {
        # WMI trimmed or the class is unavailable; the service check alone still says enough.
        Write-Verbose -Message ("Win32_SystemDriver could not be queried: {0}" -f $_.Exception.Message)
    }
    $sysmonLogName = 'Microsoft-Windows-Sysmon/Operational'
    $sysmonLog = Get-WinEvent -ListLog $sysmonLogName -ErrorAction SilentlyContinue

    if (-not $sysmonService -and -not $sysmonLog) {
        Add-Finding -Severity Info -Title 'Sysmon is not installed' `
            -Evidence ("Neither the Sysmon/Sysmon64 service nor the channel {0} exists on this machine." -f $sysmonLogName) `
            -Impact 'The Windows logs on their own do not show process trees, which process opened a network connection, or the hash of what was run. Sysmon is what makes questions like that answerable.' `
            -Fix 'No action is needed on an ordinary machine. If you want detection data at this level, the repo has an installer for Sysmon with a ready-made configuration.' `
            -Confidence Certain
    } else {
        if ($sysmonService -and [string]$sysmonService.Status -ne 'Running') {
            Add-Finding -Severity High -Title 'The Sysmon service is not running' `
                -Evidence ("The service {0} is installed, but has status {1}." -f $sysmonService.Name, $sysmonService.Status) `
                -Impact 'Sysmon is set up, but collects nothing. You think you have detection data that does not exist.' `
                -Fix ("Start the service as administrator: sc.exe start {0}. Then check that new events are arriving in {1}." -f $sysmonService.Name, $sysmonLogName) `
                -Confidence Certain
        } elseif ($sysmonService) {
            Add-Ok -Message ("The Sysmon service {0} is running." -f $sysmonService.Name)
        }

        if ($sysmonDriver -and [string]$sysmonDriver.State -ne 'Running') {
            Add-Finding -Severity High -Title 'The Sysmon driver is not loaded' `
                -Evidence ("Win32_SystemDriver {0} has State = {1} and Started = {2}." -f $sysmonDriver.Name, $sysmonDriver.State, $sysmonDriver.Started) `
                -Impact 'Without the driver the service gets no events from the kernel. Process, network and registry events are missing entirely, even though the service looks healthy.' `
                -Fix 'Reinstall Sysmon as administrator (sysmon -accepteula -i) and check that SysmonDrv reads as Running.' `
                -Confidence Certain
        } elseif ($sysmonDriver) {
            Add-Ok -Message ("The Sysmon driver {0} is loaded and running." -f $sysmonDriver.Name)
        } elseif ($sysmonService) {
            Add-Skip -Message 'The state of the Sysmon driver could not be read from Win32_SystemDriver, so only the service was checked.'
        }

        if (-not $sysmonLog) {
            # The channel is read-protected without admin, so an empty lookup does not mean it is missing.
            if (-not $ctx.IsAdmin) {
                Add-Skip -Message ("The Sysmon channel {0} requires administrator rights to read, so size and dropped events were not assessed." -f $sysmonLogName)
            } else {
                Add-Skip -Message ("The Sysmon service exists, but the channel {0} was not found. It may be a renamed installation." -f $sysmonLogName)
            }
        } elseif (-not $sysmonLog.IsEnabled) {
            Add-Finding -Severity High -Title 'The Sysmon channel is disabled' `
                -Evidence ("{0} has IsEnabled = False, with {1} events stored from before." -f $sysmonLogName, ('{0:N0}' -f $sysmonLog.RecordCount)) `
                -Impact 'Sysmon is running, but the events are written nowhere. Everything the driver picks up goes straight in the bin.' `
                -Fix "eventvwr.msc > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational > Properties > 'Enable logging'." `
                -Confidence Certain
        } else {
            $sysmonMax = [double]$sysmonLog.MaximumSizeInBytes
            $sysmonFile = [double]$sysmonLog.FileSize
            if ($sysmonMax -gt 0 -and $sysmonMax -lt 64MB) {
                Add-Finding -Severity Medium -Title 'The Sysmon log is too small to be useful' `
                    -Evidence ("MaximumSizeInBytes for {0} is {1}, and the log holds {2} events." -f $sysmonLogName, (Format-Size -Bytes $sysmonMax), ('{0:N0}' -f $sysmonLog.RecordCount)) `
                    -Impact 'Sysmon writes many events per second. With a cap that small the log only reaches a few hours back, and it is empty exactly when you need it.' `
                    -Fix "eventvwr.msc > Sysmon > Operational > Properties > set the maximum log size to at least 524288 KB (512 MB)." `
                    -Confidence Certain
            } else {
                Add-Ok -Message ("The Sysmon channel is enabled with a cap of {0} and {1} events." -f (Format-Size -Bytes $sysmonMax), ('{0:N0}' -f $sysmonLog.RecordCount))
            }

            $sysmonWrapped = ($sysmonMax -gt 0 -and ($sysmonFile / $sysmonMax) -ge 0.9 -and $sysmonLog.RecordCount -gt 200)
            if ($sysmonWrapped) {
                $sysmonSpan = Measure-LogRetention -LogName $sysmonLogName
                if ($null -eq $sysmonSpan.Days) {
                    Add-Skip -Message 'The Sysmon log is full, but the oldest and newest events could not be read, so the retention is unknown.'
                } elseif ($sysmonSpan.Days -lt 3) {
                    Add-Finding -Severity Medium -Title ("The Sysmon log only reaches {0:N1} days back" -f $sysmonSpan.Days) `
                        -Evidence ("Oldest event {0}, newest {1}. The file is {2} of a maximum {3} with {4} events." -f $sysmonSpan.Oldest, $sysmonSpan.Newest, (Format-Size -Bytes $sysmonFile), (Format-Size -Bytes $sysmonMax), ('{0:N0}' -f $sysmonLog.RecordCount)) `
                        -Impact 'The Sysmon data is perishable here. A break-in discovered after a weekend cannot be reconstructed.' `
                        -Fix 'Raise the cap in eventvwr.msc, or limit what the configuration collects, especially RegistryEvent and FileCreateTime.' `
                        -Confidence Certain
                } else {
                    Add-Ok -Message ("The Sysmon log covers {0:N1} days back." -f $sysmonSpan.Days)
                }
            } else {
                Add-Ok -Message ("The Sysmon log has not filled up yet ({0} of {1} used)." -f (Format-Size -Bytes $sysmonFile), (Format-Size -Bytes $sysmonMax))
            }

            # Sysmon writes ID 255 for several unrelated errors, so the ID alone means nothing.
            # Only the ones whose ID field is QUEUE mean events were thrown away.
            if ($Fast) {
                Add-Skip -Message 'The search for dropped Sysmon events (ID 255) was skipped because -Fast is set.'
            } else {
                $dropped = @()
                try {
                    $dropped = @(Get-WinEvent -FilterHashtable @{ LogName = $sysmonLogName; Id = 255; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 200 -ErrorAction Stop |
                            Where-Object {
                                ($_.Properties.Count -ge 2 -and ([string]$_.Properties[1].Value) -match '(?i)queue') -or
                                ($_.Message -and $_.Message -match '(?i)dropped.*queue')
                            })
                } catch {
                    # Get-WinEvent throws instead of returning nothing when no 255 exists in the window.
                    Write-Verbose -Message ("No Sysmon events with ID 255 in the window: {0}" -f $_.Exception.Message)
                }
                if ($dropped.Count -gt 0) {
                    # When the drops happened decides what to do about them, and the two
                    # cases want opposite advice. Drops spread across many hours mean the
                    # configuration collects more than this machine can sustain, and the
                    # answer is to trim it. Drops confined to a single hour mean one load
                    # spike - a driver install, a large build, a backup - overran the
                    # driver queue once. Trimming the configuration for that costs
                    # visibility every other hour of the week and buys nothing.
                    $dropHours = @($dropped | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH') })
                    $busiestHour = ($dropHours | Sort-Object Count -Descending | Select-Object -First 1)
                    $concentration = if ($dropped.Count -gt 0) { $busiestHour.Count / $dropped.Count } else { 0 }
                    # How many events were actually lost, where the message says so.
                    $lostTotal = 0
                    foreach ($dropEvent in $dropped) {
                        if ([string]$dropEvent.Message -match 'queue:\s*\w+:(\d+)') { $lostTotal += [int]$Matches[1] }
                    }
                    $lostText = if ($lostTotal -gt 0) { " Roughly {0:N0} events were lost." -f $lostTotal } else { '' }
                    # Which event type overran the queue - that is what would have to be
                    # trimmed, and naming it saves the reader from opening the log.
                    $dropTypes = @{}
                    foreach ($dropEvent in $dropped) {
                        if ([string]$dropEvent.Message -match 'queue:\s*(\w+):(\d+)') {
                            $dropTypes[$Matches[1]] = ([int]$dropTypes[$Matches[1]]) + [int]$Matches[2]
                        }
                    }
                    $dropTypeText = if ($dropTypes.Count -gt 0) {
                        ' Mostly ' + (($dropTypes.GetEnumerator() | Sort-Object Value -Descending |
                            Select-Object -First 2 | ForEach-Object { "$($_.Key) ({0:N0})" -f $_.Value }) -join ', ') + '.'
                    } else { '' }

                    # One hour holding almost everything is a spike, not a trend.
                    $isSingleBurst = ($dropHours.Count -eq 1 -or $concentration -ge 0.9)
                    # Spread alone is not enough to call it recurring. Two drop notifications
                    # in two different hours over a week is noise, and calling that High
                    # teaches the reader to skip the finding the week it actually matters.
                    # Magnitude has to clear a floor before "the configuration is too heavy"
                    # is a fair conclusion.
                    $isOccasional = (-not $isSingleBurst -and $dropped.Count -lt 5)

                    if ($isSingleBurst) {
                        Add-Finding -Severity 'Low' -Title 'Sysmon lost events during a single burst of activity' `
                            -Evidence ("{0} events with ID 255 and QUEUE in the last 7 days, and {1} of them fall in the single hour starting {2}.{3}{4}" -f $dropped.Count, $busiestHour.Count, $busiestHour.Name, $lostText, $dropTypeText) `
                            -Impact 'The driver queue overran once, during whatever was running in that hour - a driver or feature install, a large build, or a backup are the usual causes. There is a gap in the log for that period, but the configuration is sustainable the rest of the time.' `
                            -Fix 'Nothing needs changing. Trimming the configuration to survive a one-off spike would cost visibility every other hour of the week. If drops start appearing in separate hours on different days, that is the point at which the configuration is genuinely too heavy.' `
                            -Confidence 'Likely'
                    } elseif ($isOccasional) {
                        Add-Finding -Severity 'Low' -Title 'Sysmon occasionally loses events when the queue fills' `
                            -Evidence ("{0} events with ID 255 and QUEUE in the last 7 days, in {1} separate hours.{2}{3}" -f $dropped.Count, $dropHours.Count, $lostText, $dropTypeText) `
                            -Impact 'A handful of drops across a week means the machine briefly outruns the queue now and then, leaving small gaps. It is worth knowing about, but it is not the pattern of a configuration that is too heavy for the machine.' `
                            -Fix 'Nothing needs doing yet. If the count keeps climbing week over week, trim the noisiest event type named above and reload with: sysmon -c <config.xml>' `
                            -Confidence 'Likely'
                    } else {
                        Add-Finding -Severity High -Title 'Sysmon is repeatedly losing events because the queue fills up' `
                            -Evidence ("{0} events with ID 255 and QUEUE in the last 7 days, spread over {1} separate hours.{2}{3} Newest: {4}." -f $dropped.Count, $dropHours.Count, $lostText, $dropTypeText, $dropped[0].TimeCreated) `
                            -Impact 'Events disappear before they are written, and it keeps happening. The log looks complete but has gaps exactly when the machine is busiest, which is often when something is happening. Unlike a one-off spike, this means the configuration collects more than this machine can sustain.' `
                            -Fix 'Trim the noisiest event type named above in the sysmon configuration - RegistryEvent and ImageLoad are almost always the two - and reload it as administrator with: sysmon -c <config.xml>. Then check back in a few days to confirm the drops have stopped.' `
                            -Confidence Certain
                    }
                } else {
                    Add-Ok -Message 'Sysmon has not lost events to a full queue in the last 7 days.'
                }
            }

            # What the configuration actually collects. A running service says nothing about
            # which events it is set up to record: several widely used configurations ship
            # with FileDelete, ProcessTampering and ClipboardChange commented out, so those
            # events never appear even though everything looks healthy. Rather than parsing a
            # config file the machine may not even be using any more, this measures the
            # channel itself - which event IDs have actually been written recently.
            if ($Fast) {
                Add-Skip -Message 'The check of which Sysmon event types are actually being collected was skipped because -Fast is set.'
            } else {
                # ID => what it is worth. Only events that matter for an investigation.
                # A plain hashtable, not [ordered]: an OrderedDictionary indexed with an
                # integer resolves by position rather than by key, so $table[23] would
                # return the 24th entry instead of the label for event 23.
                $sysmonWanted = @{
                    1  = 'process creation'
                    3  = 'network connection'
                    7  = 'image loaded'
                    8  = 'remote thread'
                    10 = 'process access (credential theft against lsass)'
                    11 = 'file created'
                    13 = 'registry value set'
                    22 = 'DNS query'
                    23 = 'file deleted'
                    25 = 'process tampering'
                }
                # 23 (FileDelete, archives the file) and 26 (FileDeleteDetected, logs only)
                # answer the same question. A configuration that chose 26 to avoid filling
                # the disk must not be reported as having no coverage of file deletion.
                $sysmonEquivalent = @{ 23 = 26 }
                # Some of these fire constantly and some almost never. Event 1 is written
                # on every process start, so its absence really does mean the rule group is
                # off. Events 8, 10 and 25 describe things that should not happen at all on
                # a healthy machine - a week without one is the expected result, not a gap.
                # Reporting both the same way turns a correctly configured machine into a
                # finding, which is how a check trains people to ignore it.
                #
                # Event 7 belongs here too, and for a less obvious reason. ImageLoad
                # unfiltered is the highest-volume event Sysmon produces, so every usable
                # configuration scopes it down hard - typically to DLLs loading from places
                # they have no business loading from. Scoped that way it is supposed to stay
                # silent, and a quiet week means the machine is clean rather than unmonitored.
                $sysmonRareByNature = @(7, 8, 10, 25)
                # The cap matters for what may be claimed afterwards. Get-WinEvent returns the
                # NEWEST events first, so on a busy machine 20000 records can be a few hours
                # rather than seven days - and a rule group that fires rarely would then be
                # reported missing purely because the sample is short. Measure the window the
                # sample actually covers and say that instead of assuming it is seven days.
                $seenIds = @()
                $sampleWindow = $null
                $sampleCount = 0
                try {
                    $sysmonSample = @(Get-WinEvent -FilterHashtable @{ LogName = $sysmonLogName; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 20000 -ErrorAction Stop)
                    $sampleCount = $sysmonSample.Count
                    $seenIds = @($sysmonSample | Select-Object -ExpandProperty Id -Unique)
                    $oldestInSample = ($sysmonSample | Select-Object -Last 1).TimeCreated
                    if ($oldestInSample) { $sampleWindow = ((Get-Date) - $oldestInSample).TotalHours }
                } catch {
                    # Nothing in the window, or the channel is not readable at this privilege level.
                    Write-Verbose -Message ("Could not enumerate Sysmon event IDs: {0}" -f $_.Exception.Message)
                }
                $windowText = if ($null -eq $sampleWindow) { 'the last 7 days' }
                    elseif ($sampleWindow -lt 48) { '{0:N1} hours' -f $sampleWindow }
                    else { '{0:N1} days' -f ($sampleWindow / 24) }

                if ($seenIds.Count -eq 0) {
                    Add-Skip -Message 'No Sysmon events in the last 7 days, so which event types the configuration collects could not be determined.'
                } else {
                    $missing = @($sysmonWanted.Keys | Where-Object {
                            if ($seenIds -contains $_) { return $false }
                            # An accepted stand-in counts as coverage.
                            if ($sysmonEquivalent.ContainsKey($_) -and $seenIds -contains $sysmonEquivalent[$_]) { return $false }
                            return $true
                        } | Sort-Object)
                    # Event 1 is written on every process start, so a sample this size always
                    # contains it on a live machine. Its absence means the config is filtering
                    # almost everything out, not that the machine has been idle.
                    # Split the absences by what absence actually means for that event type.
                    $missingCommon = @($missing | Where-Object { $sysmonRareByNature -notcontains $_ })
                    $missingRare = @($missing | Where-Object { $sysmonRareByNature -contains $_ })
                    $capNote = if ($sampleCount -ge 20000) { " The sample hit the 20000-event cap, so it covers only the most recent activity." } else { '' }

                    if ($missingCommon.Count -eq 0) {
                        # Everything that should be there is there. Anything still missing is
                        # an event that describes an attack, and not seeing one is the goal.
                        $rareNote = if ($missingRare.Count -gt 0) {
                            " {0} did not occur, which is the expected result - those events describe an attack rather than normal activity." -f
                                (@($missingRare | ForEach-Object { "$_ ($($sysmonWanted[$_]))" }) -join ', ')
                        } else { '' }
                        Add-Ok -Message ("Every Sysmon event type that should appear on a running machine has arrived within the last {0}.{1}" -f $windowText, $rareNote)
                    } else {
                        $missingText = (@($missingCommon | ForEach-Object { "$_ ($($sysmonWanted[$_]))" }) -join ', ')
                        $rareText = if ($missingRare.Count -gt 0) {
                            " Also not seen, but expected not to be: {0} - those describe an attack rather than normal activity." -f
                                (@($missingRare | ForEach-Object { "$_ ($($sysmonWanted[$_]))" }) -join ', ')
                        } else { '' }
                        # Event 1 fires on every process start, so a sample this size always
                        # contains it on a live machine. Its absence means the configuration
                        # is filtering nearly everything out, not that the machine was idle.
                        $severity = if ($missingCommon -contains 1 -or $missingCommon -contains 3) { 'Medium' } else { 'Low' }
                        Add-Finding -Severity $severity -Title 'Sysmon event types that should be arriving are not' `
                            -Evidence ("In a sample of {0} events covering the last {1}, the channel has written IDs {2}. Not seen: {3}.{4}{5}" -f ('{0:N0}' -f $sampleCount), $windowText, (($seenIds | Sort-Object) -join ', '), $missingText, $rareText, $capNote) `
                            -Impact 'These event types describe ordinary activity that happens continuously on a running machine, so a window this long with none of them means the rule group is not collecting. Sysmon looks healthy and the service is running, but that part of the picture is simply not being recorded.' `
                            -Fix 'Print the configuration actually in effect as administrator: sysmon -c. If the rule group for a missing ID is absent or filtered down to nothing, fix it there and reload with: sysmon -c <config.xml>. Event 16 in the channel records every configuration change.' `
                            -Confidence Likely
                    }
                }

                # Event 16 = configuration changed. It is the only record of which configuration
                # is actually in effect, which matters when the file on disk has since been edited.
                try {
                    $cfgChange = @(Get-WinEvent -FilterHashtable @{ LogName = $sysmonLogName; Id = 16 } -MaxEvents 1 -ErrorAction Stop)
                    if ($cfgChange.Count -gt 0) {
                        $cfgText = (([string]$cfgChange[0].Message) -replace '\s+', ' ').Trim()
                        if ($cfgText.Length -gt 220) { $cfgText = $cfgText.Substring(0, 220) }
                        Add-Finding -Severity Info -Title 'Sysmon configuration in effect' `
                            -Evidence ("Last configuration change {0}: {1}" -f $cfgChange[0].TimeCreated, $cfgText) `
                            -Impact 'The configuration hash identifies exactly which rule set is loaded. Compare it against the file you think you deployed - the file on disk can have been edited since without anyone reloading it.' `
                            -Confidence Certain
                    }
                } catch {
                    Write-Verbose -Message ("No Sysmon event 16 found: {0}" -f $_.Exception.Message)
                }
            }
        }
    }

    # Delegated: DeepBlueCLI
    # Everything above measures whether the logging exists and reaches far enough back.
    # This reads what is actually IN it - suspicious command lines in 4688, obfuscated
    # PowerShell in 4104, password spraying in 4625. DeepBlueCLI is GPL-3.0 and this
    # project is MIT, so it is never bundled: running it as a separate program is what
    # the GPL allows without any obligation on this code, and it also means Eric Conrad
    # and the SANS team keep the credit for their detection work.
    if ($DeepBlueCliPath) {
        if ($Fast) {
            Add-Skip -Message 'DeepBlueCLI was not run because -Fast is set - it reads whole event logs and takes minutes.'
        } else {
            # The two tools are not independent: DeepBlueCLI reads 4688 command lines and
            # 4104 script blocks, and this script is what verifies those are being written.
            # On a machine where Process Creation auditing is off, DeepBlueCLI returns a
            # clean result because there is nothing to read - which is the most misleading
            # possible outcome. Say so next to its verdict rather than letting the absence
            # of findings read as an absence of problems.
            $deepBlueBlind = @()
            # Reuse what the audit-policy check above already worked out. Re-running
            # auditpol here and matching its output for the word "success" would have been
            # wrong twice over: it is translated on a localised Windows, and $auditRaw is
            # already the audit block's variable, so writing to it again would have quietly
            # clobbered state inside the same function. $auditStates is keyed by GUID,
            # which auditpol does not translate.
            if ($auditReadable -and [string]$auditStates[$processCreationGuid] -eq 'Off') {
                $deepBlueBlind += 'Process Creation auditing is off, so there are no 4688 command lines to analyse'
            }
            if ([int](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled') -ne 1) {
                $deepBlueBlind += 'process events do not carry the command line, so 4688 analysis has almost nothing to work with'
            }
            if ([int](Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging') -ne 1) {
                $deepBlueBlind += 'Script Block Logging is off, so there are no decoded 4104 events to analyse'
            }

            $deepBlueFindings = @()
            $deepBlueFailures = @()
            foreach ($logName in 'security', 'system', 'powershell') {
                Write-Host ("    running DeepBlueCLI against the {0} log..." -f $logName) -ForegroundColor DarkGray
                # Its own output is objects; Format-List gives stable text without needing
                # to guess property names that differ between its releases.
                $deepBlueExpression = "& '$($DeepBlueCliPath -replace "'", "''")' -log $logName | Format-List | Out-String -Width 400"
                $deepBlueRun = Invoke-ExternalAudit -ScriptPath $DeepBlueCliPath -Expression $deepBlueExpression -TimeoutSeconds 600
                if (-not $deepBlueRun.Ok) {
                    $deepBlueFailures += "$logName ($($deepBlueRun.Reason))"
                    continue
                }
                # A clean log produces no output at all; anything present is a detection.
                $messages = @($deepBlueRun.Lines | Where-Object { $_ -match '(?i)^\s*Message\s*:\s*(\S.*)$' } |
                        ForEach-Object { ($_ -replace '(?i)^\s*Message\s*:\s*', '').Trim() })
                foreach ($message in $messages) { $deepBlueFindings += "[$logName] $message" }
            }

            if ($deepBlueFailures.Count -gt 0 -and $deepBlueFindings.Count -eq 0) {
                Add-Skip -Message ("DeepBlueCLI could not be run: {0}" -f ($deepBlueFailures -join '; '))
            } elseif ($deepBlueFindings.Count -eq 0 -and $deepBlueBlind.Count -gt 0) {
                # Nothing found, but it was looking at logs that are not being written.
                Add-Finding -Severity 'Medium' -Title 'DeepBlueCLI found nothing, but the logs it reads are not being collected' `
                    -Evidence ($deepBlueBlind -join '; ') `
                    -Impact 'A clean result here means nothing. DeepBlueCLI analyses the contents of 4688 and 4104 events, and those are not being recorded on this machine - so it read empty logs and reported no findings. That is the most misleading possible outcome: it looks like a pass.' `
                    -Fix 'Turn the logging on first, then run again. The audit-policy and Script Block Logging findings elsewhere in this category give the exact commands. Nothing before that point is worth acting on.' `
                    -Confidence 'Certain'
            } elseif ($deepBlueFindings.Count -eq 0) {
                Add-Ok -Message 'DeepBlueCLI found nothing suspicious in the Security, System and PowerShell logs, and the logging it depends on is switched on. Attribution: sans-blue-team/DeepBlueCLI, GPL-3.0, run as a separate program.'
            } else {
                # Group identical messages: one spraying attempt produces many lines.
                $grouped = @($deepBlueFindings | Group-Object | Sort-Object Count -Descending |
                        Select-Object -First 6 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
                Add-Finding -Severity 'High' -Title 'DeepBlueCLI flagged suspicious activity in the event logs' `
                    -Evidence (($grouped -join '; ') + $(if ($deepBlueFailures.Count -gt 0) { " Logs not read: $($deepBlueFailures -join '; ')." } else { '' })) `
                    -Impact 'These come from DeepBlueCLI (Eric Conrad / SANS, GPL-3.0), not from this script. It reads the contents of the logs rather than their configuration: long or obfuscated command lines, encoded PowerShell, repeated failed logons, and service installations that match known attack patterns. Its detections are pattern-based, so an unusual but legitimate administration tool can match.' `
                    -Fix ("Run it yourself for the full context, which includes the decoded command line: {0} -log security. Then match each hit against what you were doing at that time." -f $DeepBlueCliPath) `
                    -Confidence 'Uncertain'
            }
        }
    }

    # Defender history and log
    if (-not (Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue)) {
        Add-Skip -Message 'The Defender module (Get-MpPreference) is not present, probably because the machine uses third-party antivirus or a Windows edition without Defender.'
    } else {
        $mp = $null
        try {
            $mp = Get-MpPreference -ErrorAction Stop
        } catch {
            # Defender disabled by policy, or the service is not running.
            Write-Verbose -Message ("Get-MpPreference failed: {0}" -f $_.Exception.Message)
        }
        if (-not $mp) {
            Add-Skip -Message 'Get-MpPreference returned no data, so the Defender settings could not be read.'
        } else {
            $purge = $mp.QuarantinePurgeItemsAfterDelay
            if ($null -eq $purge) {
                Add-Skip -Message 'QuarantinePurgeItemsAfterDelay could not be read from Defender.'
            } elseif ([int]$purge -eq 0) {
                Add-Ok -Message 'Defender never deletes quarantined items automatically (QuarantinePurgeItemsAfterDelay = 0).'
            } elseif ([int]$purge -le 7) {
                Add-Finding -Severity Medium -Title ("Defender empties the quarantine after {0} days" -f [int]$purge) `
                    -Evidence ("Get-MpPreference returns QuarantinePurgeItemsAfterDelay = {0}. The Windows default is 90." -f [int]$purge) `
                    -Impact 'Both the file itself and the threat history disappear before you get a chance to look at them. If you notice something a week later, the chain of evidence is already broken.' `
                    -Fix 'Set the value back in an elevated PowerShell: Set-MpPreference -QuarantinePurgeItemsAfterDelay 90' `
                    -Confidence Certain
            } elseif ([int]$purge -lt 30) {
                Add-Finding -Severity Low -Title ("Defender keeps the quarantine for only {0} days" -f [int]$purge) `
                    -Evidence ("Get-MpPreference returns QuarantinePurgeItemsAfterDelay = {0}. The Windows default is 90." -f [int]$purge) `
                    -Impact 'The threat history is emptied earlier than normal, and older detections cannot be reviewed later.' `
                    -Fix 'Set the value back in an elevated PowerShell: Set-MpPreference -QuarantinePurgeItemsAfterDelay 90' `
                    -Confidence Likely
            } else {
                Add-Ok -Message ("Defender keeps quarantine and threat history for {0} days." -f [int]$purge)
            }
        }

        $defenderLogName = 'Microsoft-Windows-Windows Defender/Operational'
        $defenderLog = Get-WinEvent -ListLog $defenderLogName -ErrorAction SilentlyContinue
        if (-not $defenderLog) {
            Add-Skip -Message ("The channel {0} does not exist on this machine." -f $defenderLogName)
        } elseif (-not $defenderLog.IsEnabled) {
            Add-Finding -Severity High -Title 'The Defender log is disabled' `
                -Evidence ("{0} has IsEnabled = False." -f $defenderLogName) `
                -Impact 'Scan results, detections and quarantine events are not written. You cannot see afterwards what Defender reacted to, or whether it reacted at all.' `
                -Fix "eventvwr.msc > Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational > Properties > 'Enable logging'." `
                -Confidence Certain
        } else {
            Add-Ok -Message ("The Defender log is enabled with {0} events and a cap of {1}." -f ('{0:N0}' -f $defenderLog.RecordCount), (Format-Size -Bytes ([double]$defenderLog.MaximumSizeInBytes)))
        }
    }
}

# Category "Software": inventory from the three uninstall hives, the Appx registry,
# SecurityCenter2 and browser extension directories.
# Win32_Product is deliberately avoided - querying it triggers an MSI self-repair on every
# installed package, which would write to the system.
function Test-SoftwareHealth {
    [CmdletBinding()]
    param()

    # Uninstall rows carry wildly different value sets, so a bare $_.Foo would throw under
    # Set-StrictMode on any machine where that particular value happens to be absent.
    $getProp = {
        param($Row, [string]$PropName)
        if ($null -eq $Row) { return $null }
        $prop = $Row.PSObject.Properties[$PropName]
        if ($null -eq $prop) { return $null }
        return $prop.Value
    }

    # Version strings in the wild look like "6.24", "1.8.0_401", "26.02.00.0" or "23".
    # We need a comparable [Version], or $null when the string carries no usable number.
    $toVersion = {
        param([string]$Raw)
        if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
        $found = [regex]::Match($Raw, '\d+(\.\d+){0,3}')
        if (-not $found.Success) { return $null }
        $text = $found.Value
        if ($text -notmatch '\.') { $text = $text + '.0' }
        try {
            return [Version]$text
        } catch {
            # Numbers that overflow a [Version] field count as an unreadable version rather
            # than as evidence of anything.
            return $null
        }
    }

    # Architecture and version tokens are stripped first so that "Foo 1.2 (x64)" and
    # "Foo 1.7 (x64)" collapse onto the product name and can be compared as the same product.
    $normalizeName = {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
        $text = $Name
        $text = $text -replace '\((?:x64|x86|amd64|arm64|64[- ]bit|32[- ]bit)[^)]*\)', ' '
        $text = $text -replace '(?i)\b(?:x64|x86|amd64|arm64|64-bit|32-bit|edition|version)\b', ' '
        $text = $text -replace '\bv?\d+(?:[._]\d+)*\b', ' '
        $text = $text -replace '[^\p{L}\p{Nd}]+', ' '
        $text = $text -replace '\s+', ' '
        return $text.Trim().ToLowerInvariant()
    }

    # inventory
    $hiveMap = [ordered]@{
        'HKLM 64-bit' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM 32-bit' = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU'        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    }

    $programs = New-Object -TypeName System.Collections.ArrayList
    $hiveParts = New-Object -TypeName System.Collections.ArrayList
    $rawTotal = 0
    $anyHiveRead = $false

    foreach ($hiveName in $hiveMap.Keys) {
        $rows = @()
        try {
            $rows = @(Get-ItemProperty -Path (Join-Path $hiveMap[$hiveName] '*') -ErrorAction SilentlyContinue)
            $anyHiveRead = $true
        } catch {
            # WOW6432Node does not exist on 32-bit Windows, and HKCU is unreachable when
            # running without a loaded user profile.
            $rows = @()
        }

        $kept = 0
        foreach ($row in $rows) {
            $displayName = & $getProp $row 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
            $rawTotal++

            # Same filter Apps & Features applies: updates, system components and child rows
            # are not programs the user chose to install, and counting them inflates everything.
            if (& $getProp $row 'ParentKeyName') { continue }
            if (& $getProp $row 'ParentDisplayName') { continue }
            if ((& $getProp $row 'SystemComponent') -eq 1) { continue }
            $releaseType = [string](& $getProp $row 'ReleaseType')
            if ($releaseType -match '^(Security Update|Update Rollup|Hotfix|ServicePack)$') { continue }

            $kept++
            $null = $programs.Add([PSCustomObject]@{
                    Name      = ([string]$displayName).Trim()
                    Version   = [string](& $getProp $row 'DisplayVersion')
                    Publisher = ([string](& $getProp $row 'Publisher')).Trim()
                    Location  = [string](& $getProp $row 'InstallLocation')
                    Uninstall = [string](& $getProp $row 'UninstallString')
                    Hive      = $hiveName
                })
        }
        $null = $hiveParts.Add("$hiveName $kept")
    }

    if (-not $anyHiveRead -or $programs.Count -eq 0) {
        Add-Skip -Message 'Could not read the uninstall registry - the whole software inventory was skipped.'
        return
    }

    Add-Finding -Severity 'Info' `
        -Title 'Software inventory' `
        -Evidence "$($programs.Count) installed programs ($($hiveParts -join ', ')); $rawTotal rows in total before filtering out updates and system components." `
        -Impact 'Every installed program is attack surface and something that has to be kept updated.' `
        -Confidence 'Certain'

    # duplicates
    # Redistributables, runtimes, SDKs and language packs are MEANT to sit side by side in many
    # versions at once. Flagging them would be pure noise on a perfectly healthy machine.
    $sideBySideOk = '(?i)visual c\+\+|redistributable|runtime|\.net|dotnet|language pack|software development kit|windows sdk|windows app sdk|driver|update for|hotfix|security update|windows subsystem'

    $dupGroups = @($programs |
        Where-Object { $_.Name -notmatch $sideBySideOk -and $_.Publisher } |
        Group-Object -Property { (& $normalizeName $_.Name) + '||' + $_.Publisher.ToLowerInvariant() } |
        Where-Object { $_.Count -gt 1 -and ($_.Name -split '\|\|')[0].Length -ge 3 })

    $realDuplicates = New-Object -TypeName System.Collections.ArrayList
    foreach ($group in $dupGroups) {
        $groupVersions = @($group.Group | ForEach-Object { $_.Version } | Sort-Object -Unique)
        $groupHives = @($group.Group | ForEach-Object { $_.Hive } | Sort-Object -Unique)
        # One product at one version registered in both the 32- and 64-bit hive is a normal
        # architecture pair, not two competing installations.
        if ($groupVersions.Count -le 1 -and $groupHives.Count -gt 1) { continue }
        $null = $realDuplicates.Add($group)
    }

    if ($realDuplicates.Count -gt 0) {
        $dupExamples = @($realDuplicates | Select-Object -First 3 | ForEach-Object {
                ($_.Group | ForEach-Object { "$($_.Name) [$($_.Version)]" }) -join ' + '
            })
        Add-Finding -Severity 'Low' `
            -Title 'Same program installed in several versions' `
            -Evidence "$($realDuplicates.Count) product(s) with parallel installations: $($dupExamples -join ' | ')" `
            -Impact 'The old version sits there unpatched, and file associations can point at the wrong version. It also takes up disk space.' `
            -Fix 'Settings > Apps > Installed apps: uninstall the oldest versions once you have confirmed nothing uses them.' `
            -Confidence 'Likely'
    } else {
        Add-Ok -Message 'No real duplicates in the program list (side-by-side runtimes such as Visual C++ are not counted as duplicates).'
    }

    # orphaned uninstall rows
    $orphans = New-Object -TypeName System.Collections.ArrayList
    foreach ($program in $programs) {
        $target = $null

        $location = $program.Location
        if ($location) {
            $location = $location.Trim().Trim('"')
            if ($location.Length -gt 3) { $target = $location }
        }

        if (-not $target) {
            $uninstall = $program.Uninstall
            # msiexec strings hold a product code, not a path, so there is nothing to test.
            if ($uninstall -and $uninstall -notmatch '(?i)msiexec') {
                $trimmed = $uninstall.Trim()
                if ($trimmed.StartsWith('"')) {
                    $target = ($trimmed.Substring(1) -split '"', 2)[0]
                } elseif ($trimmed -match '^([A-Za-z]:\\[^\s]+\.(?:exe|msi))') {
                    $target = $Matches[1]
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        # A UNC path or a path on a detached/removable drive proves nothing about the row.
        if ($target.StartsWith('\\')) { continue }

        # Malformed, over-long and reparse-looped paths can make the path APIs throw outright,
        # and a row we cannot test is never reported as an orphan.
        $targetMissing = $false
        try {
            $pathRoot = [System.IO.Path]::GetPathRoot($target)
            if ([string]::IsNullOrWhiteSpace($pathRoot)) { continue }
            if (-not (Test-Path -LiteralPath $pathRoot -ErrorAction SilentlyContinue)) { continue }
            $targetMissing = -not (Test-Path -LiteralPath $target -ErrorAction SilentlyContinue)
        } catch {
            continue
        }

        if ($targetMissing) { $null = $orphans.Add("$($program.Name) -> $target") }
    }

    if ($orphans.Count -gt 0) {
        Add-Finding -Severity 'Low' `
            -Title 'Orphaned uninstall entries' `
            -Evidence "$($orphans.Count) entry(-ies) point at paths that do not exist: $((@($orphans) | Select-Object -First 3) -join ' | ')" `
            -Impact 'The program was removed without cleaning up after itself. The entry gets in the way of inventory lists, update tools and "winget upgrade".' `
            -Fix 'Confirm the program really is gone, then delete the matching key under HKLM or HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall by hand.' `
            -Confidence 'Likely'
    } else {
        Add-Ok -Message 'Every uninstall entry points at a path that exists.'
    }

    # outdated / end-of-life software
    $riskyRules = @(
        @{
            # Version-gated on purpose: a current JDK 21 also starts with "Java", and calling
            # that end-of-life would be exactly the kind of false alarm this tool must avoid.
            # The lookahead drops "Java Auto Updater", which is a helper, not a runtime.
            Pattern    = '(?i)^(java|jre|jdk)\b(?!.*auto updater)'
            Below      = [Version]'9.0'
            Severity   = 'Medium'
            Confidence = 'Uncertain'
            Title      = 'Java 8 or older installed - check whether this build is still getting updates'
            Why        = 'Java 8 is not automatically out of support: Oracle still ships free public updates for personal use and sells Extended Support into 2030, and Temurin, Zulu and Corretto maintain their own Java 8 builds. What matters is whether THIS install still gets updates, and desktop Java has a long history of actively exploited sandbox escapes, so an abandoned one is worth finding. The check cannot tell the variants apart from the registry alone.'
            Fix        = 'Check the build with "java -version" and confirm its vendor still publishes updates. Uninstall via Settings > Apps if no program needs Java. If you do need it, a maintained current release is: winget install EclipseAdoptium.Temurin.21.JRE'
        }
        @{
            Pattern    = '(?i)adobe (flash|shockwave)'
            Below      = $null
            Severity   = 'High'
            Confidence = 'Certain'
            Title      = 'Adobe Flash or Shockwave installed'
            Why        = 'Flash reached end of life on 2020-12-31 and Shockwave in 2019. Neither gets security fixes, and both have known, exploited vulnerabilities left open.'
            Fix        = 'Uninstall via Settings > Apps > Installed apps. No modern browser can run the content anyway.'
        }
        @{
            Pattern    = '(?i)^python 2\.'
            Below      = $null
            Severity   = 'Medium'
            Confidence = 'Certain'
            Title      = 'Python 2 installed'
            Why        = 'Python 2 reached end of life on 2020-01-01. Neither the interpreter nor the pip ecosystem around it gets security fixes any more.'
            Fix        = 'Uninstall Python 2 if no scripts need it, and use Python 3: winget install Python.Python.3.12'
        }
        @{
            Pattern    = '(?i)quicktime'
            Below      = $null
            Severity   = 'High'
            Confidence = 'Certain'
            Title      = 'Apple QuickTime for Windows installed'
            Why        = 'Apple stopped supporting QuickTime for Windows in 2016 with known RCE vulnerabilities left unpatched. US-CERT recommended uninstalling it as the only remedy at the time.'
            Fix        = 'Uninstall via Settings > Apps. VLC and Media Player play .mov without QuickTime installed.'
        }
        @{
            Pattern    = '(?i)^winrar'
            Below      = [Version]'7.23'
            Severity   = 'High'
            Confidence = 'Likely'
            Title      = 'WinRAR older than 7.23'
            Why        = 'WinRAR has a run of archive-extraction flaws that a single crafted archive can trigger: CVE-2023-38831 (code execution on double-clicking an ordinary-looking file inside the archive) and CVE-2025-8088 (path traversal, exploited in the wild before 7.13). 7.23 adds fixes for a RAR5 recovery-volume heap overflow and a symbolic link that escapes the destination folder.'
            Fix        = 'Upgrade from rarlab.com, or run: winget upgrade RARLab.WinRAR'
        }
        @{
            Pattern    = '(?i)^7-?zip'
            Below      = [Version]'26.01'
            Severity   = 'High'
            Confidence = 'Likely'
            Title      = '7-Zip older than 26.01'
            Why        = 'CVE-2026-48095 (CVSS 8.8) is a heap overflow in the NTFS handler, which is on by default and runs on any crafted image regardless of file extension - fixed in 26.01. Before that, CVE-2025-11001 and CVE-2025-11002 (CVSS 7.0) let a crafted ZIP write outside the extraction folder through a symbolic link, with public proof-of-concept code but no confirmed exploitation in the wild - fixed in 25.00. Versions before 24.09 also lose Mark-of-the-Web on extracted files, so downloads no longer trigger SmartScreen.'
            Fix        = 'Upgrade from 7-zip.org, or run: winget upgrade 7zip.7zip'
        }
        @{
            Pattern    = '(?i)visual c\+\+ 200[58]'
            Below      = $null
            Severity   = 'Low'
            Confidence = 'Uncertain'
            Title      = 'Visual C++ 2005/2008 Redistributable installed'
            Why        = 'These runtimes are out of support and get no fixes. They are usually left behind because some old program needs them, and are not in themselves a sign of anything wrong.'
            Fix        = 'Do not remove them at random. Work out which program needs them first; if that program is already uninstalled, the runtime can be removed via Settings > Apps.'
        }
    )

    $riskyHits = 0
    foreach ($rule in $riskyRules) {
        $ruleHits = @($programs | Where-Object { $_.Name -match $rule.Pattern })
        # One finding per rule, not per matching program. The x86 and x64 Visual C++ 2008
        # runtimes are two rows in the registry and one fact about the machine, and emitting
        # them separately put two findings with an identical title next to each other in the
        # report. Same for a machine carrying several old Java installs.
        $ruleEvidence = @()
        $ruleConfidence = $rule.Confidence
        foreach ($hit in $ruleHits) {
            $hitVersion = & $toVersion $hit.Version
            if ($null -eq $hitVersion) { $hitVersion = & $toVersion $hit.Name }

            if ($null -ne $rule.Below) {
                if ($null -ne $hitVersion) {
                    if ($hitVersion -ge $rule.Below) { continue }
                } else {
                    # Without a readable version we cannot assert the install is actually too old,
                    # so the finding drops to Uncertain instead of being overstated. One unreadable
                    # version among several is enough to soften the whole finding.
                    $ruleConfidence = 'Uncertain'
                }
            }

            $shownVersion = $hit.Version
            if ([string]::IsNullOrWhiteSpace($shownVersion)) { $shownVersion = 'no version given in the registry' }
            $shownPublisher = $hit.Publisher
            if ([string]::IsNullOrWhiteSpace($shownPublisher)) { $shownPublisher = 'unknown publisher' }
            $ruleEvidence += "$($hit.Name), version $shownVersion, publisher $shownPublisher ($($hit.Hive))"
        }

        if ($ruleEvidence.Count -eq 0) { continue }
        $riskyHits += $ruleEvidence.Count
        $ruleTitle = if ($ruleEvidence.Count -gt 1) { "$($rule.Title) - $($ruleEvidence.Count) installations" } else { $rule.Title }
        Add-Finding -Severity $rule.Severity `
            -Title $ruleTitle `
            -Evidence (($ruleEvidence | Select-Object -First 6) -join '; ') `
            -Impact $rule.Why `
            -Fix $rule.Fix `
            -Confidence $ruleConfidence
    }

    if ($riskyHits -eq 0) {
        Add-Ok -Message 'No known end-of-life or vulnerable software found (Java 8, Flash, Python 2, QuickTime, WinRAR below 7.23, 7-Zip below 26.01).'
    }

    # IE has been retired since June 2022. On Windows 11 only a stub remains that redirects to
    # Edge, so reporting it there would be a false alarm on a completely stock machine.
    $programFilesDir = [Environment]::GetFolderPath('ProgramFiles')
    $ieInstalled = $false
    $iePath = ''
    if (-not $script:Ctx.IsWin11 -and -not [string]::IsNullOrWhiteSpace($programFilesDir)) {
        try {
            # Join-Path throws on an empty base path, and GetFolderPath can return '' in odd contexts.
            $iePath = Join-Path $programFilesDir 'Internet Explorer\iexplore.exe'
            $ieInstalled = Test-Path -LiteralPath $iePath -ErrorAction SilentlyContinue
        } catch {
            # Unreadable Program Files path: treat IE as not detectable rather than as present.
            $ieInstalled = $false
        }
    }
    if ($ieInstalled) {
        $ieVersion = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer' -Name 'svcVersion'
        if ([string]::IsNullOrWhiteSpace($ieVersion)) { $ieVersion = 'unknown' }
        Add-Finding -Severity 'Low' `
            -Title 'Internet Explorer is still installed' `
            -Evidence "$iePath exists, svcVersion = $ieVersion." `
            -Impact 'IE11 is retired and gets no feature fixes. The MSHTML engine behind it is still used in phishing chains against documents that open HTML content.' `
            -Fix 'Settings > Apps > Optional features > Internet Explorer 11 > Uninstall.' `
            -Confidence 'Likely'
    }

    # software shipping kernel drivers
    # Reported as Info, never as an accusation: these tools load signed drivers with direct
    # MMIO/MSR access, and several such drivers have historically been abused for privilege
    # escalation by attackers who already had a foothold (BYOVD).
    $kernelToolPattern = '(?i)armoury crate|ai suite|asus (aura|gpu tweak)|msi center|dragon center|mystic light|afterburner|rivatuner|gigabyte (app center|control center)|rgb fusion|easytune|@bios|icue|corsair utility|nzxt cam|signalrgb|openrgb|razer synapse|steelseries gg|aorus engine|thermaltake|core temp|hwinfo|aida64|cpu-?z|throttlestop|wemod'
    $kernelToolHits = @($programs | Where-Object { $_.Name -match $kernelToolPattern })
    if ($kernelToolHits.Count -gt 0) {
        $kernelToolList = @($kernelToolHits | Select-Object -First 6 | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; '
        Add-Finding -Severity 'Info' `
            -Title 'Tools that install kernel drivers of their own' `
            -Evidence "$($kernelToolHits.Count) hits: $kernelToolList" `
            -Impact 'RGB, fan and monitoring tools from motherboard and peripheral vendors install signed drivers with direct hardware access. Several such drivers are known to have been abused for privilege escalation by attackers who already had a foothold (BYOVD). That is not a sign of compromise, but it is code that should be kept updated or removed if you do not use it.' `
            -Fix 'Keep only what you actually use, and update it from the vendor download page. Uninstall the rest via Settings > Apps.' `
            -Confidence 'Certain'
    } else {
        Add-Ok -Message 'No known RGB, fan or overclocking tools with kernel drivers of their own installed.'
    }

    # multiple AV engines or "PC optimizers" side by side
    $avVendorPattern = '(?i)\b(norton|mcafee|avast|avg antivirus|kaspersky|bitdefender|eset|trend micro|sophos|f-secure|malwarebytes|panda (security|dome)|webroot|comodo|avira|360 total security|bullguard|g ?data|quick heal|totalav)\b'
    $avHits = @($programs | Where-Object { $_.Name -match $avVendorPattern })
    $avFamilies = @($avHits | ForEach-Object { ([regex]::Match($_.Name, $avVendorPattern)).Value.Trim().ToLowerInvariant() } | Sort-Object -Unique)

    $registeredAv = @()
    if ($script:Ctx.IsServer) {
        Add-Skip -Message 'SecurityCenter2 does not exist on Server SKUs - the number of registered antivirus products was not read.'
    } else {
        try {
            $registeredAv = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop |
                ForEach-Object { [string](& $getProp $_ 'displayName') } |
                Where-Object { $_ -and $_ -notmatch '(?i)windows defender|microsoft defender' })
        } catch {
            # SecurityCenter2 is absent from some hardened images and VM templates.
            $registeredAv = @()
        }
    }

    if ($avFamilies.Count -ge 2 -or $registeredAv.Count -ge 2) {
        $avInstalledNames = @($avHits | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
        $avEvidence = New-Object -TypeName System.Collections.ArrayList
        if ($registeredAv.Count -gt 0) { $null = $avEvidence.Add("registered in Windows Security Center: $($registeredAv -join ', ')") }
        if ($avHits.Count -gt 0) { $null = $avEvidence.Add("installed: $avInstalledNames") }
        Add-Finding -Severity 'High' `
            -Title 'Several antivirus products installed at the same time' `
            -Evidence ($avEvidence -join ' | ') `
            -Impact 'Two real-time engines fight over the same filesystem and memory hooks. The usual result is hangs on file operations, one engine quarantining the files of the other, and worse real protection than with a single product.' `
            -Fix 'Keep one product. Uninstall the rest via Settings > Apps, then run the cleanup tool from that vendor - AV uninstalls often leave filter drivers behind.' `
            -Confidence 'Likely'
    } elseif ($avFamilies.Count -eq 1 -or $registeredAv.Count -eq 1) {
        $singleAv = $registeredAv
        if ($singleAv.Count -eq 0) { $singleAv = @($avHits | Select-Object -First 3 | ForEach-Object { $_.Name }) }
        Add-Ok -Message "Only one third-party security product installed: $($singleAv -join ', ')"
    } else {
        Add-Ok -Message 'No third-party antivirus installed alongside Microsoft Defender.'
    }

    $optimizerPattern = '(?i)ccleaner|advanced systemcare|iobit|driver booster|driver easy|driverpack|driver ?updater|glary utilities|wise (care|registry)|auslogics|system mechanic|restoro|reimage|winoptimizer|tuneup|pc ?(cleaner|optimizer|speedup|booster)|smart defrag|registry (cleaner|reviver)|slimware'
    $optimizerHits = @($programs | Where-Object { $_.Name -match $optimizerPattern })
    if ($optimizerHits.Count -gt 0) {
        $optimizerSeverity = 'Medium'
        if ($optimizerHits.Count -ge 2) { $optimizerSeverity = 'High' }
        $optimizerList = @($optimizerHits | Select-Object -First 5 | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; '
        Add-Finding -Severity $optimizerSeverity `
            -Title 'Registry cleaners or driver updaters installed' `
            -Evidence "$($optimizerHits.Count) hits: $optimizerList" `
            -Impact 'These tools run with high privileges, pull drivers outside Windows Update and rummage around in the same registry hooks security software uses. Several of them at once causes outright conflicts, and driver updaters are a known source of wrong or trojanized drivers.' `
            -Fix 'Uninstall via Settings > Apps. Windows Update and the vendor driver page cover everything these promise.' `
            -Confidence 'Likely'
    } else {
        Add-Ok -Message 'No registry cleaners, "PC optimizers" or driver updater programs installed.'
    }

    # browser extensions
    $localAppData = $env:LOCALAPPDATA
    if ($Fast) {
        Add-Skip -Message 'Browser extensions and Store apps were skipped because -Fast is set.'
    } elseif ([string]::IsNullOrWhiteSpace($localAppData)) {
        # Join-Path throws on an empty base path, and LOCALAPPDATA is unset under some service accounts.
        Add-Skip -Message 'The LOCALAPPDATA environment variable is not set - browser extensions and Store apps were not counted.'
    } else {
        # Extensions shipped with the browser are not a user choice, so they are not counted.
        $builtInExtensions = @(
            'nmmhkkegccagdldgiimedpiccmgmieda', # Chrome Web Store Payments (component)
            'ghbmnnjooekpmoecnnnilnnbdlolhkhi', # Google Docs Offline (preinstalled)
            'jmjflgjpcpepeafmmgdpfkogkghcpiha'  # Edge preinstalled component
        )

        $browserRoots = [ordered]@{
            'Chrome'  = (Join-Path $localAppData 'Google\Chrome\User Data')
            'Edge'    = (Join-Path $localAppData 'Microsoft\Edge\User Data')
            'Brave'   = (Join-Path $localAppData 'BraveSoftware\Brave-Browser\User Data')
            'Vivaldi' = (Join-Path $localAppData 'Vivaldi\User Data')
        }

        $browsersSeen = 0
        $extensionParts = New-Object -TypeName System.Collections.ArrayList
        $extensionMax = 0

        $browserWalkFailed = $false
        foreach ($browserName in $browserRoots.Keys) {
            # Roaming and redirected profiles can produce access-denied, path-too-long and
            # reparse-point loops that surface as terminating errors, so each browser is
            # walked inside its own guard and a failure only costs that one browser.
            try {
                $browserRoot = $browserRoots[$browserName]
                if (-not (Test-Path -LiteralPath $browserRoot -ErrorAction SilentlyContinue)) { continue }
                $browsersSeen++

                # Profile folders are identified by having an Extensions subfolder, which filters
                # out ShaderCache, Crashpad, Guest Profile and the rest of the User Data clutter.
                $profileDirs = @(Get-ChildItem -LiteralPath $browserRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Extensions') -ErrorAction SilentlyContinue })

                foreach ($profileDir in $profileDirs) {
                    $extensionDirs = @(Get-ChildItem -LiteralPath (Join-Path $profileDir.FullName 'Extensions') -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $builtInExtensions -notcontains $_.Name })
                    if ($extensionDirs.Count -eq 0) { continue }
                    if ($extensionDirs.Count -gt $extensionMax) { $extensionMax = $extensionDirs.Count }
                    $null = $extensionParts.Add("$browserName/$($profileDir.Name): $($extensionDirs.Count)")
                }
            } catch {
                $browserWalkFailed = $true
            }
        }
        if ($browserWalkFailed) {
            Add-Skip -Message 'One or more browser profiles could not be read - the extension count below may be too low.'
        }

        if ($browsersSeen -eq 0) {
            Add-Skip -Message 'Found no Chromium-based browser profiles for this user - extensions were not counted.'
        } elseif ($extensionParts.Count -eq 0) {
            Add-Ok -Message 'No third-party extensions installed in the Chromium-based browsers.'
        } else {
            $extensionSeverity = 'Info'
            if ($extensionMax -ge 15) { $extensionSeverity = 'Low' }
            Add-Finding -Severity $extensionSeverity `
                -Title 'Browser extensions installed' `
                -Evidence "$($extensionParts -join ', ') (largest profile has $extensionMax extensions; preinstalled components are not counted)" `
                -Impact 'An extension with read access to all sites can read session cookies and inject content into the pages you visit. Sold or hijacked extensions are one of the most common routes to session hijacking. The folders also count leftovers from extensions you have turned off.' `
                -Fix 'Go through chrome://extensions and edge://extensions, remove what you do not use, and check the permissions of the rest.' `
                -Confidence 'Likely'
        }

        # Store apps
        $appxAll = $null
        try {
            $appxAll = @(Get-AppxPackage -ErrorAction Stop)
        } catch {
            # The Appx stack is missing on Server Core and in some stripped-down images.
            $appxAll = $null
        }

        if ($null -eq $appxAll) {
            Add-Skip -Message 'Get-AppxPackage is not available on this machine - Store apps were not counted.'
        } else {
            $appxUserApps = @($appxAll | Where-Object {
                    $isFramework = & $getProp $_ 'IsFramework'
                    $signatureKind = [string](& $getProp $_ 'SignatureKind')
                    (-not $isFramework) -and $signatureKind -ne 'System'
                })

            $bloatPatterns = @(
                'Clipchamp', 'BingNews', 'BingWeather', 'MicrosoftSolitaireCollection', 'ZuneVideo',
                'SkypeApp', 'YourPhone', 'Todos', 'PowerAutomateDesktop', 'DevHome', 'QuickAssist',
                'MixedReality.Portal', '549981C3F5F10', 'GetHelp', 'Getstarted', 'WindowsFeedbackHub',
                'OutlookForWindows', 'MSTeams', 'Disney', 'SpotifyAB', 'Facebook', 'TikTok',
                'Netflix', 'AmazonVideo', 'king.com', 'Instagram', 'LinkedIn', 'Duolingo', 'McAfee'
            )
            $bloatFound = New-Object -TypeName System.Collections.ArrayList
            foreach ($bloatPattern in $bloatPatterns) {
                $bloatHit = @($appxAll | Where-Object { ([string](& $getProp $_ 'Name')) -like "*$bloatPattern*" })
                if ($bloatHit.Count -gt 0) { $null = $bloatFound.Add([string](& $getProp $bloatHit[0] 'Name')) }
            }

            $appxEvidence = "$($appxAll.Count) Appx packages in total, of which $($appxUserApps.Count) are apps (the rest are frameworks and system components)."
            if ($bloatFound.Count -gt 0) {
                $appxEvidence += " Often unwanted on a new machine: $((@($bloatFound) | Select-Object -First 10) -join ', ')"
            }

            Add-Finding -Severity 'Info' `
                -Title 'Store apps installed' `
                -Evidence $appxEvidence `
                -Impact 'Preinstalled Store apps are rarely a security problem, but they take up disk space, run background tasks and send notifications you never asked for.' `
                -Fix 'Settings > Apps > Installed apps: right-click and uninstall what you do not use. Almost all of it can be installed again from the Microsoft Store later.' `
                -Confidence 'Certain'
        }
    }

    # package manager check
    $wingetCommand = @(Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue)
    if ($wingetCommand.Count -gt 0) {
        Add-Ok -Message "winget is available as a package manager ($($wingetCommand[0].Source)) - updates can be run in one go."
    } else {
        Add-Finding -Severity 'Info' `
            -Title 'winget is not available' `
            -Evidence 'Found no winget.exe in PATH for this user.' `
            -Impact 'Without a package manager every program has to be updated by hand from its own website. In practice that means several programs stay outdated longer than they should.' `
            -Fix 'Install "App Installer" from the Microsoft Store. After that, "winget upgrade --include-unknown" shows everything with a newer version available.' `
            -Confidence 'Certain'
    }

    # Microsoft Office / Click-to-Run update state. Office updates on its own schedule,
    # entirely separately from Windows Update, and a Click-to-Run installation with updates
    # disabled keeps working while quietly never receiving a fix again. Office is the most
    # attacked application surface on a Windows machine, so this matters more than the
    # third-party programs the inventory above already covers.
    $c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $c2rVersion = Get-RegValue -Path $c2rKey -Name 'VersionToReport'
    if ([string]::IsNullOrWhiteSpace([string]$c2rVersion)) {
        Add-Skip -Message 'Microsoft Office (Click-to-Run) is not installed, so its update state was not assessed.'
    } else {
        $c2rEnabled = Get-RegValue -Path $c2rKey -Name 'UpdatesEnabled'
        $c2rChannel = Get-RegValue -Path $c2rKey -Name 'CDNBaseUrl'
        $c2rLastUpdate = Get-RegValue -Path $c2rKey -Name 'LastUpdateSuccessTime'
        $c2rEvidence = "Office version $c2rVersion"
        if ($c2rLastUpdate) { $c2rEvidence += ", last successful update $c2rLastUpdate" }
        if ($c2rChannel) { $c2rEvidence += ", channel $c2rChannel" }

        if ([string]$c2rEnabled -match '(?i)^false$') {
            Add-Finding -Severity 'High' -Title 'Microsoft Office updates are turned off' `
                -Evidence ("UpdatesEnabled = False under {0}. {1}" -f $c2rKey, $c2rEvidence) `
                -Impact 'Office does not update through Windows Update - it has its own updater, and that updater is switched off. Word and Excel documents are the most common way a machine gets attacked from the outside, and this installation will never receive another fix.' `
                -Fix 'Open any Office application > File > Account > Update Options > Enable Updates. Or set UpdatesEnabled to True under the Click-to-Run Configuration key.' `
                -Confidence 'Certain'
        } else {
            # An installation that has not updated in months is as stale as one with
            # updates off, so judge the date rather than only the switch.
            $c2rAgeDays = $null
            if ($c2rLastUpdate) {
                $c2rDate = ([string]$c2rLastUpdate) -as [datetime]
                if ($null -ne $c2rDate) { $c2rAgeDays = [math]::Round(((Get-Date) - $c2rDate).TotalDays) }
            }
            if ($null -ne $c2rAgeDays -and $c2rAgeDays -gt 90) {
                Add-Finding -Severity 'Medium' -Title 'Microsoft Office has not updated in a long time' `
                    -Evidence ("{0} - that is {1} days ago, with updates enabled." -f $c2rEvidence, $c2rAgeDays) `
                    -Impact 'The updater is on but has not succeeded in months. Either it cannot reach Microsoft, or something is blocking the scheduled task that drives it.' `
                    -Fix 'Force a check: File > Account > Update Options > Update Now. If it fails, check that the "Office Automatic Updates" scheduled task exists and is enabled.' `
                    -Confidence 'Likely'
            } else {
                Add-Ok -Message ("Microsoft Office updates are enabled ({0})." -f $c2rEvidence)
            }
        }
    }

    # Browser enterprise policy. Force-installed extensions and a policy-pinned homepage or
    # search provider are set here, they cannot be removed from inside the browser, and they
    # need no administrator rights when written to HKCU. Counting extensions in the profile
    # folder - which the inventory above does - does not see them.
    $browserPolicies = @(
        @{ Name = 'Chrome'; Paths = @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKCU:\SOFTWARE\Policies\Google\Chrome') }
        @{ Name = 'Edge'; Paths = @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge') }
        @{ Name = 'Firefox'; Paths = @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox', 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox') }
    )
    $policyHits = @()
    foreach ($browser in $browserPolicies) {
        foreach ($policyPath in $browser.Paths) {
            if (-not (Test-Path -LiteralPath $policyPath)) { continue }
            $hive = if ($policyPath -match '^HKCU') { 'HKCU' } else { 'HKLM' }

            # Force-installed extensions live in a subkey of numbered values.
            foreach ($forceKey in @("$policyPath\ExtensionInstallForcelist", "$policyPath\Extensions\Install")) {
                if (-not (Test-Path -LiteralPath $forceKey)) { continue }
                $forced = @((Get-Item -LiteralPath $forceKey -ErrorAction SilentlyContinue).GetValueNames() |
                        ForEach-Object { (Get-Item -LiteralPath $forceKey).GetValue($_) })
                if ($forced.Count -gt 0) {
                    $policyHits += "$($browser.Name) [$hive] force-installs $($forced.Count) extension(s): $((@($forced | Select-Object -First 3) -join ', '))"
                }
            }

            # A pinned homepage or search provider is the other half of a hijack.
            foreach ($valueName in 'HomepageLocation', 'DefaultSearchProviderSearchURL', 'RestoreOnStartupURLs') {
                $policyValue = Get-RegValue -Path $policyPath -Name $valueName
                if (-not [string]::IsNullOrWhiteSpace([string]$policyValue)) {
                    $policyHits += "$($browser.Name) [$hive] $valueName = $((@($policyValue) -join ', '))"
                }
            }
        }
    }
    if ($policyHits.Count -gt 0) {
        Add-Finding -Severity 'High' -Title 'Browser policy forces extensions, a homepage or a search provider' `
            -Evidence (($policyHits | Select-Object -First 6) -join '; ') `
            -Impact 'A policy-installed extension cannot be removed from the browser interface, and it can hold permission to read and change every page you visit - including everything you type into one. Written under HKCU it needs no administrator rights at all, which makes it a favourite for adware and for anything wanting to sit between you and your logins.' `
            -Fix 'Inspect chrome://policy or edge://policy to see what is applied and where it comes from. If you did not set it - and no employer manages this machine - delete the key under SOFTWARE\Policies for that browser and restart it.' `
            -Confidence 'Likely'
    } else {
        Add-Ok -Message 'No browser policy forces extensions, a homepage or a search provider (Chrome, Edge and Firefox checked in both HKLM and HKCU).'
    }

    # Is the browser actually being updated? Measured from the binary date, not from
    # whether a particular updater exists. Checking for the gupdate service and the
    # GoogleUpdate scheduled tasks was the obvious approach and it is wrong: a
    # winget-managed or Store-managed browser has neither and is still perfectly current,
    # so that check reports a false alarm on an increasingly common setup. A version floor
    # is no better - it needs re-editing every few weeks. What holds regardless of how the
    # browser is kept up to date is that the executable changes when it updates, and
    # browsers ship every two to four weeks.
    $browserBinaries = @(
        @{ Name = 'Chrome'; Path = (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe') }
        @{ Name = 'Chrome'; Path = (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe') }
        @{ Name = 'Edge'; Path = (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe') }
        @{ Name = 'Firefox'; Path = (Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe') }
        @{ Name = 'Brave'; Path = (Join-Path $env:ProgramFiles 'BraveSoftware\Brave-Browser\Application\brave.exe') }
    )
    $staleBrowsers = @()
    $freshBrowsers = @()
    foreach ($browserBinary in $browserBinaries) {
        if ([string]::IsNullOrWhiteSpace($browserBinary.Path) -or -not (Test-Path -LiteralPath $browserBinary.Path)) { continue }
        $binaryInfo = Get-Item -LiteralPath $browserBinary.Path -ErrorAction SilentlyContinue
        if (-not $binaryInfo) { continue }
        $binaryAge = [math]::Round(((Get-Date) - $binaryInfo.LastWriteTime).TotalDays)
        $binaryText = "$($browserBinary.Name) $($binaryInfo.VersionInfo.ProductVersion), last changed $($binaryInfo.LastWriteTime.ToString('yyyy-MM-dd')) ($binaryAge days ago)"
        # Two months without the executable changing means several releases were missed.
        if ($binaryAge -gt 60) { $staleBrowsers += $binaryText } else { $freshBrowsers += $binaryText }
    }
    if ($staleBrowsers.Count -gt 0) {
        Add-Finding -Severity 'High' -Title 'A browser has not been updated in months' `
            -Evidence ($staleBrowsers -join '; ') `
            -Impact 'Browsers ship every two to four weeks, and each release fixes vulnerabilities that become public the moment it lands. An executable unchanged for over two months means several of those releases were missed, whatever the reason - a removed updater, a blocked update server, or a browser that is simply never closed long enough to apply one.' `
            -Fix 'Open the browser and check its own update page (chrome://settings/help, edge://settings/help, or Help > About Firefox), then restart it so the update applies. If nothing happens, reinstall the browser or update it with: winget upgrade --id <package>' `
            -Confidence 'Likely'
    } elseif ($freshBrowsers.Count -gt 0) {
        Add-Ok -Message ("Every installed browser has been updated recently: {0}." -f ($freshBrowsers -join '; '))
    }
}


# run

$allCategories = 'System', 'Stability', 'Drivers', 'Storage', 'Performance', 'Power',
'Network', 'Security', 'Privacy', 'Updates', 'Logging', 'Software'
$script:Selected = $Category
if ($Category -contains 'All') { $script:Selected = $allCategories }

Initialize-Context

$formName = 'desktop'
if ($script:Ctx.IsVM) { $formName = 'virtual machine' } elseif ($script:Ctx.IsLaptop) { $formName = 'laptop' }
$batteryNote = ''
if ($script:Ctx.HasBattery) { $batteryNote = ' with battery' }
$rightsNote = 'standard user - several checks will be skipped'
$rightsColor = 'Yellow'
if ($script:Ctx.IsAdmin) { $rightsNote = 'administrator'; $rightsColor = 'Gray' }

Write-Host ''
Write-Host ('=' * 66) -ForegroundColor Cyan
Write-Host ' WINDOWS HEALTH CHECK' -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor Cyan
Write-Host ''
Write-Host "  Machine   : $env:COMPUTERNAME  ($($script:Ctx.Model))" -ForegroundColor Gray
Write-Host "  Type      : $formName$batteryNote" -ForegroundColor Gray
Write-Host "  OS        : $($script:Ctx.Caption) $($script:Ctx.DisplayVersion) build $($script:Ctx.Build).$($script:Ctx.UBR)" -ForegroundColor Gray
Write-Host "  Hardware  : $($script:Ctx.LogicalCpus) logical cores, $($script:Ctx.TotalRamGB) GB RAM" -ForegroundColor Gray
Write-Host "  Uptime    : $($script:Ctx.UptimeHours) hours" -ForegroundColor Gray
Write-Host "  Rights    : $rightsNote" -ForegroundColor $rightsColor
Write-Host "  Categories: $($script:Selected -join ', ')" -ForegroundColor Gray
if ($script:FastMode) {
    Write-Host '  Mode      : fast - the slowest checks (SMART, component store, folder sizes) are skipped' -ForegroundColor Gray
}
Write-Host ''
Write-Host '  This script only reads - nothing on the machine is changed.' -ForegroundColor DarkGray

$started = Get-Date

Invoke-Check 'System'      { Test-SystemHealth }
Invoke-Check 'Stability'   { Test-StabilityHealth }
Invoke-Check 'Drivers'     { Test-DriverHealth }
Invoke-Check 'Storage'     { Test-StorageHealth }
Invoke-Check 'Performance' { Test-PerformanceHealth }
Invoke-Check 'Power'       { Test-PowerHealth }
Invoke-Check 'Network'     { Test-NetworkHealth }
Invoke-Check 'Security'    { Test-SecurityHealth }
Invoke-Check 'Privacy'     { Test-PrivacyHealth }
Invoke-Check 'Updates'     { Test-UpdateHealth }
Invoke-Check 'Logging'     { Test-LoggingHealth }
Invoke-Check 'Software'    { Test-SoftwareHealth }

Write-FindingReport
Write-Summary

Write-Host ''
Write-Host "  Finished in $([math]::Round(((Get-Date) - $started).TotalSeconds)) seconds." -ForegroundColor DarkGray

if ($ReportPath) { Export-Report -Path $ReportPath }

Write-Host ''
