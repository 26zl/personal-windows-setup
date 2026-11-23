<#
  Dev Drive for developer work: a trusted ReFS Dev Drive (Windows 11 22H2 and later) with the
  package caches on it, and optionally an existing projects folder moved onto it.
  Run in an ELEVATED PowerShell. Re-running is safe: it only adds or fixes what is missing.
    powershell -NoProfile -ExecutionPolicy Bypass -File .\devdrive\setup-devdrive.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\devdrive\setup-devdrive.ps1 -WhatIf
    powershell -NoProfile -ExecutionPolicy Bypass -File .\devdrive\setup-devdrive.ps1 -MoveProjectsFrom "$HOME\Desktop\Prosjekter"

  What it does:
    1. Uses the Dev Drive at -DriveLetter, the VHDX at -VhdPath, a Dev Drive that is already
       attached, or <volume>:\DevDrive\DevDrive.vhdx on any volume. Otherwise it creates a
       dynamically expanding VHDX (-SizeGB, default 150) on the internal SSD data volume with
       the most free space (else the system drive), in an admin-only folder, and formats it as
       a Dev Drive on the first free letter of D, S, V, X.
    2. Registers the SYSTEM task \DevDrive\Attach-DevDrive: Windows does not attach a VHDX again
       after a restart.
    3. Lets Defender and the Sysmon driver attach to Dev Drives. By default only antivirus
       filters attach there, so Sysmon would log no file events on the Dev Drive.
    4. Creates <drive>:\packages and points npm, pnpm (store and metadata cache), Bun, NuGet,
       pip, uv, Cargo, Go, Gradle, Maven, vcpkg and pre-commit at it (user environment variables,
       plus pnpm's global rc for pnpm 10 and older), moving existing caches over. CARGO_HOME also holds rustup's
       proxies, so the user PATH follows it. pre-commit starts a new store there instead: its
       hook environments hold absolute paths and would break if moved.
    5. Creates <drive>:\<ProjectsFolder> (private to you, like your profile) and a shortcut to it
       on the Desktop. -MoveProjectsFrom copies an existing folder there without node_modules,
       checks the copy file by file and per git repository, renames the original to
       <name>-backup-<date> (in %USERPROFILE%, or beside the folder when that is on another
       drive) and leaves a link at the old path, hidden when it is on the Desktop.

  It does not change Defender. Performance mode (asynchronous scanning on trusted Dev Drives)
  is reported, not switched: hardening baselines often turn it off on purpose.
  Programs that are already open see the new environment variables after they restart.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Letter of an existing Dev Drive, or the letter for the new one.
    [ValidatePattern('^[D-Zd-z]$')]
    [string]$DriveLetter,
    # Maximum size of a new VHDX in GB (Microsoft's minimum for a Dev Drive is 50).
    [ValidateRange(50, 4096)]
    [int]$SizeGB = 150,
    # Where the VHDX lives. Default: <data SSD or system drive>:\DevDrive\DevDrive.vhdx
    [ValidatePattern('^[A-Za-z]:\\[^"''%*?<>|]+\.vhdx$')]
    [string]$VhdPath,
    # Allocate the whole VHDX up front instead of letting it grow.
    [switch]$Fixed,
    [ValidatePattern('^[A-Za-z0-9_-]{1,32}$')]
    [string]$Label = 'DevDrive',
    # Folder for repositories on the Dev Drive, linked from the Desktop.
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$ProjectsFolder = 'Prosjekter',
    # An existing projects folder to move onto the Dev Drive.
    [string]$MoveProjectsFrom,
    # File system filters allowed on Dev Drives in addition to antivirus filters.
    [ValidatePattern('^[A-Za-z0-9_]{1,64}$')]
    [string[]]$AllowFilter = @('WdFilter', 'SysmonDrv'),
    # Leave the package caches where they are.
    [switch]$NoCaches,
    # Do not create the Desktop link to the projects folder.
    [switch]$NoDesktopLink
)

$ErrorActionPreference = 'Stop'
# Load Storage up front: under -WhatIf its import would print a line for every alias it defines.
$whatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module Storage -ErrorAction SilentlyContinue
$WhatIfPreference = $whatIf
$AdminsSid =New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SystemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$UsersSid  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$Me        = [Security.Principal.WindowsIdentity]::GetCurrent().User
$TaskPath  = '\DevDrive\'
$TaskName  = 'Attach-DevDrive'

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Detail([string]$Text) { Write-Host "    $Text" -ForegroundColor DarkGray }
function Write-Note([string]$Text) { Write-Host "    $Text" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------------------------
# Pure helpers (the tests load these on their own)
# ---------------------------------------------------------------------------------------------

function Select-DriveLetter {
    # The first preferred letter that is neither in use nor remembered for another volume.
    param([string[]]$Preferred, [string[]]$Unavailable)
    $taken = @($Unavailable | ForEach-Object { ([string]$_).ToUpperInvariant() })
    foreach ($letter in $Preferred) {
        $candidate = ([string]$letter).ToUpperInvariant()
        if ($taken -notcontains $candidate) { return $candidate }
    }
    $null
}

function ConvertFrom-DevDriveQuery {
    # Reads the English output of 'fsutil devdrv query [X:]'. Unknown text leaves a field $null.
    param([string[]]$Lines)
    $result = [ordered]@{ Enabled = $null; AntivirusAllowed = $null; AllowedFilters = $null; IsDevDrive = $null; IsTrusted = $null }
    $text = ($Lines -join "`n")
    if ($text -match 'Developer volumes are enabled') { $result.Enabled = $true }
    elseif ($text -match 'Developer volumes are (not enabled|disabled)') { $result.Enabled = $false }
    if ($text -match 'not protected by antivirus filter') { $result.AntivirusAllowed = $false }
    elseif ($text -match 'protected by antivirus filter') { $result.AntivirusAllowed = $true }
    if ($text -match 'not a developer volume') { $result.IsDevDrive = $false; $result.IsTrusted = $false }
    elseif ($text -match 'untrusted developer volume|is not trusted|not a trusted developer volume') { $result.IsDevDrive = $true; $result.IsTrusted = $false }
    elseif ($text -match 'trusted developer volume') { $result.IsDevDrive = $true; $result.IsTrusted = $true }
    elseif ($text -match 'This is a developer volume') { $result.IsDevDrive = $true; $result.IsTrusted = $false }
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match 'Filters allowed on any developer volume') {
            $names = New-Object System.Collections.Generic.List[string]
            for ($j = $i + 1; $j -lt $Lines.Count -and $Lines[$j] -match '^\s+\S'; $j++) {
                foreach ($name in ($Lines[$j] -split ',')) { if ($name.Trim()) { $names.Add($name.Trim()) } }
            }
            $result.AllowedFilters = @($names)
        }
    }
    if ($null -eq $result.AllowedFilters -and $result.Enabled -eq $true) { $result.AllowedFilters = @() }
    [pscustomobject]$result
}

function Merge-FilterList {
    # Union of two filter lists, keeping the first spelling and order seen.
    param([string[]]$Current, [string[]]$Wanted)
    $merged = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Current) + @($Wanted)) {
        if (-not $name) { continue }
        $seen = $false
        foreach ($m in $merged) { if ($m -ieq $name) { $seen = $true } }
        if (-not $seen) { $merged.Add($name) }
    }
    , @($merged)
}

function Get-UpdatedPathValue {
    # Replaces the entry that resolves to $Old with $New in a ';' list, or appends $New.
    param([string]$PathValue, [string]$Old, [string]$New)
    $norm = { param($s) ([Environment]::ExpandEnvironmentVariables($s).Trim().TrimEnd('\')).ToUpperInvariant() }
    $out = New-Object System.Collections.Generic.List[string]
    $hasNew = $false
    foreach ($entry in @(($PathValue -split ';') | Where-Object { $_ -ne '' })) {
        $value = $entry
        if ($Old -and (& $norm $entry) -eq (& $norm $Old)) { $value = $New }
        if ((& $norm $value) -eq (& $norm $New)) {
            if ($hasNew) { continue }
            $hasNew = $true
        }
        $out.Add($value)
    }
    if (-not $hasNew) { $out.Add($New) }
    $out -join ';'
}

function Get-MavenOptsValue {
    # MAVEN_OPTS with -Dmaven.repo.local pointing at $Repository, other options kept.
    param([string]$Current, [string]$Repository)
    $flag = '-Dmaven.repo.local=' + $Repository
    if (-not $Current) { return $flag }
    if ($Current -match '-Dmaven\.repo\.local=\S+') { return [regex]::Replace($Current, '-Dmaven\.repo\.local=\S+', { param($m) $null = $m; $flag }) }
    ($Current.Trim() + ' ' + $flag)
}

function Get-CacheMap {
    # Where each tool's cache goes under $Root, and where it lives by default.
    param([string]$Root, [string]$UserProfile, [string]$LocalAppData, [string]$AppData, [string]$GoPath)
    if (-not $GoPath) { $GoPath = "$UserProfile\go" }
    @(
        [pscustomobject]@{ Tool = 'npm';              Kind = 'Env';    Name = 'npm_config_cache';           Path = "$Root\npm";              Old = @("$LocalAppData\npm-cache", "$AppData\npm-cache") }
        [pscustomobject]@{ Tool = 'pnpm store';       Kind = 'PnpmRc'; Name = 'store-dir';                  Path = "$Root\pnpm-store";       Old = @("$LocalAppData\pnpm\store") }
        [pscustomobject]@{ Tool = 'pnpm cache';       Kind = 'PnpmRc'; Name = 'cache-dir';                  Path = "$Root\pnpm-cache";       Old = @("$LocalAppData\pnpm-cache") }
        [pscustomobject]@{ Tool = 'Bun';              Kind = 'Env';    Name = 'BUN_INSTALL_CACHE_DIR';      Path = "$Root\bun";              Old = @("$UserProfile\.bun\install\cache") }
        [pscustomobject]@{ Tool = 'NuGet packages';   Kind = 'Env';    Name = 'NUGET_PACKAGES';             Path = "$Root\nuget\packages";   Old = @("$UserProfile\.nuget\packages") }
        [pscustomobject]@{ Tool = 'NuGet HTTP cache'; Kind = 'Env';    Name = 'NUGET_HTTP_CACHE_PATH';      Path = "$Root\nuget\http-cache"; Old = @("$LocalAppData\NuGet\v3-cache") }
        [pscustomobject]@{ Tool = 'pip';              Kind = 'Env';    Name = 'PIP_CACHE_DIR';              Path = "$Root\pip";              Old = @("$LocalAppData\pip\Cache") }
        [pscustomobject]@{ Tool = 'uv';               Kind = 'Env';    Name = 'UV_CACHE_DIR';               Path = "$Root\uv";               Old = @("$LocalAppData\uv\cache") }
        [pscustomobject]@{ Tool = 'Cargo';            Kind = 'Env';    Name = 'CARGO_HOME';                 Path = "$Root\cargo";            Old = @("$UserProfile\.cargo") }
        [pscustomobject]@{ Tool = 'Go modules';       Kind = 'Env';    Name = 'GOMODCACHE';                 Path = "$Root\go\mod";           Old = @("$GoPath\pkg\mod") }
        [pscustomobject]@{ Tool = 'Go build cache';   Kind = 'Env';    Name = 'GOCACHE';                    Path = "$Root\go\build";         Old = @("$LocalAppData\go-build") }
        [pscustomobject]@{ Tool = 'Gradle';           Kind = 'Env';    Name = 'GRADLE_USER_HOME';           Path = "$Root\gradle";           Old = @("$UserProfile\.gradle") }
        [pscustomobject]@{ Tool = 'Maven';            Kind = 'Maven';  Name = 'MAVEN_OPTS';                 Path = "$Root\maven";            Old = @("$UserProfile\.m2\repository") }
        [pscustomobject]@{ Tool = 'vcpkg';            Kind = 'Env';    Name = 'VCPKG_DEFAULT_BINARY_CACHE'; Path = "$Root\vcpkg";            Old = @("$LocalAppData\vcpkg\archives", "$AppData\vcpkg\archives") }
        # Fresh: the hook environments hold absolute paths, so pre-commit builds them again in the new place.
        [pscustomobject]@{ Tool = 'pre-commit';       Kind = 'Env';    Name = 'PRE_COMMIT_HOME';            Path = "$Root\pre-commit";       Old = @("$UserProfile\.cache\pre-commit"); Fresh = $true }
    )
}

function Test-SamePath {
    param([string]$A, [string]$B)
    if (-not $A -or -not $B) { return $false }
    $A.Trim().TrimEnd('\') -ieq $B.Trim().TrimEnd('\')
}

function Test-PathOnDrive {
    param([string]$Path, [string]$Letter)
    [bool]($Path -and $Letter -and $Path.Length -ge 2 -and $Path.Substring(0, 2) -ieq "${Letter}:")
}

function Get-BackupPath {
    # Where the original projects folder goes. It stays on its own drive, so moving it there is a
    # rename: into the profile when that is on the same drive, else beside the folder.
    param([string]$Source, [string]$UserProfile, [datetime]$Stamp)
    $Source = $Source.TrimEnd('\')
    $cut = $Source.LastIndexOf('\')
    if ($cut -lt 0) { throw "$Source is not a folder path" }
    $drive = { param($p) if ($p -match '^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)') { $Matches[1].ToUpperInvariant() } }
    $sourceDrive = & $drive $Source
    $parent = if ($sourceDrive -and $sourceDrive -eq (& $drive $UserProfile)) { $UserProfile.TrimEnd('\') } else { $Source.Substring(0, $cut) }
    '{0}\{1}-backup-{2:yyyyMMdd-HHmm}' -f $parent, $Source.Substring($cut + 1), $Stamp
}

# ---------------------------------------------------------------------------------------------
# System queries
# ---------------------------------------------------------------------------------------------

function Get-UnavailableDriveLetter {
    # Letters in use, remembered by the mount manager, or mapped as network drives.
    $letters = New-Object System.Collections.Generic.List[string]
    foreach ($volume in @(Get-Volume -ErrorAction SilentlyContinue)) { if ($volume.DriveLetter) { $letters.Add([string]$volume.DriveLetter) } }
    foreach ($drive in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) { if ($drive.Name.Length -eq 1) { $letters.Add($drive.Name) } }
    $mounted = Get-Item 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($mounted) { foreach ($name in $mounted.GetValueNames()) { if ($name -match '^\\DosDevices\\([A-Za-z]):$') { $letters.Add($Matches[1]) } } }
    foreach ($key in @(Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue)) { if ($key.PSChildName.Length -eq 1) { $letters.Add($key.PSChildName) } }
    @($letters | ForEach-Object { $_.ToUpperInvariant() } | Sort-Object -Unique)
}

function Invoke-DevDriveQuery {
    param([string]$Letter)
    $ErrorActionPreference = 'Continue'   # Windows PowerShell 5.1 turns native stderr into errors
    $fsutilArgs = @('devdrv', 'query')
    if ($Letter) { $fsutilArgs += "${Letter}:" }
    $lines = @(& fsutil.exe @fsutilArgs 2>&1 | ForEach-Object { [string]$_ })
    ConvertFrom-DevDriveQuery -Lines $lines
}

function Get-DefaultVhdPath {
    # An internal SSD data volume with room for the whole VHDX, else the system drive.
    param([int]$SizeGB)
    $WhatIfPreference = $false   # read-only; keeps CIM session clean-up out of a -WhatIf preview
    $system = $env:SystemDrive.Substring(0, 1).ToUpperInvariant()
    $best = $null
    foreach ($volume in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' })) {
        $letter = ([string]$volume.DriveLetter).ToUpperInvariant()
        if ($letter -eq $system -or $volume.SizeRemaining -lt (([int64]$SizeGB + 20) * 1GB)) { continue }
        $partition = Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $partition) { continue }
        $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
        if (-not $disk -or @('USB', 'SD', 'MMC', '1394', 'File Backed Virtual') -contains [string]$disk.BusType) { continue }
        $physical = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq [string]$disk.Number } | Select-Object -First 1
        if (-not $physical -or [string]$physical.MediaType -ne 'SSD') { continue }
        if (-not $best -or $volume.SizeRemaining -gt $best.SizeRemaining) { $best = $volume }
    }
    if ($best) { return ('{0}:\DevDrive\DevDrive.vhdx' -f $best.DriveLetter) }
    ('{0}\DevDrive\DevDrive.vhdx' -f $env:SystemDrive)
}

function Get-VhdPathForLetter {
    param([string]$Letter)
    $partition = Get-Partition -DriveLetter $Letter -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $partition) { return $null }
    $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
    if ($disk -and [string]$disk.BusType -eq 'File Backed Virtual' -and [string]$disk.Location -match '\.vhdx?$') { return [string]$disk.Location }
    $null
}

function Find-DevDrive {
    # An attached Dev Drive: @{ Letter; VhdPath } or $null.
    foreach ($volume in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.FileSystem -eq 'ReFS' })) {
        $letter = ([string]$volume.DriveLetter).ToUpperInvariant()
        if ((Invoke-DevDriveQuery -Letter $letter).IsDevDrive) {
            return [pscustomobject]@{ Letter = $letter; VhdPath = (Get-VhdPathForLetter -Letter $letter) }
        }
    }
    $null
}

function Get-DiskForVhd {
    param([string]$Path)
    for ($i = 0; $i -lt 40; $i++) {
        $disk = Get-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue | Get-Disk -ErrorAction SilentlyContinue
        if ($disk) { return $disk }
        Start-Sleep -Milliseconds 250
    }
    $null
}

function Get-DefenderReport {
    $WhatIfPreference = $false   # read-only; in PowerShell 7 the Defender module loads through a proxy that honours -WhatIf
    $lines = New-Object System.Collections.Generic.List[string]
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableAsyncScanOnOpen -ErrorAction SilentlyContinue
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $status = $null }
    try { $prefs = Get-MpPreference -ErrorAction Stop } catch { $prefs = $null }
    if (-not $status -or [string]$status.AMRunningMode -ne 'Normal') {
        $lines.Add('Defender is not the active antivirus, so its performance mode does not apply.')
    } elseif ($policy -and $policy.DisableAsyncScanOnOpen -eq 1) {
        $lines.Add('Defender performance mode is OFF by policy (Real-Time Protection\DisableAsyncScanOnOpen = 1, a hardening baseline).')
        $lines.Add('Files on the Dev Drive are scanned before they open, as on C:. Remove that policy value to allow asynchronous scans.')
    } elseif ($prefs -and $prefs.PerformanceModeStatus -eq 1) {
        $lines.Add('Defender performance mode is on: files on the trusted Dev Drive are scanned after they open.')
    } else {
        $lines.Add('Defender performance mode is off. Turn it on with: Set-MpPreference -PerformanceModeStatus Enabled')
    }
    , @($lines)
}

function Get-ProjectTree {
    # Files and bytes under $Root, skipping node_modules and links.
    param([string]$Root)
    $files = 0L; $bytes = 0L
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        foreach ($item in ([IO.DirectoryInfo]::new($stack.Pop())).GetFileSystemInfos()) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item -is [IO.DirectoryInfo]) {
                if ($item.Name -ne 'node_modules') { $stack.Push($item.FullName) }
            } else { $files++; $bytes += $item.Length }
        }
    }
    [pscustomobject]@{ Files = $files; Bytes = $bytes }
}

function Get-GitSnapshot {
    # HEAD and short status of every repository directly under $Root (empty if git is missing).
    param([string]$Root)
    $ErrorActionPreference = 'Continue'
    $result = @{}
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $result }
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName '.git'))) { continue }
        $head = (& git -c safe.directory=* -C $dir.FullName rev-parse HEAD 2>$null) -join ''
        $state = (& git -c safe.directory=* -C $dir.FullName status --porcelain=v1 2>$null) -join "`n"
        $result[$dir.Name] = "$head|$state"
    }
    $result
}

# ---------------------------------------------------------------------------------------------
# Changes (each asks ShouldProcess, so -WhatIf previews them)
# ---------------------------------------------------------------------------------------------

function New-SecuredDirectory {
    # Creates or re-secures $Path with a protected ACL: full control for $FullControl, read for $ReadOnly.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Path,
        [Security.Principal.SecurityIdentifier]$Owner,
        [Security.Principal.SecurityIdentifier[]]$FullControl,
        [Security.Principal.SecurityIdentifier[]]$ReadOnly = @()
    )
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($Owner)
    foreach ($sid in $FullControl) { $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))) }
    foreach ($sid in $ReadOnly) { $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))) }
    if (Test-Path -LiteralPath $Path) {
        # The listed accounts are a minimum: entries added later (or carried over from a moved
        # folder) stay, so a re-run never takes access away.
        $current = Get-Acl -LiteralPath $Path
        $rules = @($current.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
        $both = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $has = {
            param($sid, [Security.AccessControl.FileSystemRights]$rights)
            [bool]@($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -eq $sid -and
                    ($_.FileSystemRights -band $rights) -eq $rights -and $_.InheritanceFlags -eq $both })
        }
        $ok = $current.AreAccessRulesProtected -and $current.GetOwner([Security.Principal.SecurityIdentifier]) -eq $Owner
        foreach ($sid in $FullControl) { if (-not (& $has $sid 'FullControl')) { $ok = $false } }
        foreach ($sid in $ReadOnly) { if (-not (& $has $sid 'ReadAndExecute')) { $ok = $false } }
        if ($ok) { return }
        foreach ($rule in $rules) {
            if (@($FullControl) -notcontains $rule.IdentityReference -and @($ReadOnly) -notcontains $rule.IdentityReference) { $acl.AddAccessRule($rule) }
        }
        if ($PSCmdlet.ShouldProcess($Path, 'restrict access to the listed accounts (other entries are kept)')) { Set-Acl -LiteralPath $Path -AclObject $acl }
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'create folder with restricted access')) { return }
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Path $parent -Force }
    if ($PSVersionTable.PSEdition -eq 'Core') { $null = [System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path) }
    else { $null = [System.IO.Directory]::CreateDirectory($Path, $acl) }
}

function New-StagingDirectory {
    # Admin-only folder for the diskpart script, so a non-elevated process cannot swap it.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $path = Join-Path $env:SystemRoot ('Temp\devdrive-' + [guid]::NewGuid().ToString('N'))
    if (-not $PSCmdlet.ShouldProcess($path, 'create admin-only staging folder')) { return $null }
    New-SecuredDirectory -Path $path -Owner $AdminsSid -FullControl @($AdminsSid, $SystemSid) -Confirm:$false
    $path
}

function New-DevDriveVhd {
    [OutputType([bool])]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path, [int]$SizeGB, [switch]$Fixed)
    $ErrorActionPreference = 'Continue'
    $kind = if ($Fixed) { 'fixed' } else { 'expandable' }
    if (-not $PSCmdlet.ShouldProcess($Path, "create a $SizeGB GB $kind VHDX")) { return $false }
    $staging = New-StagingDirectory -Confirm:$false
    try {
        $script = Join-Path $staging 'create.txt'
        [IO.File]::WriteAllText($script, ('create vdisk file="{0}" maximum={1} type={2}' -f $Path, ($SizeGB * 1024), $kind) + "`r`n", [Text.Encoding]::ASCII)
        $output = & diskpart.exe /s $script 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path)) { throw ("diskpart could not create {0}: {1}" -f $Path, (($output | Select-Object -Last 3) -join ' ')) }
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
    $true
}

function Mount-DevDriveVhd {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path)
    if ((Get-DiskImage -ImagePath $Path).Attached) { return (Get-DiskForVhd -Path $Path) }
    if (-not $PSCmdlet.ShouldProcess($Path, 'attach VHDX')) { return $null }
    $null = Mount-DiskImage -ImagePath $Path
    $disk = Get-DiskForVhd -Path $Path
    if (-not $disk) { throw "attached $Path but Windows shows no disk for it" }
    $disk
}

function Initialize-DevDriveVolume {
    [CmdletBinding(SupportsShouldProcess)]
    param($Disk, [string]$Letter, [string]$Label)
    if (-not $PSCmdlet.ShouldProcess("disk $($Disk.Number) ($($Disk.Location))", "initialize GPT and format as Dev Drive ${Letter}: '$Label'")) { return }
    if ([string]$Disk.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $Disk.Number -PartitionStyle GPT }
    # No letter until it is formatted: Explorer would otherwise offer to format the raw volume.
    $partition = New-Partition -DiskNumber $Disk.Number -UseMaximumSize
    $null = Format-Volume -Partition $partition -DevDrive -FileSystem ReFS -NewFileSystemLabel $Label -Confirm:$false -Force
    $partition = Get-Partition -DiskNumber $Disk.Number -PartitionNumber $partition.PartitionNumber
    if ([string]$partition.DriveLetter -ne $Letter) { Set-Partition -DiskNumber $Disk.Number -PartitionNumber $partition.PartitionNumber -NewDriveLetter $Letter }
}

function Set-DevDriveFilter {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Wanted)
    $ErrorActionPreference = 'Continue'
    $query = Invoke-DevDriveQuery
    if ($query.Enabled -eq $false) { throw "Dev Drive support is turned off on this PC ('fsutil devdrv query'). A policy may manage it; 'fsutil devdrv enable' turns it on." }
    $current = @($query.AllowedFilters | Where-Object { $_ })
    $merged = Merge-FilterList -Current $current -Wanted $Wanted
    if (($current -join ',') -eq ($merged -join ',')) { Write-Detail "filters allowed on Dev Drives: $($merged -join ', ')"; return }
    if (-not $PSCmdlet.ShouldProcess('Dev Drive filter attach policy', "allow $($merged -join ', ')")) { return }
    $output = & fsutil.exe devdrv setFiltersAllowed ($merged -join ', ') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "fsutil devdrv setFiltersAllowed failed: $($output -join ' ')" }
    Write-Detail "filters allowed on Dev Drives: $($merged -join ', ') (an attached Dev Drive picks this up after a restart)"
}

function Set-DevDriveTrust {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Letter)
    $ErrorActionPreference = 'Continue'
    $state = Invoke-DevDriveQuery -Letter $Letter
    if ($state.IsDevDrive -eq $false) { throw "${Letter}: is not a Dev Drive" }
    if ($state.IsTrusted) { Write-Detail "${Letter}: is a trusted Dev Drive"; return }
    if (-not $PSCmdlet.ShouldProcess("${Letter}:", 'mark the Dev Drive as trusted')) { return }
    $output = & fsutil.exe devdrv trust "${Letter}:" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "fsutil devdrv trust failed: $($output -join ' ')" }
    Write-Detail "${Letter}: marked as trusted"
}

function Register-DevDriveAttachTask {
    # Windows forgets attached VHDX files at shutdown; this attaches it again at every boot.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path)
    $command = "`$p = '$Path'; if (-not (Get-DiskImage -ImagePath `$p).Attached) { Mount-DiskImage -ImagePath `$p | Out-Null }"
    $arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$command`""
    $existing = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing -and @($existing.Actions).Count -eq 1 -and $existing.Actions[0].Arguments -eq $arguments -and $existing.Principal.UserId -match 'SYSTEM|S-1-5-18') {
        Write-Detail "task $TaskPath$TaskName attaches $Path at startup"
        return
    }
    if (-not $PSCmdlet.ShouldProcess("$TaskPath$TaskName", "attach $Path at every startup (runs as SYSTEM)")) { return }
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Attaches the Dev Drive VHDX $([Security.SecurityElement]::Escape($Path)) at startup. Windows does not attach it again on its own. Created by devdrive/setup-devdrive.ps1.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>$([Security.SecurityElement]::Escape($arguments))</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    $null = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Xml $xml -Force
    Write-Detail "task $TaskPath$TaskName registered"
}

function Set-UserEnvironmentValue {
    # Sets a user environment variable (and this process's copy). Returns $true when it changed.
    [OutputType([bool])]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Name, [string]$Value)
    $current = (Get-Item 'HKCU:\Environment').GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
    if ($current -ceq $Value) { Set-Item -LiteralPath "Env:$Name" -Value $Value -WhatIf:$false; return $false }
    if (-not $PSCmdlet.ShouldProcess("user environment variable $Name", "set to $Value")) { return $false }
    Set-ItemProperty -LiteralPath 'HKCU:\Environment' -Name $Name -Value $Value -Type String
    Set-Item -LiteralPath "Env:$Name" -Value $Value
    $true
}

function Update-UserPath {
    # Points the user PATH entry for $Old at $New (or adds $New), keeping REG_EXPAND_SZ.
    [OutputType([bool])]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Old, [string]$New)
    $raw = [string](Get-Item 'HKCU:\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    $updated = Get-UpdatedPathValue -PathValue $raw -Old $Old -New $New
    if ($updated -ceq $raw) { return $false }
    if (-not $PSCmdlet.ShouldProcess('user PATH', "use $New instead of $Old")) { return $false }
    Set-ItemProperty -LiteralPath 'HKCU:\Environment' -Name Path -Value $updated -Type ExpandString
    $env:Path = Get-UpdatedPathValue -PathValue $env:Path -Old $Old -New $New
    $true
}

function Set-PnpmRcValue {
    # pnpm reads store-dir and cache-dir from its global rc (%LOCALAPPDATA%\pnpm\config\rc).
    [OutputType([bool])]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Key, [string]$Value)
    $rc = Join-Path $env:LOCALAPPDATA 'pnpm\config\rc'
    $lines = @()
    if (Test-Path -LiteralPath $rc) { $lines = @(Get-Content -LiteralPath $rc) }
    $line = "$Key=$Value"
    if ($lines -contains $line) { return $false }
    if (-not $PSCmdlet.ShouldProcess($rc, "set $line")) { return $false }
    $kept = @($lines | Where-Object { $_ -notmatch ('^\s*' + [regex]::Escape($Key) + '\s*=') })
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $rc) -Force
    [IO.File]::WriteAllText($rc, ((@($kept) + $line) -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
    $true
}

function Move-DirectoryContent {
    # Moves everything from $From into $To (robocopy /MOVE). Returns how many files stayed behind.
    [OutputType([int])]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$From, [string]$To)
    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path -LiteralPath $From -PathType Container)) { return 0 }
    if (-not (Get-ChildItem -LiteralPath $From -Force | Select-Object -First 1)) { return 0 }
    if (-not $PSCmdlet.ShouldProcess($From, "move the contents to $To")) { return 0 }
    # Links are recreated rather than followed: rustup's proxies (cargo.exe, rustc.exe, ...) are
    # symbolic links to rustup.exe, and robocopy would otherwise skip or dereference them.
    $base = $From.TrimEnd('\')
    $links = @(Get-ChildItem -LiteralPath $From -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
    # Read-only files (the Go module cache) would otherwise stay behind in the source.
    $null = & attrib.exe -R "$From\*" /S /D 2>&1
    $output = & robocopy.exe $From $To /E /MOVE /COPY:DAT /DCOPY:DAT /XJ /R:1 /W:1 /MT:8 /NP /NFL /NDL 2>&1
    if ($LASTEXITCODE -ge 8) { throw ("robocopy could not move {0} (exit {1}): {2}" -f $From, $LASTEXITCODE, (($output | Select-Object -Last 12) -join ' ')) }
    foreach ($link in $links) {
        $target = [string]($link.Target | Select-Object -First 1)
        if ([IO.Path]::IsPathRooted($target) -and $target.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $target = $To.TrimEnd('\') + $target.Substring($base.Length)
        }
        $destination = $To.TrimEnd('\') + $link.FullName.Substring($base.Length)
        if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination))) { $null = New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force }
        $mklink = @('/c', 'mklink')
        if ($link.LinkType -eq 'Junction') { $mklink += '/J' } elseif ($link.PSIsContainer) { $mklink += '/D' }
        $null = & cmd.exe @($mklink + @($destination, $target)) 2>&1
        if ($LASTEXITCODE -eq 0) {
            if ($link.PSIsContainer) { [IO.Directory]::Delete($link.FullName) } else { [IO.File]::Delete($link.FullName) }
        }
    }
    $left = @(Get-ChildItem -LiteralPath $From -Recurse -Force -File -ErrorAction SilentlyContinue).Count
    if ($left -eq 0 -and (Test-Path -LiteralPath $From)) { Remove-Item -LiteralPath $From -Recurse -Force -ErrorAction SilentlyContinue }
    $left
}

function Set-PackageCache {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Root, [string]$Letter)
    $map = Get-CacheMap -Root $Root -UserProfile $env:USERPROFILE -LocalAppData $env:LOCALAPPDATA -AppData $env:APPDATA -GoPath $env:GOPATH
    foreach ($cache in $map) {
        if (-not (Test-Path -LiteralPath $cache.Path) -and $PSCmdlet.ShouldProcess($cache.Path, 'create folder')) { $null = New-Item -ItemType Directory -Path $cache.Path -Force }
        $old = @($cache.Old)
        $changed = $false
        switch ($cache.Kind) {
            'Env' {
                $previous = (Get-Item 'HKCU:\Environment').GetValue($cache.Name, $null, 'DoNotExpandEnvironmentNames')
                if ($previous -and -not (Test-PathOnDrive -Path $previous -Letter $Letter)) { $old += [Environment]::ExpandEnvironmentVariables($previous) }
                $changed = Set-UserEnvironmentValue -Name $cache.Name -Value $cache.Path
            }
            'Maven' {
                $previous = (Get-Item 'HKCU:\Environment').GetValue('MAVEN_OPTS', $null, 'DoNotExpandEnvironmentNames')
                $changed = Set-UserEnvironmentValue -Name 'MAVEN_OPTS' -Value (Get-MavenOptsValue -Current $previous -Repository $cache.Path)
            }
            'PnpmRc' {
                $changed = Set-PnpmRcValue -Key $cache.Name -Value $cache.Path
                # pnpm 11 no longer reads these from the rc; pnpm 10 and 11 both read pnpm_config_* variables.
                if (Set-UserEnvironmentValue -Name ('pnpm_config_' + $cache.Name.Replace('-', '_')) -Value $cache.Path) { $changed = $true }
            }
        }
        foreach ($source in ($old | Select-Object -Unique)) {
            if (-not $source -or (Test-SamePath $source $cache.Path) -or (Test-PathOnDrive -Path $source -Letter $Letter)) { continue }
            if ($cache.Fresh) {
                if ($changed -and (Test-Path -LiteralPath $source)) { Write-Note "$($cache.Tool) builds its store again in $($cache.Path); the old one in $source is no longer used and can be deleted" }
                continue
            }
            if ($cache.Tool -eq 'Cargo' -and (Get-Process -Name cargo, rustc, rustup, rust-analyzer -ErrorAction SilentlyContinue)) {
                Write-Note "Cargo is running; $source was not moved. Close it and run this again."
                continue
            }
            $left = Move-DirectoryContent -From $source -To $cache.Path
            if ($left -gt 0) { Write-Note "$($cache.Tool): $left file(s) in use stayed in $source" }
        }
        if ($cache.Tool -eq 'Cargo' -and (Update-UserPath -Old "$env:USERPROFILE\.cargo\bin" -New "$($cache.Path)\bin")) { $changed = $true }
        if (-not $WhatIfPreference) { Write-Detail ('{0,-17} {1} ({2})' -f $cache.Tool, $cache.Path, $(if ($changed) { 'set' } else { 'already set' })) }
    }
}

function Set-TreeOwner {
    # Makes $Owner the owner of every folder and file under $Root, without following links.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Root, [Security.Principal.SecurityIdentifier]$Owner)
    if (-not $PSCmdlet.ShouldProcess($Root, "make $Owner the owner of everything inside")) { return }
    $core = $PSVersionTable.PSEdition -eq 'Core'
    $stack = New-Object System.Collections.Generic.Stack[IO.DirectoryInfo]
    $stack.Push([IO.DirectoryInfo]::new($Root))
    $failed = 0
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in @($dir) + @($dir.GetFileSystemInfos())) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item -ne $dir -and $item -is [IO.DirectoryInfo]) { $stack.Push($item); continue }
            try {
                if ($core) { $sec = [IO.FileSystemAclExtensions]::GetAccessControl($item, [Security.AccessControl.AccessControlSections]::Owner) }
                else { $sec = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner) }
                if ($sec.GetOwner([Security.Principal.SecurityIdentifier]) -eq $Owner) { continue }
                $sec.SetOwner($Owner)
                if ($core) { [IO.FileSystemAclExtensions]::SetAccessControl($item, $sec) } else { $item.SetAccessControl($sec) }
            } catch { $failed++ }
        }
    }
    if ($failed) { Write-Note "$failed item(s) under $Root kept their old owner" }
}

function Move-ProjectFolder {
    # Copies $Source to $Destination without node_modules, checks the copy, renames $Source to a
    # backup on its own drive and leaves a directory junction at the old path.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Source, [string]$Destination)
    $ErrorActionPreference = 'Continue'
    $item = Get-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer) { throw "$Source is not a folder" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if (Test-SamePath ([string]$item.Target) $Destination) { Write-Detail "$Source already points to $Destination"; return }
        throw "$Source is a link to $($item.Target), not a folder"
    }
    if (-not $item.Parent) { throw "$Source is the root of a drive; move a folder instead" }
    $backup = Get-BackupPath -Source $item.FullName -UserProfile $env:USERPROFILE -Stamp (Get-Date)
    if (-not $PSCmdlet.ShouldProcess($Source, "copy to $Destination, check it, rename the original to $backup and leave a link")) { return }

    Write-Detail "copying $Source to $Destination (node_modules is left out; reinstall it from the lockfile)"
    $output = & robocopy.exe $Source $Destination /MIR /XD node_modules /COPY:DAT /DCOPY:DAT /SJ /SL /R:1 /W:1 /MT:16 /NP /NFL /NDL 2>&1
    if ($LASTEXITCODE -ge 8) { throw ("robocopy failed (exit {0}): {1}" -f $LASTEXITCODE, (($output | Select-Object -Last 12) -join ' ')) }
    # Owned by you rather than by Administrators, so git outside an elevated shell trusts the repos.
    Set-TreeOwner -Root $Destination -Owner $Me -Confirm:$false

    $a = Get-ProjectTree -Root $Source
    $b = Get-ProjectTree -Root $Destination
    if ($a.Files -ne $b.Files -or $a.Bytes -ne $b.Bytes) { throw "the copy differs: $($a.Files) files/$($a.Bytes) bytes in $Source, $($b.Files)/$($b.Bytes) on the Dev Drive. Nothing was switched." }
    $gitA = Get-GitSnapshot -Root $Source
    $gitB = Get-GitSnapshot -Root $Destination
    foreach ($repo in $gitA.Keys) {
        if ($gitA[$repo] -ne $gitB[$repo]) { throw "git shows a different state for $repo after the copy. Nothing was switched." }
    }
    Write-Detail ('copy checked: {0} files, {1:N2} GB, {2} git repositories identical' -f $b.Files, ($b.Bytes / 1GB), $gitA.Count)

    try {
        # A rename only, so it moves the whole folder or nothing. Move-Item copies and deletes
        # across drives, stops at the hidden .git folders and leaves the original in two places.
        [IO.Directory]::Move($item.FullName, $backup)
    } catch {
        $reason = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        # Sysinternals handle.exe, when present, names the programs that keep the folder open.
        $holders = ''
        $handle = Get-Command handle64.exe, handle.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($handle) {
            $names = @(& $handle.Source -accepteula -nobanner $Source 2>$null | ForEach-Object { if ($_ -match '^(\S+)\s+pid:\s*(\d+)') { '{0} ({1})' -f $Matches[1], $Matches[2] } } | Sort-Object -Unique)
            if ($names) { $holders = ' Open in: ' + ($names -join ', ') + '.' }
        }
        throw "could not move $Source aside, because a program has a file or folder in it open (VS Code, a terminal, Explorer).$holders Close those and run this again; the copy on the Dev Drive is kept and refreshed. ($reason)"
    }
    $null = New-Item -ItemType Junction -Path $Source -Target $Destination -ErrorAction Stop
    # Anything written in the seconds between the copy and the switch.
    $null = & robocopy.exe $backup $Destination /E /XO /XD node_modules /COPY:DAT /DCOPY:DAT /SJ /SL /R:1 /W:1 /NP /NFL /NDL 2>&1
    Write-Detail "the original is kept in $backup; delete it once everything works"
    $needs = @(Get-ChildItem -LiteralPath $backup -Recurse -Depth 3 -Directory -Filter node_modules -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\.*node_modules$' -and $_.FullName -notmatch '\\\.next\\' } |
        ForEach-Object { $_.Parent.FullName.Replace($backup, $Destination) })
    if ($needs) { Write-Note ('reinstall node_modules (pnpm install / npm ci / bun install) in: ' + ($needs -join ', ')) }
}

function New-ProjectLink {
    # A shortcut on the Desktop. A link that -MoveProjectsFrom left under the same name is hidden,
    # not removed: old paths keep working through it, and the Desktop shows only the shortcut.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Desktop, [string]$Name, [string]$Target)
    if (-not $Desktop -or -not (Test-Path -LiteralPath $Desktop)) { Write-Note "there is no Desktop folder; no shortcut to $Target was created"; return }
    foreach ($cloud in $env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) {
        if ($cloud -and $Desktop.StartsWith($cloud, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Note "the Desktop is synced by OneDrive; no shortcut to $Target was created there"
            return
        }
    }
    $same = Get-Item -LiteralPath (Join-Path $Desktop $Name) -Force -ErrorAction SilentlyContinue
    if ($same) {
        if (-not ($same.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-SamePath ([string]$same.Target) $Target)) {
            Write-Note "the Desktop already has a folder named $Name; no shortcut was created"
            return
        }
        # The attribute goes on the link itself, not on the folder it points to.
        if (-not ($same.Attributes -band [IO.FileAttributes]::Hidden) -and $PSCmdlet.ShouldProcess($same.FullName, 'hide this link; old paths keep working through it')) {
            $same.Attributes = $same.Attributes -bor [IO.FileAttributes]::Hidden
            Write-Detail "$($same.FullName) is now hidden; old paths keep working through it"
        }
    }
    $file = Join-Path $Desktop "$Name.lnk"
    $shell = New-Object -ComObject WScript.Shell
    if (Test-Path -LiteralPath $file) {
        $current = $shell.CreateShortcut($file).TargetPath
        if (-not (Test-SamePath $current $Target)) { Write-Note "$file points to $current; left as it is" }
        return
    }
    if ($PSCmdlet.ShouldProcess($file, "create a shortcut to $Target")) {
        $shortcut = $shell.CreateShortcut($file)
        $shortcut.TargetPath = $Target
        $shortcut.WorkingDirectory = $Target
        $shortcut.Description = "$Name on the Dev Drive"
        $shortcut.Save()
        Write-Detail "Desktop shortcut created: $file -> $Target"
    }
}

function Send-EnvironmentChange {
    # Tells Explorer and other listening programs that the environment changed.
    if (-not ('DevDrive.NativeMethods' -as [type])) {
        Add-Type -Namespace DevDrive -Name NativeMethods -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    $null = [DevDrive.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

function Invoke-DevDriveSetup {
    param(
        [string]$DriveLetter, [int]$SizeGB, [string]$VhdPath, [switch]$Fixed, [string]$Label,
        [string]$ProjectsFolder, [string]$MoveProjectsFrom, [string[]]$AllowFilter, [switch]$NoCaches, [switch]$NoDesktopLink
    )
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $WhatIfPreference) { throw 'Run this in an ELEVATED PowerShell (right-click > Run as administrator).' }
    if ([Environment]::OSVersion.Version.Build -lt 22621) { throw 'Dev Drive needs Windows 11 22H2 (build 22621.2338) or later.' }
    if (-not (Get-Command Format-Volume).Parameters.ContainsKey('DevDrive')) { throw 'This Windows build cannot format a Dev Drive (Format-Volume has no -DevDrive).' }
    if (-not $isAdmin) { Write-Note 'not elevated: fsutil cannot read the Dev Drive state, so this preview assumes nothing exists yet' }

    Write-Step 'Dev Drive filters'
    if ($isAdmin) { Set-DevDriveFilter -Wanted $AllowFilter }

    Write-Step 'Dev Drive'
    $letter = $null
    $vhd = $VhdPath
    if ($DriveLetter -and (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue)) {
        if ($isAdmin -and (Invoke-DevDriveQuery -Letter $DriveLetter).IsDevDrive -ne $true) { throw "${DriveLetter}: exists and is not a Dev Drive" }
        $letter = $DriveLetter.ToUpperInvariant()
        if (-not $vhd) { $vhd = Get-VhdPathForLetter -Letter $letter }
    }
    if (-not $letter -and -not $vhd -and $isAdmin) {
        $found = Find-DevDrive
        if ($found) { $letter = $found.Letter; $vhd = $found.VhdPath }
    }
    if (-not $letter -and -not $vhd) {
        foreach ($volume in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' })) {
            $candidate = '{0}:\DevDrive\DevDrive.vhdx' -f $volume.DriveLetter
            if (Test-Path -LiteralPath $candidate) { $vhd = $candidate; break }
        }
    }
    if (-not $letter -and $vhd -and (Test-Path -LiteralPath $vhd)) {
        $disk = Mount-DevDriveVhd -Path $vhd
        if ($disk) { $letter = [string](Get-Partition -DiskNumber $disk.Number | Where-Object DriveLetter | Select-Object -First 1).DriveLetter }
        if (-not $letter -and $WhatIfPreference) { $letter = if ($DriveLetter) { $DriveLetter.ToUpperInvariant() } else { '?' } }
        if (-not $letter) { throw "$vhd is attached but its volume has no drive letter; give it one in Disk Management or pass -DriveLetter" }
    }

    $created = $false
    if (-not $letter) {
        if (-not $vhd) { $vhd = Get-DefaultVhdPath -SizeGB $SizeGB }
        $letter = if ($DriveLetter) { $DriveLetter.ToUpperInvariant() } else { Select-DriveLetter -Preferred @('D', 'S', 'V', 'X') -Unavailable (Get-UnavailableDriveLetter) }
        if (-not $letter) { throw 'none of D, S, V, X is free; pass -DriveLetter' }
        $hostVolume = Get-Volume -DriveLetter $vhd.Substring(0, 1)
        $need = if ($Fixed) { [int64]$SizeGB * 1GB } else { 50GB }
        if ($hostVolume.SizeRemaining -lt $need) { throw ('{0}: has {1:N0} GB free; this VHDX needs {2:N0} GB' -f $vhd.Substring(0, 1), ($hostVolume.SizeRemaining / 1GB), ($need / 1GB)) }
        Write-Detail ('new Dev Drive {0}: in {1} ({2} GB, {3})' -f $letter, $vhd, $SizeGB, $(if ($Fixed) { 'allocated now' } else { 'grows as needed' }))
        New-SecuredDirectory -Path (Split-Path -Parent $vhd) -Owner $AdminsSid -FullControl @($AdminsSid, $SystemSid) -ReadOnly @($UsersSid)
        if (New-DevDriveVhd -Path $vhd -SizeGB $SizeGB -Fixed:$Fixed) {
            $disk = Mount-DevDriveVhd -Path $vhd
            Initialize-DevDriveVolume -Disk $disk -Letter $letter -Label $Label
            $created = $true
        }
    } else {
        Write-Detail ('using Dev Drive {0}:{1}' -f $letter, $(if ($vhd) { " ($vhd)" }))
    }

    if ($isAdmin -and (Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue)) { Set-DevDriveTrust -Letter $letter }
    if ($vhd) {
        Write-Step 'Attach at startup'
        Register-DevDriveAttachTask -Path $vhd
    }

    # Plain strings: Join-Path in Windows PowerShell fails on a drive that -WhatIf did not create.
    $root = "${letter}:"
    $projects = "$root\$ProjectsFolder"
    $packages = "$root\packages"
    $extra = @()
    if ($MoveProjectsFrom -and (Test-Path -LiteralPath $MoveProjectsFrom)) {
        # Keep any extra accounts the old folder granted access (for example a sandbox group), read-only.
        $standard = @($Me.Value, $SystemSid.Value, $AdminsSid.Value, 'S-1-3-0')
        $extra = @((Get-Acl -LiteralPath $MoveProjectsFrom).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Allow' -and $standard -notcontains $_.IdentityReference.Value } |
            ForEach-Object { $_.IdentityReference } | Sort-Object Value -Unique)
    }

    Write-Step "Folders on $root"
    New-SecuredDirectory -Path $packages -Owner $Me -FullControl @($Me, $SystemSid, $AdminsSid)
    New-SecuredDirectory -Path $projects -Owner $Me -FullControl @($Me, $SystemSid, $AdminsSid) -ReadOnly $extra
    Write-Detail "$packages and $projects are private to $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    if (-not $NoCaches) {
        Write-Step "Package caches -> $packages"
        Set-PackageCache -Root $packages -Letter $letter
    }

    Write-Step 'Projects'
    if ($MoveProjectsFrom) { Move-ProjectFolder -Source $MoveProjectsFrom -Destination $projects }
    if (-not $NoDesktopLink) { New-ProjectLink -Desktop ([Environment]::GetFolderPath('Desktop')) -Name $ProjectsFolder -Target $projects }
    Write-Detail "projects folder: $projects"

    Write-Step 'Defender'
    foreach ($line in (Get-DefenderReport)) { Write-Detail $line }

    if (-not $WhatIfPreference) { Send-EnvironmentChange }
    Write-Host ''
    if ($created) { Write-Host "Dev Drive $root is ready. Restart open terminals and editors so they see the new cache locations." -ForegroundColor Green }
    else { Write-Host "Dev Drive $root checked. Restart open terminals and editors if anything above was set." -ForegroundColor Green }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-DevDriveSetup -DriveLetter $DriveLetter -SizeGB $SizeGB -VhdPath $VhdPath -Fixed:$Fixed -Label $Label `
            -ProjectsFolder $ProjectsFolder -MoveProjectsFrom $MoveProjectsFrom -AllowFilter $AllowFilter `
            -NoCaches:$NoCaches -NoDesktopLink:$NoDesktopLink
    } catch {
        Write-Host "Dev Drive setup stopped: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
