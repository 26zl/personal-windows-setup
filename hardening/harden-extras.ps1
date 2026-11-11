<#
  Optional hardening pass - the few settings that Harden System Security (HotCakeX)
  and ConfigureDefender leave alone. It runs alongside them, never instead of them.
  Run standalone in an ELEVATED PowerShell (setup.ps1 offers it too):
    irm https://github.com/26zl/personal-windows-setup/raw/main/hardening/harden-extras.ps1 | iex
  Read-only until you answer y: current state is reported first, every change is its
  own prompt, and anything already in the target state is skipped. Safe to re-run.

  What it can change - and how to undo each one:
    ASR rules -> Block      Add-MpPreference -AttackSurfaceReductionRules_Ids <id>
                            -AttackSurfaceReductionRules_Actions Disabled, or put the id
                            back under ...\Windows Defender Exploit Guard\ASR\Rules
    Defender exclusions     Add-MpPreference -ExclusionPath '<path>'
    Quarantine retention    Set-MpPreference -QuarantinePurgeItemsAfterDelay <days>
    NetBIOS over TCP/IP     NetbiosOptions = 0 under NetBT\Parameters\Interfaces\*
    AutoPlay / AutoRun      remove NoDriveTypeAutoRun + NoAutorun under Policies\Explorer
    NTLMv2 only             remove LmCompatibilityLevel under Control\Lsa
    Admin shares (C$, D$)   AutoShareWks + AutoShareServer = 1, then restart LanmanServer

  Re-run this after Harden System Security: it manages some ASR rules through policy and
  can put them back.

  Run this after setup.ps1, not before: the ASR rules can block installers midway (MSYS2's
  post-install step is one) without a useful error.

  Nothing is written until the first y. Then, before that change, it creates a System Restore
  point and starts a record in %LOCALAPPDATA%\windows-setup\logs: a transcript plus
  hardening-before-*.json and hardening-after-*.json with every value it can change, the full
  Defender exclusion lists included. A session without a console answers no to every prompt.
#>

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

# Return instead of exiting because the script is commonly invoked with iex.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this in an ELEVATED PowerShell (right-click > Run as administrator)." -ForegroundColor Red
    return
}
# Restored at the end: with iex this is the caller's own session.
$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

# ASR rules a stock Harden System Security / ConfigureDefender run tends to leave below Block.
# Left out on purpose: prevalence/age (01443614-cd74-433a-b99e-2ecdc07bfc25) floods a dev and
# gaming box with false positives, and PSExec/WMI (d1e49aac-8f56-4280-b9ba-993a6d77406c) breaks
# Sysinternals and remote admin. Preview rules can change between Defender platform updates;
# turn those off first if something legitimate gets blocked.
$asrTargets = [ordered]@{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'abuse of exploited vulnerable signed drivers'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'copied or impersonated system tools [preview rule]'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'untrusted, unsigned processes run from USB'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'credential stealing from LSASS'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'rebooting the machine into Safe Mode [preview rule]'
}
# Windows default. Defender deletes quarantined files (and the threat history with them) after
# this many days, so a value well below it destroys the evidence before anyone looks at it.
$quarantineDefaultDays = 90
$asrPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
$netbtKey     = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$explorerKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$lsaKey       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lanmanKey    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$quarantinePolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine'

function Confirm-Change {
    # No console (Read-Host throws) or end of input means no.
    param([string]$Prompt)
    try { ([string](Read-Host "  $Prompt Type y (anything else skips)")) -match '^(y|yes)$' }
    catch { $false }
}

function Get-HardeningState {
    # Every value this script can change, as plain data for the JSON record.
    $pref = $null
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { $pref = $null }
    $asr = [ordered]@{}
    if ($pref) {
        $ids  = @($pref.AttackSurfaceReductionRules_Ids)
        $acts = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $asr["$($ids[$i])".ToLower()] = [int]$acts[$i] } }
    }
    $asrPolicy = [ordered]@{}
    $policy = Get-ItemProperty -LiteralPath $asrPolicyKey -ErrorAction SilentlyContinue
    if ($policy) {
        foreach ($p in @($policy.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) { $asrPolicy[$p.Name] = [string]$p.Value }
    }
    $netbios = [ordered]@{}
    foreach ($iface in @(Get-ChildItem -LiteralPath $netbtKey -ErrorAction SilentlyContinue)) {
        $netbios[$iface.PSChildName] = (Get-ItemProperty -LiteralPath $iface.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
    }
    [ordered]@{
        Time                 = (Get-Date).ToString('o')
        DefenderAvailable    = [bool]$pref
        AsrRules             = $asr
        AsrPolicy            = $asrPolicy
        ExclusionPath        = @(if ($pref) { $pref.ExclusionPath | Where-Object { $_ } })
        ExclusionProcess     = @(if ($pref) { $pref.ExclusionProcess | Where-Object { $_ } })
        ExclusionExtension   = @(if ($pref) { $pref.ExclusionExtension | Where-Object { $_ } })
        QuarantineDays       = $(if ($pref) { $pref.QuarantinePurgeItemsAfterDelay } else { $null })
        QuarantinePolicyDays = (Get-ItemProperty -LiteralPath $quarantinePolicyKey -Name PurgeItemsAfterDelay -ErrorAction SilentlyContinue).PurgeItemsAfterDelay
        NetbiosOptions       = $netbios
        NoDriveTypeAutoRun   = (Get-ItemProperty -LiteralPath $explorerKey -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        NoAutorun            = (Get-ItemProperty -LiteralPath $explorerKey -Name NoAutorun -ErrorAction SilentlyContinue).NoAutorun
        LmCompatibilityLevel = (Get-ItemProperty -LiteralPath $lsaKey -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
        AutoShareWks         = (Get-ItemProperty -LiteralPath $lanmanKey -Name AutoShareWks -ErrorAction SilentlyContinue).AutoShareWks
        AutoShareServer      = (Get-ItemProperty -LiteralPath $lanmanKey -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
        Shares               = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }
}

function New-HardeningRestorePoint {
    # Same logic as setup.ps1: lift the 24h creation throttle, create the point, put the throttle back.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Description)
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "create System Restore point '$Description'")) { return }
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    } catch {
        Write-Host "    could not enable System Protection: $($_.Exception.Message)" -ForegroundColor Yellow
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
    } catch {
        Write-Host "    restore point failed: $($_.Exception.Message)" -ForegroundColor Yellow
    } finally {
        if ($hadFreq) { Set-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -Value $prevFreq -Type DWord -ErrorAction SilentlyContinue }
        else          { Remove-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue }
    }
}

$script:ChangeRecord = $null
function Start-ChangeRecord {
    # Runs once, right before the first change the user confirmed.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($script:ChangeRecord -or -not $PSCmdlet.ShouldProcess('change record and restore point', 'start')) { return }
    $dir   = Join-Path $env:LOCALAPPDATA 'windows-setup\logs'
    $stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
    $script:ChangeRecord = [ordered]@{
        Transcript = Join-Path $dir "hardening-transcript-$stamp.log"
        Before     = Join-Path $dir "hardening-before-$stamp.json"
        After      = Join-Path $dir "hardening-after-$stamp.json"
    }
    try {
        $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop
        # Keep 90 days of hardening records.
        Get-ChildItem -LiteralPath $dir -File -Filter 'hardening-*' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Start-Transcript -Path $script:ChangeRecord.Transcript -Append | Out-Null
        [IO.File]::WriteAllText($script:ChangeRecord.Before, ((Get-HardeningState) | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
        Write-Host "    values before the change saved to $($script:ChangeRecord.Before)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    could not write the change record: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    New-HardeningRestorePoint "Before harden-extras ($stamp)"
}

function Save-ChangeRecord {
    # Rewritten after every applied change, so it always holds the latest values.
    if (-not $script:ChangeRecord) { return }
    try { [IO.File]::WriteAllText($script:ChangeRecord.After, ((Get-HardeningState) | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false))) }
    catch { Write-Host "    could not write $($script:ChangeRecord.After): $($_.Exception.Message)" -ForegroundColor Yellow }
}

function Get-AsrState {
    # Effective action per rule id straight from Defender, so policy is already merged in.
    $state = @{}
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids  = @($pref.AttackSurfaceReductionRules_Ids)
        $acts = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($ids[$i]) { $state["$($ids[$i])".ToLower()] = [int]$acts[$i] }
        }
    } catch {
        Write-Host "    could not read ASR state: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    $state
}

function Set-AsrRule {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Id, [string]$Label)
    # A rule listed under the ASR policy key outranks Add-MpPreference, so write it there
    # when it exists - otherwise the local preference is set and silently ignored.
    if (-not $PSCmdlet.ShouldProcess($Label, 'set ASR rule to Block')) { return }
    $inPolicy = (Test-Path $asrPolicyKey) -and
                ($null -ne (Get-ItemProperty $asrPolicyKey -Name $Id -ErrorAction SilentlyContinue))
    if ($inPolicy) { Set-ItemProperty $asrPolicyKey -Name $Id -Value '1' -Type String -ErrorAction Stop }
    else { Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop }
}

Write-Host "`n=== Optional hardening (opt in) ===" -ForegroundColor Magenta
Write-Host "Complements Harden System Security / ConfigureDefender - it does not replace them." -ForegroundColor DarkGray

# Defender may be inactive on a machine running third-party AV; those items are then skipped.
$mp = $null
try { $mp = Get-MpPreference -ErrorAction Stop }
catch { Write-Host "  Defender is not managing this machine - ASR and exclusion items are skipped." -ForegroundColor Yellow }

# Read-only report
$asrState   = if ($mp) { Get-AsrState } else { @{} }
$asrPending = @($asrTargets.Keys | Where-Object { $asrState[$_] -ne 1 })

# Guarded on $mp so a session with Set-StrictMode does not throw when Defender
# is not answering (the script is run with iex inside arbitrary user sessions).
$exclPath = @(); $exclProcess = @(); $exclExt = @()
if ($mp) {
    $exclPath    = @($mp.ExclusionPath      | Where-Object { $_ })
    $exclProcess = @($mp.ExclusionProcess   | Where-Object { $_ })
    $exclExt     = @($mp.ExclusionExtension | Where-Object { $_ })
}
$exclTotal   = $exclPath.Count + $exclProcess.Count + $exclExt.Count

$nbIfaces = @(Get-ChildItem $netbtKey -ErrorAction SilentlyContinue)
# NetBT keeps interface keys for removed adapters, so split live from stale; only live ones
# are exposure. If the adapter list cannot be read, treat every interface as live.
$liveAdapters = @{}
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    ForEach-Object { if ($_.InterfaceGuid) { $liveAdapters["$($_.InterfaceGuid)".ToLower()] = $_.Name } }
$nbLive   = if ($liveAdapters.Count -eq 0) { $nbIfaces }
            else { @($nbIfaces | Where-Object { $liveAdapters.ContainsKey(($_.PSChildName -replace '^Tcpip_', '').ToLower()) }) }
$nbStale  = @($nbIfaces | Where-Object { $nbLive -notcontains $_ })
$nbOn     = @($nbLive | Where-Object { (Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions -ne 2 })
# Adapter names for the ones still on, so the prompt can say which they are.
$nbOnNames = @($nbOn | ForEach-Object { $liveAdapters[($_.PSChildName -replace '^Tcpip_', '').ToLower()] } | Where-Object { $_ })

$quarantineDays = if ($mp) { $mp.QuarantinePurgeItemsAfterDelay } else { $null }

$autoRunOff = ((Get-ItemProperty $explorerKey -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun -eq 255) -and
              ((Get-ItemProperty $explorerKey -Name NoAutorun -ErrorAction SilentlyContinue).NoAutorun -eq 1)

$lmLevel = (Get-ItemProperty $lsaKey -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel

$autoWks     = (Get-ItemProperty $lanmanKey -Name AutoShareWks -ErrorAction SilentlyContinue).AutoShareWks
$autoSrv     = (Get-ItemProperty $lanmanKey -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
$adminShares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^([A-Za-z]|ADMIN)\$$' })
$sharesOff   = ($autoWks -eq 0) -and ($autoSrv -eq 0) -and ($adminShares.Count -eq 0)

Write-Host "  --- current state ---" -ForegroundColor White
if ($mp) {
    Write-Host ("  ASR rules below Block          : {0} of {1} targeted" -f $asrPending.Count, $asrTargets.Count) -ForegroundColor Gray
    Write-Host ("  Defender exclusions            : {0}" -f $(if ($exclTotal -eq 0) { 'none (good)' } else { "$exclTotal - unscanned, so review them" })) -ForegroundColor Gray
    Write-Host ("  Quarantine kept for            : {0}" -f $(if ($null -eq $quarantineDays) { 'unknown' } elseif ($quarantineDays -ge $quarantineDefaultDays) { "$quarantineDays days (default or better)" } else { "$quarantineDays days - below the $quarantineDefaultDays-day default" })) -ForegroundColor Gray
}
$nbStaleNote = if ($nbStale.Count -gt 0) { " (+$($nbStale.Count) stale entr$(if ($nbStale.Count -eq 1) { 'y' } else { 'ies' }) from removed adapters)" } else { '' }
Write-Host ("  NetBIOS over TCP/IP            : {0}{1}" -f $(if ($nbOn.Count -eq 0) { 'disabled on every live interface (good)' } else { "still on/DHCP-controlled on $($nbOn.Count) of $($nbLive.Count) live" }), $nbStaleNote) -ForegroundColor Gray
Write-Host ("  AutoPlay / AutoRun             : {0}" -f $(if ($autoRunOff) { 'disabled by policy (good)' } else { 'not policy-disabled' })) -ForegroundColor Gray
Write-Host ("  NTLM level                     : {0}" -f $(if ($lmLevel -ge 5) { "$lmLevel (NTLMv2 only, good)" } elseif ($null -eq $lmLevel) { 'not set (client sends NTLMv2 only, but LM/NTLMv1 from others is still accepted)' } else { "$lmLevel (below 5, LM/NTLMv1 still allowed)" })) -ForegroundColor Gray
Write-Host ("  Admin shares (C`$, ADMIN`$)      : {0}" -f $(if ($sharesOff) { 'off (good)' } elseif ($adminShares) { "on - $(($adminShares.Name) -join ', ')" } else { 'on' })) -ForegroundColor Gray

# Changes, each behind its own y/n
Write-Host "  --- changes (each is optional) ---" -ForegroundColor White
$applied = 0
$offered = $false

if ($mp -and $asrPending.Count -gt 0) {
    $offered = $true
    Write-Host "  Moves these Defender rules from off/audit/warn to Block:" -ForegroundColor DarkGray
    $asrPending | ForEach-Object { Write-Host "    - $($asrTargets[$_])" -ForegroundColor DarkGray }
    # This rule blocks MSYS2's unsigned bash.exe (Defender event 1121) because System32 has its
    # own bash.exe; Git for Windows' signed bash.exe is not affected.
    if ($asrPending -contains 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb') {
        Write-Host "  Note: 'copied or impersonated system tools' blocks MSYS2's C:\msys64\usr\bin\bash.exe" -ForegroundColor DarkGray
        Write-Host "  (Windows has its own bash.exe in System32). Exempt it afterwards if you use MSYS2:" -ForegroundColor DarkGray
        Write-Host "    Add-MpPreference -AttackSurfaceReductionOnlyExclusions 'C:\msys64\*'" -ForegroundColor DarkGray
    }
    if (Confirm-Change "Set these $($asrPending.Count) ASR rule(s) to Block?") {
        Start-ChangeRecord
        foreach ($id in $asrPending) {
            try { Set-AsrRule -Id $id -Label $asrTargets[$id] }
            catch { Write-Host "    could not set '$($asrTargets[$id])': $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        # Confirm against Defender rather than the write, since policy can still win.
        Start-Sleep -Seconds 2
        $after  = Get-AsrState
        $stuck  = @($asrPending | Where-Object { $after[$_] -ne 1 })
        $wonSet = $asrPending.Count - $stuck.Count
        # One item, not one per rule: $applied counts answered prompts.
        if ($wonSet -gt 0) { Write-Host "    $wonSet rule(s) now Block" -ForegroundColor DarkGray; $applied++ }
        foreach ($id in $stuck) { Write-Host "    still not Block (managed elsewhere?): $($asrTargets[$id])" -ForegroundColor Yellow }
        Save-ChangeRecord
    }
}

if ($mp -and $exclTotal -gt 0) {
    $offered = $true
    Write-Host "  Defender skips these entirely, so anything dropped there is never scanned:" -ForegroundColor DarkGray
    $exclPath    | ForEach-Object { Write-Host "    - path:      $_" -ForegroundColor DarkGray }
    $exclProcess | ForEach-Object { Write-Host "    - process:   $_" -ForegroundColor DarkGray }
    $exclExt     | ForEach-Object { Write-Host "    - extension: $_" -ForegroundColor DarkGray }
    Write-Host "  Keep only the ones you can justify; the change record keeps the full list, and Add-MpPreference -ExclusionPath '<path>' re-adds one." -ForegroundColor DarkGray
    if (Confirm-Change "Remove all $exclTotal Defender exclusion(s)?") {
        Start-ChangeRecord
        try {
            if ($exclPath)    { Remove-MpPreference -ExclusionPath $exclPath -ErrorAction Stop }
            if ($exclProcess) { Remove-MpPreference -ExclusionProcess $exclProcess -ErrorAction Stop }
            if ($exclExt)     { Remove-MpPreference -ExclusionExtension $exclExt -ErrorAction Stop }
            # Confirm against Defender, like the ASR block does - a policy-managed
            # exclusion can survive a Remove-MpPreference that did not throw.
            $post = Get-MpPreference
            $stillThere = @($post.ExclusionPath | Where-Object { $_ }).Count +
                          @($post.ExclusionProcess | Where-Object { $_ }).Count +
                          @($post.ExclusionExtension | Where-Object { $_ }).Count
            if ($stillThere -eq 0) {
                Write-Host "    exclusions cleared" -ForegroundColor DarkGray
                $applied++
            } else {
                Write-Host "    $stillThere exclusion(s) still present (set by policy?)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    could not clear exclusions (set by policy?): $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Save-ChangeRecord
    }
}

if ($mp -and $null -ne $quarantineDays -and $quarantineDays -lt $quarantineDefaultDays) {
    $offered = $true
    Write-Host "  Defender deletes quarantined files after $quarantineDays day(s) instead of the $quarantineDefaultDays-day default." -ForegroundColor DarkGray
    Write-Host "  The file and the threat history go with it, so something noticed a week later cannot be looked at." -ForegroundColor DarkGray
    if (Confirm-Change "Keep quarantined items for $quarantineDefaultDays days?") {
        Start-ChangeRecord
        try {
            # A value under the Policies key outranks Set-MpPreference, so update it there too when present.
            if ($null -ne (Get-ItemProperty $quarantinePolicyKey -Name PurgeItemsAfterDelay -ErrorAction SilentlyContinue)) {
                Set-ItemProperty $quarantinePolicyKey -Name PurgeItemsAfterDelay -Value $quarantineDefaultDays -Type DWord -ErrorAction Stop
            }
            Set-MpPreference -QuarantinePurgeItemsAfterDelay $quarantineDefaultDays -ErrorAction Stop
            # Confirm against Defender, like the blocks above - policy can override this too.
            $nowDays = (Get-MpPreference).QuarantinePurgeItemsAfterDelay
            if ($nowDays -ge $quarantineDefaultDays) {
                Write-Host "    quarantine retention is now $nowDays days" -ForegroundColor DarkGray
                $applied++
            } else {
                Write-Host "    still $nowDays days (set by policy?)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    could not change quarantine retention: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Save-ChangeRecord
    }
}

if ($nbOn.Count -gt 0) {
    $offered = $true
    Write-Host "  NetBIOS over TCP/IP is a pre-2000 name protocol used for spoofing on local networks." -ForegroundColor DarkGray
    Write-Host "  Only legacy SMB/WINS file sharing needs it. Adapters added later default back on - re-run then." -ForegroundColor DarkGray
    if ($nbOnNames.Count -gt 0) { Write-Host "  Still on: $($nbOnNames -join ', ')" -ForegroundColor DarkGray }
    # Hyper-V rebuilds "vEthernet (Default Switch)" with a fresh interface GUID on every boot, so
    # it turns up here again after each restart no matter how many times this is run. That one is
    # a host-internal NAT switch rather than a link to the LAN, so it is noise, not exposure.
    if ($nbOnNames -match '(?i)Default Switch') {
        Write-Host "  Hyper-V's 'Default Switch' is rebuilt on every boot and reappears here every time - it" -ForegroundColor DarkGray
        Write-Host "  is a host-internal NAT switch, not a path to the LAN, so leaving it is no real exposure." -ForegroundColor DarkGray
    }
    # Stale keys are written too: it costs nothing, and it stops NetBIOS coming back on if the
    # adapter is ever reinstalled into the same interface key.
    if (Confirm-Change "Disable NetBIOS on $($nbLive.Count) live interface(s)$nbStaleNote?") {
        Start-ChangeRecord
        foreach ($iface in $nbIfaces) {
            try { Set-ItemProperty $iface.PSPath -Name NetbiosOptions -Value 2 -Type DWord -ErrorAction Stop }
            catch { Write-Host "    $($iface.PSChildName): $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        $left = @(Get-ChildItem $netbtKey -ErrorAction SilentlyContinue |
                  Where-Object { (Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions -ne 2 })
        if ($left.Count -eq 0) { Write-Host "    NetBIOS disabled on every interface (live and stale)" -ForegroundColor DarkGray; $applied++ }
        else { Write-Host "    $($left.Count) interface(s) unchanged" -ForegroundColor Yellow }
        Save-ChangeRecord
    }
}

if (-not $autoRunOff) {
    $offered = $true
    Write-Host "  Blocks USB sticks and disks from auto-starting anything when plugged in." -ForegroundColor DarkGray
    if (Confirm-Change "Disable AutoPlay/AutoRun on all drive types?") {
        Start-ChangeRecord
        try {
            # New-Item -Force on an EXISTING registry key recreates it and deletes
            # every value in it, so only create the key when it is actually missing.
            if (-not (Test-Path $explorerKey)) { $null = New-Item $explorerKey -Force }
            Set-ItemProperty $explorerKey -Name NoDriveTypeAutoRun -Value 255 -Type DWord -ErrorAction Stop
            Set-ItemProperty $explorerKey -Name NoAutorun -Value 1 -Type DWord -ErrorAction Stop
            Write-Host "    AutoPlay/AutoRun disabled by policy" -ForegroundColor DarkGray
            $applied++
        } catch {
            Write-Host "    could not disable AutoPlay: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Save-ChangeRecord
    }
}

if ($null -eq $lmLevel -or $lmLevel -lt 5) {
    $offered = $true
    Write-Host "  Level 5 sends and accepts NTLMv2 only, refusing the crackable LM and NTLMv1 responses." -ForegroundColor DarkGray
    Write-Host "  Skip it if a very old NAS or network printer here can only authenticate with NTLMv1." -ForegroundColor DarkGray
    if (Confirm-Change "Restrict NTLM to v2 only? (LmCompatibilityLevel = 5)") {
        Start-ChangeRecord
        try {
            Set-ItemProperty $lsaKey -Name LmCompatibilityLevel -Value 5 -Type DWord -ErrorAction Stop
            Write-Host "    LmCompatibilityLevel = 5" -ForegroundColor DarkGray
            $applied++
        } catch {
            Write-Host "    could not set LmCompatibilityLevel: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Save-ChangeRecord
    }
}

if (-not $sharesOff) {
    $offered = $true
    Write-Host "  C`$ / D`$ / ADMIN`$ are hidden shares that hand out whole-disk access over SMB to anyone" -ForegroundColor DarkGray
    Write-Host "  holding local admin credentials. Skip if backup or remote-admin tools here use \\host\C`$." -ForegroundColor DarkGray
    Write-Host "  Restarting the Server service briefly drops any active SMB session. IPC`$ stays - Windows needs it." -ForegroundColor DarkGray
    if (Confirm-Change "Turn off the hidden admin shares?") {
        Start-ChangeRecord
        try {
            Set-ItemProperty $lanmanKey -Name AutoShareWks -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty $lanmanKey -Name AutoShareServer -Value 0 -Type DWord -ErrorAction Stop
            Restart-Service LanmanServer -Force -ErrorAction Stop
            Start-Sleep -Seconds 3
            $still = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^([A-Za-z]|ADMIN)\$$' })
            if ($still.Count -eq 0) { Write-Host "    admin shares removed (shares left: $((Get-SmbShare).Name -join ', '))" -ForegroundColor DarkGray; $applied++ }
            else { Write-Host "    still present: $(($still.Name) -join ', ')" -ForegroundColor Yellow }
        } catch {
            Write-Host "    could not turn off admin shares: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Save-ChangeRecord
    }
}

if (-not $offered) { Write-Host "  nothing to change - every item is already applied" -ForegroundColor DarkGray }

Write-Host ""
if ($applied -eq 0) { Write-Host "Hardening pass finished - nothing changed." -ForegroundColor DarkGray }
else { Write-Host "Hardening pass finished - $applied item(s) applied. Reboot so all of them take effect." -ForegroundColor Green }
if ($script:ChangeRecord) {
    Write-Host "Change record: $($script:ChangeRecord.Before) and $($script:ChangeRecord.After)" -ForegroundColor DarkGray
    try { Stop-Transcript | Out-Null } catch { Write-Verbose -Message 'The transcript was not running.' }
}
$ErrorActionPreference = $previousErrorAction
