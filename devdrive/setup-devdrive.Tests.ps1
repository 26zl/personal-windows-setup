<#
  Contract tests for setup-devdrive.ps1. They parse the script and load its pure helper
  functions on their own, so nothing here creates a disk, a task or a variable.

  Run:  Invoke-Pester .\devdrive\setup-devdrive.Tests.ps1
#>

BeforeAll {
    $script:DevDrivePath = Join-Path $PSScriptRoot 'setup-devdrive.ps1'
    $script:DevDriveBytes = [IO.File]::ReadAllBytes($script:DevDrivePath)
    $script:DevDriveRaw = [Text.Encoding]::UTF8.GetString($script:DevDriveBytes)
    $tokens = $null
    $errors = $null
    $script:DevDriveAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:DevDrivePath, [ref]$tokens, [ref]$errors)
    $script:DevDriveErrors = $errors
    $script:Functions = @($script:DevDriveAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $script:Commands = @($script:DevDriveAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

    # The pure helpers, defined here without running the script.
    foreach ($name in 'Select-DriveLetter', 'ConvertFrom-DevDriveQuery', 'Merge-FilterList', 'Get-UpdatedPathValue',
        'Get-MavenOptsValue', 'Get-CacheMap', 'Test-SamePath', 'Test-PathOnDrive') {
        $definition = $script:Functions | Where-Object { $_.Name -eq $name }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
}

Describe 'setup-devdrive.ps1 integrity' {
    It 'parses without errors' {
        $script:DevDriveErrors | Should -BeNullOrEmpty
    }

    It 'has no BOM, only LF line endings and only ASCII' {
        $hasBom = $script:DevDriveBytes.Length -ge 3 -and
        $script:DevDriveBytes[0] -eq 0xEF -and $script:DevDriveBytes[1] -eq 0xBB -and $script:DevDriveBytes[2] -eq 0xBF
        $hasBom | Should -BeFalse
        $script:DevDriveRaw | Should -Not -Match "`r`n"
        @($script:DevDriveBytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Change contract' {
    It 'changes the system only in functions that support -WhatIf and ask ShouldProcess' {
        $changing = '^(Set|New|Remove|Move|Copy|Register|Unregister|Mount|Dismount|Initialize|Format|Clear|Rename)-'
        $native = '^(diskpart|robocopy|attrib|icacls|schtasks|reg|setx)(\.exe)?$'
        # Process-local or read-only despite the verb.
        $harmless = @('New-Object')
        # The script's own functions are held to the same rule where they are defined.
        $own = @($script:Functions | ForEach-Object Name)
        $offenders = foreach ($command in $script:Commands) {
            $name = $command.GetCommandName()
            if (-not $name -or $harmless -contains $name -or $own -contains $name) { continue }
            $function = $command.Parent
            while ($function -and $function -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $function = $function.Parent }
            # fsutil only reads in the query helper; anywhere else it changes something.
            $isFsutilChange = $name -match '^fsutil(\.exe)?$' -and -not ($function -and $function.Name -eq 'Invoke-DevDriveQuery')
            if ($name -notmatch $changing -and $name -notmatch $native -and -not $isFsutilChange) { continue }
            if (-not $function) { "$name (outside any function)"; continue }
            $text = $function.Body.Extent.Text
            if ($text -notmatch 'SupportsShouldProcess' -or $text -notmatch '\$PSCmdlet\.ShouldProcess\(') { "$name in $($function.Name)" }
        }
        @($offenders) | Should -BeNullOrEmpty
    }

    It 'never changes Defender settings' {
        @($script:Commands | Where-Object { $_.GetCommandName() -match '^(Set|Add|Remove)-MpPreference$' }) | Should -BeNullOrEmpty
        $script:DevDriveRaw | Should -Not -Match '(Set|New)-ItemProperty[^\r\n]*Windows Defender'
    }

    It 'attaches the VHDX at boot with an inline command run as SYSTEM, not a script file a user could swap' {
        $task = $script:Functions | Where-Object { $_.Name -eq 'Register-DevDriveAttachTask' }
        $text = $task.Body.Extent.Text
        $text | Should -Match '<UserId>S-1-5-18</UserId>'
        $text | Should -Match '-Command'
        $text | Should -Not -Match '-File'
    }

    It 'writes the diskpart script into an admin-only staging folder' {
        $vhd = $script:Functions | Where-Object { $_.Name -eq 'New-DevDriveVhd' }
        $vhd.Body.Extent.Text | Should -Match 'New-StagingDirectory'
        ($script:Functions | Where-Object { $_.Name -eq 'New-StagingDirectory' }).Body.Extent.Text | Should -Match 'SystemRoot'
    }
}

Describe 'Drive letter choice' {
    It 'takes the first preferred letter that is free' {
        Select-DriveLetter -Preferred 'D', 'S', 'V' -Unavailable 'C', 'D', 'E' | Should -Be 'S'
    }

    It 'compares letters case-insensitively' {
        Select-DriveLetter -Preferred 'd', 's' -Unavailable 'D' | Should -Be 'S'
    }

    It 'returns nothing when every preferred letter is taken' {
        Select-DriveLetter -Preferred 'D', 'S' -Unavailable 'D', 'S' | Should -BeNullOrEmpty
    }
}

Describe 'fsutil devdrv query parsing' {
    It 'reads the machine-wide state and the allowed filters' {
        $lines = @('Developer volumes are enabled.', '', 'Developer volumes are protected by antivirus filter.', '',
            'Filters allowed on any developer volume:', '    WdFilter, SysmonDrv')
        $state = ConvertFrom-DevDriveQuery -Lines $lines
        $state.Enabled | Should -BeTrue
        $state.AntivirusAllowed | Should -BeTrue
        $state.AllowedFilters | Should -Be @('WdFilter', 'SysmonDrv')
    }

    It 'reports an empty allow list when none is set' {
        $state = ConvertFrom-DevDriveQuery -Lines @('Developer volumes are enabled.', '', 'Developer volumes are protected by antivirus filter.')
        @($state.AllowedFilters).Count | Should -Be 0
    }

    It 'tells a volume without antivirus protection apart' {
        (ConvertFrom-DevDriveQuery -Lines @('Developer volumes are enabled.', 'Developer volumes are not protected by antivirus filter.')).AntivirusAllowed | Should -BeFalse
    }

    It 'recognises an ordinary volume' {
        $state = ConvertFrom-DevDriveQuery -Lines @('This is not a developer volume.')
        $state.IsDevDrive | Should -BeFalse
        $state.IsTrusted | Should -BeFalse
    }

    It 'recognises a trusted Dev Drive' {
        $state = ConvertFrom-DevDriveQuery -Lines @('This is a trusted developer volume.')
        $state.IsDevDrive | Should -BeTrue
        $state.IsTrusted | Should -BeTrue
    }

    It 'leaves unknown (localised) output undecided instead of guessing' {
        $state = ConvertFrom-DevDriveQuery -Lines @('Utviklervolumer er aktivert.')
        $state.Enabled | Should -BeNullOrEmpty
        $state.IsDevDrive | Should -BeNullOrEmpty
    }
}

Describe 'Filter list merge' {
    It 'adds missing filters and keeps the existing order and spelling' {
        # The function returns the list as one object; the parentheses unroll it for Should.
        (Merge-FilterList -Current 'PrjFlt', 'wdfilter' -Wanted 'WdFilter', 'SysmonDrv') | Should -Be @('PrjFlt', 'wdfilter', 'SysmonDrv')
    }

    It 'handles an empty current list' {
        (Merge-FilterList -Current @() -Wanted 'WdFilter') | Should -Be @('WdFilter')
    }
}

Describe 'PATH update' {
    It 'replaces the old entry in place, ignoring case and a trailing backslash' {
        Get-UpdatedPathValue -PathValue 'C:\a;C:\Users\x\.cargo\bin\;C:\b' -Old 'c:\users\x\.CARGO\bin' -New 'S:\packages\cargo\bin' |
            Should -Be 'C:\a;S:\packages\cargo\bin;C:\b'
    }

    It 'matches an entry written with an environment variable and keeps the others unexpanded' {
        $old = Join-Path $env:SystemRoot 'cargo-test-bin'
        Get-UpdatedPathValue -PathValue '%SystemRoot%\cargo-test-bin;%USERPROFILE%\bin' -Old $old -New 'S:\cargo\bin' |
            Should -Be 'S:\cargo\bin;%USERPROFILE%\bin'
    }

    It 'appends the new entry when the old one is missing, and only once' {
        Get-UpdatedPathValue -PathValue 'C:\a' -Old 'C:\gone' -New 'S:\new' | Should -Be 'C:\a;S:\new'
        Get-UpdatedPathValue -PathValue 'C:\a;S:\new' -Old 'C:\gone' -New 'S:\new' | Should -Be 'C:\a;S:\new'
        Get-UpdatedPathValue -PathValue 'C:\old;S:\new' -Old 'C:\old' -New 'S:\new' | Should -Be 'S:\new'
    }
}

Describe 'MAVEN_OPTS' {
    It 'sets only the repository when nothing is set' {
        Get-MavenOptsValue -Current $null -Repository 'S:\packages\maven' | Should -Be '-Dmaven.repo.local=S:\packages\maven'
    }

    It 'keeps other options and replaces an existing repository' {
        Get-MavenOptsValue -Current '-Xmx2g -Dmaven.repo.local=C:\old' -Repository 'S:\m' | Should -Be '-Xmx2g -Dmaven.repo.local=S:\m'
        Get-MavenOptsValue -Current '-Xmx2g' -Repository 'S:\m' | Should -Be '-Xmx2g -Dmaven.repo.local=S:\m'
    }
}

Describe 'Cache map' {
    BeforeAll {
        $script:Map = Get-CacheMap -Root 'S:\packages' -UserProfile 'C:\Users\u' -LocalAppData 'C:\Users\u\AppData\Local' -AppData 'C:\Users\u\AppData\Roaming' -GoPath $null
    }

    It 'covers the caches Microsoft lists for Dev Drive and the ones this setup installs' {
        $names = @($script:Map | ForEach-Object Name)
        foreach ($expected in 'npm_config_cache', 'store-dir', 'BUN_INSTALL_CACHE_DIR', 'NUGET_PACKAGES', 'NUGET_HTTP_CACHE_PATH', 'PIP_CACHE_DIR',
            'UV_CACHE_DIR', 'CARGO_HOME', 'GOMODCACHE', 'GOCACHE', 'GRADLE_USER_HOME', 'MAVEN_OPTS', 'VCPKG_DEFAULT_BINARY_CACHE') {
            $names | Should -Contain $expected
        }
        ($names | Sort-Object -Unique).Count | Should -Be $names.Count
    }

    It 'puts every cache under the Dev Drive root and moves it from outside' {
        foreach ($entry in $script:Map) {
            $entry.Path | Should -BeLike 'S:\packages\*'
            foreach ($old in $entry.Old) { $old | Should -Not -BeLike 'S:\*' }
        }
    }

    It 'falls back to %USERPROFILE%\go when GOPATH is not set' {
        ($script:Map | Where-Object Name -eq 'GOMODCACHE').Old | Should -Be @('C:\Users\u\go\pkg\mod')
    }
}

Describe 'Path helpers' {
    It 'compares paths without case or a trailing backslash' {
        Test-SamePath 'C:\A\' 'c:\a' | Should -BeTrue
        Test-SamePath 'C:\A' 'C:\B' | Should -BeFalse
        Test-SamePath '' 'C:\A' | Should -BeFalse
    }

    It 'tells whether a path is on a drive' {
        Test-PathOnDrive -Path 's:\packages\npm' -Letter 'S' | Should -BeTrue
        Test-PathOnDrive -Path 'C:\Users' -Letter 'S' | Should -BeFalse
        Test-PathOnDrive -Path '' -Letter 'S' | Should -BeFalse
    }
}
