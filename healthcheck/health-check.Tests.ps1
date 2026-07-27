<#
  Contract tests for health-check.ps1.

  These assert the promises the tool makes to the people who run it - that it only
  reads, that it ships in a form "irm | iex" can execute, and that a finding always
  carries enough to act on. They parse the script rather than run it, so they work
  on any platform and are safe in CI.

  Run:  Invoke-Pester .\healthcheck\health-check.Tests.ps1
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot 'health-check.ps1'
    $script:Raw = [IO.File]::ReadAllText($script:ScriptPath)
    $script:Bytes = [IO.File]::ReadAllBytes($script:ScriptPath)

    $tokens = $null
    $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ScriptPath, [ref]$tokens, [ref]$errors)
    $script:Tokens = $tokens
    $script:ParseErrors = $errors

    $script:Commands = $script:Ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    $script:Functions = $script:Ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

    $script:Categories = 'System', 'Stability', 'Drivers', 'Storage', 'Performance', 'Power',
    'Network', 'Security', 'Privacy', 'Updates', 'Logging', 'Software'
}

Describe 'Script integrity' {
    It 'parses without errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'has no UTF-8 BOM' {
        # A BOM survives into the string that "irm <url> | iex" evaluates and makes the
        # first token unparseable, which kills the documented install path.
        $hasBom = $script:Bytes.Length -ge 3 -and
        $script:Bytes[0] -eq 0xEF -and $script:Bytes[1] -eq 0xBB -and $script:Bytes[2] -eq 0xBF
        $hasBom | Should -BeFalse -Because 'a BOM breaks "irm | iex"'
    }

    It 'is pure ASCII' {
        # Non-ASCII is what forces a BOM in the first place, and it renders as mojibake
        # on any machine whose ANSI code page is not UTF-8.
        $offenders = [regex]::Matches($script:Raw, '[^\x00-\x7F]') |
        ForEach-Object { $_.Value } | Select-Object -Unique
        $offenders | Should -BeNullOrEmpty
    }

    It 'uses LF line endings only' {
        $script:Raw | Should -Not -Match "`r`n"
    }
}

Describe 'Read-only guarantee' {
    It 'calls no state-changing cmdlet' {
        # The tool's central promise. Functions defined inside the script are exempt -
        # they cannot be a system cmdlet in disguise - as are the formatting and object
        # constructors, which touch nothing outside the process.
        $ownFunctions = @($script:Functions.Name)
        $ownFunctions += $script:Ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name

        $allowed = @(
            'Write-Host', 'Write-Verbose', 'Write-Debug', 'Write-Output',
            'Add-Member', 'Add-Type', 'New-Object', 'New-TimeSpan', 'New-PSObject',
            'Out-String', 'Out-Null', 'Out-File', 'Start-Sleep', 'Set-StrictMode',
            'Format-Table', 'Format-List', 'Format-Hex', 'Import-Module', 'Export-Csv'
        ) + $ownFunctions

        $banned = '^(Set|Remove|New|Start|Stop|Restart|Clear|Disable|Enable|Add|Rename|Move|Copy|Write|Out|Export|Import|Invoke|Register|Unregister|Install|Uninstall|Update|Reset|Suspend|Resume|Push|Pop|Mount|Dismount|Initialize|Format|Repair|Optimize)-'

        $violations = $script:Commands |
        ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ -and $_ -match $banned -and $allowed -notcontains $_ } |
        Sort-Object -Unique

        $violations | Should -BeNullOrEmpty
    }

    It 'runs external tools in analysis mode only' {
        # defrag and dism can both modify the system with the wrong switch.
        foreach ($m in [regex]::Matches($script:Raw, '(?m)&\s*defrag\.exe([^\r\n]*)')) {
            $m.Groups[1].Value | Should -Match '/A' -Because 'defrag must analyse, not defragment'
        }
        foreach ($m in [regex]::Matches($script:Raw, '(?m)&\s*dism\.exe([^\r\n]*)')) {
            $m.Groups[1].Value | Should -Match 'AnalyzeComponentStore|/Get-'
        }
        foreach ($m in [regex]::Matches($script:Raw, '(?m)&\s*winget([^\r\n]*)')) {
            $m.Groups[1].Value | Should -Not -Match '--all|install|upgrade\s+[\w.]+'
        }
    }

    It 'never queries Win32_Product' {
        # Querying that class triggers an MSI self-repair on every installed package.
        # Comments are stripped first, so the note explaining why it is avoided does
        # not trip the test.
        $code = ($script:Tokens |
            Where-Object { $_.Kind -ne 'Comment' } |
            ForEach-Object { $_.Text }) -join ' '
        $code | Should -Not -Match 'Win32_Product\b'
    }
}

Describe 'Finding contract' {
    BeforeAll {
        $script:FindingCalls = $script:Commands |
        Where-Object { $_.GetCommandName() -eq 'Add-Finding' }
    }

    It 'has findings to check' {
        $script:FindingCalls.Count | Should -BeGreaterThan 0
    }

    It 'gives every finding a Severity, Title and Evidence' {
        $incomplete = @()
        foreach ($call in $script:FindingCalls) {
            $names = $call.CommandElements |
            Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
            ForEach-Object { $_.ParameterName }
            foreach ($required in 'Severity', 'Title', 'Evidence') {
                if ($names -notcontains $required) {
                    $incomplete += "line $($call.Extent.StartLineNumber): missing -$required"
                }
            }
        }
        $incomplete | Should -BeNullOrEmpty
    }

    It 'uses only defined severity values' {
        $valid = 'Critical', 'High', 'Medium', 'Low', 'Info'
        $bad = [regex]::Matches($script:Raw, "-Severity\s+'?([A-Za-z]+)'?") |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $valid -notcontains $_ } |
        Sort-Object -Unique
        $bad | Should -BeNullOrEmpty
    }

    It 'uses only defined confidence values' {
        $valid = 'Certain', 'Likely', 'Uncertain'
        $bad = [regex]::Matches($script:Raw, "-Confidence\s+'?([A-Za-z]+)'?") |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $valid -notcontains $_ } |
        Sort-Object -Unique
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'Category wiring' {
    It 'defines a Test-*Health function for every category' {
        # The category label and the function name differ for the two plurals.
        $map = @{
            System = 'Test-SystemHealth'; Stability = 'Test-StabilityHealth'
            Drivers = 'Test-DriverHealth'; Storage = 'Test-StorageHealth'
            Performance = 'Test-PerformanceHealth'; Power = 'Test-PowerHealth'
            Network = 'Test-NetworkHealth'; Security = 'Test-SecurityHealth'
            Privacy = 'Test-PrivacyHealth'; Updates = 'Test-UpdateHealth'
            Logging = 'Test-LoggingHealth'; Software = 'Test-SoftwareHealth'
        }
        foreach ($c in $script:Categories) {
            $script:Functions.Name | Should -Contain $map[$c]
        }
    }

    It 'invokes every category through Invoke-Check' {
        foreach ($c in $script:Categories) {
            $script:Raw | Should -Match ("Invoke-Check\s+'$c'")
        }
    }

    It 'offers every category in the -Category ValidateSet' {
        $set = [regex]::Match($script:Raw, "ValidateSet\(([^)]*)\)").Groups[1].Value
        $set | Should -Match "'All'"
        foreach ($c in $script:Categories) { $set | Should -Match "'$c'" }
    }
}

Describe 'Format-Size' {
    BeforeAll {
        # Pull the single function out of the script so it can be tested without
        # executing everything else in the file.
        $fn = $script:Functions | Where-Object Name -eq 'Format-Size'
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'reports <Expected> for <Bytes> bytes' -ForEach @(
        @{ Bytes = 4096; Expected = 'KB' }
        @{ Bytes = 512KB; Expected = 'KB' }
        @{ Bytes = 5MB; Expected = 'MB' }
        @{ Bytes = 3GB; Expected = 'GB' }
        @{ Bytes = 2TB; Expected = 'TB' }
    ) {
        Format-Size -Bytes $Bytes | Should -Match $Expected
    }

    It 'does not crash on zero' {
        { Format-Size -Bytes 0 } | Should -Not -Throw
    }
}

Describe 'Lookup tables' {
    # An OrderedDictionary indexed with an integer resolves by POSITION, not by key:
    # ([ordered]@{ 1 = 'a'; 23 = 'b' })[23] is an out-of-range read, not 'b'. A plain
    # hashtable resolves by key. Any [ordered] literal in the script whose keys are bare
    # integers is therefore a latent lookup bug the moment something indexes into it.
    It 'has no [ordered] hashtable literal with integer keys' {
        $ordered = $script:Ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.ConvertExpressionAst] -and
                $n.Type.TypeName.Name -eq 'ordered' -and
                $n.Child -is [System.Management.Automation.Language.HashtableAst]
            }, $true)

        $offenders = @()
        foreach ($o in $ordered) {
            foreach ($pair in $o.Child.KeyValuePairs) {
                if ($pair.Item1 -is [System.Management.Automation.Language.ConstantExpressionAst] -and
                    $pair.Item1.Value -is [int]) {
                    $offenders += "line $($o.Extent.StartLineNumber): key $($pair.Item1.Value)"
                }
            }
        }
        $offenders | Should -BeNullOrEmpty -Because 'integer-keyed [ordered] tables index by position, so use a plain @{} hashtable'
    }
}
