<#
  Contract tests for harden-extras.ps1: it changes nothing until the user answers y to
  that change. They parse the script rather than run it, so they are safe anywhere.

  Run:  Invoke-Pester .\hardening\harden-extras.Tests.ps1
#>

BeforeAll {
    $script:HardenPath = Join-Path $PSScriptRoot 'harden-extras.ps1'
    $script:HardenBytes = [IO.File]::ReadAllBytes($script:HardenPath)
    $tokens = $null
    $errors = $null
    $script:HardenAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:HardenPath, [ref]$tokens, [ref]$errors)
    $script:HardenErrors = $errors
}

Describe 'harden-extras.ps1 integrity' {
    It 'parses without errors' {
        $script:HardenErrors | Should -BeNullOrEmpty
    }

    It 'has no BOM and only LF line endings, so irm | iex keeps working' {
        $hasBom = $script:HardenBytes.Length -ge 3 -and
        $script:HardenBytes[0] -eq 0xEF -and $script:HardenBytes[1] -eq 0xBB -and $script:HardenBytes[2] -eq 0xBF
        $hasBom | Should -BeFalse
        [Text.Encoding]::UTF8.GetString($script:HardenBytes) | Should -Not -Match "`r`n"
    }
}

Describe 'Confirmation contract' {
    It 'changes the system only inside a branch the user confirmed' {
        # A state-changing command counts as confirmed when it sits in the body of
        # "if (Confirm-Change ...)", or inside a function that is only called from there.
        $stateVerbs = '^(Set|New|Remove|Add|Clear|Restart|Stop|Start|Enable|Disable|Checkpoint|Rename|Move|Copy|Out|Export|Save|Register|Unregister|Install|Uninstall|Update|Reset|Suspend|Resume|Grant|Revoke|Block|Unblock|Mount|Dismount|Initialize|Format|Repair|Optimize|Invoke)-'
        $nativeTools = '^(reg|netsh|sc|bcdedit|powercfg|dism|wevtutil|auditpol|schtasks|icacls|takeown|net|wmic|vssadmin)(\.exe)?$'
        # Process-local or read-only despite the verb; Stop-Transcript closes the record.
        $harmless = @('New-Object', 'Out-Null', 'Out-String', 'Start-Sleep', 'Stop-Transcript')

        $commands = @($script:HardenAst.FindAll(
                { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

        $enclosingFunction = {
            param($node)
            for ($p = $node.Parent; $p; $p = $p.Parent) {
                if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name }
            }
            $null
        }
        $isConfirmed = {
            param($node)
            $child = $node
            for ($p = $node.Parent; $p; $p = $p.Parent) {
                if ($p -is [System.Management.Automation.Language.IfStatementAst]) {
                    foreach ($clause in $p.Clauses) {
                        $condition = $clause.Item1
                        if ([object]::ReferenceEquals($clause.Item2, $child) -and
                            $condition -is [System.Management.Automation.Language.PipelineAst] -and
                            $condition.PipelineElements.Count -eq 1 -and
                            $condition.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst] -and
                            $condition.PipelineElements[0].GetCommandName() -eq 'Confirm-Change') {
                            return $true
                        }
                    }
                }
                $child = $p
            }
            $false
        }
        $changesState = {
            param($name, $sensitive)
            $name -and $harmless -notcontains $name -and
            ($name -match $stateVerbs -or $name -match $nativeTools -or $sensitive.ContainsKey($name))
        }

        # Functions that change state, directly or through each other.
        $sensitive = @{}
        do {
            $grew = $false
            foreach ($command in $commands) {
                if (-not (& $changesState $command.GetCommandName() $sensitive)) { continue }
                $function = & $enclosingFunction $command
                if ($function -and -not $sensitive.ContainsKey($function)) { $sensitive[$function] = $true; $grew = $true }
            }
        } while ($grew)

        $unconfirmed = @()
        foreach ($command in $commands) {
            $name = $command.GetCommandName()
            if (-not (& $changesState $name $sensitive)) { continue }
            if (& $enclosingFunction $command) { continue }
            if (-not (& $isConfirmed $command)) { $unconfirmed += "$name (line $($command.Extent.StartLineNumber))" }
        }

        $sensitive.Keys | Should -Contain 'Set-AsrRule' -Because 'the analysis must see through helper functions'
        $unconfirmed | Should -BeNullOrEmpty
    }

    It 'answers no when there is no console to ask' {
        # Read-Host throws in a non-interactive session; Confirm-Change must turn that into no.
        $function = $script:HardenAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Confirm-Change' }, $true) |
            Select-Object -First 1
        . ([scriptblock]::Create($function.Extent.Text))
        Mock Read-Host { throw [System.Management.Automation.PSInvalidOperationException]::new('no console') }
        Confirm-Change 'Change it?' | Should -BeFalse
        Mock Read-Host { 'y' }
        Confirm-Change 'Change it?' | Should -BeTrue
        Mock Read-Host { $null }
        Confirm-Change 'Change it?' | Should -BeFalse
    }
}
