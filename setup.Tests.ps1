<#
  Contract tests for setup.ps1. They parse the script rather than run it, so they are
  safe anywhere: every prompt goes through Confirm-Step, every -Skip name is a real step,
  and the scripts this repo ships are only run from a local copy or a pinned download.

  Run:  Invoke-Pester .\setup.Tests.ps1
#>

BeforeAll {
    $script:SetupPath = Join-Path $PSScriptRoot 'setup.ps1'
    $script:SetupBytes = [IO.File]::ReadAllBytes($script:SetupPath)
    $script:SetupRaw = [Text.Encoding]::UTF8.GetString($script:SetupBytes)
    $tokens = $null
    $errors = $null
    $script:SetupAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:SetupPath, [ref]$tokens, [ref]$errors)
    $script:SetupErrors = $errors
    $script:SetupCommands = @($script:SetupAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
}

Describe 'setup.ps1 integrity' {
    It 'parses without errors' {
        $script:SetupErrors | Should -BeNullOrEmpty
    }

    It 'has no BOM, only LF line endings and only ASCII, so irm | iex keeps working' {
        $hasBom = $script:SetupBytes.Length -ge 3 -and
        $script:SetupBytes[0] -eq 0xEF -and $script:SetupBytes[1] -eq 0xBB -and $script:SetupBytes[2] -eq 0xBF
        $hasBom | Should -BeFalse
        $script:SetupRaw | Should -Not -Match "`r`n"
        @($script:SetupBytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Prompts' {
    It 'asks only through Confirm-Step' {
        $readHost = @($script:SetupCommands | Where-Object { $_.GetCommandName() -eq 'Read-Host' })
        $readHost.Count | Should -Be 1
        $enclosing = $readHost[0].Parent
        while ($enclosing -and $enclosing -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $enclosing = $enclosing.Parent }
        $enclosing.Name | Should -Be 'Confirm-Step'
    }

    It 'offers exactly the prompted steps in the -Skip ValidateSet' {
        $skipParameter = $script:SetupAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Skip' }
        $validateSet = $skipParameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
        $offered = @($validateSet.PositionalArguments | ForEach-Object { $_.Value }) | Sort-Object

        $asked = @()
        foreach ($command in $script:SetupCommands) {
            $name = $command.GetCommandName()
            if ($name -eq 'Confirm-Step') {
                $step = $command.CommandElements[1]
                if ($step -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $asked += $step.Value }
            } elseif ($name -eq 'Invoke-Tool') {
                $index = [array]::IndexOf(@($command.CommandElements | ForEach-Object { $_.Extent.Text }), '-Step')
                if ($index -gt 0) { $asked += $command.CommandElements[$index + 1].Value }
            }
        }
        (($asked | Sort-Object -Unique) -join ', ') | Should -Be ($offered -join ', ')
    }
}

Describe 'Downloads' {
    It 'runs its own scripts only through Resolve-OwnScript' {
        # A raw URL to this repo's scripts outside the help text would bypass the local copy and the pin.
        $code = ($script:SetupAst.EndBlock.Extent.Text, $script:SetupAst.BeginBlock.Extent.Text) -join "`n"
        $code | Should -Not -Match 'personal-windows-setup/raw/(main|\$RepoRef)/(sysmon|hardening)/'
        foreach ($own in 'sysmon/install-sysmon.ps1', 'hardening/harden-extras.ps1') {
            $script:SetupRaw | Should -Match ("Resolve-OwnScript '{0}'" -f [regex]::Escape($own))
        }
    }

    It 'pins every installer it takes from the owner''s other repositories' {
        $script:SetupRaw | Should -Match "nvimInstallerCommit\s*=\s*'[0-9a-f]{40}'"
        $script:SetupRaw | Should -Match "nvimInstallerSha256\s*=\s*'[A-F0-9]{64}'"
        $script:SetupRaw | Should -Match "pspCommit\s*=\s*'[0-9a-f]{40}'"
        $script:SetupRaw | Should -Match "pspSetupSha256\s*=\s*'[A-F0-9]{64}'"
        $script:SetupRaw | Should -Match "pspBundleSha256\s*=\s*'[A-F0-9]{64}'"
        $script:SetupRaw | Should -Not -Match '-SkipHashCheck'
        $script:SetupRaw | Should -Not -Match '26zl/nvim/raw/main'
    }

    It 'checks the Neovim tarball for WSL against its SHA-256' {
        $script:SetupRaw | Should -Match "nvimTarballSha256\s*=\s*'[a-f0-9]{64}'"
        $script:SetupRaw | Should -Match 'sha256sum -c -'
        $script:SetupRaw | Should -Not -Match 'releases/download/stable/'
    }
}
