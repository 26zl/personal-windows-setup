# Contributing

Three standalone PowerShell scripts for Windows 10/11 plus a Sysmon
configuration. Bug reports and pull requests are welcome. For anything that
could be abused before it is fixed, use the private route in
[SECURITY.md](SECURITY.md) instead of an issue.

## Before you start

- The scripts run only on Windows, under Windows PowerShell 5.1 (the shell a
  fresh install opens) and PowerShell 7. A change has to parse and behave in
  both. The contract tests and the analyzer run anywhere `pwsh` runs.
- `setup.ps1` is the owner's personal bootstrap; its app list is a preference,
  not a bug. The health check and the hardening pass are general-purpose.
- Keep the documented promises: `health-check.ps1` never changes the system and
  writes files only for `-ReportPath` and the delegated tools' temporary output
  (the tests pin process starts and deletions to that code), and
  `harden-extras.ps1` changes and writes nothing until the user answers `y` to
  that specific change.

## Workflow

1. Branch from `main`, make the change, open a pull request against `main`.
   CI (`.github/workflows/lint.yml`) runs on every pull request and on pushes
   to `main`.
2. Say in the pull request what you ran it on (Windows version, 5.1 or 7).
   Most behaviour cannot be exercised outside Windows; CI covers parsing,
   static analysis, the contract tests, the pins, and a disposable Windows
   runner that installs Sysmon and runs the hardening pass answering `n`.
3. Write commit messages that say what changed and why, in the imperative
   ("Pin the nvim installer to a commit"), not "Fix" or "Fixes".

## Checks

The same checks CI runs, from a clone:

```powershell
# Static analysis. CI fails on Error or Warning; the settings file excludes
# only PSAvoidUsingWriteHost. The helper checks the package against the
# SHA-256 pinned in .github/workflows/lint.yml and installs nothing.
Import-Module (./.github/scripts/Install-PinnedModule.ps1 -Name PSScriptAnalyzer -Version 1.25.0 -Sha256 14E634C828EB98EFB9F40B2918BA90F139ED5ECCDF663A2A747736D996995D60)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Contract tests for setup.ps1, the health check and the hardening pass.
# They parse the scripts, not run them.
Import-Module (./.github/scripts/Install-PinnedModule.ps1 -Name Pester -Version 5.7.1 -Sha256 4A27904C6814A5FBE4758F8E49861F6A1994AEE77B71165A5C43C0371BA6C580)
Invoke-Pester -Path . -Output Detailed

# Every script must parse under Windows PowerShell 5.1 (run this in powershell.exe)
Get-ChildItem . -Recurse -Filter *.ps1 | ForEach-Object {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors)
    if ($errors) { "$($_.Name): $($errors[0].Message)" }
}
```

CI also checks that the SHA-256 pins in the scripts match the committed files
and the pinned downloads (see below). Dependabot does not see the module and
download pins; bump them by hand.

## File rules

`.gitattributes` and the contract tests enforce these; `.editorconfig` sets
them for editors:

- LF line endings and UTF-8 without a BOM in every script. `irm <raw-url> | iex`
  runs the raw bytes, and a BOM or CRLF breaks that path and the SHA-256 pins.
- `health-check.ps1` and `setup.ps1` stay pure ASCII.
- Four-space indentation in PowerShell, two in YAML and Markdown.

## Pinned files

The pins form a chain: `sysmon/sysmonconfig-export.xml` is pinned in
`sysmon/install-sysmon.ps1` (`$configSha256`), and `install-sysmon.ps1` and
`hardening/harden-extras.ps1` are pinned in `setup.ps1` (`$sysmonScriptSha256`,
`$hardenScriptSha256`). Editing the XML therefore changes all three files.
Update each pin in the same commit (`Get-FileHash <file> -Algorithm SHA256`);
CI fails on drift.

`setup.ps1` also pins what it takes from elsewhere: the 26zl/nvim installer and
PowerShellPerfect (a commit plus the file's SHA-256, and PowerShellPerfect's
bundle hash), the WSL Neovim tarball and ConfigureDefender. CI downloads each
one and checks it.

The Sysmon configuration is a fork of SwiftOnSecurity's sysmon-config
(CC BY 4.0): keep its header, license notice and fork fields, and record any
rule change in the README's supply-chain section, which documents the full diff
from upstream.

## License

MIT, see [LICENSE](LICENSE). Contributions are accepted under the same
license.
