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
- Keep the documented promises: `health-check.ps1` never writes to the system
  (the PrivescCheck delegation is the one exception, and the tests pin it to
  that code), and `harden-extras.ps1` changes nothing until the user answers
  `y` to that specific change.

## Workflow

1. Branch from `main`, make the change, open a pull request against `main`.
   CI (`.github/workflows/lint.yml`) runs on every pull request and on pushes
   to `main`.
2. Say in the pull request what you ran it on (Windows version, 5.1 or 7).
   Most behaviour cannot be exercised outside Windows; CI covers parsing,
   static analysis and the contract tests, not the checks themselves.

## Checks

The same checks CI runs, from a clone:

```powershell
# Static analysis. CI fails on Error or Warning; the settings file excludes
# only PSAvoidUsingWriteHost.
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Contract tests for the health check. They parse the script, not run it.
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester -Path ./healthcheck -Output Detailed

# Every script must parse under Windows PowerShell 5.1 (run this in powershell.exe)
Get-ChildItem . -Recurse -Filter *.ps1 | ForEach-Object {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors)
    if ($errors) { "$($_.Name): $($errors[0].Message)" }
}
```

CI also checks that the SHA-256 pins in the scripts match the committed files
(see below).

## File rules

`.gitattributes` and the contract tests enforce these; `.editorconfig` sets
them for editors:

- LF line endings and UTF-8 without a BOM in every script. `irm <raw-url> | iex`
  runs the raw bytes, and a BOM or CRLF breaks that path and the SHA-256 pins.
- `health-check.ps1` stays pure ASCII.
- Four-space indentation in PowerShell, two in YAML and Markdown.

## Pinned files

`office/OfficeSetup.exe` is pinned in `setup.ps1` (`$officeSha256`) and
`sysmon/sysmonconfig-export.xml` in `sysmon/install-sysmon.ps1`
(`$configSha256`). If you replace or edit one, update the pin in the same
commit (`Get-FileHash <file> -Algorithm SHA256`); CI fails on drift. The Sysmon
configuration is a fork of SwiftOnSecurity's sysmon-config (CC BY 4.0): keep
its header and license notice, and record any rule change in the README's
supply-chain section, which documents the full diff from upstream.

## License

MIT, see [LICENSE](LICENSE). Contributions are accepted under the same
license.
