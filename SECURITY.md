# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/26zl/personal-windows-setup/security/advisories/new). Please do not open a public issue for anything that could be abused before it is fixed.

Include the affected script, the version you ran (commit SHA if you have it), and what an attacker could do with it. Expect an initial reply within a week.

## What is in scope

Anything that lets these scripts do something the documentation says they will not:

- The **health check** claims to be read-only. Any path where it writes to the system is in scope, including the external tools it shells out to. It writes files in exactly two documented cases, both only when you ask: `-ReportPath` writes the Markdown report to the path you give, and the delegation parameters (`-DeepBlueCliPath`, `-PrivescCheckPath`) capture each tool's output — and PrivescCheck's CSV report — in uniquely named temporary files that are deleted when the run ends. A leftover file, a write outside those paths, or a `Start-Process`/`Remove-Item` reachable without passing one of the delegation parameters is a finding — the contract tests pin both to the delegation code specifically so that stays true. The only other process it starts is the time-limited `winget upgrade` listing, pinned by a contract test in the same way.
- **Delegation to third-party tools** (`-DeepBlueCliPath`, `-PrivescCheckPath`) runs code this project did not write and does not ship. A way to make the script invoke something other than the path the user passed — argument injection through the path, an unquoted expansion, a search-order hijack on the interpreter — is in scope. Bugs in DeepBlueCLI or PrivescCheck themselves are not; report those upstream.
- The **hardening pass** claims to change nothing until you answer `y`, and that includes the restore point, transcript and JSON record it creates before the first approved change. Any change or file written without that answer is in scope; a contract test and a CI run that answers `n` to everything hold it to that.
- Weaknesses in the supply-chain controls: a way past the pinned SHA-256 checks (`sysmon/sysmonconfig-export.xml`; `install-sysmon.ps1` and `harden-extras.ps1` when `setup.ps1` downloads them; the nvim installer; PowerShellPerfect's script and bundle; the WSL Neovim tarball; `ConfigureDefender.exe`), past the Authenticode checks (ConfigureDefender, standalone Sysmon), or past the admin-only staging folder these are verified in, or a way to make the scripts fetch something other than what the pins cover.
- Command injection, privilege escalation, or unsafe handling of paths and registry values in any of the scripts.
- **Unpinned code that `setup.ps1` runs as administrator**, stated plainly rather than buried. Only after a `y`: the Claude Code native installer (`claude.ai/install.ps1`), Scoop (`get.scoop.sh`), Win11Debloat and Winhance. They serve whatever their publishers ship at that moment, so anyone who controls those endpoints gets administrator code execution on a machine where you answered `y`. Everything else `setup.ps1` downloads and runs is pinned. The nvim installer is pinned too, but the config it clones (and the WSL step's clone) comes from [26zl/nvim](https://github.com/26zl/nvim)'s default branch and runs inside Neovim as your user.

## What is not in scope

- **Bugs in third-party installers the scripts fetch at run time** — Scoop, Win11Debloat, Winhance, Claude Code and the vendor installers. Report those upstream.
- **Packages installed through winget.** Report those to the package maintainer or to Microsoft.
- The fact that `setup.ps1` runs as Administrator and installs a lot of software. That is what it is for, and the README says so.
- Findings the health check reports about *your* machine. Those are output, not vulnerabilities.

## Verifying what you are about to run

Every script is designed to be read before it is run:

```powershell
# read it instead of piping it straight to iex
irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1 | Out-File health-check.ps1
```

The pinned hashes live next to the code that checks them (`$configSha256` in `install-sysmon.ps1`; `$sysmonScriptSha256`, `$hardenScriptSha256`, `$nvimInstallerSha256`, `$pspSetupSha256`, `$pspBundleSha256`, `$nvimTarballSha256` and `$cdSha256` in `setup.ps1`), so you can verify any pinned file yourself with `Get-FileHash`. CI checks the pins on every push and pull request. To run a fixed version of `setup.ps1` rather than `main`, see the README's bootstrap section.
