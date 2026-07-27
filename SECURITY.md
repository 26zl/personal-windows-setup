# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/26zl/personal-windows-setup/security/advisories/new). Please do not open a public issue for anything that could be abused before it is fixed.

Include the affected script, the version you ran (commit SHA if you have it), and what an attacker could do with it. Expect an initial reply within a week.

## What is in scope

Anything that lets these scripts do something the documentation says they will not:

- The **health check** claims to be read-only. Any path where it writes to the system is in scope, including the external tools it shells out to.
- The **hardening pass** claims to change nothing until you answer `y`. Any change applied without that answer is in scope.
- Weaknesses in the supply-chain controls: a way past the pinned SHA-256 and Authenticode checks on `office/OfficeSetup.exe`, `ConfigureDefender.exe` or `sysmon/sysmonconfig-export.xml`, or a way to make the scripts fetch something other than what the pins cover.
- Command injection, privilege escalation, or unsafe handling of paths and registry values in any of the scripts.

## What is not in scope

- **Third-party installers the scripts fetch at run time** — Scoop, Win11Debloat, Winhance and the vendor installers, each behind a `y/n` prompt in `setup.ps1`. Report bugs in those upstream.

What *is* in scope here, and worth stating plainly rather than burying: `setup.ps1` fetches several scripts over `raw/main` and runs them with administrator rights without a pinned hash — my own [`nvim`](https://github.com/26zl/nvim) and [`PowerShellPerfect`](https://github.com/26zl/PowerShellPerfect) repos (the latter with `-SkipHashCheck`), plus the tweak tools. `main` is a moving target, so what you audit today is not necessarily what runs tomorrow. Anyone who can push to those repos, or who can sit between you and GitHub, gets administrator code execution. Pin a commit or read the scripts first if that matters to you. The three bundled artifacts below *are* pinned.
- **Packages installed through winget.** Report those to the package maintainer or to Microsoft.
- The fact that `setup.ps1` runs as Administrator and installs a lot of software. That is what it is for, and the README says so.
- Findings the health check reports about *your* machine. Those are output, not vulnerabilities.

## Verifying what you are about to run

Every script is designed to be read before it is run:

```powershell
# read it instead of piping it straight to iex
irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1 | Out-File health-check.ps1
```

The pinned hashes live next to the code that checks them (`$officeSha256`, `$cdSha256`, `$configSha256`), so you can verify any bundled file yourself with `Get-FileHash`.
