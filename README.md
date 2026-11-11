# personal-windows-setup

[![lint](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml/badge.svg)](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml)
![Platform](https://img.shields.io/badge/platform-Windows%2011%20Pro-0078D6?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Three standalone PowerShell tools for Windows 10/11 — a **health check**, a **hardening pass**, and a **bootstrap installer**. Each runs on its own; you do not need the others.

| Tool | What it does |
|---|---|
| [**Health check**](#health-check) | Read-only diagnostic that audits security, privacy, performance, drivers, storage, power and battery, network, updates, event logging and installed software. Works on any Windows 10/11 machine, laptop or desktop, and changes nothing. |
| [**Hardening pass**](#hardening-pass) | Opt-in security tightening for the settings common hardening tools leave alone. Reports first, asks before every change. |
| [**Bootstrap installer**](#bootstrap-installer) | My own winget-based setup for a fresh Windows 11 Pro machine after a factory reset. Personal by nature — read the app list before running it. |

Nothing here claims to be exhaustive; it is the starting point I use on my own machines.

## Health check

[`healthcheck/health-check.ps1`](healthcheck/health-check.ps1) is a standalone diagnostic — it is independent of the installer below and works on **any** Windows 10/11 machine, laptop or desktop, physical or virtual. Run it whenever a machine feels off, or on a schedule to catch things that creep in.

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1 | iex
```

**It changes nothing.** Every check is a `Get-`/`Test-`/query call — no `Set-`, no service or registry writes — and the few external tools it shells out to run in analysis mode only (`defrag /A`, `dism /AnalyzeComponentStore`, `fsutil behavior query`, `powercfg /query`, `auditpol /get`, and `winget upgrade` as a listing, which can refresh winget's own package index and is stopped after two minutes). It writes files only when you ask: the report for `-ReportPath`, and temporary files for the [delegated tools](#delegating-to-those-tools). Findings arrive with the observed value as evidence and the command you would run to fix it yourself, so you stay in control of what actually happens to the machine. Run through `irm | iex`, it puts the console encoding and preference settings it changes back and removes the variables it created; the functions it defines stay until you close the window. Set `NO_COLOR` for output without colours.

It runs fine as a normal user and tells you which checks it skipped for want of rights; elevate for full coverage. It also adapts to the hardware it finds: battery wear, cycle count and charge-time checks only run where there is a battery, fragmentation only on spinning disks, thermal zones only where the ACPI class exists. Anything it cannot check is reported as **skipped**, never as healthy — an unrun check is not a pass.

Twelve categories. A full elevated run took about a minute on the machine it was written on, and 13 s with `-Fast`:

| Category | Covers |
|---|---|
| `System` | Version and support window, activation, pending reboot, uptime, time sync, page file, user profile integrity |
| `Stability` | Bluescreens and bugcheck codes, unexpected shutdowns, WHEA hardware faults, app and service crashes, dump configuration |
| `Drivers` | Devices in error, duplicate driver packages, unsigned kernel drivers, drivers loading from user-writable paths, Microsoft's vulnerable-driver blocklist |
| `Storage` | Free space, SMART wear and temperature, TRIM, restore points and shadow-copy quota, component store, large temp folders |
| `Performance` | Startup items (including ones pointing at files that no longer exist), boot-time telemetry from Windows' own diagnostics log, memory pressure, processor power states, scheduled tasks |
| `Power` | Power plan, Fast Startup, hibernation, wake timers and wake-armed devices, and on laptops: battery wear against design capacity, cycle count, runtime, on-battery limits |
| `Network` | Link speed vs adapter capability, firewall profiles and inbound allows, listening ports by owning process, SMB1/signing/guest logon, NetBIOS and LLMNR, hosts file, proxy, DNS |
| `Security` | Defender in depth including exclusions and ASR coverage, VBS/HVCI, Secure Boot, TPM, BitLocker, LSA protection, UAC, accounts and password policy, RDP and remote services, root certificates |
| `Privacy` | Telemetry level (and the Pro/Enterprise nuance most guides get wrong), advertising ID, activity history, per-category app permissions, search, error reporting, delivery optimization, account type |
| `Updates` | Patch age, pending and **repeatedly failing** updates, update services, policies that quietly block updates, winget upgrades available |
| `Logging` | How many *days* each event log actually covers rather than just its size, audit policy gaps, PowerShell logging under both the Windows and PowerShell 7 policy keys, Sysmon health and dropped events |
| `Software` | Real duplicates (VC++ redistributables excluded — many versions there are normal), orphaned uninstall entries, known-risky or end-of-life software, competing antivirus products, browser extension counts |

```powershell
# just one or two areas
& ([scriptblock]::Create((irm https://github.com/26zl/personal-windows-setup/raw/main/healthcheck/health-check.ps1))) -Category Security,Privacy

# from a clone: write a Markdown report, hide the per-check OK lines, skip the slow checks
.\healthcheck\health-check.ps1 -ReportPath .\health.md -FindingsOnly -Fast
```

Severity is deliberately conservative — `Critical` means data loss or an active compromise is imminent, and a healthy machine should produce none. Findings the script cannot fully prove are marked `likely` or `uncertain` rather than stated as fact.

The evidence lines are what make a finding actionable, and they are also what makes a report identifying: computer and user names, profile paths, local addresses and the Wi-Fi network name, listening ports with the owning process, members of the local Administrators group, installed software. `-ReportPath` writes that to disk with a warning at the top of the file — read it through before pasting it into a forum thread or a support ticket.

### What it does not do

It checks **configuration and history**, not behaviour. It cannot tell you something malicious is running right now: there is no process baselining, no hash reputation lookup, no memory inspection and no traffic analysis. A machine can pass every check here and still be compromised — a clean report means "nothing is configured wrong and nothing bad is recorded", not "this machine is clean".

Four things it deliberately leaves to tools built for them:

| Not covered | Use instead | Can be delegated to |
|---|---|---|
| Compliance against a published baseline (CIS, Microsoft Security Baselines) | [HardeningKitty](https://github.com/scipag/HardeningKitty) | — |
| Privilege-escalation paths — weak service ACLs, unquoted service paths, writable `%PATH%`, DLL hijack candidates | [PrivescCheck](https://github.com/itm4n/PrivescCheck) | `-PrivescCheckPath` |
| Credential exposure — saved RDP passwords, browser credential stores, secrets in `unattend.xml` or shell history | [winPEAS](https://github.com/peass-ng/PEASS-ng) | — |
| Threat hunting *inside* log content — suspicious command lines in 4688, obfuscated PowerShell in 4104 | [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) | `-DeepBlueCliPath` |

This tool verifies that the logging those tools depend on exists and reaches far enough back. It does not read the contents looking for attacks.

### Delegating to those tools

Two of them can be folded in, if you already have them:

```powershell
.\health-check.ps1 -DeepBlueCliPath C:\tools\DeepBlueCLI\DeepBlue.ps1 `
                   -PrivescCheckPath C:\tools\PrivescCheck\PrivescCheck.ps1
```

Their findings appear in the report under `Logging` and `Security` respectively, attributed to them. Read this before using it:

- **Nothing is downloaded and neither tool is bundled.** You obtain and vet them yourself; the path you pass is the only way either runs. That is not only a supply-chain choice — DeepBlueCLI is GPL-3.0 and this project is MIT, so shipping its code here would force the whole repo to GPL. Running it as a separate program is what the GPL permits, and it leaves the credit for those detections where it belongs.
- **This is where "changes nothing" stops being a promise about code you can read in one file.** Both tools are read-only by design, but you are the one choosing to trust them.
- **Delegation writes temporary files.** Each tool's output is captured in uniquely named temporary files, and PrivescCheck also writes its CSV report there; all of them are deleted when the run ends. Apart from `-ReportPath`, these are the only disk writes in `health-check.ps1`, and the contract test pins the process launch and the cleanup to the delegation code, so neither can appear anywhere else without failing CI.
- **PrivescCheck gives more unelevated.** It deliberately skips many checks when run as administrator, to avoid reporting things only an administrator could exploit. Run the health check as an ordinary user to get its full output.

## Hardening pass

[`hardening/harden-extras.ps1`](hardening/harden-extras.ps1) tightens the handful of settings that [Harden System Security](https://github.com/HotCakeX/Harden-Windows-Security) and ConfigureDefender leave alone. It runs standalone on any machine:

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/hardening/harden-extras.ps1 | iex
```

It reports the current state first, asks before **each** change, and skips whatever is already applied. What it offers: five ASR rules moved to Block (exploited vulnerable signed drivers, copied system tools, unsigned processes from USB, LSASS credential theft, Safe Mode reboot), NetBIOS over TCP/IP off on every interface, AutoPlay/AutoRun disabled by policy, NTLM restricted to v2 only, the hidden admin shares (`C$`, `ADMIN$`) turned off, Defender quarantine retention raised back to the 90-day default when it has been lowered, and a review of any Defender exclusions with the option to remove them all.

Two are worth a thought before you accept them: NTLMv2-only breaks authentication to gear old enough to speak NTLMv1, and turning off the admin shares breaks backup or remote-admin tools that reach `\\host\C$`. The script header documents how to undo every change. Before the first change you approve, it creates a System Restore point and starts a record in `%LOCALAPPDATA%\windows-setup\logs`: a transcript plus `hardening-before-*.json` and `hardening-after-*.json` with every value it can change, the full Defender exclusion lists included. Nothing is written while you only answer `n`, and a session without a console answers `n` to everything. Re-run it after Harden System Security, which manages some ASR rules through policy and can put them back — the script writes to the policy key when a rule lives there, because `Add-MpPreference` is silently overridden in that case.

## Bootstrap installer

Open an **elevated** PowerShell (right-click → *Run as administrator*) and paste:

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1 | iex
```

Preview every step without changing anything (this needs no elevation):

```powershell
& ([scriptblock]::Create((irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1))) -WhatIf
```

Re-running is fine: installed apps are skipped. It then asks (y/n) whether to run `winget upgrade --all`, which updates every winget app on the machine, not just the list here. Failures are listed at the end, and the run then ends in an error (exit code 1 when started as a file) instead of closing the window. Every run writes two files to `%LOCALAPPDATA%\windows-setup\logs` (kept out of `%TEMP%` so cleanup tools don't wipe them, and kept for 90 days): a full console transcript (`transcript-*.log`) and a timestamped event log (`events-*.log`) showing exactly what was installed, skipped, or failed, and when.

For an unattended run, `-Yes` answers y to every prompt and `-Skip` answers n for the steps you name, for example `-Yes -Skip DiskCleanup,TweakTools,Upgrade`; a session without a console answers n. The hardening pass still asks before each change. To run a fixed version instead of `main`, use the same tag or commit twice: `& ([scriptblock]::Create((irm https://github.com/26zl/personal-windows-setup/raw/<tag>/setup.ps1))) -RepoRef <tag>`. Set `NO_COLOR` to get the output without colours.

> `irm | iex` downloads and runs this script as Administrator. Read [`setup.ps1`](setup.ps1) first if you don't trust it. If scripts are blocked, run `Set-ExecutionPolicy -Scope Process Bypass` in the same window first.

## Requirements

- **Windows 11 Pro, x64** (Sandbox and Hyper-V need Pro and won't enable on Home; ARM64 is untested).
- **winget** (ships as *App Installer*; install it from the Microsoft Store if missing).
- An **elevated** PowerShell session (not needed for a `-WhatIf` preview), with firmware virtualization enabled for Hyper-V and WSL2.

## What it installs

- **Languages:** Python, Node.js LTS, Go, Rust, Java (Temurin 21), .NET SDK, Ruby
- **Build tools:** VS Build Tools + MSVC C++ toolset (compiler, linker, CRT, Windows SDK — for Rust MSVC & native modules), LLVM/Clang, MSYS2 (gcc/make)
- **Package managers:** pnpm, Bun, Chocolatey, Scoop, pipx, uv, UniGetUI (GUI front-end) (npm/corepack come with Node; pipx via pip)
- **Dev tools:** Git, GitHub CLI, GitHub Desktop, VS Code, Neovim (+ my [nvim config](https://github.com/26zl/nvim), opt-in), Windows Terminal, PowerShell 7, 7-Zip, VC++ Redistributables, just, jq, ripgrep, fd, adb (platform-tools)
- **Fullstack:** Docker Desktop, VirtualBox, DBeaver, Bruno
- **AI:** Ollama (local LLM runtime), CUDA Toolkit (GPU compute, several GB — installed only when an NVIDIA GPU is detected)
- **Sysadmin / net:** PowerToys, Sysinternals Suite, WinSCP, PuTTY, MobaXterm, Tailscale, WireGuard, Mullvad VPN
- **Tools:** KeePassXC, ConfigureDefender (Defender settings GUI in Program Files — installed & signature-verified only, never auto-configured)
- **Sysmon:** system activity logging to the event log — built-in Sysmon on Windows 11 24H2+ (enables the optional feature if needed), signature-checked Sysinternals download on older Windows (Sysinternals lists Windows 11 and Server 2019 or later), configured with a pinned [SwiftOnSecurity config](sysmon/sysmonconfig-export.xml) and a 1 GB log (measured at ~150 MB a day on an ordinary desktop, so roughly a week of history)
- **Hardening pass (opt-in, y/n):** offered near the end of the run — see [Hardening pass](#hardening-pass) above for what it changes
- **Browser:** Google Chrome, Tor Browser
- **Cleanup / maintenance:** Malwarebytes, AdwCleaner, BleachBit, DriverStore Explorer
- **Utilities:** Rufus, balenaEtcher, Steam, Discord (only when missing — it updates itself), Windows Notepad (Store)
- **Microsoft 365** (Personal/Family, `O365HomePremRetail`): Microsoft's click-to-run bootstrapper, downloaded from `c2rsetup.officeapps.live.com` at run time and run only when it carries a valid Microsoft Corporation signature. The Office language follows the Windows regional format (`Get-Culture`, en-us as fallback). Skipped when Word is already installed. With a work or school license, install Microsoft 365 Apps for enterprise with `winget install --id Microsoft.Office` instead.
- **Desktop shortcuts** for the portable tools (O&O ShutUp10, DriverStore Explorer, AdwCleaner, Rufus, the Sysinternals folder, ConfigureDefender)
- **Tweak / privacy:** O&O ShutUp10, Win11Debloat and Winhance (both opt-in, unpinned), Harden System Security (Store)
- **Claude Code** via its official native installer (opt-in; the installer cannot be pinned)
- **PowerShellPerfect** (my own profile; opt-in, pinned to a commit and its bundle hash)
- Enables Windows Sandbox, Hyper-V, and WSL2 with Debian as the default distro
- **System Restore points** at the start and end of the run (turns on System Protection first if it's off). Restore points cover system files, the registry and installed programs — they do **not** restore your own documents, and they do not bring back anything the disk cleanup below removed.
- **System integrity:** a DISM component-store check (auto-repairs with `/RestoreHealth` only if corruption is found) followed by `sfc /scannow`
- **Disk cleanup (opt-in, y/n):** DISM component cleanup, the Windows Update download cache, both temp folders, and the Recycle Bin. None of it is reversible, so it asks first and skips by default.
- **Dual-boot checks (opt-in, y/n):** reports boot entries, Fast Startup, hibernation, hardware-clock (UTC vs local), Secure Boot, and BitLocker, then offers to disable hibernation entirely (`powercfg /h off`, which also clears Fast Startup) and set the clock to UTC

## Customize

Open `setup.ps1` and edit the `$winget` list. Find any ID with:

```powershell
winget search <name>
```

VS Build Tools and VirtualBox are large; remove those lines if you don't need them. The CUDA Toolkit is only installed when an NVIDIA GPU is detected.

## Notes

- **Reboot when it finishes** to complete Sandbox, Hyper-V, and WSL2 (`wsl -l -v` to verify).
- **Everything extra is opt-in (y/n):** Scoop, the Neovim config, Claude Code, the tweak tools (Win11Debloat, Winhance, PowerShellPerfect), GitHub sign-in, the Neovim-in-WSL step, the hardening pass and each change inside it, each dual-boot change, `winget upgrade --all` and the disk cleanup. Tweak tools each run in their own process.
- **Not behind a prompt:** the Sysmon step. It uses the `install-sysmon.ps1` next to `setup.ps1` in a clone, or downloads it and checks it against the SHA-256 pinned in `setup.ps1`.
- **Most installers are fetched at run time** — review their URLs and contents before you run the script; see [SECURITY.md](SECURITY.md) for which ones are pinned.
- **Kubernetes** runs inside Docker Desktop (enable it in Settings); no separate cluster tooling is installed.
- **Not installed here:** cloud/ops tooling (Ansible, Terraform) and Java build tools (Maven, Gradle) — use the Debian WSL, or Chocolatey/Scoop for the Java tools.
- **More cybersecurity tooling:** [cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) (580+ Linux/Termux tools, runs from the Debian WSL).

<details>
<summary><strong>Security &amp; supply-chain</strong></summary>

- **Pins:** `setup.ps1` checks `install-sysmon.ps1` and `harden-extras.ps1` (when there is no local copy), the nvim installer, PowerShellPerfect and the WSL Neovim tarball against SHA-256 pins before anything runs, and CI fails when a pin stops matching. Downloads that run as administrator are verified in an admin-only folder under `%SystemRoot%\Temp`, so a non-elevated process cannot swap them in between.
- **ConfigureDefender** is downloaded from AndyFul's repo, verified (pinned SHA-256 + signature), copied to `Program Files\ConfigureDefender` and given a Desktop shortcut — but never launched. Open it and pick a level (Default / High / Max) yourself; refresh `$cdSha256` for new builds.
- **Re-runs are additive:** installs use `winget install --no-upgrade`, so a second run adds what is missing and never moves the version of something already installed (pipx is the exception: it is installed with `pip install --upgrade`). Upgrading is a separate, explicit step at the end of the run.
- **Sysmon on its own** (existing machine, no full run): from an elevated shell, `irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex`. Re-running reapplies the config and never shrinks a log you made larger; refresh `$configSha256` in `install-sysmon.ps1` (and `$sysmonScriptSha256` in `setup.ps1`) if you replace the XML.
- **The Sysmon config is a fork, not a copy.** The base is [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) v74 (2021, CC BY 4.0, unmaintained since). The full diff, so nobody has to hunt for it: `schemaversion` raised 4.50 → 4.81; six added rule groups in a marked block at the end of the file; 23 include-rule paths rewritten from absolute `C:\` to drive-relative. Everything else is upstream, untouched.
- **What it collects that upstream does not:** **25 `ProcessTampering`** (process hollowing has no benign explanation, and the event is rare), **26 `FileDeleteDetected`** scoped to executables, scripts, `.evtx` and shadow copies, **7 `ImageLoad`** narrowed to DLLs loading out of user-writable directories, and a `RegistryEvent` watch on `SilentProcessExit`. It leaves **23 `FileDelete`** off — that one archives every deleted file to disk and fills a drive quietly — and **24 `ClipboardChange`** off, because it captures clipboard *content*, so passwords and one-time codes would land in an event log. Requires Sysmon 14 or later. Refresh `$configSha256` if you edit the XML.
- **Why not [sysmon-modular](https://github.com/olafhartong/sysmon-modular):** measured, not assumed. It carries 246 `RegistryEvent` include rules against this config's 114, and skews to `begin with` and `contains` where this one uses `end with`. On a machine already dropping RegistryEvent under load — which is what Sysmon event 255 `QUEUE` means, and it is common — that is the wrong direction. sysmon-modular is the better base if you want to tune per module; it is not a drop-in fix for a config that is flooding. The health check reports which event IDs the channel is actually receiving, so either way a config collecting less than you think shows up as a finding.
- **Hardening pass and health check** run standalone too — see their sections above; neither needs the installer. They are read-only in different senses: the health check never changes the system (it writes only the report you ask for and short-lived temporary files when delegating), while the hardening pass reports first and applies a change only after you answer `y` to that specific change.

</details>

<details>
<summary><strong>Opt-in steps: dual-boot, GitHub, Neovim</strong></summary>

- **Dual-boot** checks are read-only until you confirm each change. Turning hibernation off (`powercfg /h off`, also clears Fast Startup) is safe for any dual boot. Set the hardware clock to UTC **only** if the other OS is Linux/macOS — not for Windows + Windows. **If BitLocker is on, back up your recovery key** before touching Secure Boot or firmware.
- **GitHub sign-in** runs `gh auth login --web`, wires git to use `gh` for credentials, and sets your global git identity (login name, `@users.noreply.github.com` when your email is hidden) plus sensible `init.defaultBranch` / `pull.rebase` / `push.autoSetupRemote` defaults.
- **Neovim** installs my [nvim config](https://github.com/26zl/nvim) into `%LOCALAPPDATA%\nvim` (backs up any existing config; plugins install on first launch) — it needs the C compiler the MSVC toolset provides. The installer is pinned to a commit and its SHA-256; the config it clones comes from that repo's default branch. It can also set up the same config in WSL Debian with a pinned Neovim release checked against its SHA-256; a fresh WSL isn't ready until after a reboot, so re-run for that part.

</details>

## License

Project code is MIT licensed. The bundled Sysmon configuration is [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), licensed CC BY 4.0; its attribution and license notice are retained in the header of [`sysmon/sysmonconfig-export.xml`](sysmon/sysmonconfig-export.xml), together with a note of what this fork changed.
