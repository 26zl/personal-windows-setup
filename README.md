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

**It changes nothing.** Every check is a `Get-`/`Test-`/query call — no `Set-`, no `Remove-`, no service or registry writes — and the few external tools it shells out to run in analysis mode only (`defrag /A`, `dism /AnalyzeComponentStore`, `fsutil behavior query`, `powercfg /query`, `auditpol /get`). Findings arrive with the observed value as evidence and the command you would run to fix it yourself, so you stay in control of what actually happens to the machine.

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

## Hardening pass

[`hardening/harden-extras.ps1`](hardening/harden-extras.ps1) tightens the handful of settings that [Harden System Security](https://github.com/HotCakeX/Harden-Windows-Security) and ConfigureDefender leave alone. It runs standalone on any machine:

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/hardening/harden-extras.ps1 | iex
```

It reports the current state first, asks before **each** change, and skips whatever is already applied. What it offers: five ASR rules moved to Block (exploited vulnerable signed drivers, copied system tools, unsigned processes from USB, LSASS credential theft, Safe Mode reboot), NetBIOS over TCP/IP off on every interface, AutoPlay/AutoRun disabled by policy, NTLM restricted to v2 only, the hidden admin shares (`C$`, `ADMIN$`) turned off, and an audit of any Defender exclusions.

Two are worth a thought before you accept them: NTLMv2-only breaks authentication to gear old enough to speak NTLMv1, and turning off the admin shares breaks backup or remote-admin tools that reach `\\host\C$`. The script header documents how to undo every change. Re-run it after Harden System Security, which manages some ASR rules through policy and can put them back — the script writes to the policy key when a rule lives there, because `Add-MpPreference` is silently overridden in that case.

## Bootstrap installer

Open an **elevated** PowerShell (right-click → *Run as administrator*) and paste:

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1 | iex
```

Re-running is fine: installed apps are skipped. It then asks (y/n) whether to run `winget upgrade --all`, which updates every winget app on the machine, not just the list here. Failures are listed at the end. Every run writes two files to `%LOCALAPPDATA%\windows-setup\logs` (kept out of `%TEMP%` so cleanup tools don't wipe them): a full console transcript (`transcript-*.log`) and a timestamped event log (`events-*.log`) showing exactly what was installed, skipped, or failed, and when.

> `irm | iex` downloads and runs this script as Administrator. Read [`setup.ps1`](setup.ps1) first if you don't trust it. If scripts are blocked, run `Set-ExecutionPolicy -Scope Process Bypass` in the same window first.

## Requirements

- **Windows 11 Pro, x64** (Sandbox and Hyper-V need Pro and won't enable on Home; ARM64 is untested).
- **winget** (ships as *App Installer*; install it from the Microsoft Store if missing).
- An **elevated** PowerShell session, with firmware virtualization enabled for Hyper-V and WSL2.

## What it installs

- **Languages:** Python, Node.js LTS, Go, Rust, Java (Temurin 21), .NET SDK, Ruby
- **Build tools:** VS Build Tools + MSVC C++ toolset (compiler, linker, CRT, Windows SDK — for Rust MSVC & native modules), LLVM/Clang, MSYS2 (gcc/make)
- **Package managers:** pnpm, Bun, Chocolatey, Scoop, pipx, uv, UniGetUI (GUI front-end) (npm/corepack come with Node; pipx via pip)
- **Dev tools:** Git, GitHub CLI, GitHub Desktop, VS Code, Neovim (+ my [nvim config](https://github.com/26zl/nvim)), Windows Terminal, PowerShell 7, 7-Zip, VC++ Redistributables, just, jq, ripgrep, fd, adb (platform-tools)
- **Fullstack:** Docker Desktop, VirtualBox, DBeaver, Bruno
- **AI:** Ollama (local LLM runtime), CUDA Toolkit (GPU compute — several GB, and only useful on an NVIDIA GPU)
- **Sysadmin / net:** PowerToys, Sysinternals Suite, WinSCP, PuTTY, MobaXterm, Tailscale, WireGuard, Mullvad VPN
- **Cybersec:** Wireshark, Nmap, Burp Suite Community, KeePassXC, ConfigureDefender (Defender settings GUI — installed & signature-verified only, never auto-configured)
- **Sysmon:** system activity logging to the event log — built-in Sysmon on Windows 11 24H2+ (enables the optional feature if needed), signature-checked Sysinternals download on older Windows, configured with a pinned [SwiftOnSecurity config](sysmon/sysmonconfig-export.xml) and a 512 MB log
- **Hardening pass (opt-in, y/n):** offered near the end of the run — see [Hardening pass](#hardening-pass) above for what it changes
- **Browser:** Google Chrome, Tor Browser
- **Cleanup / maintenance:** Malwarebytes, AdwCleaner, BleachBit, DriverStore Explorer
- **Utilities:** Rufus, balenaEtcher, Steam, Windows Notepad (Store)
- **Tweak / privacy:** O&O ShutUp10, Win11Debloat, Winhance, Harden System Security (Store)
- **Claude Code** via its official native installer
- **PowerShellPerfect** (my own profile)
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

VS Build Tools, VirtualBox and the CUDA Toolkit are large; remove those lines if you don't need them. CUDA in particular is several GB and does nothing without an NVIDIA GPU.

## Notes

- **Reboot when it finishes** to complete Sandbox, Hyper-V, and WSL2 (`wsl -l -v` to verify).
- **Everything extra is opt-in (y/n):** the tweak tools (Win11Debloat, Winhance, PowerShellPerfect), GitHub sign-in, the Neovim-in-WSL step, the hardening pass and each change inside it, and each dual-boot change. Tweak tools each run in their own process.
- **Most installers are fetched at run time** — review their URLs and contents before you opt in.
- **Kubernetes** runs inside Docker Desktop (enable it in Settings); no separate cluster tooling is installed.
- **Not installed here:** cloud/ops tooling (Ansible, Terraform) and Java build tools (Maven, Gradle) — use the Debian WSL, or Chocolatey/Scoop for the Java tools.
- **More cybersecurity tooling:** [cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) (580+ Linux/Termux tools, runs from the Debian WSL).

<details>
<summary><strong>Security &amp; supply-chain</strong></summary>

- **`OfficeSetup.exe`** is Microsoft's signed stub; the script verifies its pinned SHA-256 and Authenticode signature before running it. Refresh `$officeSha256` (`Get-FileHash office\OfficeSetup.exe`) if you replace it.
- **ConfigureDefender** is downloaded from AndyFul's repo, verified (pinned SHA-256 + signature), and given a Desktop shortcut — but never launched. Open it and pick a level (Default / High / Max) yourself; refresh `$cdSha256` for new builds.
- **Re-runs are additive:** installs use `winget install --no-upgrade`, so a second run adds what is missing and never moves the version of something already installed. Upgrading is a separate, explicit step at the end of the run.
- **Sysmon on its own** (existing machine, no full run): from an elevated shell, `irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex`. Re-running only reapplies the config; refresh `$configSha256` in `install-sysmon.ps1` if you replace the XML.
- **What the Sysmon config does *not* collect:** the bundled copy is SwiftOnSecurity source version 74 (2021-07-08, schemaversion 4.50), and it keeps upstream's three commented-out rule groups off — event 23 `FileDelete`, 24 `ClipboardChange`, and 25 `ProcessTampering`. That is upstream's deliberate default (FileDelete archives deleted files and can fill a disk; ProcessTampering needs tuning and a SIEM), but it is a blind spot: files being wiped and code injected into a live process leave no trace. Uncomment the rule group in the XML, refresh `$configSha256`, and reload with `sysmon -c`. The health check reports which event IDs the channel is actually receiving, so a config that silently collects less than you think shows up as a finding.
- **Hardening pass and health check** run standalone too — see their sections above; neither needs the installer. They are read-only in different senses: the health check never writes anything at all, while the hardening pass reports first and applies a change only after you answer `y` to that specific change.

</details>

<details>
<summary><strong>Opt-in steps: dual-boot, GitHub, Neovim</strong></summary>

- **Dual-boot** checks are read-only until you confirm each change. Turning hibernation off (`powercfg /h off`, also clears Fast Startup) is safe for any dual boot. Set the hardware clock to UTC **only** if the other OS is Linux/macOS — not for Windows + Windows. **If BitLocker is on, back up your recovery key** before touching Secure Boot or firmware.
- **GitHub sign-in** runs `gh auth login --web`, wires git to use `gh` for credentials, and sets your global git identity (login name, `@users.noreply.github.com` when your email is hidden) plus sensible `init.defaultBranch` / `pull.rebase` / `push.autoSetupRemote` defaults.
- **Neovim** installs my [nvim config](https://github.com/26zl/nvim) into `%LOCALAPPDATA%\nvim` (backs up any existing config; plugins install on first launch) — it needs the C compiler the MSVC toolset provides. It can also set up the same config in WSL Debian; a fresh WSL isn't ready until after a reboot, so re-run for that part.

</details>

## License

Project code is MIT licensed. The bundled Sysmon configuration is [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), licensed CC BY 4.0; its attribution and license notice are retained in the header of [`sysmon/sysmonconfig-export.xml`](sysmon/sysmonconfig-export.xml).
