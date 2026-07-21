# personal-windows-setup

[![lint](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml/badge.svg)](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml)
![Platform](https://img.shields.io/badge/platform-Windows%2011%20Pro-0078D6?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Personal installer for a fresh **Windows 11 Pro** PC after a factory reset.
Installs everything with winget, plus a few official external installers.
It isn't meant to cover everything, just a solid starting point with the basics.

## Run

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
- **Dev tools:** Git, GitHub CLI, GitHub Desktop, VS Code, Windows Terminal, PowerShell 7, 7-Zip, VC++ Redistributables, just, jq, adb (platform-tools)
- **Fullstack:** Docker Desktop, VirtualBox, DBeaver, Bruno
- **AI:** Ollama (local LLM runtime)
- **Sysadmin / net:** PowerToys, Sysinternals Suite, WinSCP, PuTTY, MobaXterm, Tailscale, WireGuard, Mullvad VPN
- **Cybersec:** Wireshark, Nmap, Burp Suite Community, KeePassXC, ConfigureDefender (Defender settings GUI — installed & signature-verified only, never auto-configured)
- **Sysmon:** system activity logging to the event log — built-in Sysmon on Windows 11 24H2+ (enables the optional feature if needed), signature-checked Sysinternals download on older Windows, configured with a pinned [SwiftOnSecurity config](sysmon/sysmonconfig-export.xml) and a 512 MB log
- **Browser:** Google Chrome, Tor Browser
- **Cleanup / maintenance:** Malwarebytes, AdwCleaner, BleachBit, DriverStore Explorer
- **Utilities:** Rufus, balenaEtcher, Steam, Windows Notepad (Store)
- **Tweak / privacy:** O&O ShutUp10, Win11Debloat, Winhance, Harden System Security (Store)
- **Claude Code** via its official native installer
- **PowerShellPerfect** (my own profile)
- Enables Windows Sandbox, Hyper-V, and WSL2 with Debian as the default distro
- **System integrity:** a DISM component-store check (auto-repairs with `/RestoreHealth` only if corruption is found) followed by `sfc /scannow`
- **Disk cleanup** (runs near the end, just before the external tweak tools): DISM component cleanup, the Windows Update download cache, temp folders, and the Recycle Bin
- **Dual-boot checks (opt-in, y/n):** reports boot entries, Fast Startup, hibernation, hardware-clock (UTC vs local), Secure Boot, and BitLocker, then offers to disable hibernation entirely (`powercfg /h off`, which also clears Fast Startup) and set the clock to UTC

## Customize

Open `setup.ps1` and edit the `$winget` list. Find any ID with:

```powershell
winget search <name>
```

VS Build Tools and VirtualBox are large; remove those lines if you don't need them.

## Notes

- Reboot after running to finish Sandbox, Hyper-V, and WSL2 (`wsl -l -v` to verify).
- The external tweak tools (Win11Debloat, Winhance, PowerShellPerfect) only run if you explicitly type `y`, and each runs in its own process.
- Automatic installers come from the named vendors or projects; review their URLs and current contents before opting in because most are fetched at run time.
- The bundled `OfficeSetup.exe` is Microsoft's signed setup stub; the script verifies its pinned SHA-256 hash and Microsoft's Authenticode signature before running it. If you ever replace the stub, refresh `$officeSha256` in `setup.ps1` with `Get-FileHash office\OfficeSetup.exe`.
- Before updating, the script sets winget's `installBehavior.upgradeDelayInDays` to **7** in `settings.json`, so `winget upgrade --all` (and any future upgrade) skips packages released in the last 7 days. This is a **supply-chain safeguard**, not a bug-fix delay: if a publisher is compromised and pushes a malicious release, the window keeps it off the machine long enough for the bad version to be spotted and pulled before it auto-installs. It merges into your existing winget settings rather than overwriting them. Change the `7` in `setup.ps1`, or clear it later with `winget settings`.
- **ConfigureDefender** is downloaded from AndyFul's official repo and verified (pinned SHA-256 + the author's Authenticode signature) before it's kept, then given a Desktop shortcut. It is never launched or auto-configured — open it and pick a protection level (Default / High / Max) yourself. Refresh `$cdSha256` in `setup.ps1` if AndyFul ships a new build.
- **Dual-boot** checks are opt-in (y/n) and read-only until you confirm each change. Disabling hibernation (`powercfg /h off`, which also clears Fast Startup) is safe for any dual boot and should be done in *every* Windows install that shares the disk. Setting the hardware clock to UTC is only correct when the other OS uses UTC (Linux/macOS) — leave it off for Windows + Windows. If BitLocker is on, back up your recovery key before touching Secure Boot or firmware settings or you may hit a recovery prompt at boot.
- Sysmon can also be set up on its own (existing machines, no full setup needed) from an elevated PowerShell: `irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex`. Re-running only reapplies the config. If you replace `sysmon\sysmonconfig-export.xml` (e.g. with a newer SwiftOnSecurity release), refresh `$configSha256` in `install-sysmon.ps1` with `Get-FileHash sysmon\sysmonconfig-export.xml`.
- Kubernetes runs inside Docker Desktop (enable it in Settings); no separate cluster tooling is installed.
- Cloud and ops tooling (Ansible, Terraform, and similar) isn't installed by this script; install and run it inside the Debian WSL environment.
- Java build tools (Maven, Gradle) aren't on winget; install them via Chocolatey or Scoop in a normal shell, or from the Debian WSL.
- For advanced cybersecurity tooling, see [cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) (580+ Linux/Termux tools; runs from the Debian WSL above).

## License

Project code is MIT licensed. The bundled Sysmon configuration is [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), licensed CC BY 4.0; its attribution and license notice are retained in the header of [`sysmon/sysmonconfig-export.xml`](sysmon/sysmonconfig-export.xml).
